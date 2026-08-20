package terminal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/vault"
	"golang.org/x/crypto/ssh"
)

// HostKeyPrompter asks the user to approve an unrecognised host key.
//
// Implemented by the WebSocket bridge, which sends a prompt and waits for the
// answer. It is an interface so the connect path can be tested without a
// browser — and so a future non-interactive caller can supply a policy
// instead.
type HostKeyPrompter interface {
	// PromptHostKey returns true when the user accepts.
	//
	// The context bounds the wait: a prompt nobody answers must not hold an
	// SSH handshake open forever.
	PromptHostKey(ctx context.Context, info HostKeyInfo) (bool, error)
}

// Connector opens terminals for saved connections.
type Connector struct {
	manager     *Manager
	sessions    *sessions.Store
	credentials *credentials.Store
	hostKeys    *hostkeys.Store
	log         *slog.Logger
}

// NewConnector builds a Connector.
func NewConnector(
	manager *Manager,
	sess *sessions.Store,
	creds *credentials.Store,
	hostKeys *hostkeys.Store,
	log *slog.Logger,
) *Connector {
	if log == nil {
		log = slog.Default()
	}
	return &Connector{manager: manager, sessions: sess, credentials: creds, hostKeys: hostKeys, log: log}
}

// ConnectParams describes a connection to open.
type ConnectParams struct {
	UserID    string
	SessionID string

	// VaultKey decrypts the stored credential. Used for the length of the
	// dial and not retained.
	VaultKey vault.Key

	Cols int
	Rows int

	// Prompter is asked about unrecognised host keys.
	Prompter HostKeyPrompter

	// Progress reports what is happening, so the user sees something other
	// than a blank rectangle while a slow host is dialled.
	Progress func(status string)
}

// ConnectError carries a code the interface can branch on.
type ConnectError struct {
	Code    string
	Message string
	Err     error

	// HostKey carries the fingerprints when the failure was a changed key,
	// so the interface can show what was expected and what was offered.
	HostKey *HostKeyInfo
}

func (e *ConnectError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ConnectError) Unwrap() error { return e.Err }

// Connect opens a terminal for a saved connection.
func (c *Connector) Connect(ctx context.Context, p ConnectParams) (*Terminal, error) {
	progress := p.Progress
	if progress == nil {
		progress = func(string) {}
	}

	resolved, err := c.sessions.Resolve(ctx, p.UserID, p.SessionID)
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return nil, &ConnectError{Code: ErrCodeNotFound, Message: "That saved connection no longer exists."}
		}
		return nil, &ConnectError{Code: ErrCodeInternal, Message: "The saved connection could not be read.", Err: err}
	}

	if resolved.Protocol != sessions.ProtocolSSH {
		return nil, &ConnectError{
			Code:    ErrCodeInternal,
			Message: fmt.Sprintf("%s connections are not supported yet.", resolved.Protocol),
		}
	}

	cred, err := c.buildCredential(ctx, p, resolved)
	if err != nil {
		return nil, err
	}
	// The decrypted key exists only for this dial.
	defer cred.Zero()

	progress(StatusDialling)

	client, err := c.dial(ctx, p, resolved, cred, progress)
	if err != nil {
		return nil, err
	}

	progress(StatusConnected)

	term, err := c.manager.Open(client, OpenParams{
		UserID:    p.UserID,
		SessionID: resolved.ID,
		Label:     resolved.Name,
		Username:  cred.Username,
		Cols:      p.Cols,
		Rows:      p.Rows,
	})
	if err != nil {
		return nil, &ConnectError{Code: ErrCodeInternal, Message: "The remote shell could not be started.", Err: err}
	}

	if err := c.sessions.MarkUsed(ctx, resolved.ID); err != nil {
		c.log.Warn("recording session use", "error", err)
	}

	return term, nil
}

// buildCredential decrypts the credential a saved connection names.
func (c *Connector) buildCredential(ctx context.Context, p ConnectParams, resolved sessions.Resolved) (sshx.Credential, error) {
	cred := sshx.Credential{Username: resolved.EffectiveUsername}

	if cred.Username == "" {
		return sshx.Credential{}, &ConnectError{
			Code:    ErrCodeNoCredential,
			Message: "This connection has no username. Set one on the connection or its folder.",
		}
	}
	if resolved.EffectiveCredentialID == "" {
		return sshx.Credential{}, &ConnectError{
			Code:    ErrCodeNoCredential,
			Message: "This connection has no credential. Choose a key or password for it.",
		}
	}
	if p.VaultKey == nil {
		return sshx.Credential{}, &ConnectError{
			Code:    ErrCodeVaultLocked,
			Message: "Your vault is locked. Enter your passphrase to connect.",
		}
	}

	meta, err := c.credentials.Get(ctx, p.UserID, resolved.EffectiveCredentialID)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			return sshx.Credential{}, &ConnectError{
				Code:    ErrCodeNoCredential,
				Message: "The credential this connection uses no longer exists.",
			}
		}
		return sshx.Credential{}, &ConnectError{Code: ErrCodeInternal, Message: "The credential could not be read.", Err: err}
	}

	secret, err := c.credentials.Reveal(ctx, p.VaultKey, p.UserID, resolved.EffectiveCredentialID)
	if err != nil {
		return sshx.Credential{}, &ConnectError{
			Code:    ErrCodeInternal,
			Message: "The credential could not be decrypted.",
			Err:     err,
		}
	}
	defer secret.Zero()

	switch meta.Kind {
	case credentials.KindSSHKey:
		cred.PrivateKey = []byte(secret.Value)
		cred.Passphrase = secret.Extra
	default:
		cred.Password = secret.Value
	}

	if meta.Username != "" && resolved.Session.Username == "" {
		// The credential's own username applies only when the connection did
		// not specify one, so an explicit choice is never overridden.
		cred.Username = meta.Username
	}

	return cred, nil
}

// dial opens the SSH connection, wiring host key verification to the prompter.
func (c *Connector) dial(
	ctx context.Context,
	p ConnectParams,
	resolved sessions.Resolved,
	cred sshx.Credential,
	progress func(string),
) (*sshx.Client, error) {
	// Records what the verification decided, so a failure can be reported
	// with the right code rather than a generic handshake error.
	var (
		lastVerdict hostkeys.Verdict
		lastCheck   hostkeys.Check
	)

	verify := func(ctx context.Context, hostname string, port int, key ssh.PublicKey) (hostkeys.Check, error) {
		progress(StatusVerifyingHost)
		check, err := c.hostKeys.Verify(ctx, p.UserID, hostname, port, key)
		if err == nil {
			lastVerdict, lastCheck = check.Verdict, check
		}
		return check, err
	}

	decide := func(ctx context.Context, check hostkeys.Check) error {
		switch check.Verdict {
		case hostkeys.VerdictTrusted:
			progress(StatusAuthenticating)
			return nil

		case hostkeys.VerdictChanged:
			// No prompt. There is no answer that continues safely, and
			// offering one would train people to click through it.
			return sshx.ErrHostKeyRejected

		default: // unknown
			if p.Prompter == nil {
				return sshx.ErrHostKeyRejected
			}

			info := HostKeyInfo{
				Hostname:    resolved.Hostname,
				Port:        resolved.EffectivePort,
				KeyType:     check.Presented.KeyType,
				Fingerprint: check.Presented.Fingerprint,
			}

			accepted, err := p.Prompter.PromptHostKey(ctx, info)
			if err != nil {
				return fmt.Errorf("%w: %v", sshx.ErrHostKeyRejected, err)
			}
			if !accepted {
				return sshx.ErrHostKeyRejected
			}

			// Recorded only after the user accepts, so a declined prompt
			// leaves no trace that would skip the question next time.
			if _, err := c.hostKeys.Trust(ctx, p.UserID, resolved.Hostname,
				resolved.EffectivePort, check.Presented); err != nil {
				return fmt.Errorf("terminal: recording the host key: %w", err)
			}

			progress(StatusAuthenticating)
			return nil
		}
	}

	keepAlive := sshx.DefaultKeepAlive
	if resolved.Settings.KeepAliveSeconds != nil && *resolved.Settings.KeepAliveSeconds > 0 {
		keepAlive = time.Duration(*resolved.Settings.KeepAliveSeconds) * time.Second
	}

	client, err := sshx.Dial(ctx, sshx.Config{
		Target:     sshx.Target{Hostname: resolved.Hostname, Port: resolved.EffectivePort},
		Credential: cred,
		Verify:     verify,
		Decide:     decide,
		KeepAlive:  keepAlive,
	})
	if err != nil {
		return nil, c.classify(err, resolved, lastVerdict, lastCheck)
	}
	return client, nil
}

// classify turns a dial failure into something the interface can act on.
func (c *Connector) classify(
	err error,
	resolved sessions.Resolved,
	verdict hostkeys.Verdict,
	check hostkeys.Check,
) error {
	where := hostkeys.Describe(resolved.Hostname, resolved.EffectivePort)
	changedKey := ChangedKeyInfo(resolved, check)

	switch {
	case errors.Is(err, sshx.ErrHostKeyRejected) && verdict == hostkeys.VerdictChanged:
		return &ConnectError{
			Code: ErrCodeHostKeyChanged,
			Message: fmt.Sprintf(
				"The host key for %s has changed. This can mean the host was rebuilt — "+
					"or that something is impersonating it. The connection was refused.", where),
			Err: err,
			// Both fingerprints, so the interface can show the difference
			// rather than merely asserting one exists.
			HostKey: &changedKey,
		}

	case errors.Is(err, sshx.ErrHostKeyRejected):
		return &ConnectError{
			Code:    ErrCodeHostKeyRejected,
			Message: fmt.Sprintf("The host key for %s was not accepted, so nothing was sent to it.", where),
			Err:     err,
		}

	case errors.Is(err, sshx.ErrAuthFailed):
		return &ConnectError{
			Code:    ErrCodeAuthFailed,
			Message: fmt.Sprintf("%s refused the credential. Check the username and the key or password.", where),
			Err:     err,
		}

	case errors.Is(err, sshx.ErrUnreachable):
		return &ConnectError{
			Code:    ErrCodeUnreachable,
			Message: fmt.Sprintf("%s could not be reached. Check the address, the port, and the route to it.", where),
			Err:     err,
		}

	case errors.Is(err, sshx.ErrNoCredential):
		return &ConnectError{
			Code:    ErrCodeNoCredential,
			Message: "No usable credential was available for this connection.",
			Err:     err,
		}

	default:
		return &ConnectError{
			Code:    ErrCodeInternal,
			Message: fmt.Sprintf("The connection to %s failed.", where),
			Err:     err,
		}
	}
}

// ChangedKeyInfo builds the detail for a changed-key report, so the interface
// can show both fingerprints and when the recorded one was trusted.
func ChangedKeyInfo(resolved sessions.Resolved, check hostkeys.Check) HostKeyInfo {
	info := HostKeyInfo{
		Hostname:    resolved.Hostname,
		Port:        resolved.EffectivePort,
		KeyType:     check.Presented.KeyType,
		Fingerprint: check.Presented.Fingerprint,
	}
	if check.Existing != nil {
		info.PreviousFingerprint = check.Existing.Fingerprint
		info.PreviouslySeen = check.Existing.CreatedAt.Format(time.RFC3339)
		info.OrgWide = check.Existing.IsOrgWide()
	}
	return info
}
