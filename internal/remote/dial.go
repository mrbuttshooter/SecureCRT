package remote

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/vault"
	"golang.org/x/crypto/ssh"
)

// Status values reported while a connection is being established.
//
// Without them the user stares at a blank rectangle wondering whether
// anything is happening.
const (
	StatusDialling = "dialling"

	// StatusDiallingHop is reported per jump host. A chain of three takes
	// three handshakes and three host key checks, and a user watching a blank
	// rectangle deserves to know which one is slow.
	StatusDiallingHop = "dialling_hop"

	StatusVerifyingHost  = "verifying_host"
	StatusAuthenticating = "authenticating"
	StatusConnected      = "connected"
	StatusReattached     = "reattached"
)

// Error codes a caller can branch on.
const (
	// CodeHostKeyChanged means the host presented a different key. The most
	// serious thing this system reports.
	CodeHostKeyChanged = "host_key_changed"

	// CodeHostKeyRejected means an unknown key was not accepted.
	CodeHostKeyRejected = "host_key_rejected"

	// CodeAuthFailed means the host refused the credential.
	CodeAuthFailed = "auth_failed"

	// CodeUnreachable means the host could not be contacted.
	CodeUnreachable = "unreachable"

	// CodeVaultLocked means the vault must be open to read the credential.
	CodeVaultLocked = "vault_locked"

	// CodeNoCredential means the saved connection names no usable credential.
	// #nosec G101 -- an error code, not a credential.
	CodeNoCredential = "no_credential"

	// CodeNotFound means the saved connection is unknown.
	CodeNotFound = "not_found"

	// CodeJumpChain means the route through jump hosts is unusable — a hop
	// was deleted, or the chain loops. Distinct from unreachable on purpose:
	// nothing was dialled, so nothing timed out and no host refused anything.
	CodeJumpChain = "jump_chain_invalid"

	// CodeInternal is anything else.
	// CodeProtocolDisabled is an operator's decision rather than a fault:
	// the connection is fine, this server has been told not to make it.
	// Distinct from CodeInternal because it sends a person to their
	// administrator rather than to a bug report.
	CodeProtocolDisabled = "protocol_disabled"

	CodeInternal = "internal_error"
)

// HostKeyInfo describes a host key for the approval dialog.
type HostKeyInfo struct {
	Hostname    string `json:"hostname"`
	Port        int    `json:"port"`
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`

	// PreviousFingerprint is set when the key has changed, so the interface
	// can show both rather than merely asserting a difference.
	PreviousFingerprint string `json:"previous_fingerprint,omitempty"`

	// PreviouslySeen is when the recorded key was first trusted. A key
	// trusted years ago changing today reads very differently from one
	// trusted this morning.
	PreviouslySeen string `json:"previously_seen,omitempty"`

	// OrgWide reports that the recorded key was published by an
	// administrator, which means the user cannot override it.
	OrgWide bool `json:"org_wide,omitempty"`

	// Label is the saved connection's name, so a prompt can say which device
	// this is rather than only which address.
	Label string `json:"label,omitempty"`

	// JumpHop is set when this key belongs to a jump host rather than to the
	// connection the user asked for.
	JumpHop *HopInfo `json:"jump_hop,omitempty"`
}

// HostKeyPrompter asks the user to approve an unrecognised host key.
//
// An interface so the connect path can be tested without a browser, and so a
// caller that cannot ask — a background transfer, say — can supply a policy
// instead. A nil prompter refuses unknown keys, which is the safe default.
type HostKeyPrompter interface {
	// PromptHostKey returns true when the user accepts.
	//
	// The context bounds the wait: a prompt nobody answers must not hold an
	// SSH handshake open forever.
	PromptHostKey(ctx context.Context, info HostKeyInfo) (bool, error)
}

// Error carries a code the interface can branch on.
type Error struct {
	Code    string
	Message string
	Err     error

	// HostKey carries the fingerprints when the failure was a changed key,
	// so the interface can show what was expected and what was offered.
	HostKey *HostKeyInfo

	// Hop names the jump host a failure happened on, when it was not the
	// connection the user asked for. Without it, "the host refused the
	// credential" sends somebody to debug a device that never saw one.
	Hop *HopInfo
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// Dialer turns a saved connection into a live, shared SSH connection.
type Dialer struct {
	pool        *Pool
	sessions    *sessions.Store
	credentials *credentials.Store
	hostKeys    *hostkeys.Store
	log         *slog.Logger
}

// NewDialer builds a Dialer.
func NewDialer(
	pool *Pool,
	sess *sessions.Store,
	creds *credentials.Store,
	hostKeys *hostkeys.Store,
	log *slog.Logger,
) *Dialer {
	if log == nil {
		log = slog.Default()
	}
	return &Dialer{pool: pool, sessions: sess, credentials: creds, hostKeys: hostKeys, log: log}
}

// Pool exposes the underlying pool, for shutdown and diagnostics.
func (d *Dialer) Pool() *Pool { return d.pool }

// Params describes a connection to open.
type Params struct {
	UserID    string
	SessionID string

	// VaultKey decrypts the stored credential. Used for the length of the
	// dial and not retained.
	VaultKey vault.Key

	// Prompter is asked about unrecognised host keys. Nil refuses them.
	Prompter HostKeyPrompter

	// Progress reports what is happening while a slow host is dialled.
	Progress func(status string)
}

// Connection is a lease plus what the saved connection resolved to.
type Connection struct {
	*Lease

	// Resolved is the saved connection with folder inheritance applied, so
	// callers do not each repeat the lookup.
	Resolved sessions.Resolved

	// Username is who the connection authenticated as, which is not always
	// the connection's own username — a credential can carry one.
	Username string

	// Via is the route taken, outermost hop first, empty for a direct dial.
	// Carried so a terminal tab can show what it went through and the audit
	// log can record it.
	Via []HopInfo

	// AgentKeys names the keys forwarded to this host, empty when none were.
	//
	// "Which keys did I expose to that switch" is a question asked after the
	// fact, usually a bad afternoon after the fact, and it needs an answer
	// that does not depend on the connection still being open.
	AgentKeys []string
}

// Acquire returns a shared connection for a saved connection, dialling only
// if one is not already open.
//
// The common case on a busy day is that it is: someone with a terminal open
// on a switch who then browses its filesystem gets the connection they
// already have, with no second host key check and no second authentication.
func (d *Dialer) Acquire(ctx context.Context, p Params) (*Connection, error) {
	progress := p.Progress
	if progress == nil {
		progress = func(string) {}
	}

	resolved, err := d.sessions.Resolve(ctx, p.UserID, p.SessionID)
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return nil, &Error{Code: CodeNotFound, Message: "That saved connection no longer exists."}
		}
		return nil, &Error{Code: CodeInternal, Message: "The saved connection could not be read.", Err: err}
	}

	if resolved.Protocol != sessions.ProtocolSSH {
		return nil, &Error{
			Code:    CodeInternal,
			Message: fmt.Sprintf("%s connections are not supported yet.", resolved.Protocol),
		}
	}

	// Resolved before dialling even when the connection turns out to be
	// pooled: the caller needs the username, and a connection whose
	// credential has since been deleted should fail here rather than later.
	cred, err := d.buildCredential(ctx, p, resolved)
	if err != nil {
		return nil, err
	}
	// The decrypted key exists only for this dial.
	defer cred.Zero()
	username := cred.Username

	// The keyring, if this connection forwards one. Built before the pool is
	// consulted for the same reason the credential is: a connection naming a
	// key that has since been deleted should say so now.
	//
	// If the connection turns out to be pooled, this keyring is discarded and
	// the one the original dial built stays in place. So editing the agent
	// keys on a connection that is already open takes effect the next time it
	// is dialled, which is the same staleness the credential already has and
	// for the same reason — a shared connection has one identity, not one per
	// caller.
	keyring, agentKeys, err := d.buildAgent(ctx, p, resolved)
	if err != nil {
		return nil, err
	}

	// The route is expanded before anything is dialled, so a chain naming a
	// host that has since been deleted fails as a broken route rather than as
	// a mysterious connection failure.
	hops, err := d.sessions.ExpandJumpChain(ctx, p.UserID, resolved.ID)
	if err != nil {
		return nil, &Error{
			Code: CodeJumpChain,
			Message: "This connection is reached through jump hosts, and that route " +
				"is no longer usable. Check the jump hosts on the connection.",
			Err: err,
		}
	}

	route := make([]string, len(hops))
	for i, hop := range hops {
		route[i] = hop.ID
	}
	key := PathKey(p.UserID, route, resolved.ID)

	lease, err := d.pool.Acquire(ctx, key,
		func(ctx context.Context) (*sshx.Client, func(), error) {
			progress(StatusDialling)
			return d.dialThrough(ctx, p, resolved, hops, cred, keyring, progress)
		})
	if err != nil {
		return nil, err
	}

	progress(StatusConnected)

	if err := d.sessions.MarkUsed(ctx, resolved.ID); err != nil {
		d.log.Warn("recording session use", "error", err)
	}

	return &Connection{
		Lease: lease, Resolved: resolved, Username: username,
		Via:       hopInfo(hops),
		AgentKeys: agentKeys,
	}, nil
}

// buildCredential decrypts the credential a saved connection names.
func (d *Dialer) buildCredential(ctx context.Context, p Params, resolved sessions.Resolved) (sshx.Credential, error) {
	cred := sshx.Credential{Username: resolved.EffectiveUsername}

	if cred.Username == "" {
		return sshx.Credential{}, &Error{
			Code:    CodeNoCredential,
			Message: "This connection has no username. Set one on the connection or its folder.",
		}
	}
	if resolved.EffectiveCredentialID == "" {
		return sshx.Credential{}, &Error{
			Code:    CodeNoCredential,
			Message: "This connection has no credential. Choose a key or password for it.",
		}
	}
	if p.VaultKey == nil {
		return sshx.Credential{}, &Error{
			Code:    CodeVaultLocked,
			Message: "Your vault is locked. Enter your passphrase to connect.",
		}
	}

	meta, err := d.credentials.Get(ctx, p.UserID, resolved.EffectiveCredentialID)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			return sshx.Credential{}, &Error{
				Code:    CodeNoCredential,
				Message: "The credential this connection uses no longer exists.",
			}
		}
		return sshx.Credential{}, &Error{Code: CodeInternal, Message: "The credential could not be read.", Err: err}
	}

	secret, err := d.credentials.Reveal(ctx, p.VaultKey, p.UserID, resolved.EffectiveCredentialID)
	if err != nil {
		return sshx.Credential{}, &Error{
			Code:    CodeInternal,
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
// dialOne opens a connection to a single node, which may be the connection the
// user asked for or a jump host on the way to it.
//
// Every closure below reads from `resolved`, which is the node actually being
// dialled — not the eventual target. That distinction is the whole of per-hop
// identity: a bastion is verified under its own hostname and port, prompted
// for under its own name, and recorded in the trust store as itself. Reusing
// the target's identity here would trust a bastion's key under the target's
// hostname, which corrupts the trust store and shows the user a fingerprint
// attributed to a device that never presented it.
//
// through is the connection to dial from. Nil means from this host.
func (d *Dialer) dialOne(
	ctx context.Context,
	p Params,
	resolved sessions.Resolved,
	cred sshx.Credential,
	keyring agent.Agent,
	through *sshx.Client,
	hop *HopInfo,
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
		check, err := d.hostKeys.Verify(ctx, p.UserID, hostname, port, key)
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
				Label:       resolved.Name,
			}
			if hop != nil {
				// Somebody approving a fingerprint has to know which device
				// they are approving. A prompt naming an unexplained hostname
				// the user did not ask to connect to is how people learn to
				// click through host key prompts.
				info.JumpHop = hop
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
			if _, err := d.hostKeys.Trust(ctx, p.UserID, resolved.Hostname,
				resolved.EffectivePort, check.Presented); err != nil {
				return fmt.Errorf("remote: recording the host key: %w", err)
			}

			progress(StatusAuthenticating)
			return nil
		}
	}

	keepAlive := sshx.DefaultKeepAlive
	if resolved.Settings.KeepAliveSeconds != nil && *resolved.Settings.KeepAliveSeconds > 0 {
		keepAlive = time.Duration(*resolved.Settings.KeepAliveSeconds) * time.Second
	}

	var transport sshx.Transport
	if through != nil {
		transport = sshx.ThroughClient(through)
	}

	client, err := sshx.Dial(ctx, sshx.Config{
		Target:     sshx.Target{Hostname: resolved.Hostname, Port: resolved.EffectivePort},
		Credential: cred,
		Verify:     verify,
		Decide:     decide,
		KeepAlive:  keepAlive,
		Transport:  transport,
		Agent:      keyring,
	})
	if err != nil {
		return nil, classify(err, resolved, lastVerdict, lastCheck)
	}
	return client, nil
}

// classify turns a dial failure into something the interface can act on.
func classify(
	err error,
	resolved sessions.Resolved,
	verdict hostkeys.Verdict,
	check hostkeys.Check,
) error {
	where := hostkeys.Describe(resolved.Hostname, resolved.EffectivePort)
	changedKey := ChangedKeyInfo(resolved, check)

	switch {
	case errors.Is(err, sshx.ErrHostKeyRejected) && verdict == hostkeys.VerdictChanged:
		return &Error{
			Code: CodeHostKeyChanged,
			Message: fmt.Sprintf(
				"The host key for %s has changed. This can mean the host was rebuilt — "+
					"or that something is impersonating it. The connection was refused.", where),
			Err: err,
			// Both fingerprints, so the interface can show the difference
			// rather than merely asserting one exists.
			HostKey: &changedKey,
		}

	case errors.Is(err, sshx.ErrHostKeyRejected):
		return &Error{
			Code:    CodeHostKeyRejected,
			Message: fmt.Sprintf("The host key for %s was not accepted, so nothing was sent to it.", where),
			Err:     err,
		}

	case errors.Is(err, sshx.ErrAuthFailed):
		return &Error{
			Code:    CodeAuthFailed,
			Message: fmt.Sprintf("%s refused the credential. Check the username and the key or password.", where),
			Err:     err,
		}

	case errors.Is(err, sshx.ErrUnreachable):
		return &Error{
			Code:    CodeUnreachable,
			Message: fmt.Sprintf("%s could not be reached. Check the address, the port, and the route to it.", where),
			Err:     err,
		}

	case errors.Is(err, sshx.ErrNoCredential):
		return &Error{
			Code:    CodeNoCredential,
			Message: "No usable credential was available for this connection.",
			Err:     err,
		}

	default:
		return &Error{
			Code:    CodeInternal,
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
