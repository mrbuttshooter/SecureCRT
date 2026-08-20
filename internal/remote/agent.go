package remote

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// Agent forwarding, without an agent to forward.
//
// `ssh -A` reaches back to the agent on your laptop. There is no channel to a
// browser, so that arrangement is not available — but it is also not needed,
// because the keys are already here. This builds an in-memory keyring from
// credentials the user named on the connection and offers that.
//
// # How this differs from the real thing, in both directions
//
// Better: the keyring holds the keys named on this connection, not everything
// an agent happened to be holding. Somebody who forwards to a lab switch is
// not also offering it their production key, which with a real agent they
// almost certainly would be.
//
// Worse: nothing. The remote host's power is identical — it can use these
// keys to authenticate anywhere they are accepted, for as long as the
// connection lives, and bkd cannot tell the difference between the user's
// shell using the agent and the host using it behind their back. That is what
// agent forwarding *is*, and no server-side implementation changes it.
//
// Which is why this is per-connection, opt-in, never inherited from a folder,
// and audited at a severity that outlives ordinary retention.

// buildAgent assembles the keyring a connection forwards, or nil.
//
// Returns the credential names alongside it, for the audit record and the
// interface: "which keys did I expose to that switch" is a question somebody
// asks after the fact, and it must have an answer.
func (d *Dialer) buildAgent(
	ctx context.Context, p Params, resolved sessions.Resolved,
) (agent.Agent, []string, error) {
	wanted := resolved.Settings.AgentCredentials()
	if len(wanted) == 0 {
		return nil, nil, nil
	}

	if p.VaultKey == nil {
		return nil, nil, &Error{
			Code:    CodeVaultLocked,
			Message: "Your vault is locked, and this connection forwards an agent.",
		}
	}

	keyring := agent.NewKeyring()
	names := make([]string, 0, len(wanted))

	for _, id := range wanted {
		meta, err := d.credentials.Get(ctx, p.UserID, id)
		if err != nil {
			if errors.Is(err, credentials.ErrNotFound) {
				return nil, nil, &Error{
					Code: CodeNoCredential,
					Message: "This connection forwards a key that no longer exists. " +
						"Edit the connection's agent keys.",
				}
			}
			return nil, nil, &Error{
				Code: CodeInternal, Message: "An agent key could not be read.", Err: err,
			}
		}

		if meta.Kind != credentials.KindSSHKey {
			// A password cannot go in an agent, and quietly skipping it would
			// leave somebody wondering why their authentication fails on a
			// host they configured correctly.
			return nil, nil, &Error{
				Code: CodeNoCredential,
				Message: fmt.Sprintf(
					"%q is a password, and only keys can be offered through an agent.",
					meta.Name),
			}
		}

		secret, err := d.credentials.Reveal(ctx, p.VaultKey, p.UserID, id)
		if err != nil {
			return nil, nil, &Error{
				Code: CodeInternal, Message: "An agent key could not be decrypted.", Err: err,
			}
		}

		signer, err := parseAgentKey([]byte(secret.Value), secret.Extra)
		secret.Zero()
		if err != nil {
			return nil, nil, &Error{
				Code:    CodeNoCredential,
				Message: fmt.Sprintf("%q could not be read as a private key.", meta.Name),
				Err:     err,
			}
		}

		// The keyring wants the key itself rather than a Signer, so that it
		// can answer sign requests and list public keys.
		if err := keyring.Add(agent.AddedKey{
			PrivateKey: signer,
			Comment:    meta.Name,
		}); err != nil {
			return nil, nil, &Error{
				Code: CodeInternal, Message: "An agent key could not be loaded.", Err: err,
			}
		}
		names = append(names, meta.Name)
	}

	return keyring, names, nil
}

// parseAgentKey decodes a stored private key into something the keyring
// accepts, which is the key value rather than a Signer wrapping it.
func parseAgentKey(pem []byte, passphrase string) (any, error) {
	if passphrase != "" {
		key, err := ssh.ParseRawPrivateKeyWithPassphrase(pem, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("remote: decrypting an agent key: %w", err)
		}
		return key, nil
	}
	key, err := ssh.ParseRawPrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("remote: parsing an agent key: %w", err)
	}
	return key, nil
}
