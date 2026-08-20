package remote

import (
	"context"
	"errors"
	"fmt"

	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// Credentials for protocols that have no authentication of their own.
//
// SSH authenticates inside the protocol: a key or a password is offered
// during the handshake, and a device either accepts it or does not. Telnet has
// no such layer, and neither does a serial line — there is a login prompt, and
// somebody types into it. So the credential stops being something the
// transport uses and becomes something to send as keystrokes.
//
// Which changes what it is worth. An SSH password is offered to a host that
// has proved its identity with a key this system verified. A telnet password
// is typed, in the clear, at whatever answered the socket. Both come out of
// the same vault; only one of them is protected in transit, and the interface
// says which.

// Logon is what to type at a device's own login prompt.
type Logon struct {
	Username string
	Password string
}

// Resolve applies folder inheritance to a saved connection.
//
// Exported because the non-SSH transports need the resolved connection
// without dialling anything, and duplicating the lookup in each of them is
// how two of them end up disagreeing about which folder a port came from.
func (d *Dialer) Resolve(ctx context.Context, userID, sessionID string) (sessions.Resolved, error) {
	resolved, err := d.sessions.Resolve(ctx, userID, sessionID)
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return sessions.Resolved{}, &Error{
				Code:    CodeNotFound,
				Message: "That saved connection no longer exists.",
			}
		}
		return sessions.Resolved{}, &Error{
			Code:    CodeInternal,
			Message: "The saved connection could not be read.",
			Err:     err,
		}
	}
	return resolved, nil
}

// LogonFor decrypts what a connection should type at its login prompt.
//
// A connection with no credential is not an error: plenty of console lines
// answer with the device's own prompt and want nothing, and a lab switch
// reached over a serial cable frequently has no login at all. What comes back
// is empty, the logon steps find nothing to send, and the user types.
func (d *Dialer) LogonFor(
	ctx context.Context, p Params, resolved sessions.Resolved,
) (Logon, error) {
	out := Logon{Username: resolved.EffectiveUsername}

	if resolved.EffectiveCredentialID == "" {
		return out, nil
	}

	meta, err := d.credentials.Get(ctx, p.UserID, resolved.EffectiveCredentialID)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			return Logon{}, &Error{
				Code:    CodeNoCredential,
				Message: "The credential this connection uses no longer exists.",
			}
		}
		return Logon{}, &Error{
			Code: CodeInternal, Message: "The credential could not be read.", Err: err,
		}
	}

	// A private key cannot be typed at a login prompt, and pretending
	// otherwise would send a PEM block to a switch one line at a time. The
	// connection still works — the user types the password themselves — so
	// this takes the username and leaves the rest.
	if meta.Kind == credentials.KindSSHKey {
		if out.Username == "" {
			out.Username = meta.Username
		}
		return out, nil
	}

	if p.VaultKey == nil {
		return Logon{}, &Error{
			Code:    CodeVaultLocked,
			Message: "Your vault is locked. Enter your passphrase to connect.",
		}
	}

	secret, err := d.credentials.Reveal(ctx, p.VaultKey, p.UserID, resolved.EffectiveCredentialID)
	if err != nil {
		return Logon{}, &Error{
			Code: CodeInternal, Message: "The credential could not be decrypted.", Err: err,
		}
	}
	defer secret.Zero()

	out.Password = secret.Value
	if out.Username == "" {
		out.Username = meta.Username
	}
	return out, nil
}

// MarkUsed records that a connection was opened, for the recent list.
//
// Exported for the transports that do not go through Acquire: a telnet
// session is as much a use of a saved connection as an SSH one, and a recent
// list that quietly omitted half of them would be worse than none.
func (d *Dialer) MarkUsed(ctx context.Context, sessionID string) error {
	return d.sessions.MarkUsed(ctx, sessionID)
}

// Describe renders a connection for an error message.
func Describe(resolved sessions.Resolved) string {
	if resolved.Protocol == sessions.ProtocolSerial {
		return resolved.Hostname
	}
	return fmt.Sprintf("%s:%d", resolved.Hostname, resolved.EffectivePort)
}
