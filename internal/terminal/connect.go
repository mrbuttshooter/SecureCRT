package terminal

import (
	"context"
	"log/slog"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"

	"github.com/mrbuttshooter/securecrt/internal/remote"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Types shared with the file browser.
//
// Connecting to a saved host — resolving it, decrypting its credential,
// verifying its host key, dialling it — is the same operation whether the
// result is a shell or a file listing, so it lives in one place. These
// aliases keep the terminal's own vocabulary intact for callers that only
// deal with terminals, and keep the JSON shape of the wire protocol defined
// beside the rest of it.
type (
	// HostKeyPrompter asks the user to approve an unrecognised host key.
	HostKeyPrompter = remote.HostKeyPrompter

	// HostKeyInfo describes a host key for the approval dialog.
	HostKeyInfo = remote.HostKeyInfo

	// ConnectError carries a code the interface can branch on.
	ConnectError = remote.Error
)

// ChangedKeyInfo builds the detail for a changed-key report.
var ChangedKeyInfo = remote.ChangedKeyInfo

// Connector opens terminals for saved connections.
type Connector struct {
	manager *Manager
	dialer  *remote.Dialer
	log     *slog.Logger
}

// NewConnector builds a Connector.
func NewConnector(manager *Manager, dialer *remote.Dialer, log *slog.Logger) *Connector {
	if log == nil {
		log = slog.Default()
	}
	return &Connector{manager: manager, dialer: dialer, log: log}
}

// ConnectParams describes a terminal to open.
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

// Connect opens a terminal for a saved connection.
//
// The SSH connection may already exist — the same user browsing the same
// host's files, or a second terminal on it — in which case this opens another
// channel on it rather than dialling again.
func (c *Connector) Connect(ctx context.Context, p ConnectParams) (*Terminal, error) {
	conn, err := c.dialer.Acquire(ctx, remote.Params{
		UserID:    p.UserID,
		SessionID: p.SessionID,
		VaultKey:  p.VaultKey,
		Prompter:  p.Prompter,
		Progress:  p.Progress,
	})
	if err != nil {
		return nil, err
	}

	cols, rows := p.Cols, p.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	shell, err := conn.Client().Shell(sshx.PTYConfig{Cols: cols, Rows: rows})
	if err != nil {
		// The lease has to go back, or a failed shell would hold the
		// connection open with nothing using it.
		conn.Release()
		return nil, &ConnectError{
			Code:    remote.CodeInternal,
			Message: "The remote shell could not be started.",
			Err:     err,
		}
	}

	target := conn.Client().Target()

	term, err := c.manager.Open(shell, conn.Release, OpenParams{
		UserID:    p.UserID,
		SessionID: conn.Resolved.ID,
		Label:     conn.Resolved.Name,
		Username:  conn.Username,
		Cols:      cols,
		Rows:      rows,
		AgentKeys: conn.AgentKeys,

		AgentRefused: shell.AgentRefused() != nil,
		Transport: Transport{
			Protocol: sessions.ProtocolSSH,
			Host:     target.Hostname,
			Port:     target.Port,
			Detail:   viaDetail(conn.Via),
		},
	})
	if err != nil {
		_ = shell.Close()
		conn.Release()
		return nil, &ConnectError{
			Code:    remote.CodeInternal,
			Message: "The remote shell could not be started.",
			Err:     err,
		}
	}

	return term, nil
}

// viaDetail summarises the route for the terminal header.
func viaDetail(hops []remote.HopInfo) string {
	if len(hops) == 0 {
		return ""
	}
	names := make([]string, len(hops))
	for i, hop := range hops {
		names[i] = hop.Name
	}
	return "via " + strings.Join(names, " → ")
}

// Resolved re-exports the saved-connection type the dial path returns, so
// callers do not need to import the sessions package for a type they only
// pass along.
type Resolved = sessions.Resolved
