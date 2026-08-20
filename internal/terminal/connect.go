package terminal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/proto/serialx"
	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
	"github.com/mrbuttshooter/securecrt/internal/proto/telnetx"

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

// Policy is what an operator has allowed.
type Policy struct {
	// AllowTelnet permits plaintext telnet connections.
	AllowTelnet bool

	// AllowSerial permits opening serial ports on this machine.
	AllowSerial bool

	// SerialDevices is the glob list naming the ports that exist. Empty
	// opens nothing, whatever AllowSerial says.
	SerialDevices []string

	// SessionLogDir is where transcripts are written. Empty disables
	// recording entirely, whatever any connection asks for.
	SessionLogDir string

	// RecordAllSessions makes every session recorded regardless of what the
	// connection says. The user is told, on their own terminal, because
	// somebody whose work is being written to disk should learn it from the
	// thing doing it rather than from a settings page they never open.
	RecordAllSessions bool
}

// Connector opens terminals for saved connections.
type Connector struct {
	manager *Manager
	dialer  *remote.Dialer
	policy  Policy
	log     *slog.Logger

	// serialPorts tracks which line each terminal holds, so the second
	// person to ask for one is told rather than handed a wire somebody else
	// is already typing into.
	serialPorts *serialx.Registry
}

// NewConnector builds a Connector.
func NewConnector(manager *Manager, dialer *remote.Dialer, policy Policy, log *slog.Logger) *Connector {
	if log == nil {
		log = slog.Default()
	}
	return &Connector{
		manager: manager, dialer: dialer, policy: policy, log: log,
		serialPorts: serialx.NewRegistry(),
	}
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

	// OnTrigger receives a rule firing. Called from the read path, so it
	// must not block.
	OnTrigger TriggerSink
}

// Connect opens a terminal for a saved connection.
//
// Branches on the protocol here rather than behind one dialler, because the
// three have almost nothing in common on the way in. SSH consults the
// connection pool, verifies a host key and may traverse a chain of jump
// hosts. Telnet opens one socket per terminal — it multiplexes nothing, so
// sharing a connection between two tabs would interleave two people's
// keystrokes into one byte stream. Serial claims a device exclusively.
//
// What they share begins once bytes are flowing, which is where Manager.Open
// takes over.
func (c *Connector) Connect(ctx context.Context, p ConnectParams) (*Terminal, error) {
	resolved, err := c.dialer.Resolve(ctx, p.UserID, p.SessionID)
	if err != nil {
		return nil, err
	}

	switch resolved.Protocol {
	case sessions.ProtocolSSH:
		return c.connectSSH(ctx, p)
	case sessions.ProtocolTelnet:
		return c.connectTelnet(ctx, p, resolved)
	case sessions.ProtocolSerial:
		return c.connectSerial(ctx, p, resolved)
	default:
		return nil, &ConnectError{
			Code: remote.CodeInternal,
			Message: fmt.Sprintf("%s connections are not supported yet.",
				resolved.Protocol),
		}
	}
}

// connectSSH is the original path, unchanged.
func (c *Connector) connectSSH(ctx context.Context, p ConnectParams) (*Terminal, error) {
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

	transcript, forced, err := c.recordingFor(conn.Resolved)
	if err != nil {
		_ = shell.Close()
		conn.Release()
		return nil, &ConnectError{
			Code:    remote.CodeInternal,
			Message: "This session should be recorded and the transcript could not be opened.",
			Err:     err,
		}
	}

	// The credential is fetched for the triggers rather than for the dial —
	// SSH already authenticated with it — because a rule that answers an
	// enable prompt needs the same secret and should not be made to store a
	// second copy of it.
	logon, err := c.dialer.LogonFor(ctx, remote.Params{
		UserID: p.UserID, SessionID: conn.Resolved.ID, VaultKey: p.VaultKey,
	}, conn.Resolved)
	if err != nil {
		// Not fatal: the session works, and a trigger that cannot fill in a
		// password is better than a terminal that will not open.
		c.log.Warn("reading the credential for triggers", "error", err)
	}

	triggers := conn.Resolved.Settings.EffectiveTriggers()
	watched := WithTriggers(WithTranscript(shell, transcript),
		triggers, logon.Username, logon.Password, p.OnTrigger)

	term, err := c.manager.Open(watched, conn.Release, OpenParams{
		UserID:    p.UserID,
		SessionID: conn.Resolved.ID,
		Label:     conn.Resolved.Name,
		Username:  conn.Username,
		Cols:      cols,
		Rows:      rows,
		AgentKeys: conn.AgentKeys,

		AgentRefused: shell.AgentRefused() != nil,
		Triggers:     len(triggers),
		Transcript:   transcript,
		Recorded:     transcript != nil,
		RecordForced: forced,
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

// connectTelnet opens one telnet session for one terminal.
//
// No pool, and that is not a shortcut. Telnet carries exactly one session per
// TCP connection: there is no channel layer, so two terminals sharing one
// socket would be two people typing into the same byte stream. Every terminal
// gets its own connection and closes it on the way out.
func (c *Connector) connectTelnet(
	ctx context.Context, p ConnectParams, resolved sessions.Resolved,
) (*Terminal, error) {
	if !c.policy.AllowTelnet {
		return nil, &ConnectError{
			Code: remote.CodeProtocolDisabled,
			Message: "Telnet is disabled on this server. It sends everything, " +
				"including the password, in the clear; an administrator can " +
				"allow it with policy.allow_telnet.",
		}
	}

	cols, rows := p.Cols, p.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	progress := p.Progress
	if progress == nil {
		progress = func(string) {}
	}
	progress(remote.StatusDialling)

	conn, err := telnetx.Dial(ctx, telnetx.Config{
		Address: net.JoinHostPort(resolved.Hostname,
			strconv.Itoa(resolved.EffectivePort)),
		Cols: cols,
		Rows: rows,
	})
	if err != nil {
		return nil, &ConnectError{
			Code: remote.CodeUnreachable,
			Message: fmt.Sprintf("Could not reach %s over telnet.",
				remote.Describe(resolved)),
			Err: err,
		}
	}

	progress(remote.StatusConnected)

	// The credential is fetched after the connection is open rather than
	// before, so a device that is simply unreachable does not cost a vault
	// decryption — and so the secret's lifetime is as short as it can be.
	logon, err := c.dialer.LogonFor(ctx, remote.Params{
		UserID: p.UserID, SessionID: resolved.ID, VaultKey: p.VaultKey,
	}, resolved)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	transcript, forced, err := c.recordingFor(resolved)
	if err != nil {
		_ = conn.Close()
		return nil, &ConnectError{
			Code:    remote.CodeInternal,
			Message: "This session should be recorded and the transcript could not be opened.",
			Err:     err,
		}
	}

	// The transcript wraps the logon wrapper rather than the other way round,
	// so what is recorded is what reached the screen — including the login
	// exchange, which is exactly the part somebody reviewing a session wants
	// to see happened.
	steps := resolved.Settings.EffectiveLogonSteps(logon.Password != "")
	triggers := resolved.Settings.EffectiveTriggers()
	shell := WithTriggers(
		WithTranscript(WithLogon(conn, steps, logon.Username, logon.Password), transcript),
		triggers, logon.Username, logon.Password, p.OnTrigger)

	term, err := c.manager.Open(shell, nil, OpenParams{
		UserID:       p.UserID,
		SessionID:    resolved.ID,
		Label:        resolved.Name,
		Username:     resolved.EffectiveUsername,
		Cols:         cols,
		Rows:         rows,
		LogonSteps:   len(steps),
		Triggers:     len(triggers),
		Transcript:   transcript,
		Recorded:     transcript != nil,
		RecordForced: forced,
		Transport: Transport{
			Protocol: sessions.ProtocolTelnet,
			Host:     resolved.Hostname,
			Port:     resolved.EffectivePort,
			Detail:   conn.Summary(),
		},
	})
	if err != nil {
		_ = conn.Close()
		return nil, &ConnectError{
			Code:    remote.CodeInternal,
			Message: "The telnet session could not be started.",
			Err:     err,
		}
	}

	if err := c.dialer.MarkUsed(ctx, resolved.ID); err != nil {
		c.log.Warn("recording session use", "error", err)
	}

	return term, nil
}

// connectSerial opens a serial line for one terminal.
//
// The device path is the connection's hostname field, which is the one place
// in this system where a connection addresses a device rather than a host.
func (c *Connector) connectSerial(
	ctx context.Context, p ConnectParams, resolved sessions.Resolved,
) (*Terminal, error) {
	if !c.policy.AllowSerial {
		return nil, &ConnectError{
			Code: remote.CodeProtocolDisabled,
			Message: "Serial ports are disabled on this server. They only work " +
				"where it is physically cabled to the device; an administrator " +
				"can allow them with policy.allow_serial.",
		}
	}

	cfg := serialx.Config{
		Device:   resolved.Hostname,
		Allowed:  c.policy.SerialDevices,
		Baud:     valueOr(resolved.Settings.SerialBaud, 0),
		DataBits: valueOr(resolved.Settings.SerialDataBits, 0),
		StopBits: valueOr(resolved.Settings.SerialStopBits, 0),
		Parity:   serialx.Parity(valueOr(resolved.Settings.SerialParity, "")),
		Flow:     serialx.FlowControl(valueOr(resolved.Settings.SerialFlow, "")),
	}
	if err := cfg.Validate(); err != nil {
		return nil, &ConnectError{
			Code: remote.CodeInternal, Message: err.Error(), Err: err,
		}
	}

	// Claimed before opening. Two terminals on one wire interleave two
	// people's keystrokes into a device that has no idea anything is wrong.
	release, err := c.serialPorts.Claim(resolved.Hostname, p.UserID, resolved.Name)
	if err != nil {
		var inUse *serialx.InUseError
		if errors.As(err, &inUse) {
			message := "That serial port is in use by somebody else."
			if inUse.SameUser {
				message = fmt.Sprintf(
					"You already have %s open in another tab (%s). A serial line "+
						"carries one session at a time.", resolved.Hostname, inUse.Label)
			}
			return nil, &ConnectError{Code: remote.CodeConflict, Message: message, Err: err}
		}
		return nil, &ConnectError{Code: remote.CodeInternal, Message: "The port could not be claimed.", Err: err}
	}

	port, err := serialx.Open(cfg)
	if err != nil {
		release()
		return nil, serialError(err, resolved.Hostname)
	}

	logon, err := c.dialer.LogonFor(ctx, remote.Params{
		UserID: p.UserID, SessionID: resolved.ID, VaultKey: p.VaultKey,
	}, resolved)
	if err != nil {
		_ = port.Close()
		release()
		return nil, err
	}

	transcript, forced, err := c.recordingFor(resolved)
	if err != nil {
		_ = port.Close()
		release()
		return nil, &ConnectError{
			Code:    remote.CodeInternal,
			Message: "This session should be recorded and the transcript could not be opened.",
			Err:     err,
		}
	}

	steps := resolved.Settings.EffectiveLogonSteps(logon.Password != "")
	triggers := resolved.Settings.EffectiveTriggers()
	shell := WithTriggers(
		WithTranscript(WithLogon(port, steps, logon.Username, logon.Password), transcript),
		triggers, logon.Username, logon.Password, p.OnTrigger)

	term, err := c.manager.Open(shell, release, OpenParams{
		UserID:       p.UserID,
		SessionID:    resolved.ID,
		Label:        resolved.Name,
		Username:     logon.Username,
		Cols:         p.Cols,
		Rows:         p.Rows,
		LogonSteps:   len(steps),
		Triggers:     len(triggers),
		Transcript:   transcript,
		Recorded:     transcript != nil,
		RecordForced: forced,
		Transport: Transport{
			Protocol: sessions.ProtocolSerial,
			Device:   port.Device(),
			Detail:   port.Summary(),
		},
	})
	if err != nil {
		_ = port.Close()
		release()
		return nil, &ConnectError{
			Code: remote.CodeInternal, Message: "The serial session could not be started.", Err: err,
		}
	}

	if err := c.dialer.MarkUsed(ctx, resolved.ID); err != nil {
		c.log.Warn("recording session use", "error", err)
	}

	return term, nil
}

// serialError turns a refusal into something a person can act on.
//
// The distinction that matters is between "this server will not" and "this
// device will not": one sends somebody to their administrator, the other to
// the cable.
func serialError(err error, device string) error {
	switch {
	case errors.Is(err, serialx.ErrNotAllowed):
		return &ConnectError{
			Code: remote.CodeProtocolDisabled,
			Message: fmt.Sprintf(
				"%s is not one of the serial ports this server may open. An "+
					"administrator lists them in serial.allowed_devices.", device),
			Err: err,
		}
	case errors.Is(err, serialx.ErrNotADevice):
		return &ConnectError{
			Code:    remote.CodeInternal,
			Message: fmt.Sprintf("%s is not a serial device.", device),
			Err:     err,
		}
	case errors.Is(err, serialx.ErrUnsupported):
		return &ConnectError{
			Code:    remote.CodeProtocolDisabled,
			Message: "This build of bkd cannot open serial ports.",
			Err:     err,
		}
	default:
		return &ConnectError{
			Code:    remote.CodeUnreachable,
			Message: fmt.Sprintf("%s could not be opened.", device),
			Err:     err,
		}
	}
}

// valueOr reads an optional setting.
func valueOr[T any](p *T, fallback T) T {
	if p == nil {
		return fallback
	}
	return *p
}

// recordingFor opens a transcript when this connection should have one.
//
// Returns nil when it should not, which is the common case, so nothing is
// wrapped and nothing is written. A failure to open one is reported rather
// than swallowed: an operator who turned on record_all_sessions has to know
// it is not happening, and a user who ticked the box has to know their
// session is not being kept.
func (c *Connector) recordingFor(resolved sessions.Resolved) (*Transcript, bool, error) {
	if c.policy.SessionLogDir == "" {
		return nil, false, nil
	}

	forced := c.policy.RecordAllSessions
	wanted := forced
	if resolved.Settings.LogSession != nil && *resolved.Settings.LogSession {
		wanted = true
	}
	if !wanted {
		return nil, false, nil
	}

	transcript, err := NewTranscript(TranscriptConfig{
		Dir:    c.policy.SessionLogDir,
		UserID: resolved.OwnerID,
		Label:  resolved.Name,
		Forced: forced,
	}, time.Now())
	if err != nil {
		return nil, forced, err
	}
	return transcript, forced, nil
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
