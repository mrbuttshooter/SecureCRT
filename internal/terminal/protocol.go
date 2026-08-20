// Package terminal carries a live SSH session between a browser and a host.
//
// # Wire protocol
//
// WebSocket already distinguishes binary frames from text ones, so this uses
// that rather than inventing a framing layer:
//
//	binary frame  raw terminal bytes, in both directions
//	text frame    a JSON control message
//
// Terminal traffic is overwhelmingly the raw bytes, and keeping them
// unwrapped means no per-keystroke encoding cost and no base64 inflation of
// output — which matters when someone cats a large file.
//
// # Session survival
//
// The SSH connection belongs to the server, not to the WebSocket. A dropped
// browser connection — a closed laptop, a lift, a flaky office network — does
// not kill the shell. The browser reconnects with the same terminal ID, gets
// the recent scrollback replayed, and carries on. That is the difference
// between a web terminal being a curiosity and being usable.
package terminal

import (
	"encoding/json"
	"fmt"

	"github.com/mrbuttshooter/securecrt/internal/remote"
)

// ControlType identifies a JSON control message.
type ControlType string

const (
	// --- browser to server ---

	// ControlResize reports a new terminal size.
	ControlResize ControlType = "resize"

	// ControlHostKeyDecision answers a host key prompt.
	ControlHostKeyDecision ControlType = "host_key_decision"

	// ControlBroadcast puts this browser's keyboard onto several terminals
	// at once, or — with an empty list — takes it off them.
	//
	// Server-side fan-out rather than the browser writing to several sockets,
	// which is the difference between a feature that is audited by
	// construction and one that is audited if the client remembers to say so.
	ControlBroadcast ControlType = "broadcast"

	// ControlPing lets the browser check the connection is alive. The
	// WebSocket layer has its own ping, but this one traverses the whole
	// path including the SSH session's health.
	ControlPing ControlType = "ping"

	// --- server to browser ---

	// ControlStatus reports connection progress: dialling, authenticating,
	// connected, closed. Without it the user stares at a blank rectangle
	// wondering whether anything is happening.
	ControlStatus ControlType = "status"

	// ControlHostKeyPrompt asks the user to approve an unrecognised host key.
	ControlHostKeyPrompt ControlType = "host_key_prompt"

	// ControlHostKeyChanged reports a changed key. Not a prompt: there is no
	// answer that continues the connection.
	ControlHostKeyChanged ControlType = "host_key_changed"

	// ControlError reports a failure in terms the user can act on.
	ControlError ControlType = "error"

	// ControlWarning reports something the user should know that did not
	// stop the terminal from opening — a host declining a forwarded agent,
	// for instance. Distinct from ControlError, which means the terminal is
	// not there.
	ControlWarning ControlType = "warning"

	// ControlTrigger reports one of the user's rules firing. Carries what it
	// saw and never what it sent — a send may contain a password.
	ControlTrigger ControlType = "trigger"

	// ControlClosed reports that the remote session ended.
	ControlClosed ControlType = "closed"

	// ControlPong answers ControlPing.
	ControlPong ControlType = "pong"
)

// Status values for ControlStatus.
//
// Defined by the connection layer, because the interesting ones happen while
// a connection is being established and that path is shared with the file
// browser. Re-exported here so the wire protocol is readable in one place.
const (
	StatusDialling       = remote.StatusDialling
	StatusVerifyingHost  = remote.StatusVerifyingHost
	StatusAuthenticating = remote.StatusAuthenticating
	StatusConnected      = remote.StatusConnected
	StatusReattached     = remote.StatusReattached
)

// Control is a JSON control message.
//
// One envelope with optional fields, rather than a distinct type per message.
// A terminal has few control messages and they share most of their fields;
// separate types would mean a type switch at both ends for little benefit.
type Control struct {
	Type ControlType `json:"type"`

	// Resize.
	Cols int `json:"cols,omitempty"`
	Rows int `json:"rows,omitempty"`

	// Status and error reporting.
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`

	// Code is a stable identifier for an error, so the interface can react
	// to a specific failure without matching on prose.
	Code string `json:"code,omitempty"`

	// Host key prompt and decision.
	HostKey  *HostKeyInfo `json:"host_key,omitempty"`
	Accepted bool         `json:"accepted,omitempty"`

	// TerminalID is returned once a terminal exists, so the browser can
	// reattach to it after a dropped connection.
	TerminalID string `json:"terminal_id,omitempty"`

	// ExitStatus is the remote command's exit code, when it reported one.
	ExitStatus *int `json:"exit_status,omitempty"`

	// Trigger carries a rule that fired, for ControlTrigger.
	Trigger *TriggerEvent `json:"trigger,omitempty"`

	// Highlights are the browser's colouring rules, sent with the opening
	// status. Never the whole trigger set: the rest of it runs here, and one
	// of those rules holds a password.
	Highlights []Highlight `json:"highlights,omitempty"`

	// Terminals names a broadcast group, in both directions: the browser
	// sends the terminals to join, and the acknowledgement carries the ones
	// that were joined.
	Terminals []string `json:"terminals,omitempty"`
}

// Error codes carried by ControlError.
//
// The connection failures are the shared ones — a host key that changed is
// the same event whether a shell or a file listing was wanted — so they are
// defined once and re-exported. ErrCodeNotFound additionally covers a
// terminal ID the server no longer knows.
const (
	ErrCodeHostKeyChanged  = remote.CodeHostKeyChanged
	ErrCodeHostKeyRejected = remote.CodeHostKeyRejected
	ErrCodeAuthFailed      = remote.CodeAuthFailed
	ErrCodeUnreachable     = remote.CodeUnreachable
	ErrCodeVaultLocked     = remote.CodeVaultLocked
	ErrCodeNoCredential    = remote.CodeNoCredential
	ErrCodeNotFound        = remote.CodeNotFound
	ErrCodeInternal        = remote.CodeInternal
)

// Encode renders a control message.
func (c Control) Encode() ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("terminal: encode control message: %w", err)
	}
	return b, nil
}

// DecodeControl parses a control message.
func DecodeControl(data []byte) (Control, error) {
	var c Control
	if err := json.Unmarshal(data, &c); err != nil {
		return Control{}, fmt.Errorf("terminal: unreadable control message: %w", err)
	}
	if c.Type == "" {
		return Control{}, fmt.Errorf("terminal: control message has no type")
	}
	return c, nil
}

// statusMessage builds a progress update.
func statusMessage(status string) Control {
	return Control{Type: ControlStatus, Status: status}
}

// errorMessage builds an error the interface can both display and branch on.
func errorMessage(code, message string) Control {
	return Control{Type: ControlError, Code: code, Message: message}
}
