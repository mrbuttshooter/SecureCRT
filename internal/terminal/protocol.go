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
)

// ControlType identifies a JSON control message.
type ControlType string

const (
	// --- browser to server ---

	// ControlResize reports a new terminal size.
	ControlResize ControlType = "resize"

	// ControlHostKeyDecision answers a host key prompt.
	ControlHostKeyDecision ControlType = "host_key_decision"

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

	// ControlClosed reports that the remote session ended.
	ControlClosed ControlType = "closed"

	// ControlPong answers ControlPing.
	ControlPong ControlType = "pong"
)

// Status values for ControlStatus.
const (
	StatusDialling       = "dialling"
	StatusVerifyingHost  = "verifying_host"
	StatusAuthenticating = "authenticating"
	StatusConnected      = "connected"
	StatusReattached     = "reattached"
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
}

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
}

// Error codes carried by ControlError.
const (
	// ErrCodeHostKeyChanged means the host presented a different key. The
	// most serious error this protocol reports.
	ErrCodeHostKeyChanged = "host_key_changed"

	// ErrCodeHostKeyRejected means the user declined an unknown key.
	ErrCodeHostKeyRejected = "host_key_rejected"

	// ErrCodeAuthFailed means the host refused the credential.
	ErrCodeAuthFailed = "auth_failed"

	// ErrCodeUnreachable means the host could not be contacted.
	ErrCodeUnreachable = "unreachable"

	// ErrCodeVaultLocked means the vault must be unlocked to read the
	// credential.
	ErrCodeVaultLocked = "vault_locked"

	// ErrCodeNoCredential means the saved connection names no usable
	// credential.
	// #nosec G101 -- an error code sent to the browser, not a credential.
	ErrCodeNoCredential = "no_credential"

	// ErrCodeNotFound means the saved connection or terminal is unknown.
	ErrCodeNotFound = "not_found"

	// ErrCodeInternal is anything else.
	ErrCodeInternal = "internal_error"
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
