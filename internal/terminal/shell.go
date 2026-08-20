package terminal

import (
	"io"

	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// What a terminal actually needs from whatever is at the other end.
//
// Until Phase 6 this was `*sshx.Session` throughout, which was honest while
// SSH was the only protocol and became a lie the moment it was not. A telnet
// connection and a serial port both produce a bidirectional byte stream with
// a size and an end, and nothing else about them is alike.
//
// Deliberately small. Everything the terminal does — replay buffering,
// reattachment, the abandoned-session reaper, the WebSocket bridge — is
// written against these five methods and none of it had to change to gain two
// protocols, which is the test that the line is drawn in the right place.

// Shell is one interactive session on a remote device.
type Shell interface {
	// Read returns output. io.EOF ends the terminal normally.
	io.Reader

	// Write sends keystrokes.
	io.Writer

	// Resize tells the far end the terminal's new size.
	//
	// A no-op where the protocol has nowhere to put it: a serial line has no
	// concept of a window, and a telnet peer that refused NAWS is not
	// listening. Returning an error for those would make every browser resize
	// look like a failure.
	Resize(cols, rows int) error

	// Wait blocks until the session ends and reports why.
	//
	// The exit status of a remote command, where there is one. Telnet and
	// serial have no such thing, so they report the transport's own failure
	// or nil.
	Wait() error

	// Close ends the session.
	Close() error
}

// Transport describes how a shell was reached, for the interface and the
// audit log.
//
// Host and Port are empty and zero for a serial line, which addresses a
// device rather than a host — the one place in this system where "no
// hostname" is correct rather than a missing field.
type Transport struct {
	Protocol sessions.Protocol

	Host string
	Port int

	// Device is the serial port's path, empty for everything else.
	Device string

	// Detail is a short human-readable summary of the link: the baud rate and
	// framing for a serial line, the negotiated options for telnet. Shown
	// once when the terminal opens, because "9600 8N1" is the first thing
	// somebody checks when a console shows nothing but rubbish.
	Detail string
}

// Encrypted reports whether the bytes are protected in transit.
//
// False for telnet and for a serial line reached over the network, and the
// interface says so rather than leaving a person to remember which of their
// tabs is carrying a password in the clear.
func (t Transport) Encrypted() bool { return t.Protocol == sessions.ProtocolSSH }
