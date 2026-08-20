package terminal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/coder/websocket"
)

// WebSocket tuning.
const (
	// maxIncomingFrame bounds what a browser may send in one frame. Keystrokes
	// and pasted text are small; a large frame indicates something other than
	// a terminal at the far end.
	maxIncomingFrame = 1 << 20 // 1 MiB

	// writeTimeout bounds a single frame write. A browser that has stopped
	// reading must not hold this goroutine indefinitely.
	writeTimeout = 15 * time.Second

	// pingInterval keeps intermediaries from closing an idle connection, and
	// detects a browser that has gone away without closing cleanly — which is
	// what actually happens when a laptop lid shuts.
	pingInterval = 30 * time.Second
)

// Broadcaster resolves the other terminals a keystroke should also reach.
//
// Supplied by the caller rather than looked up here, because deciding which
// terminals a person may type into is an authorisation question and this
// package has no idea who anybody is.
type Broadcaster interface {
	// Targets returns the terminals to mirror to, or an error naming the
	// first one that is not available. An error means nothing is mirrored:
	// half a rack receiving a command is worse than none of it.
	Targets(ids []string) ([]*Terminal, error)

	// GroupChanged records a broadcast group being set or cleared. Called
	// once per change, never per keystroke — the audit log wants "at 03:14
	// this person put forty production switches on one keyboard", not four
	// thousand rows of individual letters.
	GroupChanged(primary *Terminal, targets []*Terminal)
}

// Bridge carries one browser's WebSocket to one Terminal.
type Bridge struct {
	conn *websocket.Conn
	term *Terminal
	log  *slog.Logger

	broadcaster Broadcaster

	// mirror is the other terminals this browser's keystrokes also reach.
	//
	// Held on the bridge rather than on the Terminal, so it belongs to one
	// browser session: a second tab attached to the same terminal does not
	// inherit somebody else's broadcast group, and closing the tab ends it.
	// A broadcast that outlived the window it was set up in is how somebody
	// reloads a page and types `reload` into forty switches.
	mirror []*Terminal
}

// NewBridge builds a Bridge.
func NewBridge(conn *websocket.Conn, term *Terminal, log *slog.Logger) *Bridge {
	if log == nil {
		log = slog.Default()
	}
	conn.SetReadLimit(maxIncomingFrame)
	return &Bridge{conn: conn, term: term, log: log}
}

// WithBroadcast lets this bridge mirror keystrokes to other terminals.
func (b *Bridge) WithBroadcast(broadcaster Broadcaster) *Bridge {
	b.broadcaster = broadcaster
	return b
}

// Run pumps in both directions until the terminal ends or the browser leaves.
//
// Returning does not close the terminal. That is the point: the browser
// detaching is a normal event, and the shell keeps running so the user can
// come back to it.
func (b *Bridge) Run(ctx context.Context) error {
	att, err := b.term.Attach()
	if err != nil {
		b.sendControl(ctx, errorMessage(ErrCodeInternal, "That terminal is no longer available."))
		return err
	}
	defer b.term.Detach()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Tell the browser which terminal it is on, so it can reattach after a
	// drop without having to remember what it asked for.
	cols, rows := b.term.Size()
	status := StatusConnected
	if att.Reattached {
		status = StatusReattached
	}
	b.sendControl(ctx, Control{
		Type:       ControlStatus,
		Status:     status,
		TerminalID: b.term.ID,
		Cols:       cols,
		Rows:       rows,
	})

	// Replay before live output, so the terminal reads in the order it was
	// printed rather than interleaving history with what is arriving now.
	if len(att.Replay) > 0 {
		if err := b.writeBinary(ctx, att.Replay); err != nil {
			return err
		}
	}

	errs := make(chan error, 2)
	go func() { errs <- b.readFromBrowser(ctx) }()
	go func() { errs <- b.writeToBrowser(ctx, att.Output) }()

	select {
	case err := <-errs:
		cancel()
		return err
	case <-b.term.Done():
		cancel()
		b.reportClosed(context.WithoutCancel(ctx))
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// readFromBrowser handles keystrokes and control messages.
func (b *Bridge) readFromBrowser(ctx context.Context) error {
	for {
		typ, data, err := b.conn.Read(ctx)
		if err != nil {
			// A browser going away is ordinary, not a fault.
			if isNormalClosure(err) {
				return nil
			}
			return err
		}

		switch typ {
		case websocket.MessageBinary:
			if err := b.term.Write(data); err != nil {
				if errors.Is(err, ErrTerminalClosed) {
					return nil
				}
				return err
			}

			// Mirrored after this terminal has taken it, so the tab the
			// person is looking at is never behind the ones they are not.
			//
			// A mirror that has ended — the far end hung up, somebody closed
			// it from another tab — is dropped from the group rather than
			// failing the keystroke. The alternative is that one dead switch
			// stops somebody typing at the other thirty-nine.
			b.mirrorInput(ctx, data)

		case websocket.MessageText:
			if err := b.handleControl(ctx, data); err != nil {
				return err
			}
		}
	}
}

// handleControl acts on a JSON control message.
func (b *Bridge) handleControl(ctx context.Context, data []byte) error {
	msg, err := DecodeControl(data)
	if err != nil {
		// A malformed control message is the client's problem; say so and
		// keep the terminal running rather than tearing down a working shell.
		b.sendControl(ctx, errorMessage(ErrCodeInternal, "That control message could not be read."))
		return nil
	}

	switch msg.Type {
	case ControlResize:
		if msg.Cols <= 0 || msg.Rows <= 0 {
			return nil
		}
		if err := b.term.Resize(msg.Cols, msg.Rows); err != nil {
			if errors.Is(err, ErrTerminalClosed) {
				return nil
			}
			// A failed resize is cosmetic; the session is still usable, so it
			// is logged rather than fatal.
			b.log.Debug("resize failed", "terminal", b.term.ID, "error", err)
		}

	case ControlBroadcast:
		b.setBroadcast(ctx, msg.Terminals)

	case ControlPing:
		b.sendControl(ctx, Control{Type: ControlPong})

	default:
		// Unknown types are ignored so an older server tolerates a newer
		// client sending something it has not heard of.
		b.log.Debug("ignoring unknown control message", "type", msg.Type)
	}
	return nil
}

// setBroadcast puts this browser's keyboard onto several terminals, or takes
// it off them.
//
// Every target is resolved before any of them is used, so a group naming a
// terminal that has gone is refused entirely rather than silently smaller
// than the person believes. Somebody who thinks they are typing at forty
// devices and is typing at thirty-nine has a problem they will not discover
// until it matters.
func (b *Bridge) setBroadcast(ctx context.Context, ids []string) {
	if b.broadcaster == nil {
		b.sendControl(ctx, errorMessage(ErrCodeInternal,
			"This server does not support broadcasting."))
		return
	}

	if len(ids) == 0 {
		b.mirror = nil
		b.broadcaster.GroupChanged(b.term, nil)
		b.sendControl(ctx, Control{Type: ControlBroadcast})
		return
	}

	targets, err := b.broadcaster.Targets(ids)
	if err != nil {
		b.sendControl(ctx, errorMessage(ErrCodeNotFound,
			"One of those terminals is no longer open, so nothing was joined."))
		return
	}

	// The terminal this browser is looking at is written directly and must
	// not also be mirrored to, or every keystroke would arrive twice.
	b.mirror = b.mirror[:0]
	for _, target := range targets {
		if target.ID != b.term.ID {
			b.mirror = append(b.mirror, target)
		}
	}

	b.broadcaster.GroupChanged(b.term, b.mirror)
	b.sendControl(ctx, Control{Type: ControlBroadcast, Terminals: idsOf(b.mirror)})
}

// mirrorInput sends one keystroke to the rest of the group.
func (b *Bridge) mirrorInput(ctx context.Context, data []byte) {
	if len(b.mirror) == 0 {
		return
	}

	live := b.mirror[:0]
	for _, target := range b.mirror {
		if err := target.Write(data); err != nil {
			b.log.Debug("dropping a terminal from a broadcast group",
				"terminal", target.ID, "error", err)
			b.sendControl(ctx, Control{
				Type: ControlWarning, Code: "broadcast_target_ended",
				Message: target.Label + " has ended and left the broadcast group.",
			})
			continue
		}
		live = append(live, target)
	}
	b.mirror = live
}

// idsOf names a group, for the acknowledgement.
func idsOf(terminals []*Terminal) []string {
	out := make([]string, 0, len(terminals))
	for _, t := range terminals {
		out = append(out, t.ID)
	}
	return out
}

// writeToBrowser forwards terminal output and keeps the connection alive.
func (b *Bridge) writeToBrowser(ctx context.Context, output <-chan []byte) error {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case chunk, ok := <-output:
			if !ok {
				return nil // detached or the terminal ended
			}
			if err := b.writeBinary(ctx, chunk); err != nil {
				return err
			}

		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := b.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				// The browser is gone. Returning detaches, leaving the shell
				// running for when they come back.
				return nil
			}
		}
	}
}

// writeBinary sends terminal bytes.
func (b *Bridge) writeBinary(ctx context.Context, data []byte) error {
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	if err := b.conn.Write(writeCtx, websocket.MessageBinary, data); err != nil {
		if isNormalClosure(err) {
			return nil
		}
		return fmt.Errorf("terminal: write to browser: %w", err)
	}
	return nil
}

// sendControl sends a JSON control message, best-effort.
//
// A failure here means the browser has gone, which the read or write loop is
// about to discover anyway; failing loudly would only add noise.
func (b *Bridge) sendControl(ctx context.Context, msg Control) {
	encoded, err := msg.Encode()
	if err != nil {
		b.log.Error("encoding control message", "type", msg.Type, "error", err)
		return
	}

	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	if err := b.conn.Write(writeCtx, websocket.MessageText, encoded); err != nil && !isNormalClosure(err) {
		b.log.Debug("sending control message", "type", msg.Type, "error", err)
	}
}

// SendControl sends a control message from outside the bridge, used during
// connection setup before Run takes over.
func (b *Bridge) SendControl(ctx context.Context, msg Control) { b.sendControl(ctx, msg) }

// reportClosed tells the browser the remote session ended, and why.
func (b *Bridge) reportClosed(ctx context.Context) {
	msg := Control{Type: ControlClosed, TerminalID: b.term.ID}

	if code := b.term.ExitCode(); code != nil {
		msg.ExitStatus = code
	}
	if err := b.term.Err(); err != nil {
		msg.Message = err.Error()
	} else {
		msg.Message = "The remote session ended."
	}

	b.sendControl(ctx, msg)
	_ = b.conn.Close(websocket.StatusNormalClosure, "session ended")
}

// isNormalClosure reports whether an error is an ordinary disconnection
// rather than a fault worth reporting.
func isNormalClosure(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return true
	}

	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway,
		websocket.StatusNoStatusRcvd, websocket.StatusAbnormalClosure:
		return true
	}
	return false
}
