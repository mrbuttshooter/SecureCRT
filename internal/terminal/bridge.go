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

// Bridge carries one browser's WebSocket to one Terminal.
type Bridge struct {
	conn *websocket.Conn
	term *Terminal
	log  *slog.Logger
}

// NewBridge builds a Bridge.
func NewBridge(conn *websocket.Conn, term *Terminal, log *slog.Logger) *Bridge {
	if log == nil {
		log = slog.Default()
	}
	conn.SetReadLimit(maxIncomingFrame)
	return &Bridge{conn: conn, term: term, log: log}
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

	case ControlPing:
		b.sendControl(ctx, Control{Type: ControlPong})

	default:
		// Unknown types are ignored so an older server tolerates a newer
		// client sending something it has not heard of.
		b.log.Debug("ignoring unknown control message", "type", msg.Type)
	}
	return nil
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
