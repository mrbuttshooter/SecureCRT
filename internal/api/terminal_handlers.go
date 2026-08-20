package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// hostKeyPromptTimeout bounds how long a connection waits for someone to
// approve an unknown host key.
//
// The wait happens inside the SSH handshake, so it cannot be indefinite. Two
// minutes is long enough to read a fingerprint and compare it against
// whatever the user keeps it in, and short enough that an abandoned prompt
// releases the connection.
const hostKeyPromptTimeout = 2 * time.Minute

// handleListTerminals returns the user's live terminals.
//
// This is the visible payoff of server-side session survival: open a fresh
// browser, and the sessions left running are still there.
func (a *API) handleListTerminals(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"terminals": a.terminals.ListForUser(u.ID),
	})
}

// handleCloseTerminal ends a terminal.
func (a *API) handleCloseTerminal(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/terminals/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No terminal was specified.")
		return
	}

	if err := a.terminals.CloseTerminal(u.ID, id); err != nil {
		if errors.Is(err, terminal.ErrTerminalNotFound) {
			writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such terminal.")
			return
		}
		writeInternal(w, a.log, "closing a terminal", err)
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionTerminalClosed, TargetType: "terminal", TargetID: id,
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"closed": true})
}

// handleTerminalSocket upgrades to a WebSocket and runs a terminal.
//
// Two shapes:
//
//	?session=<id>   connect a saved connection, opening a new terminal
//	?terminal=<id>  reattach to a terminal already running
//
// Reattach is what makes a dropped connection survivable, so it is a
// first-class case rather than a retry of connect.
func (a *API) handleTerminalSocket(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	sess, _ := SessionFrom(r.Context())
	ctx := r.Context()

	// The upgrade is same-origin only. A WebSocket is not subject to the
	// same-origin policy the way fetch is, so without this check any page on
	// the internet could open a terminal using the visitor's cookies.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns:  a.wsOriginPatterns(),
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		// Accept has already written a response.
		a.log.Debug("websocket upgrade refused", "error", err, "request_id", RequestIDFrom(ctx))
		return
	}
	// The status is corrected on the clean paths; this is the catch-all.
	defer conn.CloseNow() //nolint:errcheck

	query := r.URL.Query()
	cols := atoiOr(query.Get("cols"), 80)
	rows := atoiOr(query.Get("rows"), 24)

	var term *terminal.Terminal

	switch {
	case query.Get("terminal") != "":
		term, err = a.terminals.Get(u.ID, query.Get("terminal"))
		if err != nil {
			sendSocketError(ctx, conn, a, terminal.ErrCodeNotFound,
				"That terminal is no longer available. It may have ended while you were away.")
			return
		}

	case query.Get("session") != "":
		term, err = a.openTerminal(ctx, conn, u.ID, sess.ID, query.Get("session"), cols, rows, r)
		if err != nil {
			return // openTerminal has already reported it
		}

	default:
		sendSocketError(ctx, conn, a, terminal.ErrCodeNotFound,
			"No connection or terminal was specified.")
		return
	}

	bridge := terminal.NewBridge(conn, term, a.log)
	if err := bridge.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		a.log.Debug("terminal bridge ended", "terminal", term.ID, "error", err)
	}
}

// openTerminal dials a saved connection, reporting progress and host key
// prompts over the socket as it goes.
func (a *API) openTerminal(
	ctx context.Context,
	conn *websocket.Conn,
	userID, sessionID, savedSessionID string,
	cols, rows int,
	r *http.Request,
) (*terminal.Terminal, error) {
	u, _ := UserFrom(ctx)

	vaultKey, err := a.vaults.Key(userID, sessionID)
	if err != nil {
		sendSocketError(ctx, conn, a, terminal.ErrCodeVaultLocked,
			"Your vault is locked. Enter your passphrase, then try again.")
		return nil, err
	}

	prompter := &socketPrompter{conn: conn, api: a}

	term, connectErr := a.connector.Connect(ctx, terminal.ConnectParams{
		UserID:    userID,
		SessionID: savedSessionID,
		VaultKey:  vaultKey,
		Cols:      cols,
		Rows:      rows,
		Prompter:  prompter,
		Progress: func(status string) {
			writeControl(ctx, conn, a, terminal.Control{
				Type: terminal.ControlStatus, Status: status,
			})
		},
	})
	if connectErr != nil {
		var ce *terminal.ConnectError
		if errors.As(connectErr, &ce) {
			msg := terminal.Control{
				Type:    terminal.ControlError,
				Code:    ce.Code,
				Message: ce.Message,
			}
			// A changed key carries both fingerprints so the interface can
			// show the difference rather than merely asserting one.
			if ce.HostKey != nil {
				msg.Type = terminal.ControlHostKeyChanged
				msg.HostKey = ce.HostKey
			}
			writeControl(ctx, conn, a, msg)

			severity := audit.SeverityNotice
			if ce.Code == terminal.ErrCodeHostKeyChanged {
				// The most serious thing this system reports: either a host
				// was rebuilt, or something is impersonating it.
				severity = audit.SeverityCritical
			}
			a.audit.Record(ctx, audit.Event{
				ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
				Action: audit.ActionTerminalConnectFailed, Outcome: audit.OutcomeFailure,
				Severity: severity, TargetType: "session", TargetID: savedSessionID,
				Detail: map[string]any{"reason": ce.Code},
			})
		} else {
			sendSocketError(ctx, conn, a, terminal.ErrCodeInternal, "The connection failed.")
		}
		return nil, connectErr
	}

	a.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionTerminalConnected, TargetType: "session",
		TargetID: savedSessionID, TargetLabel: term.Label,
		Detail: map[string]any{
			"host": term.Host, "port": term.Port,
			"username": term.Username, "terminal_id": term.ID,
		},
	})

	if len(term.AgentKeys) > 0 {
		// A separate record from the connection itself, because it answers a
		// different question and has to be findable on its own: not "did
		// somebody open a shell here" but "which keys were in this host's
		// reach, and when".
		//
		// The key is "keys_offered". forbiddenDetailKeys matches substrings,
		// so anything containing "credential_secret" or "private_key" would
		// be dropped by the recorder and the record would say an agent was
		// forwarded without saying what was in it.
		a.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
			Action: audit.ActionAgentForwarded, TargetType: "session",
			TargetID: savedSessionID, TargetLabel: term.Label,
			Detail: map[string]any{
				"host": term.Host, "port": term.Port,
				"keys_offered": term.AgentKeys,
				"accepted":     !term.AgentRefused,
				"terminal_id":  term.ID,
			},
		})

		if term.AgentRefused {
			// Said out loud rather than logged. Somebody who ticked this box
			// is about to try an authentication that will fail three hops
			// away, and "the host would not take it" is the only useful
			// moment to learn why.
			writeControl(ctx, conn, a, terminal.Control{
				Type: terminal.ControlWarning,
				Code: "agent_refused",
				Message: "This host declined the forwarded agent, so your keys " +
					"are not available from it. Its sshd sets AllowAgentForwarding no.",
			})
		}
	}

	return term, nil
}

// socketPrompter asks the browser to approve an unknown host key and waits
// for the answer.
type socketPrompter struct {
	conn *websocket.Conn
	api  *API
}

// PromptHostKey sends the fingerprint and blocks until the user answers.
//
// Called from inside the SSH handshake, so the timeout matters: an
// unanswered prompt must eventually release the connection rather than
// holding a handshake open indefinitely.
func (p *socketPrompter) PromptHostKey(ctx context.Context, info terminal.HostKeyInfo) (bool, error) {
	writeControl(ctx, p.conn, p.api, terminal.Control{
		Type:    terminal.ControlHostKeyPrompt,
		HostKey: &info,
	})

	waitCtx, cancel := context.WithTimeout(ctx, hostKeyPromptTimeout)
	defer cancel()

	for {
		typ, data, err := p.conn.Read(waitCtx)
		if err != nil {
			return false, err
		}
		// Anything the user types before answering is discarded: accepting
		// keystrokes into a session that does not exist yet would be
		// meaningless, and buffering them risks replaying them somewhere
		// unintended.
		if typ != websocket.MessageText {
			continue
		}

		msg, err := terminal.DecodeControl(data)
		if err != nil {
			continue
		}
		if msg.Type == terminal.ControlHostKeyDecision {
			return msg.Accepted, nil
		}
	}
}

// wsOriginPatterns restricts which origins may open a terminal socket.
//
// Derived from the configured external URL rather than accepting anything,
// because a WebSocket upgrade is not covered by the same-origin policy:
// without this, any page could open a terminal with the visitor's cookies.
func (a *API) wsOriginPatterns() []string {
	if a.cfg.ExternalURL == "" {
		return nil // websocket.Accept then requires a same-host Origin
	}

	trimmed := strings.TrimPrefix(strings.TrimPrefix(a.cfg.ExternalURL, "https://"), "http://")
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	if trimmed == "" {
		return nil
	}
	return []string{trimmed}
}

func writeControl(ctx context.Context, conn *websocket.Conn, a *API, msg terminal.Control) {
	encoded, err := msg.Encode()
	if err != nil {
		a.log.Error("encoding terminal control message", "type", msg.Type, "error", err)
		return
	}

	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := conn.Write(writeCtx, websocket.MessageText, encoded); err != nil {
		a.log.Debug("writing terminal control message", "type", msg.Type, "error", err)
	}
}

func sendSocketError(ctx context.Context, conn *websocket.Conn, a *API, code, message string) {
	writeControl(ctx, conn, a, terminal.Control{
		Type: terminal.ControlError, Code: code, Message: message,
	})
	_ = conn.Close(websocket.StatusNormalClosure, code)
}

func atoiOr(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 10000 {
		return fallback
	}
	return n
}
