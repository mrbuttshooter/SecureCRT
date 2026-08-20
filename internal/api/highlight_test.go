package api

import (
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// Keyword highlighting, from the saved rule to the browser.
//
// Highlighting is the one trigger action the server does not perform: it has
// no idea what a colour is, and the text has to be marked as it is drawn. So
// the server's whole job here is to hand the browser the rules — and, much
// more importantly, to hand it only those rules.

// TestHighlightRulesReachTheBrowser.
func TestHighlightRulesReachTheBrowser(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")

	sessionID := h.savedHostWithTriggers(t, srv, "hunter2", []map[string]any{{
		"name": "errors in red", "pattern": "(?i)error|down",
		"action": "highlight", "colour": "red",
	}})

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})

	// The connection reports "connected" twice: once as dialling progress,
	// and once from the bridge when the browser attaches. Only the second
	// names a terminal, and only the second carries the rules.
	status := view.waitFor(t, "", terminal.ControlStatus, 20*time.Second)
	for status.TerminalID == "" {
		status = view.waitFor(t, "", terminal.ControlStatus, 20*time.Second)
	}

	if len(status.Highlights) != 1 {
		t.Fatalf("the browser was sent %d highlight rules, want 1: %+v",
			len(status.Highlights), status.Highlights)
	}
	got := status.Highlights[0]
	if got.Name != "errors in red" || got.Pattern != "(?i)error|down" || got.Colour != "red" {
		t.Errorf("the rule arrived as %+v", got)
	}
}

// TestOnlyHighlightRulesReachTheBrowser.
//
// The rule that matters. A send trigger holds what it types, which is a
// password or the macro that becomes one, and the browser has no use for
// either. Reverted against a version that sends the whole trigger set, this
// finds the secret sitting in a control frame.
func TestOnlyHighlightRulesReachTheBrowser(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")

	// The send rule's pattern deliberately cannot match anything the test
	// server prints, so the only way its text can appear on the socket is by
	// having been sent as configuration.
	const secret = "correct-horse-battery-staple"
	sessionID := h.savedHostWithTriggers(t, srv, "hunter2", []map[string]any{
		{
			"name": "enable", "pattern": "this-string-is-never-printed",
			"action": "send", "send": secret + "\\r",
		},
		{
			"name": "errors in red", "pattern": "ERROR",
			"action": "highlight", "colour": "red",
		},
	})

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})

	view.type_(t, "echo settled\n")
	view.waitFor(t, "settled", "", 20*time.Second)

	for _, control := range view.controls {
		encoded, err := control.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("a send trigger's text reached the browser: %s", encoded)
		}
		for _, rule := range control.Highlights {
			if rule.Name != "errors in red" {
				t.Errorf("a rule the server runs was sent to the browser: %+v", rule)
			}
		}
	}
}

// TestHighlightRulesComeBackOnReattach.
//
// The browser holds no state across a dropped socket, so rules sent once at
// connect would leave a reattached session uncoloured until the next reload —
// and the colours are most wanted on the session that has been running long
// enough for the network to have dropped once.
func TestHighlightRulesComeBackOnReattach(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")

	sessionID := h.savedHostWithTriggers(t, srv, "hunter2", []map[string]any{{
		"name": "errors in red", "pattern": "ERROR", "action": "highlight", "colour": "red",
	}})

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.type_(t, "echo before the drop\n")
	view.waitFor(t, "before the drop", "", 20*time.Second)

	var terminalID string
	for _, c := range view.controls {
		if c.TerminalID != "" {
			terminalID = c.TerminalID
		}
	}
	if terminalID == "" {
		t.Fatal("no terminal ID was announced")
	}

	_ = conn.CloseNow()
	time.Sleep(200 * time.Millisecond)

	view2 := newSocketView(h.dialTerminal(t, "terminal="+terminalID))
	status := view2.waitFor(t, "", terminal.ControlStatus, 20*time.Second)
	for status.TerminalID == "" {
		status = view2.waitFor(t, "", terminal.ControlStatus, 20*time.Second)
	}
	if status.Status != terminal.StatusReattached {
		t.Fatalf("status = %q, want reattached", status.Status)
	}
	if len(status.Highlights) != 1 {
		t.Fatalf("a reattached browser was sent %d rules, want 1", len(status.Highlights))
	}
}
