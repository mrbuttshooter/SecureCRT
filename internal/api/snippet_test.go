package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// Snippets, and the endpoint that types one at a device.
//
// The CRUD is checked in the store's own tests. What is only visible here is
// the send: that it goes to terminals the user already has open, that naming
// several is the deliberate case, and that a stale terminal id stops the
// whole thing rather than half of it.

func (h *harness) createSnippet(t *testing.T, name, body string) string {
	t.Helper()

	resp, snippet := h.post("/api/snippets", map[string]any{
		"name": name, "body": body,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating %s = %d: %v", name, resp.StatusCode, snippet)
	}
	id, _ := snippet["id"].(string)
	return id
}

// openTerminalOn connects and returns the live terminal's id.
func (h *harness) openTerminalOn(t *testing.T, sessionID string) (*socketView, string) {
	t.Helper()

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	// The first connection to a host asks about its key.
	prompt := view.waitFor(t, "PROMPT>", terminal.ControlHostKeyPrompt, 20*time.Second)
	if prompt.Type == terminal.ControlHostKeyPrompt {
		view.sendControl(t, terminal.Control{
			Type: terminal.ControlHostKeyDecision, Accepted: true,
		})
		view.waitFor(t, "PROMPT>", "", 20*time.Second)
	}

	// Found by the saved connection it came from rather than by position.
	// The list is ordered now, but "the last one" would still be wrong the
	// moment a test opens two terminals on one connection — and the failure
	// is a test that sends to the wrong device and blames the feature.
	_, body := h.get("/api/terminals")
	terminals, _ := body["terminals"].([]any)
	for i := len(terminals) - 1; i >= 0; i-- {
		info, _ := terminals[i].(map[string]any)
		if got, _ := info["session_id"].(string); got == sessionID {
			id, _ := info["id"].(string)
			return view, id
		}
	}
	t.Fatalf("no live terminal for %s: %v", sessionID, body)
	return nil, ""
}

// TestASnippetIsTypedAtATerminal, with its parameters filled in.
func TestASnippetIsTypedAtATerminal(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	view, terminalID := h.openTerminalOn(t, sessionID)
	snippetID := h.createSnippet(t, "Say something", "echo {{word}}\r")

	resp, body := h.post("/api/snippets/send", map[string]any{
		"snippet_id": snippetID,
		"values":     map[string]string{"word": "from-a-snippet"},
		"terminals":  []string{terminalID},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send = %d: %v", resp.StatusCode, body)
	}

	view.waitFor(t, "from-a-snippet", "", 20*time.Second)
}

// TestOneSnippetReachesSeveralTerminals is the deliberate case: a command
// across a rack is the reason this endpoint takes a list.
func TestOneSnippetReachesSeveralTerminals(t *testing.T) {
	h := signedInWithVault(t)
	first := startSSH(t, "hunter2")
	second := startSSH(t, "hunter2")

	firstID := h.savedConnection(t, first, "hunter2")
	secondID := h.savedConnection(t, second, "hunter2")

	firstView, firstTerm := h.openTerminalOn(t, firstID)
	secondView, secondTerm := h.openTerminalOn(t, secondID)

	snippetID := h.createSnippet(t, "Everywhere", "echo across-the-rack\r")

	resp, body := h.post("/api/snippets/send", map[string]any{
		"snippet_id": snippetID,
		"terminals":  []string{firstTerm, secondTerm},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send = %d: %v", resp.StatusCode, body)
	}
	sent, _ := body["sent"].([]any)
	if len(sent) != 2 {
		t.Fatalf("sent to %d terminals, want 2", len(sent))
	}

	firstView.waitFor(t, "across-the-rack", "", 20*time.Second)
	secondView.waitFor(t, "across-the-rack", "", 20*time.Second)
}

// TestAStaleTerminalStopsTheWholeSend.
//
// Half a rack having received a configuration command is worse than none of
// it, and the failure people actually hit is a terminal id from a tab that
// was closed on another device.
func TestAStaleTerminalStopsTheWholeSend(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	view, terminalID := h.openTerminalOn(t, sessionID)
	snippetID := h.createSnippet(t, "Careful", "echo should-not-arrive\r")

	resp, body := h.post("/api/snippets/send", map[string]any{
		"snippet_id": snippetID,
		"terminals": []string{
			terminalID,
			"01920000-0000-7000-8000-000000000000", // long gone
		},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("= %d, want 404: %v", resp.StatusCode, body)
	}

	failure, _ := body["error"].(map[string]any)
	message, _ := failure["message"].(string)
	if !strings.Contains(message, "Nothing was sent") {
		t.Errorf("the refusal does not say the send was abandoned: %q", message)
	}

	// And genuinely nothing was: the live terminal did not receive it either.
	time.Sleep(300 * time.Millisecond)
	if strings.Contains(view.screen.String(), "should-not-arrive") {
		t.Error("part of the send landed before the check failed")
	}
}

// TestASnippetBelongsToOnePerson.
func TestASnippetBelongsToOnePerson(t *testing.T) {
	h := signedInWithVault(t)
	snippetID := h.createSnippet(t, "Mine", "write memory")

	// A second account in the same instance.
	h.createLocalUser("mallory@example.com", "another long password", false)
	h.post("/api/auth/logout", nil)
	h.login("mallory@example.com", "another long password")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "mallory's long passphrase"})

	_, body := h.get("/api/snippets")
	list, _ := body["snippets"].([]any)
	if len(list) != 0 {
		t.Errorf("mallory can see %d of somebody else's snippets", len(list))
	}

	resp, _ := h.do(http.MethodDelete, "/api/snippets/"+snippetID, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("deleting somebody else's snippet = %d, want 404", resp.StatusCode)
	}
}

// TestParametersAreReportedSoTheInterfaceCanAsk.
func TestParametersAreReportedSoTheInterfaceCanAsk(t *testing.T) {
	h := signedInWithVault(t)
	h.createSnippet(t, "Describe", "interface {{interface}}\ndescription {{text}}")

	_, body := h.get("/api/snippets")
	list, _ := body["snippets"].([]any)
	if len(list) != 1 {
		t.Fatalf("got %d snippets", len(list))
	}

	snippet, _ := list[0].(map[string]any)
	params, _ := snippet["parameters"].([]any)
	if len(params) != 2 {
		t.Fatalf("parameters = %v", snippet["parameters"])
	}
	if params[0] != "interface" {
		t.Errorf("first parameter = %v, want the order the command uses", params[0])
	}
}
