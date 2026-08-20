package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// Triggers, through the whole stack.
//
// The terminal package tests the matching against a scripted device. These
// prove the parts only the server can: that a rule saved through the API
// reaches the session, that firing it reaches the browser, and that a pattern
// which does not compile is refused while somebody is looking at the form
// rather than three weeks later on a device.

// savedHostWithTriggers stores a connection carrying watch rules.
func (h *harness) savedHostWithTriggers(
	t *testing.T, srv *sshTestServer, password string, triggers []map[string]any,
) string {
	t.Helper()

	_, cred := h.post("/api/credentials", map[string]string{
		"name": "trigger password", "kind": "password", "secret": password,
	})
	credID, _ := cred["id"].(string)

	resp, sess := h.post("/api/tree/sessions", map[string]any{
		"name": "core-sw-01", "hostname": srv.Host, "port": srv.Port,
		"username": "alice", "credential_id": credID,
		"settings": map[string]any{"triggers": triggers},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating the connection = %d: %v", resp.StatusCode, sess)
	}
	id, _ := sess["id"].(string)
	return id
}

// TestATriggerFiresAndTheBrowserIsTold.
//
// A trigger nobody sees fire is indistinguishable from one that never fired,
// which is why the notice matters as much as the action.
func TestATriggerFiresAndTheBrowserIsTold(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")

	sessionID := h.savedHostWithTriggers(t, srv, "hunter2", []map[string]any{{
		"name": "found the prompt", "pattern": "PROMPT>", "action": "notify",
	}})

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})

	control := view.waitFor(t, "", terminal.ControlTrigger, 20*time.Second)
	if control.Trigger == nil {
		t.Fatal("the trigger message carries no event")
	}
	if control.Trigger.Name != "found the prompt" {
		t.Errorf("name = %q", control.Trigger.Name)
	}
	if !strings.Contains(control.Trigger.Line, "PROMPT>") {
		t.Errorf("the notice does not carry what it saw: %q", control.Trigger.Line)
	}
}

// TestATriggerTypesAtTheDevice, which is the automation half.
func TestATriggerTypesAtTheDevice(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")

	// The test server echoes what it is sent, so a rule that reacts to the
	// prompt by typing a command is visible in the output it produces.
	sessionID := h.savedHostWithTriggers(t, srv, "hunter2", []map[string]any{{
		"name": "say hello", "pattern": "PROMPT>", "action": "send",
		"send": "echo trigger-typed-this\\r", "max_fires": 1,
	}})

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})

	view.waitFor(t, "trigger-typed-this", "", 20*time.Second)
}

// TestABrokenPatternIsRefusedWhileYouAreLookingAtIt.
//
// The alternative is a rule that is saved happily and silently never matches,
// which is the failure mode of every rule engine that validates lazily.
func TestABrokenPatternIsRefusedWhileYouAreLookingAtIt(t *testing.T) {
	h := signedInWithVault(t)

	resp, body := h.post("/api/tree/sessions", map[string]any{
		"name": "sw", "hostname": "10.0.0.1", "username": "alice",
		"settings": map[string]any{"triggers": []map[string]any{{
			"name": "broken", "pattern": "([unclosed", "action": "notify",
		}}},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("= %d, want 400: %v", resp.StatusCode, body)
	}

	failure, _ := body["error"].(map[string]any)
	message, _ := failure["message"].(string)
	if !strings.Contains(message, "broken") {
		t.Errorf("the refusal does not name the rule: %q", message)
	}
}

// TestTriggersAreBounded, in count and in shape.
func TestTriggersAreBounded(t *testing.T) {
	h := signedInWithVault(t)

	tooMany := make([]map[string]any, 0, 20)
	for i := range 20 {
		tooMany = append(tooMany, map[string]any{
			"name": string(rune('a'+i)) + "-rule", "pattern": "x", "action": "notify",
		})
	}

	cases := map[string][]map[string]any{
		"too many": tooMany,
		"a send with nothing to send": {
			{"name": "empty", "pattern": "x", "action": "send"},
		},
		"an action nobody implements": {
			{"name": "reboot", "pattern": "x", "action": "reboot-the-server"},
		},
		"two rules with one name": {
			{"name": "same", "pattern": "x", "action": "notify"},
			{"name": "same", "pattern": "y", "action": "notify"},
		},
	}

	for name, triggers := range cases {
		t.Run(name, func(t *testing.T) {
			resp, body := h.post("/api/tree/sessions", map[string]any{
				"name": "sw " + name, "hostname": "10.0.0.1", "username": "alice",
				"settings": map[string]any{"triggers": triggers},
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("= %d, want 400: %v", resp.StatusCode, body)
			}
		})
	}
}
