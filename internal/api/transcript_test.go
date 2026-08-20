package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// Transcripts, from the WebSocket to a file on disk.
//
// The setting existed for five phases and nothing read it. These prove the
// whole path: that a connection asking to be recorded produces a file, that
// an operator recording everything overrides the connection, and — the part
// that is a decision rather than a mechanism — that the person being recorded
// is told on their own terminal.

// withRecording points the harness at a transcript directory.
func withRecording(dir string) harnessOption {
	return func(c *config.Config) { c.Paths.SessionLogDir = dir }
}

// recordEverything is the operator's switch.
func recordEverything(c *config.Config) { c.Policy.RecordAllSessions = true }

// transcripts lists what landed in the directory.
func transcripts(t *testing.T, dir string) []string {
	t.Helper()

	var out []string
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		out = append(out, path)
		return nil
	})
	return out
}

// waitForTranscript polls, because the file appears when the terminal opens
// rather than when the socket does.
func waitForTranscript(t *testing.T, dir string) string {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if found := transcripts(t, dir); len(found) > 0 {
			return found[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no transcript was written")
	return ""
}

// savedRecordedHost stores a connection that asks to be recorded.
func (h *harness) savedRecordedHost(t *testing.T, srv *sshTestServer, password string) string {
	t.Helper()

	_, cred := h.post("/api/credentials", map[string]string{
		"name": "recorded password", "kind": "password", "secret": password,
	})
	credID, _ := cred["id"].(string)

	resp, sess := h.post("/api/tree/sessions", map[string]any{
		"name": "core-sw-01", "hostname": srv.Host, "port": srv.Port,
		"username": "alice", "credential_id": credID,
		"settings": map[string]any{"log_session": true},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating the connection = %d: %v", resp.StatusCode, sess)
	}
	id, _ := sess["id"].(string)
	return id
}

// TestARecordedSessionLandsOnDisk.
func TestARecordedSessionLandsOnDisk(t *testing.T) {
	dir := t.TempDir()
	h := signedInWithVault(t, withRecording(dir))
	srv := startSSH(t, "hunter2")
	sessionID := h.savedRecordedHost(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.waitFor(t, "PROMPT>", "", 20*time.Second)

	path := waitForTranscript(t, dir)

	// And the person being recorded was told, on the terminal, rather than
	// having to find it in a settings page.
	var told bool
	for _, control := range view.controls {
		if control.Code == "session_recorded" {
			told = true
		}
	}
	if !told {
		t.Error("the session is being written to disk and nothing said so")
	}

	// The list says so too, so a second browser sees it.
	_, body := h.get("/api/terminals")
	terminals, _ := body["terminals"].([]any)
	if len(terminals) != 1 {
		t.Fatalf("got %d terminals", len(terminals))
	}
	info, _ := terminals[0].(map[string]any)
	if recorded, _ := info["recorded"].(bool); !recorded {
		t.Error("the terminal list does not report the recording")
	}

	view.type_(t, "echo written-down\r")
	waitUntil(t, func() bool {
		body, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(body), "written-down")
	}, "the command reached the transcript")
}

// TestRecordingEverythingOverridesTheConnection, and says whose decision it
// was — which is the difference between a policy and a surprise.
func TestRecordingEverythingOverridesTheConnection(t *testing.T) {
	dir := t.TempDir()
	h := signedInWithVault(t, withRecording(dir), recordEverything)
	srv := startSSH(t, "hunter2")

	// A connection that says nothing about recording.
	sessionID := h.savedConnection(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.waitFor(t, "PROMPT>", "", 20*time.Second)

	path := waitForTranscript(t, dir)

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "record_all_sessions") {
		t.Errorf("the transcript does not say whose decision this was:\n%s", body)
	}

	var message string
	for _, control := range view.controls {
		if control.Code == "session_recorded" {
			message = control.Message
		}
	}
	if !strings.Contains(message, "every session") {
		t.Errorf("the notice does not say it is the server's policy: %q", message)
	}
}

// TestNothingIsWrittenWhenNobodyAskedForIt, which is the default.
func TestNothingIsWrittenWhenNobodyAskedForIt(t *testing.T) {
	dir := t.TempDir()
	h := signedInWithVault(t, withRecording(dir))
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.waitFor(t, "PROMPT>", "", 20*time.Second)

	view.type_(t, "echo nothing-to-see\r")
	view.waitFor(t, "nothing-to-see", "", 20*time.Second)

	if found := transcripts(t, dir); len(found) != 0 {
		t.Errorf("a session nobody asked to record wrote %v", found)
	}
	for _, control := range view.controls {
		if control.Code == "session_recorded" {
			t.Error("a session that is not recorded claimed to be")
		}
	}
}

// TestRecordingIsOffWhenThereIsNowhereToWrite.
//
// A server with no session_log_dir records nothing, whatever a connection or
// a policy asks for — and must still open the terminal, because refusing to
// connect over a logging misconfiguration helps nobody.
func TestRecordingIsOffWhenThereIsNowhereToWrite(t *testing.T) {
	h := signedInWithVault(t, recordEverything) // no directory
	srv := startSSH(t, "hunter2")
	sessionID := h.savedRecordedHost(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.waitFor(t, "PROMPT>", "", 20*time.Second)
}
