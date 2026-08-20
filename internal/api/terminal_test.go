package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	gssh "github.com/gliderlabs/ssh"
	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
	"golang.org/x/crypto/ssh"
)

// --- a real SSH server for the terminal tests --------------------------------

type sshTestServer struct {
	Host string
	Port int

	// authAttempts counts how many times a credential was offered. A test
	// that declines a host key asserts this stayed at zero, which is the
	// property that matters: refusing an unrecognised fingerprint must mean
	// nothing was sent, not merely that the session did not open.
	mu           sync.Mutex
	authAttempts int
}

func (s *sshTestServer) attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authAttempts
}

func startSSH(t *testing.T, password string) *sshTestServer {
	t.Helper()

	server := &sshTestServer{}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	srv := &gssh.Server{
		HostSigners: []gssh.Signer{signer},
		PasswordHandler: func(_ gssh.Context, given string) bool {
			server.mu.Lock()
			server.authAttempts++
			server.mu.Unlock()
			return given == password
		},
		Handler: func(s gssh.Session) {
			if _, _, isPty := s.Pty(); !isPty {
				_ = s.Exit(1)
				return
			}
			_, _ = io.WriteString(s, "PROMPT> ")

			buf := make([]byte, 512)
			for {
				n, err := s.Read(buf)
				if n > 0 {
					line := strings.TrimSpace(string(buf[:n]))
					if line == "whoami" {
						_, _ = io.WriteString(s, "\r\n"+s.User()+"\r\nPROMPT> ")
					} else {
						_, _ = s.Write(buf[:n])
					}
				}
				if err != nil {
					return
				}
			}
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	server.Host = host
	server.Port = port
	return server
}

// --- harness helpers ---------------------------------------------------------

// signedInWithVault returns a harness with a user signed in and a vault open.
// harnessOption tweaks the configuration a harness is built with.
type harnessOption func(*config.Config)

// allowPlaintextExport turns on the policy switch that gates every
// unencrypted export format.
func allowPlaintextExport(c *config.Config) { c.Policy.AllowPlaintextExport = true }

func signedInWithVault(t *testing.T, options ...harnessOption) *harness {
	t.Helper()

	h := newHarness(t, func(c *config.Config) {
		for _, option := range options {
			option(c)
		}
	})
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.login("alice@example.com", "correct horse battery staple")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "a long enough passphrase"})
	return h
}

// savedConnection stores a password credential and a saved connection for srv.
func (h *harness) savedConnection(t *testing.T, srv *sshTestServer, password string) string {
	t.Helper()

	_, cred := h.post("/api/credentials", map[string]string{
		"name": "test password", "kind": "password", "secret": password,
	})
	credID, _ := cred["id"].(string)
	if credID == "" {
		t.Fatalf("no credential was created: %v", cred)
	}

	resp, sess := h.post("/api/tree/sessions", map[string]any{
		"name": "test host", "hostname": srv.Host, "port": srv.Port,
		"username": "alice", "credential_id": credID,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating the saved connection failed: %d %v", resp.StatusCode, sess)
	}
	id, _ := sess["id"].(string)
	return id
}

// dialTerminal opens the terminal WebSocket, carrying the session cookie.
func (h *harness) dialTerminal(t *testing.T, query string) *websocket.Conn {
	t.Helper()

	url := strings.Replace(h.server.URL, "http://", "ws://", 1) + "/api/terminals/socket?" + query

	header := http.Header{}
	var pairs []string
	for name, value := range h.cookies {
		pairs = append(pairs, name+"="+value)
	}
	header.Set("Cookie", strings.Join(pairs, "; "))
	// The upgrade is same-origin only, so the Origin must match.
	header.Set("Origin", h.server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

// socketView accumulates what the browser would see.
type socketView struct {
	conn     *websocket.Conn
	screen   strings.Builder
	controls []terminal.Control
}

func newSocketView(conn *websocket.Conn) *socketView {
	return &socketView{conn: conn}
}

// pump reads until want appears on screen, a matching control arrives, or the
// deadline passes.
func (v *socketView) waitFor(t *testing.T, wantText string, wantControl terminal.ControlType, timeout time.Duration) terminal.Control {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		typ, data, err := v.conn.Read(ctx)
		if err != nil {
			t.Fatalf("socket closed while waiting for %q/%q: %v (screen held %q)",
				wantText, wantControl, err, v.screen.String())
		}

		switch typ {
		case websocket.MessageBinary:
			v.screen.Write(data)
			if wantText != "" && strings.Contains(v.screen.String(), wantText) {
				return terminal.Control{}
			}

		case websocket.MessageText:
			msg, err := terminal.DecodeControl(data)
			if err != nil {
				t.Fatalf("undecodable control message: %v", err)
			}
			v.controls = append(v.controls, msg)
			if wantControl != "" && msg.Type == wantControl {
				return msg
			}
		}
	}
}

func (v *socketView) sendControl(t *testing.T, msg terminal.Control) {
	t.Helper()
	encoded, err := msg.Encode()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := v.conn.Write(ctx, websocket.MessageText, encoded); err != nil {
		t.Fatal(err)
	}
}

func (v *socketView) type_(t *testing.T, text string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := v.conn.Write(ctx, websocket.MessageBinary, []byte(text)); err != nil {
		t.Fatal(err)
	}
}

// --- tests -------------------------------------------------------------------

// TestTerminalEndToEnd is the whole point of this phase: sign in, connect to a
// real SSH server through the WebSocket, run a command, see the output.
func TestTerminalEndToEnd(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID+"&cols=100&rows=30")
	view := newSocketView(conn)

	// First contact asks about the host key, with a fingerprint to compare.
	prompt := view.waitFor(t, "", terminal.ControlHostKeyPrompt, 10*time.Second)
	if prompt.HostKey == nil {
		t.Fatal("the prompt carried no host key detail")
	}
	if !strings.HasPrefix(prompt.HostKey.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q", prompt.HostKey.Fingerprint)
	}
	if prompt.HostKey.Hostname != srv.Host {
		t.Errorf("hostname = %q, want %q", prompt.HostKey.Hostname, srv.Host)
	}

	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})

	// Then the shell.
	view.waitFor(t, "PROMPT>", "", 10*time.Second)

	view.type_(t, "whoami\n")
	view.waitFor(t, "alice", "", 10*time.Second)

	// A terminal ID must have been announced, so the browser can reattach.
	var terminalID string
	for _, c := range view.controls {
		if c.TerminalID != "" {
			terminalID = c.TerminalID
		}
	}
	if terminalID == "" {
		t.Fatal("no terminal ID was announced; the browser could not reattach after a drop")
	}

	// The host was offered a credential, which is what makes the counter
	// meaningful when TestDecliningTheHostKeySendsNothing asserts it stayed
	// at zero. Without this the negative assertion could pass for the wrong
	// reason — a counter nothing ever increments proves nothing.
	if n := srv.attempts(); n == 0 {
		t.Error("the host recorded no authentication attempt on a successful connection")
	}

	// And it must be listed.
	_, body := h.get("/api/terminals")
	list, _ := body["terminals"].([]any)
	if len(list) != 1 {
		t.Fatalf("listed %d terminals, want 1", len(list))
	}
}

// TestTerminalSurvivesADroppedSocket is what makes this usable on a laptop.
func TestTerminalSurvivesADroppedSocket(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 10*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.waitFor(t, "PROMPT>", "", 10*time.Second)

	view.type_(t, "before the drop\n")
	view.waitFor(t, "before the drop", "", 10*time.Second)

	var terminalID string
	for _, c := range view.controls {
		if c.TerminalID != "" {
			terminalID = c.TerminalID
		}
	}
	if terminalID == "" {
		t.Fatal("no terminal ID was announced")
	}

	// The network drops. Not a clean close — the browser just vanishes.
	_ = conn.CloseNow()
	time.Sleep(200 * time.Millisecond)

	// The shell must still be running.
	_, body := h.get("/api/terminals")
	list, _ := body["terminals"].([]any)
	if len(list) != 1 {
		t.Fatalf("the terminal did not survive the drop: %d listed", len(list))
	}

	// Reattaching replays what was on screen and the session continues.
	conn2 := h.dialTerminal(t, "terminal="+terminalID)
	view2 := newSocketView(conn2)

	view2.waitFor(t, "before the drop", "", 10*time.Second)

	view2.type_(t, "after returning\n")
	view2.waitFor(t, "after returning", "", 10*time.Second)

	// The status must say "reattached", not "connected". They mean very
	// different things to someone who just watched their screen freeze, and
	// the interface says so.
	var status string
	for _, c := range view2.controls {
		if c.Type == terminal.ControlStatus && c.Status != "" {
			status = c.Status
		}
	}
	if status != terminal.StatusReattached {
		t.Errorf("status after reattaching = %q, want %q", status, terminal.StatusReattached)
	}
}

// TestDecliningTheHostKeySendsNothing confirms a refused key means no
// credential reached the host.
func TestDecliningTheHostKeySendsNothing(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 10*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: false})

	msg := view.waitFor(t, "", terminal.ControlError, 10*time.Second)
	if msg.Code != terminal.ErrCodeHostKeyRejected {
		t.Fatalf("code = %q, want host_key_rejected", msg.Code)
	}

	// No terminal may exist.
	_, body := h.get("/api/terminals")
	list, _ := body["terminals"].([]any)
	if len(list) != 0 {
		t.Fatalf("%d terminals exist despite the key being declined", len(list))
	}

	// And nothing may have been recorded, so the question is asked again.
	_, hosts := h.get("/api/known-hosts")
	known, _ := hosts["known_hosts"].([]any)
	if len(known) != 0 {
		t.Fatalf("%d host keys were recorded despite the user declining", len(known))
	}

	// The point of the whole exercise: the host was never offered anything to
	// authenticate with. Verification happens inside the handshake, before
	// any credential is sent, so a declined fingerprint leaks nothing — not
	// even a username paired with a password attempt.
	if n := srv.attempts(); n != 0 {
		t.Fatalf("%d credentials were offered to a host whose key was declined", n)
	}
}

// TestTerminalRefusedWhileTheVaultIsLocked stops a connection being attempted
// with no way to read the credential.
func TestTerminalRefusedWhileTheVaultIsLocked(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	h.post("/api/vault/lock", nil)

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	msg := view.waitFor(t, "", terminal.ControlError, 10*time.Second)
	if msg.Code != terminal.ErrCodeVaultLocked {
		t.Fatalf("code = %q, want vault_locked", msg.Code)
	}
}

// TestTerminalSocketRequiresAuthentication is the obvious one, and the one
// whose absence would be catastrophic.
func TestTerminalSocketRequiresAuthentication(t *testing.T) {
	h := newHarness(t, nil)

	url := strings.Replace(h.server.URL, "http://", "ws://", 1) + "/api/terminals/socket?session=whatever"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	header := http.Header{}
	header.Set("Origin", h.server.URL)

	conn, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
	if err == nil {
		_ = conn.CloseNow()
		t.Fatal("an unauthenticated client opened a terminal socket")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestTerminalSocketRejectsForeignOrigins closes the hole a WebSocket would
// otherwise leave: the upgrade is not covered by the same-origin policy, so
// without this any page could open a terminal using the visitor's cookies.
func TestTerminalSocketRejectsForeignOrigins(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	url := strings.Replace(h.server.URL, "http://", "ws://", 1) +
		"/api/terminals/socket?session=" + sessionID

	header := http.Header{}
	var pairs []string
	for name, value := range h.cookies {
		pairs = append(pairs, name+"="+value)
	}
	header.Set("Cookie", strings.Join(pairs, "; "))
	header.Set("Origin", "https://evil.example.com")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
	if err == nil {
		_ = conn.CloseNow()
		t.Fatal("a page on another origin opened a terminal with the user's cookies")
	}
}

// TestTerminalIsScopedToItsOwner stops one user attaching to another's shell.
func TestTerminalIsScopedToItsOwner(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 10*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.waitFor(t, "PROMPT>", "", 10*time.Second)

	var terminalID string
	for _, c := range view.controls {
		if c.TerminalID != "" {
			terminalID = c.TerminalID
		}
	}

	// A second user on the same client.
	h.createLocalUser("bob@example.com", "correct horse battery staple", false)
	h.post("/api/auth/logout", nil)
	h.get("/api/auth/config")
	h.login("bob@example.com", "correct horse battery staple")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "bob's long passphrase"})

	// Bob must not see it...
	_, body := h.get("/api/terminals")
	list, _ := body["terminals"].([]any)
	if len(list) != 0 {
		t.Fatalf("another user's terminals leaked into the list: %d", len(list))
	}

	// ...nor attach to it by guessing the ID.
	conn2 := h.dialTerminal(t, "terminal="+terminalID)
	view2 := newSocketView(conn2)
	msg := view2.waitFor(t, "", terminal.ControlError, 10*time.Second)
	if msg.Code != terminal.ErrCodeNotFound {
		t.Fatalf("code = %q, want not_found", msg.Code)
	}
}

func TestResizeReachesTheRemoteTerminal(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID+"&cols=80&rows=24")
	view := newSocketView(conn)

	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 10*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.waitFor(t, "PROMPT>", "", 10*time.Second)

	// A resize must not disturb the session; the SSH-level assertion that the
	// far side sees the new size lives in the sshx package.
	view.sendControl(t, terminal.Control{Type: terminal.ControlResize, Cols: 200, Rows: 60})

	view.type_(t, "still here\n")
	view.waitFor(t, "still here", "", 10*time.Second)
}

func TestPingIsAnswered(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 10*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.waitFor(t, "PROMPT>", "", 10*time.Second)

	view.sendControl(t, terminal.Control{Type: terminal.ControlPing})
	view.waitFor(t, "", terminal.ControlPong, 10*time.Second)
}

// --- session tree endpoints ---------------------------------------------------

func TestSessionTreeCRUD(t *testing.T) {
	h := signedInWithVault(t)

	t.Run("empty to begin with", func(t *testing.T) {
		resp, body := h.get("/api/tree")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		folders, _ := body["folders"].([]any)
		saved, _ := body["sessions"].([]any)
		if len(folders) != 0 || len(saved) != 0 {
			t.Fatalf("a new account should have an empty tree, got %d folders and %d connections",
				len(folders), len(saved))
		}
	})

	var folderID string
	t.Run("create a folder with defaults", func(t *testing.T) {
		resp, body := h.post("/api/tree/folders", map[string]any{
			"name":     "Production",
			"defaults": map[string]any{"username": "netops"},
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
		folderID, _ = body["id"].(string)
		if folderID == "" {
			t.Fatal("no folder ID returned")
		}
	})

	var sessionID string
	t.Run("create a connection inside it", func(t *testing.T) {
		resp, body := h.post("/api/tree/sessions", map[string]any{
			"name": "core1", "folder_id": folderID, "hostname": "core1.example.com",
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
		sessionID, _ = body["id"].(string)
		// Two fields, saying two different things: the column is what the
		// user typed, where zero means inherit and the form renders blank,
		// and effective_port is what that resolves to.
		if body["port"] != float64(0) {
			t.Errorf("port = %v, want 0 when none was given", body["port"])
		}
		if body["effective_port"] != float64(22) {
			t.Errorf("effective_port = %v, want the SSH default", body["effective_port"])
		}
	})

	t.Run("resolution shows where the username came from", func(t *testing.T) {
		resp, body := h.get("/api/tree/sessions/" + sessionID + "/resolved")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
		effective, _ := body["effective"].(map[string]any)
		if effective["username"] != "netops" {
			t.Errorf("username = %v; it should be inherited from the folder", effective["username"])
		}
		inherited, _ := body["inherited_from"].([]any)
		if len(inherited) != 1 || inherited[0] != "Production" {
			t.Errorf("inherited_from = %v; the interface needs this to explain the value", inherited)
		}
	})

	t.Run("deleting a non-empty folder is refused with counts", func(t *testing.T) {
		resp, body := h.do(http.MethodDelete, "/api/tree/folders/"+folderID, nil)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("status = %d, want 409: %v", resp.StatusCode, body)
		}
		e, _ := body["error"].(map[string]any)
		if e["code"] != "folder_not_empty" {
			t.Errorf("code = %v", e["code"])
		}
		// The counts are what let the interface say exactly what would be lost.
		if e["sessions"] != float64(1) {
			t.Errorf("sessions = %v, want 1", e["sessions"])
		}
	})

	t.Run("recursive delete removes everything", func(t *testing.T) {
		resp, body := h.do(http.MethodDelete, "/api/tree/folders/"+folderID+"?recursive=true", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
		if body["connections_deleted"] != float64(1) {
			t.Errorf("connections_deleted = %v, want 1", body["connections_deleted"])
		}

		_, tree := h.get("/api/tree")
		folders, _ := tree["folders"].([]any)
		saved, _ := tree["sessions"].([]any)
		if len(folders) != 0 || len(saved) != 0 {
			t.Fatalf("the tree is not empty: %d folders, %d connections", len(folders), len(saved))
		}
	})
}

func TestSessionTreeIsScopedToItsOwner(t *testing.T) {
	h := signedInWithVault(t)

	_, created := h.post("/api/tree/sessions", map[string]any{
		"name": "alice's router", "hostname": "r1.example.com",
	})
	sessionID, _ := created["id"].(string)

	h.createLocalUser("bob@example.com", "correct horse battery staple", false)
	h.post("/api/auth/logout", nil)
	h.get("/api/auth/config")
	h.login("bob@example.com", "correct horse battery staple")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "bob's long passphrase"})

	_, tree := h.get("/api/tree")
	saved, _ := tree["sessions"].([]any)
	if len(saved) != 0 {
		t.Fatalf("another user's connections leaked: %d", len(saved))
	}

	resp, _ := h.do(http.MethodDelete, "/api/tree/sessions/"+sessionID, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestSessionTreeValidation(t *testing.T) {
	h := signedInWithVault(t)

	cases := map[string]map[string]any{
		"no name":      {"hostname": "h.example.com"},
		"no hostname":  {"name": "x"},
		"bad port":     {"name": "x", "hostname": "h.example.com", "port": 70000},
		"bad protocol": {"name": "x", "hostname": "h.example.com", "protocol": "carrier-pigeon"},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp, got := h.post("/api/tree/sessions", body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %v", resp.StatusCode, got)
			}
		})
	}
}

// TestKnownHostsAreListedAfterConnecting closes the loop: a key the user
// accepted must be visible and removable afterwards.
func TestKnownHostsAreListedAfterConnecting(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	sessionID := h.savedConnection(t, srv, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 10*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	view.waitFor(t, "PROMPT>", "", 10*time.Second)

	_, body := h.get("/api/known-hosts")
	known, _ := body["known_hosts"].([]any)
	if len(known) != 1 {
		t.Fatalf("listed %d known hosts, want 1", len(known))
	}

	entry, _ := known[0].(map[string]any)
	if entry["org_wide"] != false {
		t.Error("a personally accepted key should not be marked as published")
	}
	fingerprint, _ := entry["fingerprint"].(string)
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q", fingerprint)
	}

	id, _ := entry["id"].(string)
	resp, _ := h.do(http.MethodDelete, "/api/known-hosts/"+id, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("forgetting a host key failed: %d", resp.StatusCode)
	}

	_, after := h.get("/api/known-hosts")
	remaining, _ := after["known_hosts"].([]any)
	if len(remaining) != 0 {
		t.Fatalf("%d host keys remain", len(remaining))
	}
}
