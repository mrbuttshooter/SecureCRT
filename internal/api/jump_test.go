package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
	"golang.org/x/crypto/ssh"
)

// Connecting through a jump host, through the whole stack.
//
// The pool's own tests prove the lease arithmetic. This proves the thing a
// user actually does: a saved connection whose jump chain names a bastion,
// opened from the browser's WebSocket, arriving at a host that could not have
// been reached any other way.

// bastionServer is an SSH server that will open direct-tcpip channels.
type bastionServer struct {
	Host string
	Port int

	mu       sync.Mutex
	forwards []string
}

// forwarded returns the addresses this bastion was asked to reach.
func (b *bastionServer) forwarded() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.forwards...)
}

func startBastion(t *testing.T, password string) *bastionServer {
	t.Helper()

	bastion := &bastionServer{}

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
			return given == password
		},
		// Configured before Serve. Setting these on a running server is a
		// data race — the accept loop reads them.
		ChannelHandlers: map[string]gssh.ChannelHandler{
			"session":      gssh.DefaultSessionHandler,
			"direct-tcpip": gssh.DirectTCPIPHandler,
		},
		LocalPortForwardingCallback: func(_ gssh.Context, host string, port uint32) bool {
			bastion.mu.Lock()
			bastion.forwards = append(bastion.forwards, net.JoinHostPort(host, strconv.Itoa(int(port))))
			bastion.mu.Unlock()
			return true
		},
		Handler: func(s gssh.Session) { _ = s.Exit(0) },
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
	bastion.Host, bastion.Port = host, port
	return bastion
}

// savedHost stores a credential and a saved connection, optionally behind a
// jump chain, and returns the connection's identifier.
func (h *harness) savedHost(
	t *testing.T, name, host string, port int, password string, chain ...string,
) string {
	t.Helper()

	_, cred := h.post("/api/credentials", map[string]string{
		"name": name + " password", "kind": "password", "secret": password,
	})
	credID, _ := cred["id"].(string)
	if credID == "" {
		t.Fatalf("no credential for %s: %v", name, cred)
	}

	body := map[string]any{
		"name": name, "hostname": host, "port": port,
		"username": "alice", "credential_id": credID,
	}
	if len(chain) > 0 {
		body["jump_chain"] = chain
	}

	resp, sess := h.post("/api/tree/sessions", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating %s failed: %d %v", name, resp.StatusCode, sess)
	}
	id, _ := sess["id"].(string)
	return id
}

// TestATerminalOpensThroughAJumpHost is Phase 5a's reason for existing.
func TestATerminalOpensThroughAJumpHost(t *testing.T) {
	h := signedInWithVault(t)

	bastion := startBastion(t, "bastion-pass")
	target := startSSH(t, "target-pass")

	bastionID := h.savedHost(t, "bastion", bastion.Host, bastion.Port, "bastion-pass")
	targetID := h.savedHost(t, "core-sw-01", target.Host, target.Port, "target-pass", bastionID)

	conn := h.dialTerminal(t, "session="+targetID)
	view := newSocketView(conn)

	// The host key prompt fires per hop, so both have to be answered.
	for range 2 {
		control := view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
		if control.HostKey == nil {
			t.Fatal("a host key prompt arrived with no fingerprint")
		}
		view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	}

	view.waitFor(t, "PROMPT>", "", 20*time.Second)

	// The bastion was genuinely used: it was asked to reach the target's
	// address. Without this the test would pass just as well against a
	// direct dial, because both hosts are on loopback.
	forwards := bastion.forwarded()
	want := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	if len(forwards) == 0 {
		t.Fatal("the bastion was never asked to forward anything")
	}
	if forwards[0] != want {
		t.Errorf("the bastion forwarded to %q, want %q", forwards[0], want)
	}
}

// TestApprovingABastionsKeyRecordsItAsTheBastion.
//
// Every hop is verified under its own identity. If the target's hostname were
// reused for the prompt and the trust store, approving a bastion's key would
// file it against the target — a corrupted trust store, and a fingerprint
// shown to the user attributed to a device that never presented it.
func TestApprovingABastionsKeyRecordsItAsTheBastion(t *testing.T) {
	h := signedInWithVault(t)

	bastion := startBastion(t, "bastion-pass")
	target := startSSH(t, "target-pass")

	bastionID := h.savedHost(t, "bastion", bastion.Host, bastion.Port, "bastion-pass")
	targetID := h.savedHost(t, "core-sw-01", target.Host, target.Port, "target-pass", bastionID)

	conn := h.dialTerminal(t, "session="+targetID)
	view := newSocketView(conn)

	seen := map[int]string{}
	for range 2 {
		control := view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
		seen[control.HostKey.Port] = control.HostKey.Fingerprint
		view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
	}
	view.waitFor(t, "PROMPT>", "", 20*time.Second)

	// Two prompts, two ports: the bastion's and the target's. One prompt, or
	// two prompts naming the same port, would both mean a hop was verified
	// under somebody else's identity.
	if len(seen) != 2 {
		t.Fatalf("saw %d distinct hosts prompted, want 2: %v", len(seen), seen)
	}

	_, hosts := h.get("/api/known-hosts")
	entries, _ := hosts["known_hosts"].([]any)
	if len(entries) != 2 {
		t.Fatalf("the trust store holds %d entries, want 2", len(entries))
	}

	ports := map[int]bool{}
	for _, raw := range entries {
		entry, _ := raw.(map[string]any)
		port, _ := entry["port"].(float64)
		ports[int(port)] = true
	}
	if !ports[bastion.Port] {
		t.Errorf("the bastion's key was not recorded under its own port %d: %v", bastion.Port, ports)
	}
	if !ports[target.Port] {
		t.Errorf("the target's key was not recorded under its own port %d: %v", target.Port, ports)
	}
}

// TestABrokenRouteSaysSoRatherThanFailingToConnect. Nothing was dialled, so
// reporting it as unreachable would send somebody to check a device that was
// never contacted.
func TestABrokenRouteSaysSoRatherThanFailingToConnect(t *testing.T) {
	h := signedInWithVault(t)
	target := startSSH(t, "target-pass")

	bastionID := h.savedHost(t, "bastion", "10.255.255.1", 22, "bastion-pass")
	targetID := h.savedHost(t, "core-sw-01", target.Host, target.Port, "target-pass", bastionID)

	// Remove the bastion behind the chain's back — the delete guard refuses
	// this through the API, which is the point: the only way to reach this
	// state is something that bypassed it, and the dial still has to cope.
	// Through the store's wrapper, not the embedded *sql.DB: the wrapper
	// rewrites placeholders per driver, and "?" reaches PostgreSQL verbatim
	// otherwise. That is the whole reason this suite runs against both.
	if _, err := h.db.Exec(context.Background(),
		`DELETE FROM sessions WHERE id = ?`, bastionID); err != nil {
		t.Fatal(err)
	}

	conn := h.dialTerminal(t, "session="+targetID)
	view := newSocketView(conn)

	control := view.waitFor(t, "", terminal.ControlError, 20*time.Second)
	if control.Code != "jump_chain_invalid" {
		t.Errorf("code = %q, want jump_chain_invalid", control.Code)
	}
	if !strings.Contains(strings.ToLower(control.Message), "jump host") {
		t.Errorf("message does not mention the route: %q", control.Message)
	}
}
