package api

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/proto/telnetx"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// Telnet, from the browser's end of the WebSocket to a device that speaks the
// protocol.
//
// The telnetx package tests the protocol against a peer under the test's
// control. What these add is everything in between: that a saved connection
// with protocol=telnet reaches the telnet path rather than the SSH one, that
// no host key is demanded of a protocol that has none, and that the plaintext
// nature of the thing reaches the interface and the audit log rather than
// being known only to the code.

// telnetDevice is a small device that speaks telnet and echoes a prompt.
type telnetDevice struct {
	Host string
	Port int

	mu       sync.Mutex
	sessions int
	received []byte
}

// startTelnetDevice runs a server that negotiates like a switch and then
// echoes what it is sent, prefixed, so a test can tell its output from its
// own keystrokes.
func startTelnetDevice(t *testing.T) *telnetDevice {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	device := &telnetDevice{}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			device.mu.Lock()
			device.sessions++
			device.mu.Unlock()

			go device.serve(conn)
		}
	}()

	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	device.Host, device.Port = host, port
	return device
}

func (d *telnetDevice) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// What a switch does: take echo and suppress-go-ahead, ask for the window
	// size and the terminal type.
	_, _ = conn.Write([]byte{
		telnetx.IAC, telnetx.WILL, telnetx.OptEcho,
		telnetx.IAC, telnetx.WILL, telnetx.OptSuppressGA,
		telnetx.IAC, telnetx.DO, telnetx.OptNAWS,
		telnetx.IAC, telnetx.DO, telnetx.OptTerminalType,
	})
	_, _ = conn.Write([]byte("switch> "))

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			d.mu.Lock()
			d.received = append(d.received, buf[:n]...)
			d.mu.Unlock()

			// Echo the data back, since this end took echo. Commands are
			// skipped rather than parsed: this device only needs to be
			// convincing, not complete.
			var data []byte
			for i := 0; i < n; i++ {
				if buf[i] == telnetx.IAC {
					// Skip the command. Two bytes for a negotiation, and a
					// subnegotiation runs to IAC SE.
					if i+1 < n && buf[i+1] == telnetx.SB {
						for i < n && !(buf[i] == telnetx.IAC && i+1 < n && buf[i+1] == telnetx.SE) {
							i++
						}
						i++
						continue
					}
					i += 2
					continue
				}
				data = append(data, buf[i])
			}
			if len(data) > 0 {
				_, _ = conn.Write(data)
				if strings.Contains(string(data), "\r") {
					_, _ = conn.Write([]byte("\r\nswitch> "))
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (d *telnetDevice) sessionCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessions
}

func (d *telnetDevice) bytesReceived() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.received...)
}

// savedTelnetHost stores a telnet connection, with no credential — telnet has
// nothing to do with one at dial time.
func (h *harness) savedTelnetHost(t *testing.T, name, host string, port int) string {
	t.Helper()

	resp, sess := h.post("/api/tree/sessions", map[string]any{
		"name": name, "protocol": "telnet",
		"hostname": host, "port": port, "username": "admin",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating %s = %d: %v", name, resp.StatusCode, sess)
	}
	id, _ := sess["id"].(string)
	return id
}

// TestATelnetTerminalOpensWithoutAHostKey is the feature working, and the
// absence in it matters as much as the presence: telnet has no host identity
// to verify, so demanding a fingerprint would be theatre.
func TestATelnetTerminalOpensWithoutAHostKey(t *testing.T) {
	h := signedInWithVault(t)
	device := startTelnetDevice(t)
	sessionID := h.savedTelnetHost(t, "old-switch", device.Host, device.Port)

	conn := h.dialTerminal(t, "session="+sessionID+"&cols=100&rows=30")
	view := newSocketView(conn)

	// Straight to the prompt. No host key dialog on the way.
	view.waitFor(t, "switch> ", "", 20*time.Second)

	for _, control := range view.controls {
		if control.Type == terminal.ControlHostKeyPrompt {
			t.Error("a telnet connection asked about a host key it cannot have")
		}
	}

	// Typing reaches the device.
	view.type_(t, "show version\r")
	waitUntil(t, func() bool {
		return strings.Contains(string(device.bytesReceived()), "show version")
	}, "the keystrokes reached the device")

	// And the window size was negotiated, which is what makes a full-screen
	// tool draw correctly on a device that asked for it.
	waitUntil(t, func() bool {
		got := device.bytesReceived()
		return strings.Contains(string(got),
			string([]byte{telnetx.IAC, telnetx.SB, telnetx.OptNAWS, 0, 100, 0, 30}))
	}, "the window size reached the device")
}

// TestTelnetIsReportedAsUnencrypted. A person with nine tabs open cannot be
// expected to remember which one is sending a password in the clear, so the
// server says which.
func TestTelnetIsReportedAsUnencrypted(t *testing.T) {
	h := signedInWithVault(t)
	device := startTelnetDevice(t)
	sessionID := h.savedTelnetHost(t, "old-switch", device.Host, device.Port)

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	view.waitFor(t, "switch> ", "", 20*time.Second)

	_, body := h.get("/api/terminals")
	terminals, _ := body["terminals"].([]any)
	if len(terminals) != 1 {
		t.Fatalf("got %d terminals: %v", len(terminals), body)
	}

	info, _ := terminals[0].(map[string]any)
	if protocol, _ := info["protocol"].(string); protocol != "telnet" {
		t.Errorf("protocol = %v", info["protocol"])
	}
	if encrypted, _ := info["encrypted"].(bool); encrypted {
		t.Error("a telnet session must not be reported as encrypted")
	}
}

// TestEachTelnetTerminalGetsItsOwnConnection.
//
// The SSH path shares one connection between every terminal on a host, which
// is the point of the pool. Telnet must not: it carries exactly one session
// per socket, so two terminals sharing one would be two people typing into
// the same byte stream.
func TestEachTelnetTerminalGetsItsOwnConnection(t *testing.T) {
	h := signedInWithVault(t)
	device := startTelnetDevice(t)
	sessionID := h.savedTelnetHost(t, "old-switch", device.Host, device.Port)

	first := newSocketView(h.dialTerminal(t, "session="+sessionID))
	first.waitFor(t, "switch> ", "", 20*time.Second)

	second := newSocketView(h.dialTerminal(t, "session="+sessionID))
	second.waitFor(t, "switch> ", "", 20*time.Second)

	if got := device.sessionCount(); got != 2 {
		t.Errorf("the device saw %d connections, want 2 — a shared telnet "+
			"socket would interleave two people's keystrokes", got)
	}
}

// TestTelnetCanBeTurnedOff, with the setting named.
func TestTelnetCanBeTurnedOff(t *testing.T) {
	h := signedInWithVault(t, func(c *config.Config) { c.Policy.AllowTelnet = false })
	device := startTelnetDevice(t)
	sessionID := h.savedTelnetHost(t, "old-switch", device.Host, device.Port)

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	control := view.waitFor(t, "", terminal.ControlError, 20*time.Second)
	if !strings.Contains(control.Message, "allow_telnet") {
		t.Errorf("the refusal does not name the setting: %q", control.Message)
	}
	if device.sessionCount() != 0 {
		t.Error("the device was contacted despite the policy")
	}
}

// waitUntil polls a condition, for the things that are true a moment after a
// write rather than at the moment of it.
func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// TestTheStoredPasswordIsTypedAtTheDevicesPrompt is what makes an imported
// telnet tree usable rather than merely present.
//
// Telnet has no authentication, so a stored credential is worth nothing until
// something types it. SecureCRT calls this Logon Actions; here it is a
// sequence of expect/send steps with the password substituted from the vault
// at connect time.
func TestTheStoredPasswordIsTypedAtTheDevicesPrompt(t *testing.T) {
	h := signedInWithVault(t)
	device := startLoginDevice(t)

	_, cred := h.post("/api/credentials", map[string]string{
		"name": "switch login", "kind": "password", "secret": "hunter2",
	})
	credID, _ := cred["id"].(string)
	if credID == "" {
		t.Fatalf("no credential: %v", cred)
	}

	resp, sess := h.post("/api/tree/sessions", map[string]any{
		"name": "old-switch", "protocol": "telnet",
		"hostname": device.Host, "port": device.Port,
		"username": "netops", "credential_id": credID,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating the connection = %d: %v", resp.StatusCode, sess)
	}
	sessionID, _ := sess["id"].(string)

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	// The device asks, the sequence answers, and the device lets it in.
	view.waitFor(t, "switch#", "", 20*time.Second)

	// The whole exchange is in the user's own scrollback, which is the reason
	// this wraps the shell rather than running before one exists: an
	// automated login that nobody can see is an automated login nobody can
	// check.
	screen := view.screen.String()
	if !strings.Contains(screen, "Username:") || !strings.Contains(screen, "Password:") {
		t.Errorf("the login exchange is not visible to the user:\n%s", screen)
	}
	if strings.Contains(screen, "hunter2") {
		t.Error("the password was echoed to the screen")
	}
}

// loginDevice is a telnet device that demands a username and password.
type loginDevice struct {
	Host string
	Port int
}

func startLoginDevice(t *testing.T) *loginDevice {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveLogin(conn)
		}
	}()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return &loginDevice{Host: host, Port: port}
}

// serveLogin plays a switch: banner, username, password, prompt.
func serveLogin(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Takes echo, like a switch, so nothing this end sends is echoed back and
	// the password never reaches the screen.
	_, _ = conn.Write([]byte{
		telnetx.IAC, telnetx.WILL, telnetx.OptEcho,
		telnetx.IAC, telnetx.WILL, telnetx.OptSuppressGA,
	})
	_, _ = conn.Write([]byte("\r\nUser Access Verification\r\n\r\nUsername: "))

	line := func() string {
		var out []byte
		buf := make([]byte, 1)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return string(out)
			}
			if n == 0 {
				continue
			}
			// Skip negotiation rather than parsing it; this device only has
			// to be convincing.
			if buf[0] == telnetx.IAC {
				skip := make([]byte, 2)
				_, _ = io.ReadFull(conn, skip)
				continue
			}
			if buf[0] == '\r' || buf[0] == '\n' {
				return string(out)
			}
			out = append(out, buf[0])
		}
	}

	user := line()
	_, _ = conn.Write([]byte("\r\nPassword: "))
	password := line()

	if user == "netops" && password == "hunter2" {
		_, _ = conn.Write([]byte("\r\nswitch#"))
	} else {
		_, _ = conn.Write([]byte("\r\n% Access denied\r\n\r\nUsername: "))
	}

	// Held open so the test can read the prompt.
	buf := make([]byte, 256)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}
