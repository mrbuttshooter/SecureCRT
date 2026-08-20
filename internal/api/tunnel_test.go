package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/config"
)

// Tunnels, through the HTTP surface.
//
// The properties worth testing here are the refusals: a feature that opens
// ports on a shared server and proxies untrusted markup has more ways to be
// wrong than to be right, and most of them are silent.

// allowTunnelListeners turns on the policy switch that gates listening ports.
func allowTunnelListeners(c *config.Config) { c.Policy.AllowTCPTunnels = true }

// withTunnelDomain configures the wildcard base web tunnels are served under.
func withTunnelDomain(domain string) harnessOption {
	return func(c *config.Config) { c.Tunnels.Domain = domain }
}

// startForwardingSSH runs an SSH server that opens direct-tcpip channels,
// which is what any tunnel needs from the host it rides.
func startForwardingSSH(t *testing.T, password string) *bastionServer {
	t.Helper()
	return startBastion(t, password)
}

// TestWebTunnelsAreUnavailableWithoutADomain is the whole security argument
// for this feature, stated as a test.
//
// A device's own pages cannot be served from bkd's origin: the CSRF cookie is
// readable by JavaScript by design and the session cookie rides along on
// same-origin requests, so one script on one compromised switch would have
// the user's entire API access. Without a separate domain configured there is
// nowhere safe to put them, so the answer must be "no", not "here anyway".
func TestWebTunnelsAreUnavailableWithoutADomain(t *testing.T) {
	h := signedInWithVault(t) // no tunnels.domain
	srv := startForwardingSSH(t, "hunter2")
	sessionID := h.savedHost(t, "switch", srv.Host, srv.Port, "hunter2")

	resp, body := h.post("/api/tunnels", map[string]any{
		"session_id": sessionID, "kind": "web", "host": "10.0.0.1", "port": 80,
	})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("= %d, want 503: %v", resp.StatusCode, body)
	}

	failure, _ := body["error"].(map[string]any)
	message, _ := failure["message"].(string)
	if !strings.Contains(message, "separate domain") {
		t.Errorf("the refusal does not explain why: %q", message)
	}

	// And the interface is told, so it can say so rather than offering a
	// button that always fails.
	_, cfg := h.get("/api/tunnels/config")
	if enabled, _ := cfg["web_enabled"].(bool); enabled {
		t.Error("the config claims web tunnels are available")
	}
}

// TestListeningTunnelsAreRefusedWhenPolicyForbidsThem.
func TestListeningTunnelsAreRefusedWhenPolicyForbidsThem(t *testing.T) {
	h := signedInWithVault(t) // listeners off, which is the default
	srv := startForwardingSSH(t, "hunter2")
	sessionID := h.savedHost(t, "switch", srv.Host, srv.Port, "hunter2")

	for _, kind := range []string{"local", "socks"} {
		resp, body := h.post("/api/tunnels", map[string]any{
			"session_id": sessionID, "kind": kind, "host": "10.0.0.1", "port": 443,
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s = %d, want 403: %v", kind, resp.StatusCode, body)
		}
	}

	_, cfg := h.get("/api/tunnels/config")
	if enabled, _ := cfg["listeners_enabled"].(bool); enabled {
		t.Error("the config claims listeners are available")
	}
}

// TestALocalTunnelCarriesTraffic opens a real listener, connects to it, and
// checks the bytes came back from a server only reachable through SSH.
func TestALocalTunnelCarriesTraffic(t *testing.T) {
	h := signedInWithVault(t, allowTunnelListeners)

	// The thing on the far side. Reached only via the SSH host's
	// direct-tcpip channel, as far as this test is concerned.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from behind the tunnel")
	}))
	defer target.Close()

	targetHost, targetPortStr, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	targetPort, _ := strconv.Atoi(targetPortStr)

	srv := startForwardingSSH(t, "hunter2")
	sessionID := h.savedHost(t, "jump", srv.Host, srv.Port, "hunter2")

	resp, body := h.openTunnel(t, map[string]any{
		"session_id": sessionID, "kind": "local", "label": "web ui",
		"host": targetHost, "port": targetPort,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("opening the tunnel = %d: %v", resp.StatusCode, body)
	}

	listen, _ := body["listen"].(string)
	if listen == "" {
		t.Fatal("the tunnel reported no address to connect to")
	}

	// Through the tunnel, with an ordinary HTTP client.
	client := &http.Client{Timeout: 20 * time.Second}
	through, err := client.Get("http://" + listen + "/")
	if err != nil {
		t.Fatalf("reaching the target through the tunnel: %v", err)
	}
	defer func() { _ = through.Body.Close() }()

	got, err := io.ReadAll(through.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello from behind the tunnel" {
		t.Errorf("through the tunnel = %q", got)
	}

	// The SSH host was genuinely asked to reach the target, which is what
	// distinguishes this from a direct connection — both are on loopback.
	forwards := srv.forwarded()
	want := net.JoinHostPort(targetHost, targetPortStr)
	if len(forwards) == 0 || forwards[0] != want {
		t.Errorf("the host forwarded %v, want %q", forwards, want)
	}
}

// TestClosingATunnelReleasesItsPort. A port held after its tunnel is gone is
// a range that quietly runs out.
func TestClosingATunnelReleasesItsPort(t *testing.T) {
	h := signedInWithVault(t, allowTunnelListeners)
	srv := startForwardingSSH(t, "hunter2")
	sessionID := h.savedHost(t, "jump", srv.Host, srv.Port, "hunter2")

	resp, body := h.openTunnel(t, map[string]any{
		"session_id": sessionID, "kind": "local", "host": "127.0.0.1", "port": 9,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("= %d: %v", resp.StatusCode, body)
	}
	id, _ := body["id"].(string)
	listen, _ := body["listen"].(string)

	if resp, _ := h.do(http.MethodDelete, "/api/tunnels/"+id, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("closing = %d", resp.StatusCode)
	}

	// The listener is gone: nothing answers there any more.
	conn, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Error("the listener survived its tunnel")
	}

	_, list := h.get("/api/tunnels")
	tunnels, _ := list["tunnels"].([]any)
	if len(tunnels) != 0 {
		t.Errorf("the closed tunnel is still listed: %v", tunnels)
	}
}

// TestATunnelBelongsToOneUser. Another person's tunnel is not listed, not
// closable, and reported as missing rather than forbidden.
func TestATunnelBelongsToOneUser(t *testing.T) {
	h := signedInWithVault(t, allowTunnelListeners)
	srv := startForwardingSSH(t, "hunter2")
	sessionID := h.savedHost(t, "jump", srv.Host, srv.Port, "hunter2")

	resp, body := h.openTunnel(t, map[string]any{
		"session_id": sessionID, "kind": "local", "host": "127.0.0.1", "port": 9,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("= %d: %v", resp.StatusCode, body)
	}
	id, _ := body["id"].(string)

	// A second account on the same server.
	h.createLocalUser("bob@example.com", "correct horse battery staple", false)
	h.login("bob@example.com", "correct horse battery staple")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "another long passphrase"})

	_, list := h.get("/api/tunnels")
	if tunnels, _ := list["tunnels"].([]any); len(tunnels) != 0 {
		t.Errorf("bob can see alice's tunnels: %v", tunnels)
	}

	resp, _ = h.do(http.MethodDelete, "/api/tunnels/"+id, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("closing somebody else's tunnel = %d, want 404", resp.StatusCode)
	}
}

// TestTheTunnelQuotaIsEnforced.
func TestTheTunnelQuotaIsEnforced(t *testing.T) {
	h := signedInWithVault(t, allowTunnelListeners, func(c *config.Config) {
		c.Tunnels.MaxPerUser = 2
	})
	srv := startForwardingSSH(t, "hunter2")
	sessionID := h.savedHost(t, "jump", srv.Host, srv.Port, "hunter2")

	for i := range 2 {
		resp, body := h.openTunnel(t, map[string]any{
			"session_id": sessionID, "kind": "local", "host": "127.0.0.1", "port": 9 + i,
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("tunnel %d = %d: %v", i, resp.StatusCode, body)
		}
	}

	resp, body := h.openTunnel(t, map[string]any{
		"session_id": sessionID, "kind": "local", "host": "127.0.0.1", "port": 11,
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the third tunnel = %d, want 429: %v", resp.StatusCode, body)
	}
}

// openTunnel opens a tunnel, answering the host key prompt the way the
// interface does — the first attempt refuses with a fingerprint and the
// second carries the answer.
func (h *harness) openTunnel(t *testing.T, body map[string]any) (*http.Response, map[string]any) {
	t.Helper()

	resp, out := h.post("/api/tunnels", body)
	if resp.StatusCode != http.StatusConflict {
		return resp, out
	}

	failure, _ := out["error"].(map[string]any)
	hostKey, _ := failure["host_key"].(map[string]any)
	fingerprint, _ := hostKey["fingerprint"].(string)
	if fingerprint == "" {
		return resp, out
	}

	body["accept_host_key"] = fingerprint
	return h.post("/api/tunnels", body)
}

// TestASOCKSTunnelReachesWhereverItIsAsked. The point of SOCKS over a fixed
// forward is that the destination comes per connection, so one tunnel reaches
// everything the far side can.
func TestASOCKSTunnelReachesWhereverItIsAsked(t *testing.T) {
	h := signedInWithVault(t, allowTunnelListeners)

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "first")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "second")
	}))
	defer second.Close()

	srv := startForwardingSSH(t, "hunter2")
	sessionID := h.savedHost(t, "jump", srv.Host, srv.Port, "hunter2")

	resp, body := h.openTunnel(t, map[string]any{
		"session_id": sessionID, "kind": "socks", "label": "into the lab",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("= %d: %v", resp.StatusCode, body)
	}
	listen, _ := body["listen"].(string)

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return socksDial(ctx, listen, addr)
			},
		},
	}

	// Two different destinations, one tunnel.
	for _, tc := range []struct{ url, want string }{
		{first.URL, "first"},
		{second.URL, "second"},
	} {
		got, err := fetch(client, tc.url)
		if err != nil {
			t.Fatalf("reaching %s through SOCKS: %v", tc.url, err)
		}
		if got != tc.want {
			t.Errorf("%s returned %q, want %q", tc.url, got, tc.want)
		}
	}

	if len(srv.forwarded()) < 2 {
		t.Errorf("the host forwarded %v; both destinations should have gone through it",
			srv.forwarded())
	}
}

// TestSOCKSRefusesWhatItDoesNotImplement. BIND and UDP ASSOCIATE both need
// this proxy to accept inbound traffic on a client's behalf, which is a second
// listening surface for a case that has no place in reaching network gear.
func TestSOCKSRefusesWhatItDoesNotImplement(t *testing.T) {
	h := signedInWithVault(t, allowTunnelListeners)
	srv := startForwardingSSH(t, "hunter2")
	sessionID := h.savedHost(t, "jump", srv.Host, srv.Port, "hunter2")

	resp, body := h.openTunnel(t, map[string]any{
		"session_id": sessionID, "kind": "socks",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("= %d: %v", resp.StatusCode, body)
	}
	listen, _ := body["listen"].(string)

	conn, err := net.DialTimeout("tcp", listen, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// Greeting, then BIND rather than CONNECT.
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatal(err)
	}

	// BIND = 0x02, to 127.0.0.1:80.
	if _, err := conn.Write([]byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("no reply to an unsupported command: %v", err)
	}
	if reply[1] == 0 {
		t.Error("BIND was accepted; only CONNECT is implemented")
	}
}

// socksDial performs a SOCKS5 CONNECT through proxyAddr to target.
func socksDial(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	fail := func(err error) (net.Conn, error) {
		_ = conn.Close()
		return nil, err
	}

	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return fail(err)
	}
	if greeting[1] != 0 {
		return fail(errNoSOCKSMethod)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fail(err)
	}

	// Sent as a name rather than an address, deliberately: the far side is
	// supposed to resolve it.
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, host...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fail(err)
	}
	if reply[1] != 0 {
		return fail(errSOCKSRefused)
	}
	return conn, nil
}

func fetch(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

var (
	errNoSOCKSMethod = errors.New("the proxy accepted no authentication method")
	errSOCKSRefused  = errors.New("the proxy refused the request")
)
