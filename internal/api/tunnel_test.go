package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"

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

// Remote forwarding — `ssh -R`, the one shape that survives the move to a
// browser with its OpenSSH meaning intact.
//
// The device listens; a connection arriving there is carried back over SSH
// and dialled from this server. Which reverses the direction of trust, and is
// why most of what follows is about what the destination is allowed to be.

// reverseServer is an SSH server that honours tcpip-forward requests, and
// remembers which binds it was asked for.
type reverseServer struct {
	Host string
	Port int

	mu    sync.Mutex
	binds []string
}

func (r *reverseServer) requestedBinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.binds...)
}

// startReverseSSH runs a server that will listen on a client's behalf.
//
// Separate from startBastion because refusing reverse forwarding is the
// default in gliderlabs/ssh exactly as it is in OpenSSH: a nil
// ReversePortForwardingCallback denies everything. Opting in explicitly here
// keeps the test honest about what a real device has to be configured to do.
func startReverseSSH(t *testing.T, password string, allow bool) *reverseServer {
	t.Helper()

	rev := &reverseServer{}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	forwarder := &gssh.ForwardedTCPHandler{}
	srv := &gssh.Server{
		HostSigners: []gssh.Signer{signer},
		PasswordHandler: func(_ gssh.Context, given string) bool {
			return given == password
		},
		// Everything below is set before Serve: the accept loop reads these,
		// so configuring a running server is a data race.
		ChannelHandlers: map[string]gssh.ChannelHandler{
			"session":      gssh.DefaultSessionHandler,
			"direct-tcpip": gssh.DirectTCPIPHandler,
		},
		RequestHandlers: map[string]gssh.RequestHandler{
			"tcpip-forward":        forwarder.HandleSSHRequest,
			"cancel-tcpip-forward": forwarder.HandleSSHRequest,
		},
		ReversePortForwardingCallback: func(_ gssh.Context, host string, port uint32) bool {
			rev.mu.Lock()
			rev.binds = append(rev.binds, net.JoinHostPort(host, strconv.Itoa(int(port))))
			rev.mu.Unlock()
			return allow
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
	port, _ := strconv.Atoi(portStr)
	rev.Host, rev.Port = host, port
	return rev
}

// allowRemoteForwards turns on the policy switch that gates `ssh -R`.
func allowRemoteForwards(c *config.Config) { c.Policy.AllowRemoteForwards = true }

// lanAddress finds an address of this machine that is not loopback, so a test
// can name a destination the guard permits.
//
// Skipped rather than failed when there is none: a container with only `lo`
// is a legitimate place to run the suite, and there is genuinely nothing to
// forward to there.
func lanAddress(t *testing.T) string {
	t.Helper()

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	t.Skip("this machine has no non-loopback address to forward to")
	return ""
}

// TestRemoteForwardsAreRefusedWhenPolicyForbidsThem. Off by default, like the
// listeners, and for a reason of its own: this one lets a device reach into
// the server's network rather than the other way round.
func TestRemoteForwardsAreRefusedWhenPolicyForbidsThem(t *testing.T) {
	h := signedInWithVault(t) // remote forwarding off, which is the default
	srv := startReverseSSH(t, "hunter2", true)
	sessionID := h.savedHost(t, "switch", srv.Host, srv.Port, "hunter2")

	resp, body := h.post("/api/tunnels", map[string]any{
		"session_id": sessionID, "kind": "remote",
		"host": "10.0.0.5", "port": 80, "remote_port": 8080,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("= %d, want 403: %v", resp.StatusCode, body)
	}

	failure, _ := body["error"].(map[string]any)
	message, _ := failure["message"].(string)
	if !strings.Contains(message, "allow_remote_forwards") {
		t.Errorf("the refusal does not name the setting: %q", message)
	}

	// Nothing was asked of the device: the refusal happened here.
	if binds := srv.requestedBinds(); len(binds) != 0 {
		t.Errorf("the device was asked to listen anyway: %v", binds)
	}

	_, cfg := h.get("/api/tunnels/config")
	if enabled, _ := cfg["remote_enabled"].(bool); enabled {
		t.Error("the config claims remote forwarding is available")
	}
}

// TestARemoteForwardCarriesTraffic is the feature working: the device
// listens, something connects there, and the bytes come from a service on
// this side.
func TestARemoteForwardCarriesTraffic(t *testing.T) {
	h := signedInWithVault(t, allowRemoteForwards)

	// The service on bkd's side of the world. Bound to a real address rather
	// than loopback, because the destination guard refuses loopback — which
	// is the point of the guard and must not be worked around in a test.
	lan := lanAddress(t)
	listener, err := net.Listen("tcp", net.JoinHostPort(lan, "0"))
	if err != nil {
		t.Skipf("cannot bind %s: %v", lan, err)
	}
	target := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "reached from the device")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = target.Serve(listener) }()
	defer func() { _ = target.Close() }()

	_, targetPortStr, _ := net.SplitHostPort(listener.Addr().String())
	targetPort, _ := strconv.Atoi(targetPortStr)

	srv := startReverseSSH(t, "hunter2", true)
	sessionID := h.savedHost(t, "switch", srv.Host, srv.Port, "hunter2")

	// Port 0: the device picks, and has to tell us which one it picked.
	resp, body := h.openTunnel(t, map[string]any{
		"session_id": sessionID, "kind": "remote", "label": "back to the mirror",
		"host": lan, "port": targetPort, "remote_port": 0,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("opening the tunnel = %d: %v", resp.StatusCode, body)
	}

	listen, _ := body["listen"].(string)
	if listen == "" {
		t.Fatal("the tunnel did not report where the device is listening")
	}
	_, listenPortStr, err := net.SplitHostPort(listen)
	if err != nil {
		t.Fatalf("listen address %q: %v", listen, err)
	}
	if listenPortStr == "0" {
		t.Error("port 0 was reported back unchanged; the device's choice was lost")
	}

	// The device was asked for what we asked for.
	if binds := srv.requestedBinds(); len(binds) != 1 {
		t.Fatalf("binds requested = %v, want exactly one", binds)
	}

	// Now play the part of something on the device connecting to that port.
	// The test server listens on 127.0.0.1, so the forwarded port is there.
	conn, err := net.DialTimeout("tcp",
		net.JoinHostPort("127.0.0.1", listenPortStr), 5*time.Second)
	if err != nil {
		t.Fatalf("connecting to the forwarded port: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn,
		"GET / HTTP/1.0\r\nHost: test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if !strings.Contains(string(got), "reached from the device") {
		t.Fatalf("the forward did not reach the service: %q", got)
	}

	// And it was counted, so the interface can show the tunnel doing work.
	id, _ := body["id"].(string)
	_, list := h.get("/api/tunnels")
	tunnels, _ := list["tunnels"].([]any)
	for _, entry := range tunnels {
		info, _ := entry.(map[string]any)
		if info["id"] != id {
			continue
		}
		if count, _ := info["connections"].(float64); count < 1 {
			t.Errorf("connections = %v, want at least 1", info["connections"])
		}
	}
}

// TestARemoteForwardWillNotReachThisServerItself is the guard that matters.
//
// bkd's own API sits on loopback behind a reverse proxy in the default
// deployment, and so does its database socket. A remote forward pointed there
// would hand a device the unauthenticated inside of the application. So would
// 169.254.169.254, which on every major cloud answers instance credentials to
// anything that asks.
func TestARemoteForwardWillNotReachThisServerItself(t *testing.T) {
	h := signedInWithVault(t, allowRemoteForwards)
	srv := startReverseSSH(t, "hunter2", true)
	sessionID := h.savedHost(t, "switch", srv.Host, srv.Port, "hunter2")

	refused := []struct {
		name string
		host string
	}{
		{"loopback v4", "127.0.0.1"},
		{"loopback, spelled differently", "127.9.9.9"},
		{"loopback v6", "::1"},
		{"cloud metadata", "169.254.169.254"},
		{"link-local v6", "fe80::1"},
		{"unspecified", "0.0.0.0"},
		{"multicast", "224.0.0.1"},
		{"localhost by name", "localhost"},
	}

	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := h.post("/api/tunnels", map[string]any{
				"session_id": sessionID, "kind": "remote",
				"host": tc.host, "port": 8080, "remote_port": 0,
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 400: %v", tc.host, resp.StatusCode, body)
			}
		})
	}

	// Nothing reached the device: every one of those was refused here.
	if binds := srv.requestedBinds(); len(binds) != 0 {
		t.Errorf("the device was asked to listen for a refused destination: %v", binds)
	}
}

// TestADeviceThatRefusesToListenSaysSo. AllowTcpForwarding is off on plenty
// of network equipment, and the failure has to name whose decision it was —
// otherwise the natural reading is that bkd is broken.
func TestADeviceThatRefusesToListenSaysSo(t *testing.T) {
	h := signedInWithVault(t, allowRemoteForwards)
	lan := lanAddress(t)

	srv := startReverseSSH(t, "hunter2", false) // refuses
	sessionID := h.savedHost(t, "switch", srv.Host, srv.Port, "hunter2")

	resp, body := h.openTunnel(t, map[string]any{
		"session_id": sessionID, "kind": "remote",
		"host": lan, "port": 8080, "remote_port": 9999,
	})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("= %d, want 502: %v", resp.StatusCode, body)
	}

	failure, _ := body["error"].(map[string]any)
	if code, _ := failure["code"].(string); code != string(CodeRemoteRefused) {
		// The distinction is not decorative: "forbidden" would send someone
		// to their administrator here, when the answer is on the device.
		t.Errorf("code = %q, want %q", code, CodeRemoteRefused)
	}
	message, _ := failure["message"].(string)
	if !strings.Contains(message, "AllowTcpForwarding") {
		t.Errorf("the failure does not say whose configuration refused: %q", message)
	}

	// The device did see the request; it turned it down.
	if binds := srv.requestedBinds(); len(binds) != 1 {
		t.Errorf("binds = %v, want the one that was refused", binds)
	}
}

// TestClosingARemoteForwardDoesNotFreeALocalPort guards the bookkeeping bug
// this kind introduced: a remote tunnel's listener reports a port on the
// *device*, and releasing that number into the local pool would free a port
// another tunnel is still using whenever the two coincided.
func TestClosingARemoteForwardDoesNotFreeALocalPort(t *testing.T) {
	lan := lanAddress(t)
	h := signedInWithVault(t, allowRemoteForwards, allowTunnelListeners,
		func(c *config.Config) {
			// One port in the range, so "was it wrongly freed" has exactly
			// one possible answer.
			c.Tunnels.PortRange = "34500-34500"
			// Bound to the LAN address rather than loopback, so the number
			// can collide with the device's without the two sockets
			// conflicting. The test server is in this process, so a port it
			// "opens on the device" is a real port on this machine — and a
			// genuine conflict would fail the bind rather than exercise the
			// bookkeeping, which is what is under test.
			c.Tunnels.Bind = lan
		})

	forwarder := startForwardingSSH(t, "hunter2")
	forwardID := h.savedHost(t, "jump", forwarder.Host, forwarder.Port, "hunter2")

	// Take the only local port.
	resp, local := h.openTunnel(t, map[string]any{
		"session_id": forwardID, "kind": "local", "host": "10.0.0.1", "port": 443,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("opening the local tunnel = %d: %v", resp.StatusCode, local)
	}
	listen, _ := local["listen"].(string)
	_, takenStr, _ := net.SplitHostPort(listen)
	taken, _ := strconv.Atoi(takenStr)
	if taken != 34500 {
		t.Fatalf("local tunnel took port %d, want the only one in range", taken)
	}

	// Open a remote forward and arrange for the device to bind that same
	// number, which is the collision the bug needed.
	rev := startReverseSSH(t, "hunter2", true)
	revID := h.savedHost(t, "switch", rev.Host, rev.Port, "hunter2")

	resp, body := h.openTunnel(t, map[string]any{
		"session_id": revID, "kind": "remote",
		// remote_bind empty means loopback, so the device binds
		// 127.0.0.1:34500 while the local tunnel holds lan:34500.
		"host": lan, "port": 80, "remote_port": taken,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("opening the remote forward = %d: %v", resp.StatusCode, body)
	}
	remoteID, _ := body["id"].(string)

	// Close it. If forget() read the port off the listener, this frees 34500
	// while the local tunnel is still bound to it.
	resp, _ = h.do(http.MethodDelete, "/api/tunnels/"+remoteID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("closing = %d", resp.StatusCode)
	}

	// The pool must still consider the port taken, so a third tunnel is
	// refused rather than handed a port that is already bound.
	resp, body = h.post("/api/tunnels", map[string]any{
		"session_id": forwardID, "kind": "local", "host": "10.0.0.2", "port": 443,
	})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a second local tunnel = %d, want 503 (no port free): %v",
			resp.StatusCode, body)
	}
}
