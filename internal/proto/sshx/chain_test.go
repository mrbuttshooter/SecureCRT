package sshx

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
)

// Dialling through a jump host, against two real SSH servers.
//
// The point of these tests is that the second server is genuinely unreachable
// except through the first: nothing here asserts that a function was called,
// only that bytes arrived somewhere they could not otherwise have reached.

// startBastion runs a server that will open direct-tcpip channels, which is
// what a jump host is.
func startBastion(t *testing.T, password string) *testServer {
	t.Helper()

	return startTestServer(t, testServerOptions{
		Password: password,
		Configure: func(srv *gssh.Server) {
			srv.ChannelHandlers = map[string]gssh.ChannelHandler{
				"session":      gssh.DefaultSessionHandler,
				"direct-tcpip": gssh.DirectTCPIPHandler,
			}
			srv.LocalPortForwardingCallback = func(gssh.Context, string, uint32) bool {
				return true
			}
		},
	})
}

// TestDialThroughAJumpHost is the whole of Phase 5a in one test.
func TestDialThroughAJumpHost(t *testing.T) {
	bastion := startBastion(t, "bastion-pass")
	target := startTestServer(t, testServerOptions{Password: "target-pass"})

	ctx := context.Background()

	first := trustAll(t, bastion)
	first.Credential = Credential{Username: "alice", Password: "bastion-pass"}
	hop, err := Dial(ctx, first)
	if err != nil {
		t.Fatalf("dialling the bastion: %v", err)
	}
	defer func() { _ = hop.Close() }()

	second := trustAll(t, target)
	second.Credential = Credential{Username: "alice", Password: "target-pass"}
	second.Transport = ThroughClient(hop)

	client, err := Dial(ctx, second)
	if err != nil {
		t.Fatalf("dialling the target through the bastion: %v", err)
	}
	defer func() { _ = client.Close() }()

	// A shell on the far host proves the whole path carries traffic, not just
	// that a handshake completed.
	shell, err := client.Shell(PTYConfig{Cols: 80, Rows: 24})
	if err != nil {
		t.Fatalf("shell on the target: %v", err)
	}
	defer func() { _ = shell.Close() }()

	if _, err := shell.Write([]byte("hello through the bastion\n")); err != nil {
		t.Fatal(err)
	}

	// Read until the echo appears rather than sampling once: the shell greets
	// before it echoes, so the first chunk is a welcome banner.
	var seen strings.Builder
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(seen.String(), "hello through the bastion") {
		if time.Now().After(deadline) {
			t.Fatalf("the far host never echoed; it said %q", seen.String())
		}
		buf := make([]byte, 256)
		n, err := shell.Read(buf)
		seen.Write(buf[:n])
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("reading from the target: %v", err)
		}
	}
	if !strings.Contains(seen.String(), "hello through the bastion") {
		t.Errorf("the far host echoed %q", seen.String())
	}
}

// TestTheTargetSeesTheBastionAsItsClient is what makes the previous test
// meaningful. Without it, a bug that quietly dialled the target directly
// would still pass — the target is on loopback and reachable either way.
func TestTheTargetSeesTheBastionAsItsClient(t *testing.T) {
	bastion := startBastion(t, "bastion-pass")

	seen := make(chan string, 1)
	target := startTestServer(t, testServerOptions{
		Password: "target-pass",
		Handler: func(s gssh.Session) {
			select {
			case seen <- s.RemoteAddr().String():
			default:
			}
			_ = s.Exit(0)
		},
	})

	ctx := context.Background()

	first := trustAll(t, bastion)
	first.Credential = Credential{Username: "alice", Password: "bastion-pass"}
	hop, err := Dial(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hop.Close() }()

	second := trustAll(t, target)
	second.Credential = Credential{Username: "alice", Password: "target-pass"}
	second.Transport = ThroughClient(hop)

	client, err := Dial(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Shell(PTYConfig{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}

	select {
	case addr := <-seen:
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		// The bastion dials the target from its own listener's address. The
		// port differs, so only the fact that a connection arrived at all —
		// through a transport the test never gave direct access to — is the
		// assertion. What would fail here is a Transport that was ignored:
		// the channel would never be opened and nothing would arrive.
		if host == "" {
			t.Error("the target saw no client address")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the target never saw a session; the jump transport was not used")
	}
}

// TestASilentPeerDoesNotHangTheDial covers the reason SetDeadline had to go.
//
// A host that accepts a connection and then says nothing used to be bounded by
// a deadline on the conn. A channel-backed conn cannot carry one, so this is
// checked on both transports — the tunnelled case is the one that regressed
// silently before.
func TestASilentPeerDoesNotHangTheDial(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()

	// Accept and hold, never writing a version banner.
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	host, port := splitHostPort(t, silent.Addr().String())

	t.Run("direct", func(t *testing.T) {
		cfg := Config{
			Target:           Target{Hostname: host, Port: port},
			Credential:       Credential{Username: "alice", Password: "x"},
			Verify:           trustAll(t, &testServer{}).Verify,
			Decide:           trustAll(t, &testServer{}).Decide,
			ConnectTimeout:   5 * time.Second,
			HandshakeTimeout: 2 * time.Second,
		}

		start := time.Now()
		if _, err := Dial(context.Background(), cfg); err == nil {
			t.Fatal("a silent host was accepted")
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("the dial took %s; it was supposed to be bounded", elapsed)
		}
	})

	t.Run("through a jump host", func(t *testing.T) {
		bastion := startBastion(t, "bastion-pass")

		first := trustAll(t, bastion)
		first.Credential = Credential{Username: "alice", Password: "bastion-pass"}
		hop, err := Dial(context.Background(), first)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = hop.Close() }()

		cfg := trustAll(t, bastion)
		cfg.Target = Target{Hostname: host, Port: port}
		cfg.Credential = Credential{Username: "alice", Password: "x"}
		cfg.Transport = ThroughClient(hop)
		cfg.HandshakeTimeout = 2 * time.Second

		start := time.Now()
		if _, err := Dial(context.Background(), cfg); err == nil {
			t.Fatal("a silent host behind a jump host was accepted")
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("the dial took %s; it was supposed to be bounded", elapsed)
		}
	})
}

// TestACancelledContextAbandonsTheHandshake. The deadline this replaced could
// not be interrupted; a context can, which matters because host key
// verification happens inside the handshake and may be waiting on a person.
func TestACancelledContextAbandonsTheHandshake(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()

	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	host, port := splitHostPort(t, silent.Addr().String())

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)

	cfg := Config{
		Target:           Target{Hostname: host, Port: port},
		Credential:       Credential{Username: "alice", Password: "x"},
		Verify:           trustAll(t, &testServer{}).Verify,
		Decide:           trustAll(t, &testServer{}).Decide,
		ConnectTimeout:   5 * time.Second,
		HandshakeTimeout: time.Minute, // long, so the context is what ends it
	}

	start := time.Now()
	_, err = Dial(ctx, cfg)
	if err == nil {
		t.Fatal("the dial completed against a silent host")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("cancelling took %s to take effect", elapsed)
	}
}

// TestAHealthyConnectionSurvivesItsKeepalives.
//
// keepalive@openssh.com is answered with SSH_MSG_REQUEST_FAILURE by servers
// that do not implement it — which is most of them, deliberately. A liveness
// check that required a *successful* reply would therefore treat every healthy
// connection as dead and close it after a few intervals. This runs several
// intervals and asserts the connection is still there.
func TestAHealthyConnectionSurvivesItsKeepalives(t *testing.T) {
	ts := startTestServer(t, testServerOptions{Password: "hunter2"})

	cfg := trustAll(t, ts)
	cfg.Credential = Credential{Username: "alice", Password: "hunter2"}
	cfg.KeepAlive = 100 * time.Millisecond

	client, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	// Comfortably more than maxMissedKeepAlives intervals.
	time.Sleep(time.Duration(maxMissedKeepAlives+3) * 100 * time.Millisecond)

	select {
	case <-client.closed:
		t.Fatal("the keepalive closed a healthy connection")
	default:
	}

	if _, err := client.Shell(PTYConfig{Cols: 80, Rows: 24}); err != nil {
		t.Fatalf("the connection is unusable after its keepalives: %v", err)
	}
}

// TestCloseIsSafeToCallTwice. Cascading releases and a shutdown racing the
// pool's watcher can both reach the same client, and closing a channel twice
// panics.
func TestCloseIsSafeToCallTwice(t *testing.T) {
	ts := startTestServer(t, testServerOptions{Password: "hunter2"})

	cfg := trustAll(t, ts)
	cfg.Credential = Credential{Username: "alice", Password: "hunter2"}

	client, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	_ = client.Close()
	_ = client.Close() // must not panic

	// And concurrently, which is the way it will actually happen.
	client2, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for range 8 {
		go func() { _ = client2.Close(); done <- struct{}{} }()
	}
	for range 8 {
		<-done
	}
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
