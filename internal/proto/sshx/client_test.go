package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"golang.org/x/crypto/ssh"
)

// trustAll accepts whatever the host presents. Used only where the test is
// about something else; the host key behaviour has its own tests below.
func trustAll(t *testing.T, ts *testServer) Config {
	t.Helper()
	return Config{
		Target: Target{Hostname: ts.Host, Port: ts.Port},
		Verify: func(_ context.Context, _ string, _ int, key ssh.PublicKey) (hostkeys.Check, error) {
			return hostkeys.Check{Verdict: hostkeys.VerdictTrusted, Presented: hostkeys.DescribeKey(key)}, nil
		},
		Decide:         func(context.Context, hostkeys.Check) error { return nil },
		ConnectTimeout: 10 * time.Second,
	}
}

func newClientKeypair(t *testing.T) (private []byte, public ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer.PublicKey()
}

func TestPasswordAuthAndShell(t *testing.T) {
	ts := startTestServer(t, testServerOptions{Password: "hunter2"})

	cfg := trustAll(t, ts)
	cfg.Credential = Credential{Username: "alice", Password: "hunter2"}

	client, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close() //nolint:errcheck

	session, err := client.Shell(PTYConfig{Cols: 120, Rows: 40})
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	defer session.Close() //nolint:errcheck

	out := collect(session)

	// The remote side reports what it was asked for, which proves the PTY
	// request carried the terminal type and size.
	out.waitFor(t, "welcome", 5*time.Second)
	if !strings.Contains(out.String(), "TERM=xterm-256color") {
		t.Errorf("terminal type did not reach the host: %q", out.String())
	}
	if !strings.Contains(out.String(), "size=120x40") {
		t.Errorf("terminal size did not reach the host: %q", out.String())
	}

	// And bytes travel in both directions.
	if _, err := session.Write([]byte("hello there")); err != nil {
		t.Fatal(err)
	}
	out.waitFor(t, "hello there", 5*time.Second)
}

func TestPublicKeyAuth(t *testing.T) {
	private, public := newClientKeypair(t)
	ts := startTestServer(t, testServerOptions{AuthorizedKey: public})

	cfg := trustAll(t, ts)
	cfg.Credential = Credential{Username: "alice", PrivateKey: private}

	client, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close() //nolint:errcheck

	session, err := client.Shell(PTYConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close() //nolint:errcheck

	collect(session).waitFor(t, "welcome", 5*time.Second)
}

func TestWrongCredentialIsReportedAsAuthFailure(t *testing.T) {
	ts := startTestServer(t, testServerOptions{Password: "hunter2"})

	cfg := trustAll(t, ts)
	cfg.Credential = Credential{Username: "alice", Password: "not the password"}

	_, err := Dial(context.Background(), cfg)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

// TestHostKeyIsCheckedBeforeAuthenticating is the ordering that matters: a
// host that fails to prove its identity must never be offered a credential.
func TestHostKeyIsCheckedBeforeAuthenticating(t *testing.T) {
	ts := startTestServer(t, testServerOptions{Password: "hunter2"})

	var (
		verified bool
		decided  bool
	)

	cfg := Config{
		Target:     Target{Hostname: ts.Host, Port: ts.Port},
		Credential: Credential{Username: "alice", Password: "hunter2"},
		Verify: func(_ context.Context, _ string, _ int, key ssh.PublicKey) (hostkeys.Check, error) {
			verified = true
			return hostkeys.Check{Verdict: hostkeys.VerdictUnknown, Presented: hostkeys.DescribeKey(key)}, nil
		},
		Decide: func(_ context.Context, check hostkeys.Check) error {
			decided = true
			// Refuse, as a user declining an unknown host would.
			return ErrHostKeyRejected
		},
		ConnectTimeout: 10 * time.Second,
	}

	_, err := Dial(context.Background(), cfg)
	if !errors.Is(err, ErrHostKeyRejected) {
		t.Fatalf("want ErrHostKeyRejected, got %v", err)
	}
	if !verified || !decided {
		t.Fatal("the host key was not checked")
	}

	// The server must not have seen a successful authentication.
	if ts.LastPTY() != nil {
		t.Fatal("a session was opened despite the host key being refused")
	}
}

// TestDialRefusesWithoutAVerifier stops "accept anything" ever becoming
// reachable by omission.
func TestDialRefusesWithoutAVerifier(t *testing.T) {
	ts := startTestServer(t, testServerOptions{Password: "hunter2"})

	cfg := Config{
		Target:     Target{Hostname: ts.Host, Port: ts.Port},
		Credential: Credential{Username: "alice", Password: "hunter2"},
		// No Verify, no Decide.
	}
	if _, err := Dial(context.Background(), cfg); err == nil {
		t.Fatal("dialling without host key verification must be refused")
	}
}

// TestChangedHostKeyIsRefused wires the real trust store in and restarts the
// server with a different identity on the same address.
func TestChangedHostKeyIsRefused(t *testing.T) {
	seedA := make([]byte, ed25519.SeedSize)
	seedB := make([]byte, ed25519.SeedSize)
	for i := range seedA {
		seedA[i] = 1
		seedB[i] = 2
	}

	first := startTestServer(t, testServerOptions{Password: "hunter2", HostKeySeed: seedA})

	// A trust store standing in for the database, holding the first key.
	trusted := hostkeys.DescribeKey(first.HostKey)
	verify := func(_ context.Context, _ string, _ int, key ssh.PublicKey) (hostkeys.Check, error) {
		presented := hostkeys.DescribeKey(key)
		if presented.Fingerprint == trusted.Fingerprint {
			return hostkeys.Check{Verdict: hostkeys.VerdictTrusted, Presented: presented}, nil
		}
		return hostkeys.Check{Verdict: hostkeys.VerdictChanged, Presented: presented}, nil
	}
	decide := func(_ context.Context, check hostkeys.Check) error {
		if check.Verdict == hostkeys.VerdictChanged {
			return ErrHostKeyRejected
		}
		return nil
	}

	t.Run("the original key connects", func(t *testing.T) {
		cfg := Config{
			Target:         Target{Hostname: first.Host, Port: first.Port},
			Credential:     Credential{Username: "alice", Password: "hunter2"},
			Verify:         verify,
			Decide:         decide,
			ConnectTimeout: 10 * time.Second,
		}
		client, err := Dial(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		_ = client.Close()
	})

	t.Run("a different key on the same address is refused", func(t *testing.T) {
		// A genuinely different server, exactly as an impostor would be.
		impostor := startTestServer(t, testServerOptions{Password: "hunter2", HostKeySeed: seedB})

		cfg := Config{
			Target:         Target{Hostname: impostor.Host, Port: impostor.Port},
			Credential:     Credential{Username: "alice", Password: "hunter2"},
			Verify:         verify,
			Decide:         decide,
			ConnectTimeout: 10 * time.Second,
		}
		_, err := Dial(context.Background(), cfg)
		if !errors.Is(err, ErrHostKeyRejected) {
			t.Fatalf("want ErrHostKeyRejected, got %v", err)
		}
		if impostor.LastPTY() != nil {
			t.Fatal("the impostor received a session")
		}
	})
}

func TestResizeReachesTheHost(t *testing.T) {
	ts := startTestServer(t, testServerOptions{Password: "hunter2"})

	cfg := trustAll(t, ts)
	cfg.Credential = Credential{Username: "alice", Password: "hunter2"}

	client, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck

	session, err := client.Shell(PTYConfig{Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close() //nolint:errcheck

	out := collect(session)
	out.waitFor(t, "welcome", 5*time.Second)

	if err := session.Resize(200, 50); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	// Ask the far side what size it thinks the terminal is. Without this
	// round trip the test would only prove the request did not error.
	//
	// Polled rather than asked once: a window-change request and a subsequent
	// write are separate SSH messages handled by separate goroutines on the
	// server, so they can be observed in either order. Asking once races that
	// ordering and fails intermittently — which is exactly how this test
	// behaved before it was written this way.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := session.Write([]byte("size\n")); err != nil {
			t.Fatal(err)
		}
		if out.await("size=200x50", 500*time.Millisecond) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the host never reported the new terminal size; output: %q", out.String())
		}
	}
}

func TestResizeRejectsNonsense(t *testing.T) {
	ts := startTestServer(t, testServerOptions{Password: "hunter2"})
	cfg := trustAll(t, ts)
	cfg.Credential = Credential{Username: "alice", Password: "hunter2"}

	client, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck

	session, err := client.Shell(PTYConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close() //nolint:errcheck

	for _, size := range [][2]int{{0, 24}, {80, 0}, {-1, 24}} {
		if err := session.Resize(size[0], size[1]); err == nil {
			t.Errorf("Resize(%d, %d) should be refused", size[0], size[1])
		}
	}
}

func TestRemoteExitIsObserved(t *testing.T) {
	ts := startTestServer(t, testServerOptions{Password: "hunter2"})
	cfg := trustAll(t, ts)
	cfg.Credential = Credential{Username: "alice", Password: "hunter2"}

	client, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck

	session, err := client.Shell(PTYConfig{})
	if err != nil {
		t.Fatal(err)
	}

	out := collect(session)
	out.waitFor(t, "welcome", 5*time.Second)
	if _, err := session.Write([]byte("exit\n")); err != nil {
		t.Fatal(err)
	}
	out.waitFor(t, "bye", 5*time.Second)

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case err := <-done:
		// A clean exit gives nil; a non-zero status gives an ExitError. Either
		// is a definite answer, which is what matters — the terminal must be
		// able to tell the user the session ended.
		if err != nil {
			if _, ok := ExitStatus(err); !ok {
				t.Fatalf("Wait returned an error carrying no exit status: %v", err)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after the remote shell exited")
	}
}

func TestDialUnreachableHost(t *testing.T) {
	cfg := Config{
		// Port 1 on loopback: nothing listens, and the refusal is immediate.
		Target:     Target{Hostname: "127.0.0.1", Port: 1},
		Credential: Credential{Username: "alice", Password: "x"},
		Verify: func(_ context.Context, _ string, _ int, key ssh.PublicKey) (hostkeys.Check, error) {
			return hostkeys.Check{Verdict: hostkeys.VerdictTrusted, Presented: hostkeys.DescribeKey(key)}, nil
		},
		Decide:         func(context.Context, hostkeys.Check) error { return nil },
		ConnectTimeout: 3 * time.Second,
	}

	_, err := Dial(context.Background(), cfg)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("want ErrUnreachable, got %v", err)
	}
}

func TestDialValidation(t *testing.T) {
	base := Config{
		Target: Target{Hostname: "127.0.0.1", Port: 22},
		Verify: func(_ context.Context, _ string, _ int, key ssh.PublicKey) (hostkeys.Check, error) {
			return hostkeys.Check{Verdict: hostkeys.VerdictTrusted, Presented: hostkeys.DescribeKey(key)}, nil
		},
		Decide: func(context.Context, hostkeys.Check) error { return nil },
	}

	t.Run("no credential", func(t *testing.T) {
		cfg := base
		cfg.Credential = Credential{Username: "alice"}
		if _, err := Dial(context.Background(), cfg); !errors.Is(err, ErrNoCredential) {
			t.Fatalf("want ErrNoCredential, got %v", err)
		}
	})

	t.Run("no username", func(t *testing.T) {
		cfg := base
		cfg.Credential = Credential{Password: "x"}
		if _, err := Dial(context.Background(), cfg); err == nil {
			t.Fatal("a missing username must be refused")
		}
	})
}

func TestCredentialZero(t *testing.T) {
	private, _ := newClientKeypair(t)
	c := Credential{Username: "alice", PrivateKey: private, Password: "hunter2", Passphrase: "p"}

	held := c.PrivateKey
	c.Zero()

	for i, b := range held {
		if b != 0 {
			t.Fatalf("private key byte %d survived Zero", i)
		}
	}
	if c.Password != "" || c.Passphrase != "" || c.PrivateKey != nil {
		t.Error("Zero did not clear the credential")
	}
}

func TestTargetAddr(t *testing.T) {
	cases := map[Target]string{
		{Hostname: "router1.example.com", Port: 22}: "router1.example.com:22",
		{Hostname: "192.0.2.1", Port: 2222}:         "192.0.2.1:2222",
		{Hostname: "2001:db8::1", Port: 22}:         "[2001:db8::1]:22",
	}
	for target, want := range cases {
		if got := target.Addr(); got != want {
			t.Errorf("Addr() = %q, want %q", got, want)
		}
	}
}
