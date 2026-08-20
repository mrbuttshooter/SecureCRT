package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

// testServer is a real SSH server, in-process.
//
// A mock would only confirm this code agrees with itself. This performs an
// actual handshake, actual authentication and an actual pseudo-terminal
// request, so the tests exercise the protocol rather than an imitation of it.
type testServer struct {
	Addr     string
	Host     string
	Port     int
	HostKey  ssh.PublicKey
	listener net.Listener
	server   *gssh.Server

	mu sync.Mutex
	// lastPTY records what the client asked for, so tests can assert the
	// terminal type and size actually crossed the wire.
	lastPTY *gssh.Pty
	// resizes records window changes.
	resizes []gssh.Window
}

type testServerOptions struct {
	// Password, when set, is the only accepted password.
	Password string
	// AuthorizedKey, when set, is the only accepted public key.
	AuthorizedKey ssh.PublicKey
	// HostKeySeed makes the host key deterministic, so a test can restart the
	// server with the same or a different identity.
	HostKeySeed []byte
	// Handler overrides the default echoing shell.
	Handler gssh.Handler

	// Configure adjusts the server before it starts serving. It has to happen
	// before Serve rather than after: the accept loop reads these fields, so
	// setting them on a running server is a data race, which is exactly what
	// the first version of the jump-host tests did.
	Configure func(*gssh.Server)
}

func startTestServer(t *testing.T, opts testServerOptions) *testServer {
	t.Helper()

	seed := opts.HostKeySeed
	if seed == nil {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
	}
	hostPriv := ed25519.NewKeyFromSeed(seed)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	ts := &testServer{HostKey: hostSigner.PublicKey()}

	handler := opts.Handler
	if handler == nil {
		handler = ts.defaultShell
	}

	ts.server = &gssh.Server{
		Handler:     handler,
		HostSigners: []gssh.Signer{hostSigner},
	}

	if opts.Password != "" {
		want := opts.Password
		ts.server.PasswordHandler = func(_ gssh.Context, password string) bool {
			return password == want
		}
	}
	if opts.AuthorizedKey != nil {
		want := opts.AuthorizedKey
		ts.server.PublicKeyHandler = func(_ gssh.Context, key gssh.PublicKey) bool {
			return gssh.KeysEqual(key, want)
		}
	}
	if opts.Password == "" && opts.AuthorizedKey == nil {
		t.Fatal("the test server must accept something, or every test would fail identically")
	}

	if opts.Configure != nil {
		opts.Configure(ts.server)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts.listener = listener
	ts.Addr = listener.Addr().String()

	host, portStr, err := net.SplitHostPort(ts.Addr)
	if err != nil {
		t.Fatal(err)
	}
	ts.Host = host
	if ts.Port, err = strconv.Atoi(portStr); err != nil {
		t.Fatal(err)
	}

	go func() { _ = ts.server.Serve(listener) }()
	t.Cleanup(func() { _ = ts.server.Close() })

	return ts
}

// defaultShell echoes what it receives and answers a couple of commands, which
// is enough to prove bytes travel in both directions through a real PTY.
func (ts *testServer) defaultShell(s gssh.Session) {
	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		_, _ = io.WriteString(s, "no pty requested\n")
		_ = s.Exit(1)
		return
	}

	ts.mu.Lock()
	ts.lastPTY = &ptyReq
	ts.mu.Unlock()

	go func() {
		for win := range winCh {
			ts.mu.Lock()
			ts.resizes = append(ts.resizes, win)
			ts.mu.Unlock()
		}
	}()

	_, _ = fmt.Fprintf(s, "welcome TERM=%s size=%dx%d\r\n", ptyReq.Term, ptyReq.Window.Width, ptyReq.Window.Height)

	buf := make([]byte, 1024)
	for {
		n, err := s.Read(buf)
		if n > 0 {
			line := string(buf[:n])
			switch {
			case line == "exit\n" || line == "exit\r":
				_, _ = io.WriteString(s, "bye\r\n")
				_ = s.Exit(0)
				return
			case line == "size\n" || line == "size\r":
				ts.mu.Lock()
				last := ts.resizes
				ts.mu.Unlock()
				w, h := ptyReq.Window.Width, ptyReq.Window.Height
				if len(last) > 0 {
					w, h = last[len(last)-1].Width, last[len(last)-1].Height
				}
				_, _ = fmt.Fprintf(s, "size=%dx%d\r\n", w, h)
			default:
				// Echo, as a terminal in canonical mode would.
				_, _ = s.Write(buf[:n])
			}
		}
		if err != nil {
			return
		}
	}
}

// LastPTY returns what the client requested.
func (ts *testServer) LastPTY() *gssh.Pty {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.lastPTY
}

// Resizes returns the window changes seen.
func (ts *testServer) Resizes() []gssh.Window {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([]gssh.Window, len(ts.resizes))
	copy(out, ts.resizes)
	return out
}

// output collects a session's bytes on one goroutine.
//
// A stream has exactly one reader. Spawning a goroutine per assertion — which
// an earlier version of these helpers did — means an assertion that times out
// leaves a reader behind, silently consuming the bytes the next assertion is
// waiting for. The symptom is a test that passes alone and fails in a suite,
// which is a miserable thing to debug.
type output struct {
	mu      sync.Mutex
	buf     []byte
	err     error
	changed chan struct{}
}

func collect(r io.Reader) *output {
	o := &output{changed: make(chan struct{}, 1)}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)

			o.mu.Lock()
			if n > 0 {
				o.buf = append(o.buf, buf[:n]...)
			}
			if err != nil {
				o.err = err
			}
			o.mu.Unlock()

			select {
			case o.changed <- struct{}{}:
			default:
			}

			if err != nil {
				return
			}
		}
	}()

	return o
}

// String returns everything read so far.
func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.buf)
}

// has reports whether want has appeared.
func (o *output) has(want string) bool {
	return contains(o.String(), want)
}

// waitFor blocks until want appears or the timeout passes.
func (o *output) waitFor(t *testing.T, want string, timeout time.Duration) {
	t.Helper()
	if o.await(want, timeout) {
		return
	}
	t.Fatalf("timed out after %s waiting for %q; output so far: %q", timeout, want, o.String())
}

// await is waitFor without failing, for callers that poll.
func (o *output) await(want string, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if o.has(want) {
			return true
		}
		select {
		case <-o.changed:
		case <-deadline:
			return o.has(want)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
