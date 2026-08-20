package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
	"golang.org/x/crypto/ssh"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestASecondCallerSharesTheConnection is the property the whole package
// exists for: browsing a host's files while a terminal is open on it must not
// authenticate a second time.
func TestASecondCallerSharesTheConnection(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	key := Key{UserID: "alice", SessionID: "switch-1"}

	first, err := pool.Acquire(context.Background(), key, srv.dial)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	second, err := pool.Acquire(context.Background(), key, srv.dial)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}

	if first.Client() != second.Client() {
		t.Error("two leases on one key returned different connections")
	}
	if n := srv.dials(); n != 1 {
		t.Errorf("the host was dialled %d times, want 1", n)
	}
	if n := pool.Len(); n != 1 {
		t.Errorf("the pool holds %d connections, want 1", n)
	}

	// Releasing one must not disturb the other. This is what stops closing a
	// file browser from killing the terminal beside it.
	first.Release()

	if err := aliveCheck(second.Client()); err != nil {
		t.Fatalf("releasing one lease broke the connection the other holds: %v", err)
	}

	second.Release()
	if n := pool.Len(); n != 0 {
		t.Errorf("the pool holds %d connections after every lease was released", n)
	}
}

// TestDifferentUsersNeverShare guards the boundary that matters most: two
// people on the same switch have separate credentials and separate audit
// trails, and must never land on one another's SSH session.
func TestDifferentUsersNeverShare(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	alice, err := pool.Acquire(context.Background(),
		Key{UserID: "alice", SessionID: "switch-1"}, srv.dial)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := pool.Acquire(context.Background(),
		Key{UserID: "bob", SessionID: "switch-1"}, srv.dial)
	if err != nil {
		t.Fatal(err)
	}

	if alice.Client() == bob.Client() {
		t.Fatal("two users were given the same SSH connection")
	}
	if n := srv.dials(); n != 2 {
		t.Errorf("the host was dialled %d times, want 2", n)
	}
}

func TestDifferentSavedConnectionsDoNotShare(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	one, err := pool.Acquire(context.Background(),
		Key{UserID: "alice", SessionID: "switch-1"}, srv.dial)
	if err != nil {
		t.Fatal(err)
	}
	two, err := pool.Acquire(context.Background(),
		Key{UserID: "alice", SessionID: "switch-2"}, srv.dial)
	if err != nil {
		t.Fatal(err)
	}

	if one.Client() == two.Client() {
		t.Error("two saved connections shared a connection")
	}
}

// TestConcurrentAcquiresDialOnce covers the race worth caring about: opening
// a terminal and a file browser at the same moment must not authenticate
// twice against a host that may well be counting sessions.
func TestConcurrentAcquiresDialOnce(t *testing.T) {
	srv := startSSH(t)
	srv.dialDelay = 50 * time.Millisecond

	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	key := Key{UserID: "alice", SessionID: "switch-1"}

	const callers = 12
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		leases  []*Lease
		clients = map[*sshx.Client]int{}
	)

	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()

			lease, err := pool.Acquire(context.Background(), key, srv.dial)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}

			mu.Lock()
			leases = append(leases, lease)
			clients[lease.Client()]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(leases) != callers {
		t.Fatalf("%d leases, want %d", len(leases), callers)
	}
	if len(clients) != 1 {
		t.Errorf("%d distinct connections were handed out, want 1", len(clients))
	}
	if n := srv.dials(); n != 1 {
		t.Errorf("the host was dialled %d times, want 1", n)
	}

	// Every lease must be released before the connection closes; releasing
	// all but one and checking the connection still works is the assertion
	// that reference counting is real rather than incidental.
	for _, lease := range leases[:callers-1] {
		lease.Release()
	}
	if n := pool.Len(); n != 1 {
		t.Errorf("the connection closed while a lease was still held")
	}

	leases[callers-1].Release()
	if n := pool.Len(); n != 0 {
		t.Errorf("the pool holds %d connections after the last release", n)
	}
}

// TestAFailedDialIsNotCached: a host that was down when first tried must be
// retried, not remembered as broken.
func TestAFailedDialIsNotCached(t *testing.T) {
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	key := Key{UserID: "alice", SessionID: "switch-1"}
	boom := errors.New("the host was down")

	var attempts atomic.Int32
	failing := func(context.Context) (*sshx.Client, error) {
		attempts.Add(1)
		return nil, boom
	}

	if _, err := pool.Acquire(context.Background(), key, failing); !errors.Is(err, boom) {
		t.Fatalf("first acquire = %v, want the dial error", err)
	}
	if n := pool.Len(); n != 0 {
		t.Errorf("a failed dial left %d entries in the pool", n)
	}

	srv := startSSH(t)
	lease, err := pool.Acquire(context.Background(), key, srv.dial)
	if err != nil {
		t.Fatalf("the second attempt inherited the first failure: %v", err)
	}
	lease.Release()

	if attempts.Load() != 1 {
		t.Errorf("the failing dialler ran %d times", attempts.Load())
	}
}

// TestWaitersSeeADialFailure: a caller that joined an in-flight dial gets the
// error too, rather than a nil connection.
func TestWaitersSeeADialFailure(t *testing.T) {
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	key := Key{UserID: "alice", SessionID: "switch-1"}
	boom := errors.New("refused")

	release := make(chan struct{})
	slowFailure := func(context.Context) (*sshx.Client, error) {
		<-release
		return nil, boom
	}

	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := pool.Acquire(context.Background(), key, slowFailure)
			errs <- err
		}()
	}

	// Let both callers reach the pool before the dial resolves, so one of
	// them is genuinely a waiter rather than a fresh dialler.
	time.Sleep(50 * time.Millisecond)
	close(release)

	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if !errors.Is(err, boom) {
				t.Errorf("acquire = %v, want the dial error", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a caller never returned")
		}
	}

	if n := pool.Len(); n != 0 {
		t.Errorf("a failed dial left %d entries in the pool", n)
	}
}

// TestACancelledWaiterGivesItsReferenceBack: without this the connection
// would never close, because a reference taken before the wait would be
// abandoned when the caller walked away.
func TestACancelledWaiterGivesItsReferenceBack(t *testing.T) {
	srv := startSSH(t)

	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	key := Key{UserID: "alice", SessionID: "switch-1"}

	release := make(chan struct{})
	gated := func(ctx context.Context) (*sshx.Client, error) {
		<-release
		return srv.dial(ctx)
	}

	go func() { _, _ = pool.Acquire(context.Background(), key, gated) }()

	// A second caller joins the in-flight dial and then gives up.
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := pool.Acquire(ctx, key, gated); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled acquire = %v, want context.Canceled", err)
	}

	close(release)

	// The first caller's lease is the only one left, so releasing it must
	// close the connection. A leaked reference would leave it open.
	waitFor(t, func() bool { return pool.Len() == 1 }, "the dial to finish")

	pool.mu.Lock()
	entry := pool.conns[key]
	pool.mu.Unlock()

	if entry == nil {
		t.Fatal("the connection vanished")
	}
	if got := refs(pool, key); got != 1 {
		t.Errorf("reference count = %d, want 1 — a cancelled waiter leaked one", got)
	}
}

// TestADeadConnectionIsEvicted: the next caller must dial fresh rather than
// be handed a connection the host has already dropped.
func TestADeadConnectionIsEvicted(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	key := Key{UserID: "alice", SessionID: "switch-1"}

	lease, err := pool.Acquire(context.Background(), key, srv.dial)
	if err != nil {
		t.Fatal(err)
	}

	// The host goes away.
	_ = lease.Client().Close()
	waitFor(t, func() bool { return pool.Len() == 0 }, "the dead connection to be evicted")

	next, err := pool.Acquire(context.Background(), key, srv.dial)
	if err != nil {
		t.Fatalf("acquire after the connection died: %v", err)
	}
	if next.Client() == lease.Client() {
		t.Error("a dead connection was handed out again")
	}
	if n := srv.dials(); n != 2 {
		t.Errorf("the host was dialled %d times, want 2", n)
	}

	// Releasing the dead lease must not disturb its replacement.
	lease.Release()
	if n := pool.Len(); n != 1 {
		t.Errorf("releasing a stale lease evicted its replacement")
	}
	next.Release()
}

// TestReleasingTwiceIsIgnored: a double release would decrement somebody
// else's reference and could close a connection still in use.
func TestReleasingTwiceIsIgnored(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	key := Key{UserID: "alice", SessionID: "switch-1"}

	first, err := pool.Acquire(context.Background(), key, srv.dial)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Acquire(context.Background(), key, srv.dial)
	if err != nil {
		t.Fatal(err)
	}

	first.Release()
	first.Release()
	first.Release()

	if n := pool.Len(); n != 1 {
		t.Fatal("a repeated release closed a connection still in use")
	}
	if err := aliveCheck(second.Client()); err != nil {
		t.Fatalf("the surviving lease's connection is broken: %v", err)
	}
}

func TestClosedPoolRefusesToDial(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())
	pool.Close()

	_, err := pool.Acquire(context.Background(),
		Key{UserID: "alice", SessionID: "switch-1"}, srv.dial)
	if !errors.Is(err, ErrPoolClosed) {
		t.Errorf("acquire on a closed pool = %v, want ErrPoolClosed", err)
	}
	if n := srv.dials(); n != 0 {
		t.Errorf("a closed pool dialled anyway")
	}
}

// --- helpers ----------------------------------------------------------------

func refs(p *Pool, key Key) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if e, ok := p.conns[key]; ok {
		return e.refs
	}
	return 0
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// aliveCheck proves a connection still works by opening a channel on it.
func aliveCheck(client *sshx.Client) error {
	session, err := client.Conn().NewSession()
	if err != nil {
		return err
	}
	return session.Close()
}

// sshTestServer is a real SSH server, counting how many times it is dialled.
type sshTestServer struct {
	Host string
	Port int

	// dialDelay slows the handshake, so a test can reliably have a second
	// caller arrive while the first dial is still in flight.
	dialDelay time.Duration

	mu    sync.Mutex
	count int
}

func startSSH(t *testing.T) *sshTestServer {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	srv := &gssh.Server{
		HostSigners:     []gssh.Signer{signer},
		PasswordHandler: func(gssh.Context, string) bool { return true },
		Handler:         func(s gssh.Session) { _ = s.Exit(0) },
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

	return &sshTestServer{Host: host, Port: port}
}

func (ts *sshTestServer) dials() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.count
}

func (ts *sshTestServer) dial(ctx context.Context) (*sshx.Client, error) {
	ts.mu.Lock()
	ts.count++
	delay := ts.dialDelay
	ts.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return sshx.Dial(ctx, sshx.Config{
		Target:     sshx.Target{Hostname: ts.Host, Port: ts.Port},
		Credential: sshx.Credential{Username: "tester", Password: "anything"},
		Verify: func(context.Context, string, int, ssh.PublicKey) (hostkeys.Check, error) {
			return hostkeys.Check{Verdict: hostkeys.VerdictUnknown}, nil
		},
		Decide: func(context.Context, hostkeys.Check) error { return nil },
	})
}
