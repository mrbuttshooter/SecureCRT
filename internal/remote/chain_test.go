package remote

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
)

// Routes, and what the pool does with them.
//
// These drive the Pool directly rather than through the Dialer. The property
// under test is the lifetime of a borrowed transport, and a hand-made DialFunc
// states it in two lines where a full dial would bury it under three SSH
// handshakes.

func TestARouteDistinguishesOtherwiseIdenticalConnections(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	direct := PathKey("alice", nil, "switch-1")
	viaBastion := PathKey("alice", []string{"bastion"}, "switch-1")

	if direct == viaBastion {
		t.Fatal("a direct route and a tunnelled one share a key")
	}

	first, err := pool.Acquire(context.Background(), direct, srv.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()

	second, err := pool.Acquire(context.Background(), viaBastion, srv.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()

	// Two entries, two dials. Sharing them would hand the second caller a
	// transport it did not ask for — and the two routes may not even reach
	// the same device.
	if pool.Len() != 2 {
		t.Errorf("pool holds %d connections, want 2", pool.Len())
	}
	if srv.dials() != 2 {
		t.Errorf("the server saw %d dials, want 2", srv.dials())
	}
}

// TestOneBastionServesManyTargets is the property the whole design turns on.
//
// Fifty devices behind one bastion must cost one bastion connection, and it
// must live exactly as long as the last thing riding it.
func TestOneBastionServesManyTargets(t *testing.T) {
	bastion := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	ctx := context.Background()
	bastionKey := PathKey("alice", nil, "bastion")

	// Two targets, each borrowing a lease on the same bastion and handing the
	// pool a release for it — which is what dialThrough does.
	openTarget := func(name string) *Lease {
		t.Helper()
		lease, err := pool.Acquire(ctx, PathKey("alice", []string{"bastion"}, name),
			func(ctx context.Context) (*sshx.Client, func(), error) {
				hop, err := pool.Acquire(ctx, bastionKey, bastion.dial)
				if err != nil {
					return nil, nil, err
				}
				client, _, err := bastion.dial(ctx)
				if err != nil {
					hop.Release()
					return nil, nil, err
				}
				return client, hop.Release, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		return lease
	}

	one := openTarget("switch-1")
	two := openTarget("switch-2")

	// Three entries: two targets and the one bastion they share.
	if pool.Len() != 3 {
		t.Fatalf("pool holds %d connections, want 3", pool.Len())
	}

	one.Release()

	// The first target is gone; the bastion is not, because the second target
	// is still riding it. Two entries left, and acquiring the bastion again
	// must not dial — it is still there to be shared.
	if pool.Len() != 2 {
		t.Fatalf("pool holds %d connections after one target closed, want 2", pool.Len())
	}
	probe, err := pool.Acquire(ctx, bastionKey, failDial(t))
	if err != nil {
		t.Fatalf("the bastion went down while a target was still riding it: %v", err)
	}
	probe.Release()

	two.Release()

	// Now nothing holds it, so it is gone and the next caller dials fresh.
	if pool.Len() != 0 {
		t.Errorf("pool still holds %d connections after everything was released", pool.Len())
	}
}

// TestAChainThatFailsPartWayLeaksNothing. A dial that reached the third hop
// and then failed must not pin the first two for the life of the process.
func TestAChainThatFailsPartWayLeaksNothing(t *testing.T) {
	bastion := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	ctx := context.Background()
	boom := errors.New("the far host refused")

	var released atomic.Int32

	_, err := pool.Acquire(ctx, PathKey("alice", []string{"bastion"}, "switch-1"),
		func(ctx context.Context) (*sshx.Client, func(), error) {
			hop, err := pool.Acquire(ctx, PathKey("alice", nil, "bastion"), bastion.dial)
			if err != nil {
				return nil, nil, err
			}
			release := func() { released.Add(1); hop.Release() }

			// The target refuses. dialThrough unwinds; the pool must not be
			// left holding the hop.
			release()
			return nil, nil, boom
		})

	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the dial failure", err)
	}
	if released.Load() != 1 {
		t.Errorf("the borrowed lease was released %d times, want once", released.Load())
	}
	if pool.Len() != 0 {
		t.Errorf("pool holds %d connections after a failed chain, want none", pool.Len())
	}
}

// TestTheReleaseHookRunsOnceTheLastLeaseGoes, and not before. A bastion shared
// by two terminals must survive one of them closing.
func TestTheReleaseHookRunsOnceTheLastLeaseGoes(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	var released atomic.Int32
	key := PathKey("alice", []string{"bastion"}, "switch-1")

	dial := func(ctx context.Context) (*sshx.Client, func(), error) {
		client, _, err := srv.dial(ctx)
		return client, func() { released.Add(1) }, err
	}

	first, err := pool.Acquire(context.Background(), key, dial)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Acquire(context.Background(), key, dial)
	if err != nil {
		t.Fatal(err)
	}

	first.Release()
	if released.Load() != 0 {
		t.Fatal("the transport was given back while a lease still held it")
	}

	second.Release()
	if released.Load() != 1 {
		t.Errorf("release ran %d times, want once", released.Load())
	}
}

// TestAcquiringFromInsideADialDoesNotDeadlock.
//
// dialThrough acquires each hop from inside the DialFunc of the hop in front
// of it, which is only safe because Acquire unlocks before running the dial.
// That holds today; this is here so it keeps holding.
func TestAcquiringFromInsideADialDoesNotDeadlock(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())
	t.Cleanup(pool.Close)

	done := make(chan error, 1)

	go func() {
		_, err := pool.Acquire(context.Background(), PathKey("alice", []string{"a", "b"}, "c"),
			func(ctx context.Context) (*sshx.Client, func(), error) {
				inner, err := pool.Acquire(ctx, PathKey("alice", []string{"a"}, "b"),
					func(ctx context.Context) (*sshx.Client, func(), error) {
						deepest, err := pool.Acquire(ctx, PathKey("alice", nil, "a"), srv.dial)
						if err != nil {
							return nil, nil, err
						}
						client, _, err := srv.dial(ctx)
						return client, deepest.Release, err
					})
				if err != nil {
					return nil, nil, err
				}
				client, _, err := srv.dial(ctx)
				return client, inner.Release, err
			})
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("nested acquire: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("nested acquire deadlocked")
	}

	if pool.Len() != 3 {
		t.Errorf("pool holds %d connections, want 3", pool.Len())
	}
}

// TestShutdownClosesTheDeepestRouteFirst. A connection reached through a
// bastion needs that bastion still up to send its disconnect through.
func TestShutdownClosesTheDeepestRouteFirst(t *testing.T) {
	srv := startSSH(t)
	pool := NewPool(quiet())

	ctx := context.Background()
	var order []string
	var mu sync.Mutex

	record := func(name string) func() {
		return func() {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
		}
	}

	// Deliberately acquired shallowest first, so passing cannot be an
	// accident of insertion order.
	for _, tc := range []struct {
		name string
		key  Key
	}{
		{"direct", PathKey("alice", nil, "a")},
		{"one-hop", PathKey("alice", []string{"a"}, "b")},
		{"two-hop", PathKey("alice", []string{"a", "b"}, "c")},
	} {
		name := tc.name
		if _, err := pool.Acquire(ctx, tc.key,
			func(ctx context.Context) (*sshx.Client, func(), error) {
				client, _, err := srv.dial(ctx)
				return client, record(name), err
			}); err != nil {
			t.Fatal(err)
		}
	}

	pool.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 {
		t.Fatalf("released %d connections, want 3: %v", len(order), order)
	}
	if order[0] != "two-hop" || order[2] != "direct" {
		t.Errorf("closed in order %v; the deepest route must go first", order)
	}
}

// failDial fails if it is ever called, which is how a test asserts that a
// connection was already pooled.
func failDial(t *testing.T) DialFunc {
	t.Helper()
	return func(context.Context) (*sshx.Client, func(), error) {
		t.Error("dialled again; the connection should have been shared")
		return nil, nil, errors.New("should not dial")
	}
}
