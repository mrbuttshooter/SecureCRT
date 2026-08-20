// Package remote owns SSH connections to managed hosts and hands them out to
// whatever wants one.
//
// A connection is shared rather than owned. SSH multiplexes channels, so a
// shell and a file transfer to the same host ride the same TCP connection,
// the same authentication and — on equipment that counts them — the same vty
// line. Opening a second connection to browse files on a host you already
// have a terminal on would mean a second host key check, a second
// authentication, and one more session against a limit that on plenty of
// network gear is four.
//
// Sharing is by reference count. The connection lives while anything holds a
// lease and closes when the last one is released, so closing a file browser
// never disconnects a terminal and closing a terminal never interrupts a
// transfer.
package remote

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
)

// ErrPoolClosed means the pool is shutting down and will not dial.
var ErrPoolClosed = errors.New("remote: the connection pool is closed")

// Key identifies a shared connection.
//
// Scoped to the user as well as the saved connection: two people connecting
// to the same switch have separate credentials and separate audit trails, and
// must never end up on one another's SSH session.
type Key struct {
	UserID    string
	SessionID string

	// Via is the route taken to reach SessionID: the jump hosts hopped
	// through, in order, joined by ">". Empty for a direct dial.
	//
	// Without it, a host reachable both directly and through a bastion would
	// share one entry, and the second caller would silently get the wrong
	// transport — which is worse than failing, because the direct route may
	// be reachable from this server while the tunnelled one is not, or the
	// two may reach different devices entirely.
	//
	// It also gives sharing for free at the other end: the first hop of every
	// chain has an empty Via, which is *the same key* a plain terminal on
	// that bastion uses. Fifty devices behind one bastion and somebody's own
	// shell on it are one TCP connection, one authentication, one vty line.
	Via string
}

// PathKey builds the key for reaching sessionID through hops.
func PathKey(userID string, hops []string, sessionID string) Key {
	return Key{UserID: userID, SessionID: sessionID, Via: strings.Join(hops, ">")}
}

// depth reports how many hops the route has, so shutdown can close the
// deepest connections first — a tunnelled connection needs a live bastion
// underneath it to send its disconnect through.
func (k Key) depth() int {
	if k.Via == "" {
		return 0
	}
	return strings.Count(k.Via, ">") + 1
}

// Pool holds live SSH connections, one per Key.
type Pool struct {
	log *slog.Logger

	mu     sync.Mutex
	conns  map[Key]*entry
	closed bool
}

// entry is one shared connection, possibly still being dialled.
type entry struct {
	key Key

	// ready is closed once the dial finishes, successfully or not. A second
	// caller arriving mid-dial waits on it rather than starting a second
	// connection to the same host.
	ready  chan struct{}
	client *sshx.Client
	err    error

	// release gives back whatever the dial borrowed to build this connection
	// — in practice the leases on the jump hosts it was reached through.
	//
	// It belongs to the entry rather than to each Lease because Acquire runs
	// the dial at most once per key: the second and subsequent callers take
	// the reference-count fast path and never see it. If hop leases were held
	// per-lease, those callers would have to take them separately, which
	// reopens the dial-coalescing race this pool exists to close.
	release func()

	// refs counts outstanding leases. The connection closes when it reaches
	// zero, and not before.
	refs int

	// evicted marks an entry no longer in the map — because the connection
	// died, or because the last lease was released. Leases already held stay
	// valid until released; new callers dial fresh.
	evicted bool
}

// NewPool builds an empty pool.
func NewPool(log *slog.Logger) *Pool {
	if log == nil {
		log = slog.Default()
	}
	return &Pool{log: log, conns: map[Key]*entry{}}
}

// Lease is one holder's claim on a shared connection.
//
// Release exactly once, from the holder that acquired it. Releasing twice
// would decrement another holder's reference and could close a connection
// still in use, so the second release is ignored rather than trusted.
type Lease struct {
	pool  *Pool
	entry *entry

	once   sync.Once
	client *sshx.Client
}

// Client is the connection this lease holds.
func (l *Lease) Client() *sshx.Client { return l.client }

// Release gives up this lease. The connection closes when the last one does.
func (l *Lease) Release() {
	l.once.Do(func() { l.pool.release(l.entry) })
}

// DialFunc opens a connection. Called at most once per Key at a time.
type DialFunc func(ctx context.Context) (*sshx.Client, func(), error)

// Acquire returns a lease on the connection for key, dialling if there is not
// one already.
//
// Callers arriving while a dial is in progress wait for it rather than
// starting their own. That matters more than it looks: without it, opening a
// terminal and a file browser at the same moment would race to authenticate
// twice against a host that may well be counting.
func (p *Pool) Acquire(ctx context.Context, key Key, dial DialFunc) (*Lease, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}

	if existing, ok := p.conns[key]; ok {
		existing.refs++
		p.mu.Unlock()
		return p.wait(ctx, existing)
	}

	fresh := &entry{key: key, ready: make(chan struct{}), refs: 1}
	p.conns[key] = fresh
	p.mu.Unlock()

	client, release, err := dial(ctx)

	p.mu.Lock()
	fresh.client, fresh.release, fresh.err = client, release, err
	if err != nil {
		// A failed dial is not cached: the next attempt should try again
		// rather than inherit a stale failure, and anyone waiting on this
		// entry gets the error too.
		p.evict(fresh)
	}
	p.mu.Unlock()
	close(fresh.ready)

	if err != nil {
		// A dial that got three hops along and then failed must not keep
		// those three bastions pinned for the life of the process.
		if release != nil {
			release()
		}
		return nil, err
	}

	// Notice the connection dying so a later caller dials fresh instead of
	// being handed a corpse.
	go p.watch(fresh, client)

	return &Lease{pool: p, entry: fresh, client: client}, nil
}

// wait blocks until an in-flight dial finishes.
func (p *Pool) wait(ctx context.Context, e *entry) (*Lease, error) {
	select {
	case <-e.ready:
	case <-ctx.Done():
		// The reference was taken before the wait, so it has to be given
		// back or the connection would never close.
		p.release(e)
		return nil, ctx.Err()
	}

	if e.err != nil {
		return nil, e.err
	}
	return &Lease{pool: p, entry: e, client: e.client}, nil
}

// watch removes an entry once its connection ends.
func (p *Pool) watch(e *entry, client *sshx.Client) {
	_ = client.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	if !e.evicted {
		p.log.Debug("shared SSH connection ended",
			"user", e.key.UserID, "session", e.key.SessionID, "leases", e.refs)
		p.evict(e)
	}
}

// release drops one reference, closing the connection at zero.
func (p *Pool) release(e *entry) {
	p.mu.Lock()

	e.refs--
	last := e.refs <= 0
	if last && !e.evicted {
		p.evict(e)
	}
	client := e.client
	release := e.release
	p.mu.Unlock()

	if last {
		// The connection first, then the transport it rode on: a disconnect
		// still has somewhere to go.
		if client != nil {
			_ = client.Close()
		}
		if release != nil {
			release()
		}
	}
}

// evict removes an entry from the map. Callers hold p.mu.
//
// Only if it is still the current one for its key: a connection that died and
// was replaced must not have its successor removed by the dying one's watcher.
func (p *Pool) evict(e *entry) {
	if current, ok := p.conns[e.key]; ok && current == e {
		delete(p.conns, e.key)
	}
	e.evicted = true
}

// Close shuts every connection down.
//
// Used at process shutdown, where the point is to send each host a clean
// disconnect rather than to leave it noticing a dropped TCP connection later.
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true

	// Snapshotted under the lock rather than carrying entry pointers out of
	// it: a dial still in flight writes client and release when it finishes,
	// and reading those fields outside the mutex is a data race.
	type doomed struct {
		depth   int
		client  *sshx.Client
		release func()
	}

	entries := make([]doomed, 0, len(p.conns))
	for key, e := range p.conns {
		entries = append(entries, doomed{
			depth: e.key.depth(), client: e.client, release: e.release,
		})
		e.evicted = true
		delete(p.conns, key)
	}
	p.mu.Unlock()

	// Deepest route first. A connection reached through a bastion needs that
	// bastion still up to send its disconnect through; closing the bastion
	// first would leave every host behind it to time the session out itself.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].depth > entries[j].depth
	})

	for _, e := range entries {
		if e.client != nil {
			_ = e.client.Close()
		}
		// Released as well as closed. The hop entries are in this same map
		// and being torn down anyway, so this is bookkeeping rather than
		// lifecycle — but skipping it would leave a reference count that a
		// surviving Lease could later decrement below zero.
		if e.release != nil {
			e.release()
		}
	}
}

// Len reports how many connections are open, for tests and diagnostics.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}
