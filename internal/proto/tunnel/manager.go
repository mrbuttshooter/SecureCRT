package tunnel

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/remote"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Config is what the manager needs from the operator's settings.
type Config struct {
	// AllowListeners gates the kinds that open a port on this server.
	AllowListeners bool

	// Bind is the address those listeners bind.
	Bind string

	// PortLow and PortHigh bound the ports they are allocated.
	PortLow, PortHigh int

	// Domain is the wildcard base web tunnels are served under. Empty
	// disables them.
	Domain string

	// MaxPerUser caps concurrent tunnels per person.
	MaxPerUser int

	// IdleTimeout closes a tunnel nothing has used.
	IdleTimeout time.Duration
}

// Manager owns every live tunnel.
//
// Shaped after files.Manager, deliberately: a tunnel has the same lifetime
// problem as an open SFTP session — it holds a shared SSH connection that
// something else may also be using, it is abandoned rather than closed when a
// browser tab goes away, and it has to be reaped.
type Manager struct {
	cfg    Config
	dialer *remote.Dialer
	log    *slog.Logger

	mu      sync.Mutex
	tunnels map[string]*Tunnel
	ports   map[int]bool // allocated, so two tunnels never race for one
	closed  bool

	stop chan struct{}
	done chan struct{}
}

// NewManager starts the manager and its reaper.
func NewManager(cfg Config, dialer *remote.Dialer, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	if cfg.MaxPerUser <= 0 {
		cfg.MaxPerUser = 8
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = time.Hour
	}

	m := &Manager{
		cfg: cfg, dialer: dialer, log: log,
		tunnels: map[string]*Tunnel{},
		ports:   map[int]bool{},
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go m.reap()
	return m
}

// WebTunnelsEnabled reports whether a domain is configured to serve them from.
func (m *Manager) WebTunnelsEnabled() bool { return m.cfg.Domain != "" }

// ListenersEnabled reports whether ports may be opened on this server.
func (m *Manager) ListenersEnabled() bool { return m.cfg.AllowListeners }

// Domain returns the configured wildcard base.
func (m *Manager) Domain() string { return m.cfg.Domain }

// OpenParams describe a tunnel to open.
type OpenParams struct {
	UserID    string
	SessionID string
	Kind      Kind
	Label     string

	// Host and Port are where a local tunnel forwards to. Ignored by the
	// other kinds.
	Host string
	Port int

	VaultKey vault.Key
	Prompter remote.HostKeyPrompter
	Progress func(status string)
}

// Open establishes a tunnel.
func (m *Manager) Open(ctx context.Context, p OpenParams) (*Tunnel, error) {
	if err := p.Kind.Validate(); err != nil {
		return nil, err
	}
	if p.Kind == KindWeb && !m.WebTunnelsEnabled() {
		return nil, ErrWebTunnelsOff
	}
	if p.Kind.NeedsListener() && !m.cfg.AllowListeners {
		return nil, ErrListenersOff
	}
	if p.Kind == KindLocal {
		if p.Host == "" {
			return nil, fmt.Errorf("tunnel: a local tunnel needs somewhere to forward to")
		}
		if p.Port < 1 || p.Port > 65535 {
			return nil, fmt.Errorf("tunnel: port %d is out of range", p.Port)
		}
	}
	if p.Kind == KindWeb && p.Port == 0 {
		p.Port = 80
	}

	if err := m.checkQuota(p.UserID); err != nil {
		return nil, err
	}

	conn, err := m.dialer.Acquire(ctx, remote.Params{
		UserID:    p.UserID,
		SessionID: p.SessionID,
		VaultKey:  p.VaultKey,
		Prompter:  p.Prompter,
		Progress:  p.Progress,
	})
	if err != nil {
		return nil, err
	}

	t := newTunnel(p.UserID, p.SessionID, p.Label, p.Kind, conn)
	t.Host, t.Port = p.Host, p.Port

	// The tunnel's own context, so closing it stops every forwarded
	// connection rather than waiting for each to notice.
	tunnelCtx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel

	if p.Kind.NeedsListener() {
		if err := m.listen(tunnelCtx, t); err != nil {
			cancel()
			conn.Release()
			return nil, err
		}
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		cancel()
		if t.listener != nil {
			_ = t.listener.Close()
		}
		conn.Release()
		return nil, ErrManagerClosed
	}
	m.tunnels[t.ID] = t
	m.mu.Unlock()

	return t, nil
}

// checkQuota refuses a user more tunnels than the policy allows.
//
// Counted rather than tracked: a tunnel that failed still occupies a slot
// until it is closed, which is right — it is still holding a connection.
func (m *Manager) checkQuota(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrManagerClosed
	}

	open := 0
	for _, t := range m.tunnels {
		if t.UserID == userID {
			open++
		}
	}
	if open >= m.cfg.MaxPerUser {
		return fmt.Errorf("%w: the limit is %d", ErrTooManyTunnels, m.cfg.MaxPerUser)
	}
	return nil
}

// listen binds a port for a tunnel and starts accepting on it.
func (m *Manager) listen(ctx context.Context, t *Tunnel) error {
	port, err := m.allocatePort()
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(m.cfg.Bind, strconv.Itoa(port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		m.releasePort(port)
		return fmt.Errorf("tunnel: listening on %s: %w", addr, err)
	}

	t.listener = listener
	t.mu.Lock()
	t.listenAddr = addr
	t.mu.Unlock()

	go m.accept(ctx, t, port)
	return nil
}

// allocatePort picks a free port from the configured range.
//
// Chosen at random rather than sequentially, and from crypto/rand — but the
// port is not a secret and should not be treated as one. A thousand-port
// range is scanned in under a second by anyone who can reach the bind
// address, and the bind address is the actual boundary. What randomness buys
// is only that one tunnel's port does not give away the next one, which
// matters when several people are using the server at once.
func (m *Manager) allocatePort() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	span := m.cfg.PortHigh - m.cfg.PortLow + 1
	if span <= 0 {
		return 0, ErrNoPortAvailable
	}

	// Bounded attempts, then a linear sweep: random probing is fast while the
	// range is mostly empty and hopeless once it is nearly full, and the
	// sweep is what makes "nearly full" terminate.
	for range 32 {
		offset, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
		if err != nil {
			break // fall through to the sweep rather than fail
		}
		port := m.cfg.PortLow + int(offset.Int64())
		if !m.ports[port] {
			m.ports[port] = true
			return port, nil
		}
	}
	for port := m.cfg.PortLow; port <= m.cfg.PortHigh; port++ {
		if !m.ports[port] {
			m.ports[port] = true
			return port, nil
		}
	}
	return 0, ErrNoPortAvailable
}

func (m *Manager) releasePort(port int) {
	m.mu.Lock()
	delete(m.ports, port)
	m.mu.Unlock()
}

// Get returns a tunnel, refusing another user's.
//
// Reported as not-found rather than forbidden, matching every other lookup
// here: confirming that somebody else has a tunnel open discloses that they
// are working on something.
func (m *Manager) Get(userID, id string) (*Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.tunnels[id]
	if !ok || t.UserID != userID {
		return nil, ErrNotFound
	}
	return t, nil
}

// lookup finds a tunnel by ID without an ownership check, for the proxy —
// which authenticates the request itself and needs the tunnel to know whose
// it is.
func (m *Manager) lookup(id string) (*Tunnel, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[id]
	return t, ok
}

// Close ends one tunnel.
func (m *Manager) Close(userID, id string) error {
	m.mu.Lock()
	t, ok := m.tunnels[id]
	if !ok || t.UserID != userID {
		m.mu.Unlock()
		return ErrNotFound
	}
	delete(m.tunnels, id)
	m.mu.Unlock()

	m.forget(t)
	return nil
}

// forget closes a tunnel and gives back its port.
func (m *Manager) forget(t *Tunnel) {
	t.close()

	if t.listener != nil {
		if _, portStr, err := net.SplitHostPort(t.listener.Addr().String()); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil {
				m.releasePort(port)
			}
		}
	}
}

// ListForUser returns a user's tunnels, newest first.
func (m *Manager) ListForUser(userID string, urlFor func(*Tunnel) string) []Info {
	m.mu.Lock()
	tunnels := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		if t.UserID == userID {
			tunnels = append(tunnels, t)
		}
	}
	m.mu.Unlock()

	out := make([]Info, 0, len(tunnels))
	for _, t := range tunnels {
		out = append(out, t.Info(urlFor))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt.After(out[j].OpenedAt) })
	return out
}

// Len reports how many tunnels are open, for tests and metrics.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tunnels)
}

// reap closes tunnels nothing has used.
func (m *Manager) reap() {
	defer close(m.done)

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case now := <-ticker.C:
			m.reapOnce(now)
		}
	}
}

// reapOnce closes idle tunnels and returns how many went.
func (m *Manager) reapOnce(now time.Time) int {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0
	}

	var stale []*Tunnel
	for id, t := range m.tunnels {
		// A tunnel with a connection in flight is in use whatever its clock
		// says — a long transfer through it is exactly the case that must not
		// be cut off.
		if t.active.Load() > 0 {
			continue
		}
		t.mu.Lock()
		idle := now.Sub(t.lastUsed) > m.cfg.IdleTimeout
		t.mu.Unlock()

		if idle {
			stale = append(stale, t)
			delete(m.tunnels, id)
		}
	}
	m.mu.Unlock()

	// Closed outside the lock: close waits for in-flight connections, and
	// holding the manager's mutex through that would stall every other
	// tunnel operation.
	for _, t := range stale {
		m.log.Info("closing an idle tunnel", "tunnel", t.ID, "kind", t.Kind)
		m.forget(t)
	}
	return len(stale)
}

// Shutdown closes every tunnel.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true

	tunnels := make([]*Tunnel, 0, len(m.tunnels))
	for id, t := range m.tunnels {
		tunnels = append(tunnels, t)
		delete(m.tunnels, id)
	}
	m.mu.Unlock()

	// The reaper is stopped and waited for before anything is closed, so it
	// cannot wake up mid-shutdown and race for the same tunnel.
	close(m.stop)
	<-m.done

	for _, t := range tunnels {
		m.forget(t)
	}
}
