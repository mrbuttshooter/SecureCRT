// Package files browses and moves files on managed hosts.
//
// It sits on internal/remote, so a file session rides whatever SSH connection
// is already open to a host — the terminal tab beside it, most often — and
// dials only when there is none.
//
// # What lives where
//
// Nothing is spooled to the bkd server's disk. A download streams from the
// host through the process to the browser; an upload streams the other way; a
// host-to-host copy streams through without ever landing. That is deliberate:
// a server that never writes a customer's files anywhere is a server whose
// disk cannot leak them, and it removes an entire class of question about
// retention, encryption at rest and cleanup.
package files

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/proto/sftpx"
	"github.com/mrbuttshooter/securecrt/internal/remote"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Errors callers distinguish.
var (
	// ErrSessionNotFound means there is no open file session for that host.
	ErrSessionNotFound = errors.New("files: no file session for that connection")
)

// IdleTimeout is how long an unused file session is kept.
//
// Long enough that switching to a terminal tab and back does not cost a
// reconnection, short enough that a browser left open overnight is not still
// holding an SFTP channel on a device in the morning. The SSH connection
// underneath survives independently while a terminal holds it.
const IdleTimeout = 15 * time.Minute

// Session is an open SFTP session on one host.
type Session struct {
	// SessionID is the saved connection this browses. It is also the handle:
	// the interface asks for "the files on connection X" rather than tracking
	// an opaque session identifier of its own.
	SessionID string
	UserID    string

	Label    string
	Host     string
	Port     int
	Username string

	// Home is where the session starts, resolved from the server rather than
	// assumed — on network equipment it is frequently neither /home/<user>
	// nor /.
	Home string

	OpenedAt time.Time

	client *sftpx.Client
	conn   *remote.Connection

	mu       sync.Mutex
	lastUsed time.Time
	closed   bool
}

// Client is the SFTP session. Safe for concurrent use.
func (s *Session) Client() *sftpx.Client {
	s.mu.Lock()
	s.lastUsed = time.Now()
	s.mu.Unlock()
	return s.client
}

// Info describes an open file session for the interface.
type Info struct {
	SessionID string    `json:"session_id"`
	Label     string    `json:"label"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Username  string    `json:"username,omitempty"`
	Home      string    `json:"home"`
	OpenedAt  time.Time `json:"opened_at"`
}

func (s *Session) info() Info {
	return Info{
		SessionID: s.SessionID,
		Label:     s.Label,
		Host:      s.Host,
		Port:      s.Port,
		Username:  s.Username,
		Home:      s.Home,
		OpenedAt:  s.OpenedAt,
	}
}

// Manager holds open file sessions.
type Manager struct {
	dialer *remote.Dialer
	log    *slog.Logger

	mu       sync.Mutex
	sessions map[key]*Session
	closed   bool

	stop chan struct{}
	done chan struct{}
}

type key struct {
	userID    string
	sessionID string
}

// NewManager builds a Manager and starts reaping idle sessions.
func NewManager(dialer *remote.Dialer, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}

	m := &Manager{
		dialer:   dialer,
		log:      log,
		sessions: map[key]*Session{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go m.reap()
	return m
}

// OpenParams describes a file session to open.
type OpenParams struct {
	UserID    string
	SessionID string

	// VaultKey decrypts the credential, when a dial is needed. Not required
	// when the connection is already open — which is the common case, and
	// the reason a locked vault does not stop someone browsing a host they
	// already have a terminal on.
	VaultKey vault.Key

	// Prompter is asked about unrecognised host keys. Nil refuses them.
	Prompter remote.HostKeyPrompter

	// Progress reports what is happening while a slow host is dialled.
	Progress func(status string)
}

// Open returns a file session for a saved connection, starting one if needed.
//
// Opening the same host twice returns the same session: SFTP tolerates
// concurrent use, and a second subsystem channel would be pure cost.
func (m *Manager) Open(ctx context.Context, p OpenParams) (*Session, error) {
	k := key{userID: p.UserID, sessionID: p.SessionID}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("files: the manager is shutting down")
	}
	if existing, ok := m.sessions[k]; ok {
		existing.mu.Lock()
		alive := !existing.closed
		if alive {
			existing.lastUsed = time.Now()
		}
		existing.mu.Unlock()

		if alive {
			m.mu.Unlock()
			return existing, nil
		}
		delete(m.sessions, k)
	}
	m.mu.Unlock()

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

	client, err := sftpx.Open(conn.Client())
	if err != nil {
		conn.Release()
		return nil, &remote.Error{
			Code: remote.CodeInternal,
			Message: "This host refused an SFTP session. It may not offer the SFTP " +
				"subsystem — some network devices only support SCP.",
			Err: err,
		}
	}

	// Read the host's own user and group names before the first listing, so
	// owners render as names rather than numbers from the outset.
	client.LoadOwnerNames(ctx)

	home, err := client.Home()
	if err != nil {
		// Not fatal: a server that will not resolve "." can still be browsed
		// from an absolute path the user types.
		m.log.Debug("resolving the remote home directory", "error", err)
		home = "/"
	}

	session := &Session{
		SessionID: p.SessionID,
		UserID:    p.UserID,
		Label:     conn.Resolved.Name,
		Host:      conn.Resolved.Hostname,
		Port:      conn.Resolved.EffectivePort,
		Username:  conn.Username,
		Home:      home,
		OpenedAt:  time.Now().UTC(),
		client:    client,
		conn:      conn,
		lastUsed:  time.Now(),
	}

	m.mu.Lock()
	// Another caller may have opened one while this dial was in flight. Theirs
	// wins, and this one is discarded rather than replacing a session other
	// requests may already be using.
	if existing, ok := m.sessions[k]; ok {
		m.mu.Unlock()
		session.close()
		return existing, nil
	}
	m.sessions[k] = session
	m.mu.Unlock()

	return session, nil
}

// Get returns an open session without opening one.
func (m *Manager) Get(userID, sessionID string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[key{userID: userID, sessionID: sessionID}]
	if !ok {
		return nil, ErrSessionNotFound
	}

	session.mu.Lock()
	closed := session.closed
	if !closed {
		session.lastUsed = time.Now()
	}
	session.mu.Unlock()

	if closed {
		return nil, ErrSessionNotFound
	}
	return session, nil
}

// Close ends a file session. The SSH connection survives if anything else
// holds it.
func (m *Manager) Close(userID, sessionID string) error {
	k := key{userID: userID, sessionID: sessionID}

	m.mu.Lock()
	session, ok := m.sessions[k]
	if ok {
		delete(m.sessions, k)
	}
	m.mu.Unlock()

	if !ok {
		return ErrSessionNotFound
	}
	session.close()
	return nil
}

// ListForUser returns a user's open file sessions.
func (m *Manager) ListForUser(userID string) []Info {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]Info, 0)
	for k, session := range m.sessions {
		if k.userID != userID {
			continue
		}
		out = append(out, session.info())
	}
	return out
}

// close ends the SFTP session and gives back the connection.
func (s *Session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	_ = s.client.Close()
	s.conn.Release()
}

// reap closes sessions nobody has used.
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

func (m *Manager) reapOnce(now time.Time) int {
	m.mu.Lock()

	var stale []*Session
	for k, session := range m.sessions {
		session.mu.Lock()
		idle := now.Sub(session.lastUsed)
		session.mu.Unlock()

		if idle > IdleTimeout {
			stale = append(stale, session)
			delete(m.sessions, k)
		}
	}
	m.mu.Unlock()

	for _, session := range stale {
		m.log.Debug("closing an idle file session",
			"user", session.UserID, "host", session.Host)
		session.close()
	}
	return len(stale)
}

// Shutdown closes every session.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true

	sessions := make([]*Session, 0, len(m.sessions))
	for k, session := range m.sessions {
		sessions = append(sessions, session)
		delete(m.sessions, k)
	}
	m.mu.Unlock()

	close(m.stop)
	<-m.done

	for _, session := range sessions {
		session.close()
	}
}
