package terminal

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
	"github.com/mrbuttshooter/securecrt/internal/remote"
)

// Errors returned by this package.
var (
	ErrTerminalNotFound = errors.New("terminal: no such terminal")
	ErrNotOwner         = errors.New("terminal: that terminal belongs to someone else")
	ErrTerminalClosed   = errors.New("terminal: the session has ended")
)

// ReplayBytes is how much recent output is kept for a reattaching browser.
//
// 256 KiB is roughly a few hundred lines of dense output — enough to restore
// context after a reconnect without letting an idle terminal that once printed
// a large file hold megabytes indefinitely. The buffer keeps the most recent
// bytes, since that is what the user was looking at.
const ReplayBytes = 256 * 1024

// DetachedGrace is how long a terminal survives with no browser attached.
//
// Long enough to cover a laptop lid, a lift, or a train tunnel; short enough
// that a forgotten tab does not hold an SSH session to production open for a
// day. A terminal the user returns to inside this window is exactly as they
// left it, including whatever was mid-edit.
const DetachedGrace = 15 * time.Minute

// Terminal is a live SSH shell owned by the server.
//
// Its lifetime is deliberately independent of any WebSocket. Browsers attach
// and detach; the shell keeps running.
type Terminal struct {
	ID     string
	UserID string

	// SessionID names the saved connection this came from, when it came from
	// one. Empty for an ad-hoc connection.
	SessionID string

	Label     string
	Host      string
	Port      int
	Username  string
	CreatedAt time.Time

	// AgentKeys names the keys forwarded to this host, empty when none were.
	AgentKeys []string

	// AgentRefused is set when keys were offered and the host would not take
	// them. The terminal works; the keys are simply not there, and the user
	// has to be told now rather than discovering it when an authentication
	// fails somewhere else.
	AgentRefused bool

	lease *remote.Lease
	shell *sshx.Session
	log   *slog.Logger

	mu       sync.Mutex
	replay   *ringBuffer
	attached chan []byte // nil when no browser is attached
	cols     int
	rows     int
	closed   bool
	closeErr error
	exitCode *int

	// detachedAt is when the last browser left, used to reap abandoned
	// terminals.
	detachedAt time.Time

	// attachments counts how many browsers have taken this terminal over,
	// so the second and later ones can be told apart from the first.
	attachments int

	done chan struct{}
}

// ringBuffer keeps the most recent bytes written to it.
//
// A plain slice that is truncated from the front would copy on every write.
// This overwrites in place, so a terminal producing continuous output costs
// nothing extra.
type ringBuffer struct {
	buf    []byte
	size   int
	start  int
	length int
}

func newRingBuffer(size int) *ringBuffer {
	return &ringBuffer{buf: make([]byte, size), size: size}
}

func (r *ringBuffer) Write(p []byte) {
	// Only the last size bytes can survive, so a huge write is trimmed first.
	if len(p) >= r.size {
		copy(r.buf, p[len(p)-r.size:])
		r.start, r.length = 0, r.size
		return
	}

	for _, b := range p {
		idx := (r.start + r.length) % r.size
		r.buf[idx] = b
		if r.length < r.size {
			r.length++
		} else {
			r.start = (r.start + 1) % r.size
		}
	}
}

// Bytes returns the contents oldest-first.
func (r *ringBuffer) Bytes() []byte {
	out := make([]byte, r.length)
	for i := 0; i < r.length; i++ {
		out[i] = r.buf[(r.start+i)%r.size]
	}
	return out
}

// Manager owns every live terminal.
type Manager struct {
	log *slog.Logger

	mu        sync.RWMutex
	terminals map[string]*Terminal

	stopOnce sync.Once
	stop     chan struct{}
}

// NewManager builds a Manager and starts reaping abandoned terminals.
func NewManager(log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{
		log:       log,
		terminals: make(map[string]*Terminal),
		stop:      make(chan struct{}),
	}
	go m.reap()
	return m
}

// reap closes terminals nobody has come back to.
func (m *Manager) reap() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.reapOnce(time.Now())
		}
	}
}

func (m *Manager) reapOnce(now time.Time) int {
	m.mu.Lock()
	var abandoned []*Terminal
	for id, t := range m.terminals {
		t.mu.Lock()
		detached := t.attached == nil && !t.detachedAt.IsZero()
		expired := detached && now.Sub(t.detachedAt) > DetachedGrace
		t.mu.Unlock()

		if expired {
			abandoned = append(abandoned, t)
			delete(m.terminals, id)
		}
	}
	m.mu.Unlock()

	for _, t := range abandoned {
		m.log.Info("closing abandoned terminal",
			"terminal", t.ID, "user", t.UserID, "host", t.Host,
			"detached_for", now.Sub(t.detachedAt).Round(time.Second))
		t.close(errors.New("terminal: abandoned"))
	}
	return len(abandoned)
}

// Close ends every terminal. Called during shutdown.
func (m *Manager) Close() {
	m.stopOnce.Do(func() { close(m.stop) })

	m.mu.Lock()
	all := make([]*Terminal, 0, len(m.terminals))
	for id, t := range m.terminals {
		all = append(all, t)
		delete(m.terminals, id)
	}
	m.mu.Unlock()

	for _, t := range all {
		t.close(errors.New("terminal: server shutting down"))
	}
}

// OpenParams describes a terminal to open.
type OpenParams struct {
	UserID    string
	SessionID string
	Label     string
	Username  string
	Cols      int
	Rows      int

	// AgentKeys names the keys this connection forwards, for the record.
	AgentKeys []string
}

// Open starts a shell on a leased SSH connection and registers it.
//
// The Manager takes ownership of the lease: closing the terminal releases it,
// which closes the connection only if nothing else — a file browser, a second
// terminal — still holds one.
func (m *Manager) Open(lease *remote.Lease, p OpenParams) (*Terminal, error) {
	cols, rows := p.Cols, p.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	client := lease.Client()

	shell, err := client.Shell(sshx.PTYConfig{Cols: cols, Rows: rows})
	if err != nil {
		// The lease goes back rather than the connection being closed: another
		// holder may be using it perfectly happily.
		lease.Release()
		return nil, err
	}

	target := client.Target()
	t := &Terminal{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    p.UserID,
		SessionID: p.SessionID,
		Label:     p.Label,
		Username:  p.Username,
		Host:      target.Hostname,
		Port:      target.Port,
		CreatedAt: time.Now().UTC(),

		AgentKeys:    p.AgentKeys,
		AgentRefused: shell.AgentRefused() != nil,

		lease:  lease,
		shell:  shell,
		log:    m.log,
		replay: newRingBuffer(ReplayBytes),
		cols:   cols,
		rows:   rows,
		done:   make(chan struct{}),
	}

	m.mu.Lock()
	m.terminals[t.ID] = t
	m.mu.Unlock()

	go t.pump()
	return t, nil
}

// pump reads from the shell forever, feeding the replay buffer and whichever
// browser is attached.
//
// It runs whether or not anybody is watching. That is what makes a terminal
// survive a dropped connection: output continues to be consumed and buffered,
// so a long-running command does not block on a full SSH window while the
// user's train is in a tunnel.
func (t *Terminal) pump() {
	defer close(t.done)

	buf := make([]byte, 32*1024)
	for {
		n, err := t.shell.Read(buf)

		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])

			t.mu.Lock()
			t.replay.Write(chunk)
			attached := t.attached
			t.mu.Unlock()

			if attached != nil {
				select {
				case attached <- chunk:
				default:
					// The browser is not keeping up. Dropping the frame is
					// better than blocking this loop, which would stall the
					// SSH connection and eventually the remote command: the
					// replay buffer still holds it, so a reattach recovers
					// the state even if this frame never lands.
					t.log.Debug("dropped a terminal frame; the browser is not keeping up",
						"terminal", t.ID, "bytes", n)
				}
			}
		}

		if err != nil {
			var exit *int
			if waitErr := t.shell.Wait(); waitErr != nil {
				if code, ok := sshx.ExitStatus(waitErr); ok {
					exit = &code
				}
			}

			t.mu.Lock()
			t.exitCode = exit
			t.mu.Unlock()

			if errors.Is(err, io.EOF) {
				t.close(nil)
			} else {
				t.close(err)
			}
			return
		}
	}
}

// Attach connects a browser to this terminal.
//
// Returns the replay buffer and a channel of subsequent output. Only one
// browser may be attached: a second attach displaces the first, which is what
// happens when someone reopens a tab after a network drop and the old
// connection has not yet timed out.
func (t *Terminal) Attach() (Attachment, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return Attachment{}, ErrTerminalClosed
	}

	if t.attached != nil {
		// Closing the previous channel ends the old writer's loop cleanly.
		close(t.attached)
	}

	ch := make(chan []byte, 256)
	t.attached = ch
	t.detachedAt = time.Time{}
	t.attachments++

	return Attachment{
		Replay:     t.replay.Bytes(),
		Output:     ch,
		Reattached: t.attachments > 1,
	}, nil
}

// Attachment is what a browser gets when it takes over a terminal.
type Attachment struct {
	// Replay is the recent scrollback, to be written before live output so
	// the terminal reads in the order it was printed.
	Replay []byte

	// Output carries live bytes from the remote shell.
	Output <-chan []byte

	// Reattached distinguishes returning to a running session from starting
	// one. The interface says so, because "reconnected" and "connected" mean
	// very different things to someone who just watched their screen freeze.
	Reattached bool
}

// Detach disconnects the current browser, leaving the shell running.
func (t *Terminal) Detach() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.attached != nil {
		close(t.attached)
		t.attached = nil
	}
	t.detachedAt = time.Now()
}

// Write sends keystrokes to the remote shell.
func (t *Terminal) Write(p []byte) error {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()

	if closed {
		return ErrTerminalClosed
	}
	if _, err := t.shell.Write(p); err != nil {
		return fmt.Errorf("terminal: write: %w", err)
	}
	return nil
}

// Resize tells the remote side the terminal's new size.
func (t *Terminal) Resize(cols, rows int) error {
	t.mu.Lock()
	closed := t.closed
	if !closed {
		t.cols, t.rows = cols, rows
	}
	t.mu.Unlock()

	if closed {
		return ErrTerminalClosed
	}
	return t.shell.Resize(cols, rows)
}

// Size reports the current terminal dimensions.
func (t *Terminal) Size() (cols, rows int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cols, t.rows
}

// Done is closed when the terminal ends.
func (t *Terminal) Done() <-chan struct{} { return t.done }

// ExitCode reports the remote command's exit status, if it gave one.
func (t *Terminal) ExitCode() *int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.exitCode
}

// Err reports why the terminal ended.
func (t *Terminal) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeErr
}

// Closed reports whether the terminal has ended.
func (t *Terminal) Closed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// close ends the terminal exactly once.
func (t *Terminal) close(cause error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.closeErr = cause
	if t.attached != nil {
		close(t.attached)
		t.attached = nil
	}
	t.mu.Unlock()

	_ = t.shell.Close()

	// Release, not close. The SSH connection may still be carrying a file
	// browser or another terminal on the same host, and ending a shell must
	// not take those with it.
	t.lease.Release()
}

// Get returns a terminal, checking ownership.
func (m *Manager) Get(userID, terminalID string) (*Terminal, error) {
	m.mu.RLock()
	t, ok := m.terminals[terminalID]
	m.mu.RUnlock()

	if !ok {
		return nil, ErrTerminalNotFound
	}
	if t.UserID != userID {
		// Not-found rather than forbidden: confirming a terminal exists but
		// belongs to someone else discloses that they are connected to
		// something.
		return nil, ErrTerminalNotFound
	}
	return t, nil
}

// CloseTerminal ends a terminal on request.
func (m *Manager) CloseTerminal(userID, terminalID string) error {
	t, err := m.Get(userID, terminalID)
	if err != nil {
		return err
	}

	m.mu.Lock()
	delete(m.terminals, terminalID)
	m.mu.Unlock()

	t.close(errors.New("terminal: closed by the user"))
	return nil
}

// Info summarises a terminal for listing.
type Info struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id,omitempty"`
	Label     string    `json:"label"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Username  string    `json:"username,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Attached  bool      `json:"attached"`
	Closed    bool      `json:"closed"`
}

// ListForUser returns a user's live terminals.
//
// This is what lets someone open a fresh browser and find the sessions they
// left running, which is the visible payoff of server-side survival.
func (m *Manager) ListForUser(userID string) []Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Info, 0)
	for _, t := range m.terminals {
		if t.UserID != userID {
			continue
		}
		t.mu.Lock()
		info := Info{
			ID:        t.ID,
			SessionID: t.SessionID,
			Label:     t.Label,
			Host:      t.Host,
			Port:      t.Port,
			Username:  t.Username,
			CreatedAt: t.CreatedAt,
			Attached:  t.attached != nil,
			Closed:    t.closed,
		}
		t.mu.Unlock()
		out = append(out, info)
	}
	return out
}

// CountForUser reports how many terminals a user has open.
func (m *Manager) CountForUser(userID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	n := 0
	for _, t := range m.terminals {
		if t.UserID == userID {
			n++
		}
	}
	return n
}
