package terminal

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
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

// Terminal is a live interactive session owned by the server.
//
// Its lifetime is deliberately independent of any WebSocket. Browsers attach
// and detach; the session keeps running.
type Terminal struct {
	ID     string
	UserID string

	// SessionID names the saved connection this came from, when it came from
	// one. Empty for an ad-hoc connection.
	SessionID string

	Label string

	// Transport records what this session is running over — SSH, telnet or a
	// serial line — and how it was reached.
	Transport Transport

	Username  string
	CreatedAt time.Time

	// AgentKeys names the keys forwarded to this host, empty when none were.
	AgentKeys []string

	// AgentRefused is set when keys were offered and the host would not take
	// them. The terminal works; the keys are simply not there, and the user
	// has to be told now rather than discovering it when an authentication
	// fails somewhere else.
	AgentRefused bool

	// LogonSteps is how many login steps were queued for this session, for
	// the audit record. The count only — one of them holds a password.
	LogonSteps int

	// Recorded reports that this session's output is being written to disk,
	// and RecordForced that it was the operator's decision rather than the
	// user's. Both reach the browser: somebody whose work is being recorded
	// should learn it from the terminal rather than from a settings page they
	// never open.
	Recorded     bool
	RecordForced bool

	// Triggers is how many rules are watching, for the record.
	Triggers int

	// Highlights are the colouring rules the browser draws, sent to it when
	// it attaches. Held on the terminal rather than handed to the bridge, so
	// a browser that reconnects after a dropped socket gets them back with
	// the scrollback instead of losing its colours until the next reload.
	Highlights []Highlight

	recording *TranscriptHolder

	shell Shell
	log   *slog.Logger

	// release gives back whatever the shell borrowed: a pool lease for SSH,
	// the exclusive claim on a device for serial, nothing for telnet. Called
	// once, after the shell is closed.
	release func()

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

	// draining refuses new sessions while an upgrade waits for the old ones.
	draining atomic.Bool
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
			"terminal", t.ID, "user", t.UserID, "host", t.Transport.Host,
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

	// AgentRefused reports a host that declined a forwarded agent.
	AgentRefused bool

	// Transport says what this session runs over and how it was reached.
	Transport Transport

	// LogonSteps is how many login steps were queued for this session.
	//
	// The count and never the content: one of those steps carries a
	// password, and an audit log is exactly the wrong place for it to end up.
	LogonSteps int

	// Recorded reports that this session's output is being written to disk,
	// Triggers is how many rules are watching this session.
	Triggers int

	// Highlights are the rules the browser draws rather than the server.
	Highlights []Highlight

	// Recording is the slot the transcript occupies, present whether or not
	// anything is recording right now, so recording can start later.
	Recording *TranscriptHolder

	// Recorded and RecordForced describe that recording to the interface.
	Recorded     bool
	RecordForced bool
}

// TranscriptPath is where this session is being written, or empty.
func (t *Terminal) TranscriptPath() string {
	if t.recording == nil {
		return ""
	}
	current := t.recording.Current()
	if current == nil {
		return ""
	}
	return current.Path()
}

// StartRecording installs an open transcript on a running session.
func (t *Terminal) StartRecording(transcript *Transcript) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return fmt.Errorf("terminal: the session has ended")
	}
	if t.recording == nil {
		return fmt.Errorf("terminal: this session cannot be recorded")
	}
	if t.recording.Current() != nil {
		return fmt.Errorf("terminal: this session is already being recorded")
	}
	t.recording.Swap(transcript)
	t.Recorded = true
	return nil
}

// StopRecording closes the transcript and leaves the session running.
//
// Refused when the recording is the operator's policy rather than the user's
// choice: the person being recorded does not get to turn the camera off.
func (t *Terminal) StopRecording() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.RecordForced {
		return fmt.Errorf("terminal: recording is required by this server's policy")
	}
	if t.recording == nil || t.recording.Current() == nil {
		return nil
	}
	old := t.recording.Swap(nil)
	t.Recorded = false
	if old != nil {
		_ = old.Close(time.Now())
	}
	return nil
}

// Open registers a shell somebody else opened and starts pumping it.
//
// The Manager takes ownership: closing the terminal closes the shell and then
// calls release, which for SSH gives back a pool lease — closing the
// underlying connection only if nothing else, a file browser or a second
// terminal, still holds one — and for a serial line gives back the exclusive
// claim on the device.
//
// The shell arrives already open rather than being dialled here, because the
// three protocols have nothing in common at that point: one negotiates a pty
// on a multiplexed connection, one negotiates telnet options on a bare
// socket, and one sets termios on a file descriptor. What they have in common
// starts once bytes are flowing, which is exactly where this begins.
func (m *Manager) Open(shell Shell, release func(), p OpenParams) (*Terminal, error) {
	cols, rows := p.Cols, p.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	if release == nil {
		release = func() {}
	}

	t := &Terminal{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    p.UserID,
		SessionID: p.SessionID,
		Label:     p.Label,
		Transport: p.Transport,
		Username:  p.Username,
		CreatedAt: time.Now().UTC(),

		AgentKeys:    p.AgentKeys,
		AgentRefused: p.AgentRefused,
		LogonSteps:   p.LogonSteps,
		Triggers:     p.Triggers,
		Highlights:   p.Highlights,
		Recorded:     p.Recorded,
		RecordForced: p.RecordForced,
		recording:    p.Recording,

		shell:   shell,
		release: release,
		log:     m.log,
		replay:  newRingBuffer(ReplayBytes),
		cols:    cols,
		rows:    rows,
		done:    make(chan struct{}),
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

			// The send happens under the lock, not after it.
			//
			// Reading the channel out and sending once the mutex is released
			// looks harmless and is not: Detach and close both close this
			// channel while holding the lock, so a browser going away between
			// the read and the send is a send on a closed channel — which is
			// a panic, not an error, and takes the process with it. The
			// window is microseconds wide, which is why it survived three
			// phases and only ever appeared under -race.
			//
			// Holding the lock across the send is safe precisely because the
			// send cannot block: the default arm below means this never
			// waits, so the mutex is held for a copy and no longer.
			t.mu.Lock()
			t.replay.Write(chunk)
			if t.attached != nil {
				select {
				case t.attached <- chunk:
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
			t.mu.Unlock()
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

	// Then give back whatever it borrowed. For SSH that is a pool lease
	// rather than the connection itself: it may still be carrying a file
	// browser or another terminal on the same host, and ending one shell must
	// not take those with it.
	t.release()
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
	ID string `json:"id"`
	// UserID is filled for the administrator's all-users view and omitted
	// from a user's own listing, where it would only repeat the obvious.
	UserID    string `json:"user_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Label     string `json:"label"`

	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`

	// Device is the serial port's path, empty for everything else.
	Device string `json:"device,omitempty"`

	// Encrypted is false for telnet and for a raw serial-over-network link.
	// Carried so the interface can mark the tab rather than leaving somebody
	// to remember which of nine tabs is sending a password in the clear.
	Encrypted bool `json:"encrypted"`

	Username  string    `json:"username,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Attached  bool      `json:"attached"`
	Closed    bool      `json:"closed"`

	// Recorded says this session's output is being written to disk, and
	// Forced that the operator required it rather than the user choosing it.
	Recorded     bool `json:"recorded"`
	RecordForced bool `json:"record_forced,omitempty"`
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
			ID:           t.ID,
			SessionID:    t.SessionID,
			Label:        t.Label,
			Protocol:     string(t.Transport.Protocol),
			Host:         t.Transport.Host,
			Port:         t.Transport.Port,
			Device:       t.Transport.Device,
			Encrypted:    t.Transport.Encrypted(),
			Recorded:     t.Recorded,
			RecordForced: t.RecordForced,
			Username:     t.Username,
			CreatedAt:    t.CreatedAt,
			Attached:     t.attached != nil,
			Closed:       t.closed,
		}
		t.mu.Unlock()
		out = append(out, info)
	}

	// Oldest first, because the map this came out of has no order at all and
	// a list that rearranges itself between refreshes is a list nobody can
	// use. Ties broken by identifier, which is time-ordered, so two terminals
	// opened in the same instant still come out the same way twice.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// SetDraining flips maintenance mode: new sessions are refused, existing
// ones run on, and reattachment keeps working — a browser reload during a
// drain must not orphan someone's work.
func (m *Manager) SetDraining(on bool) { m.draining.Store(on) }

// Draining reports whether the server is refusing new sessions.
func (m *Manager) Draining() bool { return m.draining.Load() }

// OpenCount is how many terminals are still running, for the drain watcher.
func (m *Manager) OpenCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, t := range m.terminals {
		t.mu.Lock()
		if !t.closed {
			n++
		}
		t.mu.Unlock()
	}
	return n
}

// ListAll returns every live terminal, for the administrator's view.
//
// The same shape ListForUser returns, unfiltered. Authorisation is the
// caller's business — this package does not know who is asking.
func (m *Manager) ListAll() []Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Info, 0, len(m.terminals))
	for _, t := range m.terminals {
		t.mu.Lock()
		out = append(out, Info{
			ID:           t.ID,
			UserID:       t.UserID,
			SessionID:    t.SessionID,
			Label:        t.Label,
			Protocol:     string(t.Transport.Protocol),
			Host:         t.Transport.Host,
			Port:         t.Transport.Port,
			Device:       t.Transport.Device,
			Encrypted:    t.Transport.Encrypted(),
			Recorded:     t.Recorded,
			RecordForced: t.RecordForced,
			Username:     t.Username,
			CreatedAt:    t.CreatedAt,
			Attached:     t.attached != nil,
			Closed:       t.closed,
		})
		t.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
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
