package terminal

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Writing down what scrolled past.
//
// The setting for this has existed since Phase 2 and nothing has ever read
// it: sessions.Settings.LogSession, policy.record_all_sessions and
// paths.session_log_dir were all in place, the directory was created at
// startup with mode 0700, and no byte was ever written to it. This is the
// code that makes those true.
//
// # What is recorded, and what is not
//
// The output stream only — what appeared on the screen. Not keystrokes.
//
// That is not laziness, it is the safer of the two and by some distance. A
// password typed at a login prompt is not echoed, by the device's own choice:
// telnet servers send WILL ECHO to suppress it and SSH servers simply do not
// print it. So a transcript of output contains the session and not the
// credential, automatically, without this code having to identify a password
// in order to avoid writing it — which is the kind of thing that works until
// the day some device asks for one in a way nobody anticipated.
//
// Recording input as well would capture every password anybody typed, in the
// clear, in a file kept for months. The value of that over an output
// transcript is close to nil.
//
// # Why the size cap is not optional
//
// A transcript is written by whatever the far end decides to print. One
// `cat /dev/urandom` on one console fills the disk of a server that also
// holds the database and the master key, and the failure would land on
// everybody. So each transcript stops at a limit, says so in the file, and
// leaves the session running: ending somebody's connection to a production
// device because a log file got long is the wrong trade.

const (
	// MaxTranscriptBytes bounds one transcript.
	//
	// 64 MiB is a very long day of interactive work — the busiest real
	// session anybody has is a few megabytes — and is small enough that a
	// hundred of them cannot fill a modest disk.
	MaxTranscriptBytes = 64 << 20

	// transcriptFileMode is 0600 because a transcript holds whatever scrolled
	// past on a production console, which is frequently as sensitive as the
	// credentials themselves.
	transcriptFileMode = 0o600
)

// Transcript records a session's output to a file.
type Transcript struct {
	path string

	mu      sync.Mutex
	file    *os.File
	written int64
	full    bool
	failed  error
}

// TranscriptConfig describes where and what to record.
type TranscriptConfig struct {
	// Dir is the directory transcripts are written under. Empty disables
	// recording entirely, whatever anything else says.
	Dir string

	// UserID and Label identify the session in the filename.
	UserID string
	Label  string

	// Forced marks a transcript the operator required rather than the user
	// chose. It is written into the header, because somebody whose session is
	// being recorded by policy should be able to find that out from the
	// record itself and not only from a settings page.
	Forced bool
}

// NewTranscript opens a transcript file.
//
// The name carries the user, the connection and the time, in that order, so
// an operator answering "what did Priya do on core-sw-01 last Tuesday" can
// find it with a glob rather than a search.
func NewTranscript(cfg TranscriptConfig, now time.Time) (*Transcript, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("terminal: no session log directory is configured")
	}

	dir := filepath.Join(cfg.Dir, safeName(cfg.UserID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("terminal: creating the transcript directory: %w", err)
	}

	// Opened through a root scoped to that directory, so containment is
	// enforced by the kernel rather than by safeName being correct.
	//
	// safeName is still there and still tested — a filename with a slash in
	// it is a bug whether or not anything catches it — but the label comes
	// from a user, and "my sanitiser handles every case" is a claim that has
	// gone wrong for everybody who has ever made it. A root refuses to leave
	// the directory even if the name that reaches it is one safeName should
	// have rejected and did not.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("terminal: opening the transcript directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	name := fmt.Sprintf("%s-%s.log",
		now.UTC().Format("20060102-150405"), safeName(cfg.Label))

	// O_EXCL rather than O_TRUNC: two sessions opened in the same second
	// would otherwise have one silently overwrite the other's record, which
	// is the one failure a transcript must not have.
	file, err := root.OpenFile(name,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, transcriptFileMode)
	if err != nil {
		// A collision means a second session in the same second. Falling back
		// to a unique suffix beats refusing to record.
		name = fmt.Sprintf("%s-%s-%d.log",
			now.UTC().Format("20060102-150405"), safeName(cfg.Label), os.Getpid())
		file, err = root.OpenFile(name,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL, transcriptFileMode)
		if err != nil {
			return nil, fmt.Errorf("terminal: opening the transcript: %w", err)
		}
	}
	path := filepath.Join(dir, name)

	t := &Transcript{path: path, file: file}

	header := fmt.Sprintf(
		"# bkd session transcript\n"+
			"# connection: %s\n"+
			"# started:    %s\n"+
			"# recording:  %s\n"+
			"# contents:   output only — keystrokes are not recorded, so a "+
			"password typed at a prompt that does not echo is not here\n\n",
		cfg.Label, now.UTC().Format(time.RFC3339), recordingReason(cfg.Forced))
	t.write([]byte(header))

	return t, nil
}

// recordingReason says whose decision this was.
func recordingReason(forced bool) string {
	if forced {
		return "required by this server's policy (record_all_sessions)"
	}
	return "enabled on this connection"
}

// Path is where the transcript is being written.
func (t *Transcript) Path() string { return t.path }

// write appends, stopping at the cap.
func (t *Transcript) write(b []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.file == nil || t.full || t.failed != nil {
		return
	}

	remaining := MaxTranscriptBytes - t.written
	if remaining <= 0 {
		t.markFull()
		return
	}

	chunk := b
	if int64(len(chunk)) > remaining {
		chunk = chunk[:remaining]
	}

	n, err := t.file.Write(chunk)
	t.written += int64(n)
	if err != nil {
		t.failed = err
		_ = t.file.Close()
		t.file = nil
		return
	}

	if t.written >= MaxTranscriptBytes {
		t.markFull()
	}
}

// markFull closes the transcript with a note saying why it stops.
//
// Called with the mutex held. The note matters: a transcript that simply ends
// is indistinguishable from one where the session ended, and somebody reading
// it later would draw the wrong conclusion about when work stopped.
func (t *Transcript) markFull() {
	if t.full || t.file == nil {
		return
	}
	t.full = true

	_, _ = t.file.WriteString(fmt.Sprintf(
		"\n\n# transcript truncated at %d bytes; the session continued\n",
		MaxTranscriptBytes))
	_ = t.file.Close()
	t.file = nil
}

// Close finishes the transcript.
func (t *Transcript) Close(now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.file == nil {
		return t.failed
	}

	_, _ = t.file.WriteString(fmt.Sprintf(
		"\n\n# session ended %s\n", now.UTC().Format(time.RFC3339)))

	err := t.file.Close()
	t.file = nil
	return err
}

// Bytes reports how much has been written, for the record.
func (t *Transcript) Bytes() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.written
}

// Truncated reports whether the cap was reached.
func (t *Transcript) Truncated() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.full
}

// safeName makes a string safe to put in a filename.
//
// Connection names are user-supplied and can contain slashes, dots and a
// great deal worse; a name of "../../etc/cron.d/x" would otherwise choose
// where the file lands.
func safeName(in string) string {
	if in == "" {
		return "unnamed"
	}

	var b strings.Builder
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}

	out := b.String()
	// Bounded, because some filesystems stop at 255 bytes and a connection
	// named by a script can be longer than that.
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// recordingShell tees a session's output into a transcript.
//
// A wrapper for the same reason the logon sequence is one: everything the
// user sees passes through it, so the transcript is what was on the screen
// rather than an approximation assembled somewhere else. And it works while
// the browser is detached, which is exactly when a long operation is running
// and a record of it is most worth having.
type recordingShell struct {
	Shell
	recording *TranscriptHolder
}

// WithTranscript returns shell with its output recorded.
func WithTranscript(shell Shell, recording *TranscriptHolder) Shell {
	return &recordingShell{Shell: shell, recording: recording}
}

// TranscriptHolder is the slot a recording occupies while a session runs.
//
// The wrapper is always present and the transcript is what comes and goes:
// that is what lets File-menu-style "start logging now" exist at all, because
// the alternative — rewrapping a shell that is mid-Read from another
// goroutine — is not an alternative. One atomic load per Read is the price,
// which on a 32 KiB read is nothing.
type TranscriptHolder struct {
	p atomic.Pointer[Transcript]
}

// NewTranscriptHolder starts with the given transcript, which may be nil.
func NewTranscriptHolder(t *Transcript) *TranscriptHolder {
	h := &TranscriptHolder{}
	if t != nil {
		h.p.Store(t)
	}
	return h
}

// Current is the open recording, or nil.
func (h *TranscriptHolder) Current() *Transcript { return h.p.Load() }

// Swap installs a transcript (or nil to stop) and returns what was there.
func (h *TranscriptHolder) Swap(t *Transcript) *Transcript {
	return h.p.Swap(t)
}

func (r *recordingShell) Read(p []byte) (int, error) {
	n, err := r.Shell.Read(p)
	if n > 0 {
		if t := r.recording.Current(); t != nil {
			t.write(p[:n])
		}
	}
	return n, err
}

// Close ends the transcript with the session.
func (r *recordingShell) Close() error {
	err := r.Shell.Close()
	if t := r.recording.Current(); t != nil {
		_ = t.Close(time.Now())
	}
	return err
}

// TranscriptInfo describes one recorded file, for the interface.
type TranscriptInfo struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// ListTranscripts returns a user's transcripts, newest first.
//
// A missing directory is an empty list, not an error: it means this user has
// never recorded anything, which is the ordinary state of affairs.
func ListTranscripts(dir, userID string) ([]TranscriptInfo, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(filepath.Join(dir, safeName(userID)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("terminal: listing transcripts: %w", err)
	}
	out := make([]TranscriptInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, TranscriptInfo{
			Name: e.Name(), Size: info.Size(), Modified: info.ModTime().UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified.After(out[j].Modified) })
	return out, nil
}

// UserTranscript is one transcript with the directory (user) it belongs to.
type UserTranscript struct {
	UserDir string `json:"user_dir"`
	TranscriptInfo
}

// ListAllTranscripts walks every user's transcript directory, newest first —
// the administrator's answer to "what did anyone do last Tuesday". UserDir is
// the on-disk name, which is the user id; the caller maps it to an email.
func ListAllTranscripts(dir string) ([]UserTranscript, error) {
	if dir == "" {
		return nil, nil
	}
	users, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("terminal: listing transcript directories: %w", err)
	}
	var out []UserTranscript
	for _, u := range users {
		if !u.IsDir() {
			continue
		}
		list, err := ListTranscripts(dir, u.Name())
		if err != nil {
			continue
		}
		for _, t := range list {
			out = append(out, UserTranscript{UserDir: u.Name(), TranscriptInfo: t})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified.After(out[j].Modified) })
	return out, nil
}

// OpenTranscriptFile opens one of a user's transcripts for reading.
//
// The open goes through a root scoped to the user's own directory, the same
// containment the writer uses: whatever name arrives, the kernel refuses to
// leave the directory.
func OpenTranscriptFile(dir, userID, name string) (*os.File, error) {
	if dir == "" {
		return nil, os.ErrNotExist
	}
	root, err := os.OpenRoot(filepath.Join(dir, safeName(userID)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.Open(name)
}
