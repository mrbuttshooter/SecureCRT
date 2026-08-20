package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/proto/sftpx"
)

// Transfers that run on the server.
//
// Uploads and downloads deliberately do not: those are one HTTP request each,
// streaming straight through, and the browser reports their progress far
// better than a server-side queue re-reporting it second-hand. What genuinely
// needs a job here is work with no browser in the middle — copying a
// directory from one host to another, or deleting a tree — where something
// has to keep going and keep count while the user looks at another tab.

// Errors callers distinguish.
var (
	// ErrJobNotFound means the job is unknown, or belongs to someone else.
	ErrJobNotFound = errors.New("files: no such transfer")

	// ErrTooManyJobs means the user already has as many running as allowed.
	ErrTooManyJobs = errors.New("files: too many transfers are already running")
)

// MaxJobsPerUser bounds concurrent server-side transfers per user.
//
// Each one holds an SFTP channel on two hosts and a buffer. The limit is
// generous for deliberate work and low enough that a mis-click on a hundred
// directories cannot exhaust the process.
const MaxJobsPerUser = 8

// JobRetention is how long a finished job stays visible.
//
// Long enough for the interface to show what happened and for a user to come
// back from a meeting and read the failure; short enough that a busy day does
// not accumulate thousands.
const JobRetention = 30 * time.Minute

// copyBufferSize is the chunk size for host-to-host streaming.
//
// Larger than the SFTP packet size so each read fills several packets, which
// keeps the pipeline busy on a high-latency link without holding much memory.
const copyBufferSize = 256 * 1024

// JobKind says what a job is doing.
type JobKind string

const (
	// JobCopy streams a path from one host to another.
	JobCopy JobKind = "copy"

	// JobDelete removes a path and everything beneath it.
	JobDelete JobKind = "delete"
)

// JobState is where a job has got to.
type JobState string

const (
	JobRunning   JobState = "running"
	JobDone      JobState = "done"
	JobFailed    JobState = "failed"
	JobCancelled JobState = "cancelled"
)

// Job is one server-side transfer.
type Job struct {
	ID     string   `json:"id"`
	Kind   JobKind  `json:"kind"`
	State  JobState `json:"state"`
	UserID string   `json:"-"`

	// Source and Destination describe the endpoints in the interface's own
	// terms: which saved connection, and which path on it.
	SourceSession string `json:"source_session"`
	SourcePath    string `json:"source_path"`
	DestSession   string `json:"dest_session,omitempty"`
	DestPath      string `json:"dest_path,omitempty"`

	// Name is what to call this in a list: the basename being moved.
	Name string `json:"name"`

	// TotalBytes is the sum of the sizes discovered by walking the source.
	// Zero until the walk finishes, which for a large tree can take a moment
	// — the interface shows a count of files until then rather than a
	// progress bar that would be lying.
	TotalBytes int64 `json:"total_bytes"`
	DoneBytes  int64 `json:"done_bytes"`

	TotalFiles int `json:"total_files"`
	DoneFiles  int `json:"done_files"`

	// Current is the file being worked on, so a long transfer shows movement
	// rather than a frozen total.
	Current string `json:"current,omitempty"`

	// Error is set when State is failed. Written for a person to act on.
	Error string `json:"error,omitempty"`

	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// job is the mutable half, kept apart from the snapshot handed out.
type job struct {
	mu     sync.Mutex
	state  Job
	cancel context.CancelFunc
}

func (j *job) snapshot() Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state
}

func (j *job) update(f func(*Job)) {
	j.mu.Lock()
	f(&j.state)
	j.mu.Unlock()
}

// Transfers runs and tracks server-side jobs.
type Transfers struct {
	sessions *Manager
	log      *slog.Logger

	mu   sync.Mutex
	jobs map[string]*job
}

// NewTransfers builds a transfer runner.
func NewTransfers(sessions *Manager, log *slog.Logger) *Transfers {
	if log == nil {
		log = slog.Default()
	}
	return &Transfers{sessions: sessions, log: log, jobs: map[string]*job{}}
}

// CopyParams describes a host-to-host copy.
type CopyParams struct {
	UserID string

	SourceSession string
	SourcePath    string
	DestSession   string
	DestDirectory string

	// Overwrite permits replacing files that already exist at the
	// destination. Off by default: a copy that silently overwrites is how
	// somebody loses a configuration they meant to keep.
	Overwrite bool
}

// StartCopy begins copying a file or directory between two hosts.
//
// The bytes stream source → bkd → destination and are never written to disk
// here, so a large transfer costs a buffer rather than free space, and
// nothing is left behind to clean up or to leak.
func (t *Transfers) StartCopy(p CopyParams) (Job, error) {
	source, err := t.sessions.Get(p.UserID, p.SourceSession)
	if err != nil {
		return Job{}, err
	}
	dest, err := t.sessions.Get(p.UserID, p.DestSession)
	if err != nil {
		return Job{}, err
	}

	if err := t.checkQuota(p.UserID); err != nil {
		return Job{}, err
	}

	name := path.Base(p.SourcePath)
	ctx, cancel := context.WithCancel(context.Background())

	j := &job{
		cancel: cancel,
		state: Job{
			ID:            uuid.Must(uuid.NewV7()).String(),
			Kind:          JobCopy,
			State:         JobRunning,
			UserID:        p.UserID,
			SourceSession: p.SourceSession,
			SourcePath:    p.SourcePath,
			DestSession:   p.DestSession,
			DestPath:      path.Join(p.DestDirectory, name),
			Name:          name,
			StartedAt:     time.Now().UTC(),
		},
	}

	t.mu.Lock()
	t.jobs[j.state.ID] = j
	t.mu.Unlock()

	go func() {
		defer cancel()
		err := t.runCopy(ctx, j, source, dest, p)
		t.finish(j, err)
	}()

	return j.snapshot(), nil
}

// DeleteParams describes a recursive delete.
type DeleteParams struct {
	UserID    string
	SessionID string
	Path      string
}

// StartDelete removes a path and everything beneath it.
//
// A job rather than a request because deleting a deep tree over SFTP is one
// round trip per entry, which on a slow link takes long enough that an HTTP
// request would time out first.
func (t *Transfers) StartDelete(p DeleteParams) (Job, error) {
	session, err := t.sessions.Get(p.UserID, p.SessionID)
	if err != nil {
		return Job{}, err
	}
	if err := t.checkQuota(p.UserID); err != nil {
		return Job{}, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	j := &job{
		cancel: cancel,
		state: Job{
			ID:            uuid.Must(uuid.NewV7()).String(),
			Kind:          JobDelete,
			State:         JobRunning,
			UserID:        p.UserID,
			SourceSession: p.SessionID,
			SourcePath:    p.Path,
			Name:          path.Base(p.Path),
			StartedAt:     time.Now().UTC(),
		},
	}

	t.mu.Lock()
	t.jobs[j.state.ID] = j
	t.mu.Unlock()

	go func() {
		defer cancel()
		err := session.Client().RemoveAll(ctx, p.Path)
		t.finish(j, err)
	}()

	return j.snapshot(), nil
}

// checkQuota refuses when a user already has too many jobs running.
func (t *Transfers) checkQuota(userID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	running := 0
	for _, j := range t.jobs {
		snapshot := j.snapshot()
		if snapshot.UserID == userID && snapshot.State == JobRunning {
			running++
		}
	}
	if running >= MaxJobsPerUser {
		return ErrTooManyJobs
	}
	return nil
}

// finish records how a job ended.
func (t *Transfers) finish(j *job, err error) {
	now := time.Now().UTC()

	j.update(func(state *Job) {
		state.FinishedAt = &now
		state.Current = ""

		switch {
		case err == nil:
			state.State = JobDone
		case errors.Is(err, context.Canceled):
			state.State = JobCancelled
		default:
			state.State = JobFailed
			state.Error = userFacing(err)
		}
	})

	t.sweep()
}

// userFacing renders an error for someone who has to decide what to do next.
func userFacing(err error) string {
	switch {
	case errors.Is(err, sftpx.ErrPermission):
		return "Permission denied by the remote host."
	case errors.Is(err, sftpx.ErrNotFound):
		return "The path no longer exists."
	case errors.Is(err, sftpx.ErrExists):
		return "Something is already there. Choose to overwrite, or a different name."
	case errors.Is(err, sftpx.ErrNotSupported):
		return "The remote host does not support that operation."
	default:
		return err.Error()
	}
}

// runCopy walks the source and streams every file to the destination.
func (t *Transfers) runCopy(ctx context.Context, j *job, source, dest *Session, p CopyParams) error {
	src := source.Client()
	dst := dest.Client()

	info, err := src.Stat(ctx, p.SourcePath)
	if err != nil {
		return err
	}

	destRoot := path.Join(p.DestDirectory, path.Base(p.SourcePath))

	// Copying a host onto itself, into a directory inside what is being
	// copied, would walk into its own output and never finish.
	if p.SourceSession == p.DestSession && within(destRoot, p.SourcePath) {
		return fmt.Errorf("files: cannot copy %s into itself", p.SourcePath)
	}

	if !info.IsDir && !info.TargetIsDir {
		j.update(func(state *Job) {
			state.TotalFiles = 1
			state.TotalBytes = info.Size
		})
		return t.copyFile(ctx, j, src, dst, p.SourcePath, destRoot, info.Size, p.Overwrite)
	}

	// The walk happens first so the interface can show a real total rather
	// than a bar that grows its own maximum as it goes.
	files, err := walk(ctx, src, p.SourcePath)
	if err != nil {
		return err
	}

	var total int64
	for _, f := range files {
		total += f.Size
	}
	j.update(func(state *Job) {
		state.TotalFiles = len(files)
		state.TotalBytes = total
	})

	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return err
		}

		relative := f.Path[len(p.SourcePath):]
		target := path.Join(destRoot, relative)

		if f.IsDir {
			if err := dst.Mkdir(target); err != nil {
				return err
			}
			continue
		}

		if err := dst.Mkdir(path.Dir(target)); err != nil {
			return err
		}
		if err := t.copyFile(ctx, j, src, dst, f.Path, target, f.Size, p.Overwrite); err != nil {
			return err
		}
	}

	return nil
}

// copyFile streams one file, counting bytes as they pass.
func (t *Transfers) copyFile(
	ctx context.Context,
	j *job,
	src, dst *sftpx.Client,
	from, to string,
	size int64,
	overwrite bool,
) error {
	if !overwrite {
		if _, err := dst.Size(to); err == nil {
			return fmt.Errorf("%w: %s", sftpx.ErrExists, to)
		}
	}

	j.update(func(state *Job) { state.Current = from })

	reader, err := src.Reader(from, 0)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	writer, err := dst.Writer(to, 0)
	if err != nil {
		return err
	}

	if err := stream(ctx, writer, reader, func(n int64) {
		j.update(func(state *Job) { state.DoneBytes += n })
	}); err != nil {
		// Closing on the error path too, so a cancelled transfer does not
		// leave a channel open on the destination host.
		_ = writer.Close()
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	j.update(func(state *Job) { state.DoneFiles++ })

	// Permissions follow the file. A script copied without its execute bit
	// is a support ticket.
	if info, err := src.Stat(ctx, from); err == nil {
		if mode, parseErr := sftpx.ParseMode(info.Mode); parseErr == nil {
			_ = dst.Chmod(to, mode)
		}
	}

	return nil
}

// stream copies with cancellation and progress.
//
// io.Copy would be shorter and would neither stop when a user presses cancel
// nor report how far it had got, which are the two things a transfer needs.
func stream(ctx context.Context, dst io.Writer, src io.Reader, progress func(int64)) error {
	buf := make([]byte, copyBufferSize)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			if written > 0 {
				progress(int64(written))
			}
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

// walked is one entry found under a source path.
type walked struct {
	Path  string
	Size  int64
	IsDir bool
}

// walk lists a tree, directories before their contents.
//
// Ordered that way because the copy creates each directory as it reaches it,
// and a file cannot be written into a directory that does not exist yet.
// Symlinks are not followed: a link pointing at / would otherwise turn a
// directory copy into an attempt to copy the entire host.
func walk(ctx context.Context, client *sftpx.Client, root string) ([]walked, error) {
	var out []walked

	var descend func(string) error
	descend = func(dir string) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		entries, err := client.List(ctx, dir)
		if err != nil {
			return err
		}

		sort.SliceStable(entries, func(i, j int) bool {
			return entries[i].IsDir && !entries[j].IsDir
		})

		for _, entry := range entries {
			if entry.IsSymlink {
				continue
			}
			if entry.IsDir {
				out = append(out, walked{Path: entry.Path, IsDir: true})
				if err := descend(entry.Path); err != nil {
					return err
				}
				continue
			}
			out = append(out, walked{Path: entry.Path, Size: entry.Size})
		}
		return nil
	}

	if err := descend(root); err != nil {
		return nil, err
	}
	return out, nil
}

// within reports whether inner is at or beneath outer.
func within(inner, outer string) bool {
	inner, outer = path.Clean(inner), path.Clean(outer)
	if inner == outer {
		return true
	}
	return len(inner) > len(outer) && inner[:len(outer)] == outer && inner[len(outer)] == '/'
}

// Get returns one job, checking ownership.
func (t *Transfers) Get(userID, id string) (Job, error) {
	t.mu.Lock()
	j, ok := t.jobs[id]
	t.mu.Unlock()

	if !ok {
		return Job{}, ErrJobNotFound
	}

	snapshot := j.snapshot()
	if snapshot.UserID != userID {
		// Reported as missing rather than forbidden: whether somebody else's
		// job exists is not this user's business.
		return Job{}, ErrJobNotFound
	}
	return snapshot, nil
}

// ListForUser returns a user's jobs, newest first.
func (t *Transfers) ListForUser(userID string) []Job {
	t.mu.Lock()
	all := make([]*job, 0, len(t.jobs))
	for _, j := range t.jobs {
		all = append(all, j)
	}
	t.mu.Unlock()

	out := make([]Job, 0, len(all))
	for _, j := range all {
		if snapshot := j.snapshot(); snapshot.UserID == userID {
			out = append(out, snapshot)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

// Cancel stops a running job.
func (t *Transfers) Cancel(userID, id string) error {
	t.mu.Lock()
	j, ok := t.jobs[id]
	t.mu.Unlock()

	if !ok || j.snapshot().UserID != userID {
		return ErrJobNotFound
	}

	j.cancel()
	return nil
}

// sweep forgets jobs that finished long enough ago.
func (t *Transfers) sweep() {
	cutoff := time.Now().Add(-JobRetention)

	t.mu.Lock()
	defer t.mu.Unlock()

	for id, j := range t.jobs {
		snapshot := j.snapshot()
		if snapshot.FinishedAt != nil && snapshot.FinishedAt.Before(cutoff) {
			delete(t.jobs, id)
		}
	}
}

// Shutdown cancels everything still running.
func (t *Transfers) Shutdown() {
	t.mu.Lock()
	jobs := make([]*job, 0, len(t.jobs))
	for _, j := range t.jobs {
		jobs = append(jobs, j)
	}
	t.mu.Unlock()

	for _, j := range jobs {
		j.cancel()
	}
}
