package files

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/proto/sftpx"
	"github.com/mrbuttshooter/securecrt/internal/remote"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
	"github.com/mrbuttshooter/securecrt/internal/vault"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

// TestOpeningTwiceReusesOneSession: browsing a host you already have open
// must not cost a second SFTP channel, nor a second authentication.
func TestOpeningTwiceReusesOneSession(t *testing.T) {
	f := newFixture(t)
	host := f.host(t, "alpha")

	first := f.open(t, host)
	second := f.open(t, host)

	if first != second {
		t.Error("opening the same host twice produced two sessions")
	}
	if n := host.authCount(); n != 1 {
		t.Errorf("the host authenticated %d times, want 1", n)
	}
	if n := f.pool.Len(); n != 1 {
		t.Errorf("%d SSH connections are open, want 1", n)
	}
}

// TestClosingAFileSessionLeavesTheTerminalConnection: the SSH connection
// belongs to whoever still holds a lease, which is exactly what stops closing
// a file browser from killing the shell beside it.
func TestClosingAFileSessionLeavesTheTerminalConnection(t *testing.T) {
	f := newFixture(t)
	host := f.host(t, "alpha")

	// Something else — a terminal, in production — holds the connection.
	held, err := f.dialer.Acquire(context.Background(), remote.Params{
		UserID:    f.userID,
		SessionID: host.savedID,
		VaultKey:  f.vaultKey,
		Prompter:  acceptEverything{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	f.open(t, host)
	if err := f.files.Close(f.userID, host.savedID); err != nil {
		t.Fatal(err)
	}

	if n := f.pool.Len(); n != 1 {
		t.Fatal("closing the file browser closed the shared SSH connection")
	}
	if _, err := held.Client().Conn().NewSession(); err != nil {
		t.Fatalf("the connection the terminal holds is broken: %v", err)
	}
}

func TestSessionsAreScopedToTheirOwner(t *testing.T) {
	f := newFixture(t)
	host := f.host(t, "alpha")
	f.open(t, host)

	if _, err := f.files.Get("someone-else", host.savedID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("another user could reach the session: %v", err)
	}
	if list := f.files.ListForUser("someone-else"); len(list) != 0 {
		t.Errorf("another user saw %d sessions", len(list))
	}
	if list := f.files.ListForUser(f.userID); len(list) != 1 {
		t.Errorf("the owner saw %d sessions, want 1", len(list))
	}
}

func TestIdleSessionsAreReaped(t *testing.T) {
	f := newFixture(t)
	host := f.host(t, "alpha")
	session := f.open(t, host)

	// Not idle yet.
	if n := f.files.reapOnce(time.Now()); n != 0 {
		t.Fatalf("reaped %d sessions that were in use", n)
	}

	session.mu.Lock()
	session.lastUsed = time.Now().Add(-2 * IdleTimeout)
	session.mu.Unlock()

	if n := f.files.reapOnce(time.Now()); n != 1 {
		t.Fatalf("reaped %d idle sessions, want 1", n)
	}
	if _, err := f.files.Get(f.userID, host.savedID); !errors.Is(err, ErrSessionNotFound) {
		t.Error("a reaped session is still reachable")
	}
	// And the SSH connection goes with it, since nothing else held it.
	if n := f.pool.Len(); n != 0 {
		t.Errorf("%d SSH connections survived the reap", n)
	}
}

// TestCopyBetweenHosts is the feature SecureCRT does not have: moving a
// directory straight from one managed host to another without it touching
// anybody's laptop.
func TestCopyBetweenHosts(t *testing.T) {
	f := newFixture(t)
	source := f.host(t, "source")
	dest := f.host(t, "dest")

	writeFile(t, source, "release/app.bin", "the binary")
	writeFile(t, source, "release/conf/settings.yaml", "key: value")
	writeFile(t, source, "release/conf/nested/deep.txt", "buried")

	f.open(t, source)
	f.open(t, dest)

	job, err := f.transfers.StartCopy(CopyParams{
		UserID:        f.userID,
		SourceSession: source.savedID,
		SourcePath:    path.Join(source.Root, "release"),
		DestSession:   dest.savedID,
		DestDirectory: dest.Root,
	})
	if err != nil {
		t.Fatalf("start copy: %v", err)
	}

	final := f.await(t, job.ID)
	if final.State != JobDone {
		t.Fatalf("copy ended %s: %s", final.State, final.Error)
	}

	// Everything arrived, with its contents intact.
	for rel, want := range map[string]string{
		"release/app.bin":              "the binary",
		"release/conf/settings.yaml":   "key: value",
		"release/conf/nested/deep.txt": "buried",
	} {
		if got := readFile(t, dest, rel); got != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}

	// And the accounting matches what was actually moved.
	if final.DoneFiles != 3 {
		t.Errorf("copied %d files, want 3", final.DoneFiles)
	}
	if final.DoneBytes != final.TotalBytes {
		t.Errorf("copied %d of %d bytes", final.DoneBytes, final.TotalBytes)
	}
	if final.TotalBytes != int64(len("the binary")+len("key: value")+len("buried")) {
		t.Errorf("total = %d bytes, which does not match the source", final.TotalBytes)
	}
}

// TestCopyKeepsTheExecuteBit: a script that arrives without it is a support
// ticket.
func TestCopyKeepsTheExecuteBit(t *testing.T) {
	f := newFixture(t)
	source := f.host(t, "source")
	dest := f.host(t, "dest")

	writeFile(t, source, "deploy.sh", "#!/bin/sh\necho hello\n")
	if err := os.Chmod(filepath.Join(source.Root, "deploy.sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	f.open(t, source)
	f.open(t, dest)

	job, err := f.transfers.StartCopy(CopyParams{
		UserID:        f.userID,
		SourceSession: source.savedID,
		SourcePath:    path.Join(source.Root, "deploy.sh"),
		DestSession:   dest.savedID,
		DestDirectory: dest.Root,
	})
	if err != nil {
		t.Fatal(err)
	}
	if final := f.await(t, job.ID); final.State != JobDone {
		t.Fatalf("copy ended %s: %s", final.State, final.Error)
	}

	info, err := os.Stat(filepath.Join(dest.Root, "deploy.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode at the destination = %04o, want 0755", info.Mode().Perm())
	}
}

// TestCopyRefusesToOverwriteUnlessAsked: a copy that silently replaces a
// file is how somebody loses a configuration they meant to keep.
func TestCopyRefusesToOverwriteUnlessAsked(t *testing.T) {
	f := newFixture(t)
	source := f.host(t, "source")
	dest := f.host(t, "dest")

	writeFile(t, source, "config.yaml", "the new one")
	writeFile(t, dest, "config.yaml", "the one already there")

	f.open(t, source)
	f.open(t, dest)

	start := func(overwrite bool) Job {
		t.Helper()
		job, err := f.transfers.StartCopy(CopyParams{
			UserID:        f.userID,
			SourceSession: source.savedID,
			SourcePath:    path.Join(source.Root, "config.yaml"),
			DestSession:   dest.savedID,
			DestDirectory: dest.Root,
			Overwrite:     overwrite,
		})
		if err != nil {
			t.Fatal(err)
		}
		return f.await(t, job.ID)
	}

	refused := start(false)
	if refused.State != JobFailed {
		t.Fatalf("a copy over an existing file ended %s, want failed", refused.State)
	}
	if got := readFile(t, dest, "config.yaml"); got != "the one already there" {
		t.Fatalf("the destination was overwritten anyway: %q", got)
	}
	if refused.Error == "" {
		t.Error("the failure carried no message for the user to act on")
	}

	allowed := start(true)
	if allowed.State != JobDone {
		t.Fatalf("an explicit overwrite ended %s: %s", allowed.State, allowed.Error)
	}
	if got := readFile(t, dest, "config.yaml"); got != "the new one" {
		t.Errorf("after an explicit overwrite = %q", got)
	}
}

// TestCopyRefusesToCopyADirectoryIntoItself: the walk would descend into its
// own output and never finish.
func TestCopyRefusesToCopyADirectoryIntoItself(t *testing.T) {
	f := newFixture(t)
	host := f.host(t, "alpha")

	writeFile(t, host, "tree/file.txt", "x")
	f.open(t, host)

	job, err := f.transfers.StartCopy(CopyParams{
		UserID:        f.userID,
		SourceSession: host.savedID,
		SourcePath:    path.Join(host.Root, "tree"),
		DestSession:   host.savedID,
		DestDirectory: path.Join(host.Root, "tree", "inner"),
	})
	if err != nil {
		t.Fatal(err)
	}

	final := f.await(t, job.ID)
	if final.State != JobFailed {
		t.Fatalf("copying a directory into itself ended %s", final.State)
	}
}

// TestCopyDoesNotFollowSymlinks: a link pointing at / would turn a directory
// copy into an attempt to copy the whole host.
func TestCopyDoesNotFollowSymlinks(t *testing.T) {
	f := newFixture(t)
	source := f.host(t, "source")
	dest := f.host(t, "dest")

	writeFile(t, source, "tree/real.txt", "kept")
	if err := os.Symlink("/", filepath.Join(source.Root, "tree", "everything")); err != nil {
		t.Fatal(err)
	}

	f.open(t, source)
	f.open(t, dest)

	job, err := f.transfers.StartCopy(CopyParams{
		UserID:        f.userID,
		SourceSession: source.savedID,
		SourcePath:    path.Join(source.Root, "tree"),
		DestSession:   dest.savedID,
		DestDirectory: dest.Root,
	})
	if err != nil {
		t.Fatal(err)
	}

	final := f.await(t, job.ID)
	if final.State != JobDone {
		t.Fatalf("copy ended %s: %s", final.State, final.Error)
	}
	if final.TotalFiles != 1 {
		t.Errorf("walked %d entries, want 1 — the symlink was followed", final.TotalFiles)
	}
	if got := readFile(t, dest, "tree/real.txt"); got != "kept" {
		t.Errorf("the real file = %q", got)
	}
	if _, err := os.Lstat(filepath.Join(dest.Root, "tree", "everything")); !os.IsNotExist(err) {
		t.Error("the symlink was recreated at the destination")
	}
}

func TestCancellingACopyStopsIt(t *testing.T) {
	f := newFixture(t)
	source := f.host(t, "source")
	dest := f.host(t, "dest")

	// Big enough that the copy cannot finish between starting and cancelling.
	big := bytes.Repeat([]byte("payload."), 16*1024*1024/8)
	writeBytes(t, source, "huge.bin", big)

	f.open(t, source)
	f.open(t, dest)

	job, err := f.transfers.StartCopy(CopyParams{
		UserID:        f.userID,
		SourceSession: source.savedID,
		SourcePath:    path.Join(source.Root, "huge.bin"),
		DestSession:   dest.savedID,
		DestDirectory: dest.Root,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Cancel once bytes are actually moving, rather than at some arbitrary
	// moment that might land before the transfer starts or after it ends.
	// Racing the transfer would make this test prove nothing on a fast day.
	deadline := time.Now().Add(30 * time.Second)
	for {
		current, err := f.transfers.Get(f.userID, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.State != JobRunning {
			t.Fatalf("the copy finished before any bytes were seen: %s", current.State)
		}
		if current.DoneBytes > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the copy never started moving bytes")
		}
		time.Sleep(time.Millisecond)
	}

	if err := f.transfers.Cancel(f.userID, job.ID); err != nil {
		t.Fatal(err)
	}

	final := f.await(t, job.ID)
	if final.State != JobCancelled {
		t.Fatalf("cancelled copy ended %s: %s", final.State, final.Error)
	}
	if final.DoneBytes >= int64(len(big)) {
		t.Errorf("a cancelled copy transferred everything anyway: %d bytes", final.DoneBytes)
	}
}

// TestStreamStopsOnCancellation covers the copy loop on its own.
//
// io.Copy would be shorter and would neither stop when a user presses cancel
// nor report how far it had got; this is the test that would fail if someone
// simplified it back.
func TestStreamStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var written int64
	dst := writerFunc(func(p []byte) (int, error) {
		written += int64(len(p))
		// Cancel partway through, from inside the loop, so there is no
		// timing assumption at all.
		if written >= 2*copyBufferSize {
			cancel()
		}
		return len(p), nil
	})

	var progress int64
	err := stream(ctx, dst, endlessReader{}, func(n int64) { progress += n })

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("stream = %v, want context.Canceled", err)
	}
	if progress == 0 {
		t.Error("no progress was reported before cancellation")
	}
	if progress != written {
		t.Errorf("progress reported %d bytes, %d were written", progress, written)
	}
}

// TestStreamReportsOnlyWhatWasWritten: counting what was read rather than
// what was written would show a transfer as complete when the destination
// had rejected the tail of it.
func TestStreamReportsOnlyWhatWasWritten(t *testing.T) {
	boom := errors.New("the disk filled up")

	var written int64
	dst := writerFunc(func(p []byte) (int, error) {
		if written >= copyBufferSize {
			return 0, boom
		}
		written += int64(len(p))
		return len(p), nil
	})

	var progress int64
	err := stream(context.Background(), dst, endlessReader{}, func(n int64) { progress += n })

	if !errors.Is(err, boom) {
		t.Fatalf("stream = %v, want the write error", err)
	}
	if progress != written {
		t.Errorf("progress reported %d bytes, %d were written", progress, written)
	}
}

func TestJobsAreScopedToTheirOwner(t *testing.T) {
	f := newFixture(t)
	host := f.host(t, "alpha")
	writeFile(t, host, "tree/file.txt", "x")
	f.open(t, host)

	job, err := f.transfers.StartDelete(DeleteParams{
		UserID:    f.userID,
		SessionID: host.savedID,
		Path:      path.Join(host.Root, "tree"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Reported as missing rather than forbidden: whether someone else's job
	// exists is not this user's business.
	if _, err := f.transfers.Get("someone-else", job.ID); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("another user could read the job: %v", err)
	}
	if err := f.transfers.Cancel("someone-else", job.ID); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("another user could cancel the job: %v", err)
	}

	if final := f.await(t, job.ID); final.State != JobDone {
		t.Fatalf("delete ended %s: %s", final.State, final.Error)
	}
	if _, err := os.Stat(filepath.Join(host.Root, "tree")); !os.IsNotExist(err) {
		t.Error("the tree survived the delete")
	}
}

// TestTooManyJobsIsRefused bounds what one user can start.
//
// Driven against the quota directly rather than by racing real deletes to
// stay running: an earlier version raced, and on any reasonably fast machine
// the jobs finished before the quota was reached, so it skipped itself and
// proved nothing.
func TestTooManyJobsIsRefused(t *testing.T) {
	f := newFixture(t)
	host := f.host(t, "alpha")
	f.open(t, host)

	for i := 0; i < MaxJobsPerUser; i++ {
		f.addRunningJob(f.userID)
	}

	// Someone else's jobs must not count against this user.
	for i := 0; i < MaxJobsPerUser*2; i++ {
		f.addRunningJob("someone-else")
	}

	mkdir(t, host, "target")
	_, err := f.transfers.StartDelete(DeleteParams{
		UserID:    f.userID,
		SessionID: host.savedID,
		Path:      path.Join(host.Root, "target"),
	})
	if !errors.Is(err, ErrTooManyJobs) {
		t.Fatalf("the %dth job = %v, want ErrTooManyJobs", MaxJobsPerUser+1, err)
	}

	// A finished job frees its slot.
	f.finishOneJob(f.userID)

	if _, err := f.transfers.StartDelete(DeleteParams{
		UserID:    f.userID,
		SessionID: host.savedID,
		Path:      path.Join(host.Root, "target"),
	}); err != nil {
		t.Fatalf("a job was refused after a slot was freed: %v", err)
	}
}

func TestParseModeRoundTripsWhatAListingShows(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want os.FileMode
		bad  bool
	}{
		{in: "0644", want: 0o644},
		{in: "644", want: 0o644},
		{in: "0o600", want: 0o600},
		{in: "0755", want: 0o755},
		{in: "", bad: true},
		{in: "999", bad: true},   // not octal
		{in: "4755", bad: true},  // setuid is not settable through this path
		{in: "rwxr", bad: true},  // symbolic modes are not accepted
		{in: "07777", bad: true}, // beyond the permission bits
	} {
		got, err := sftpx.ParseMode(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("ParseMode(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMode(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseMode(%q) = %04o, want %04o", tc.in, got, tc.want)
		}
	}
}

// --- fixture ----------------------------------------------------------------

type fixture struct {
	files     *Manager
	transfers *Transfers
	dialer    *remote.Dialer
	pool      *remote.Pool
	sessions  *sessions.Store
	creds     *credentials.Store
	userID    string
	vaultKey  vault.Key
	credID    string
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newFixture(t *testing.T) *fixture {
	t.Helper()

	db := storetest.New(t)
	ctx := context.Background()

	userID := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		userID, "alice@example.com", "alice@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}

	credStore := credentials.NewStore(db)
	cred, err := credStore.Create(ctx, key, credentials.CreateParams{
		OwnerID: userID,
		Name:    "test password",
		Kind:    credentials.KindPassword,
		Secret:  testPassword,
	})
	if err != nil {
		t.Fatal(err)
	}

	sessStore := sessions.NewStore(db)
	pool := remote.NewPool(quiet())
	dialer := remote.NewDialer(pool, sessStore, credStore, hostkeys.NewStore(db), quiet())

	manager := NewManager(dialer, quiet())
	transfers := NewTransfers(manager, quiet())

	t.Cleanup(func() {
		transfers.Shutdown()
		manager.Shutdown()
		pool.Close()
	})

	return &fixture{
		files:     manager,
		transfers: transfers,
		dialer:    dialer,
		pool:      pool,
		sessions:  sessStore,
		creds:     credStore,
		userID:    userID,
		vaultKey:  key,
		credID:    cred.ID,
	}
}

// host starts an SFTP server and saves a connection pointing at it.
func (f *fixture) host(t *testing.T, name string) *testHost {
	t.Helper()

	host := startSFTP(t)

	saved, err := f.sessions.CreateSession(context.Background(), sessions.CreateSessionParams{
		OwnerID:      f.userID,
		Name:         name,
		Protocol:     sessions.ProtocolSSH,
		Hostname:     host.Host,
		Port:         host.Port,
		Username:     "tester",
		CredentialID: f.credID,
	})
	if err != nil {
		t.Fatal(err)
	}

	host.savedID = saved.ID
	return host
}

func (f *fixture) open(t *testing.T, host *testHost) *Session {
	t.Helper()

	session, err := f.files.Open(context.Background(), OpenParams{
		UserID:    f.userID,
		SessionID: host.savedID,
		VaultKey:  f.vaultKey,
		Prompter:  acceptEverything{},
	})
	if err != nil {
		t.Fatalf("open a file session: %v", err)
	}
	return session
}

// await blocks until a job stops running.
func (f *fixture) await(t *testing.T, id string) Job {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		job, err := f.transfers.Get(f.userID, id)
		if err != nil {
			t.Fatalf("the job vanished: %v", err)
		}
		if job.State != JobRunning {
			return job
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("the job never finished")
	return Job{}
}

// addRunningJob inserts a job that is running and will never finish, so the
// quota can be tested without depending on how fast real work completes.
func (f *fixture) addRunningJob(userID string) {
	f.transfers.mu.Lock()
	defer f.transfers.mu.Unlock()

	id := uuid.Must(uuid.NewV7()).String()
	f.transfers.jobs[id] = &job{
		cancel: func() {},
		state: Job{
			ID:        id,
			Kind:      JobCopy,
			State:     JobRunning,
			UserID:    userID,
			StartedAt: time.Now().UTC(),
		},
	}
}

// finishOneJob marks one of a user's running jobs as finished.
func (f *fixture) finishOneJob(userID string) {
	f.transfers.mu.Lock()
	defer f.transfers.mu.Unlock()

	for _, j := range f.transfers.jobs {
		if j.snapshot().UserID == userID && j.snapshot().State == JobRunning {
			now := time.Now().UTC()
			j.update(func(state *Job) {
				state.State = JobDone
				state.FinishedAt = &now
			})
			return
		}
	}
}

// writerFunc adapts a function to io.Writer, for testing the copy loop
// without a remote host at either end.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// endlessReader never runs out, so a copy only stops when told to.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) { return len(p), nil }

type acceptEverything struct{}

func (acceptEverything) PromptHostKey(context.Context, remote.HostKeyInfo) (bool, error) {
	return true, nil
}

// --- a real SFTP host -------------------------------------------------------

const testPassword = "a throwaway password"

type testHost struct {
	Host string
	Port int
	Root string

	// savedID is the saved connection pointing at this host.
	savedID string

	mu    sync.Mutex
	auths int
}

func (h *testHost) authCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.auths
}

func startSFTP(t *testing.T) *testHost {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	host := &testHost{Root: t.TempDir()}

	srv := &gssh.Server{
		HostSigners: []gssh.Signer{signer},
		PasswordHandler: func(_ gssh.Context, given string) bool {
			host.mu.Lock()
			host.auths++
			host.mu.Unlock()
			return given == testPassword
		},
		SubsystemHandlers: map[string]gssh.SubsystemHandler{
			"sftp": func(s gssh.Session) {
				server, err := sftp.NewServer(s)
				if err != nil {
					return
				}
				defer func() { _ = server.Close() }()
				_ = server.Serve()
			},
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	hostname, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	host.Host, host.Port = hostname, port
	return host
}

func writeFile(t *testing.T, h *testHost, rel, contents string) {
	t.Helper()
	writeBytes(t, h, rel, []byte(contents))
}

func writeBytes(t *testing.T, h *testHost, rel string, contents []byte) {
	t.Helper()

	full := filepath.Join(h.Root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, contents, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, h *testHost, rel string) string {
	t.Helper()

	// #nosec G304 -- a path the test itself built under its own temp dir
	data, err := os.ReadFile(filepath.Join(h.Root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(data)
}

func mkdir(t *testing.T, h *testHost, rel string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Join(h.Root, filepath.FromSlash(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
}
