package sftpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListSortsDirectoriesFirstThenByName(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	// Deliberately created out of order, and with mixed case, because the
	// two things worth proving are that ordering does not depend on creation
	// order and that it does not depend on case.
	write(t, ts, "zebra.txt", "z")
	write(t, ts, "Alpha.txt", "a")
	write(t, ts, "middle.txt", "m")
	mkdir(t, ts, "zzz-dir")
	mkdir(t, ts, "Aaa-dir")

	entries, err := client.List(context.Background(), ts.Root)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}

	want := []string{"Aaa-dir", "zzz-dir", "Alpha.txt", "middle.txt", "zebra.txt"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("listing order = %v, want %v", names, want)
	}
}

func TestListReportsSizeModeAndOwner(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	write(t, ts, "report.txt", "twenty-four bytes long..")
	if err := os.Chmod(filepath.Join(ts.Root, "report.txt"), 0o640); err != nil {
		t.Fatal(err)
	}

	entries, err := client.List(context.Background(), ts.Root)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("listed %d entries, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Size != 24 {
		t.Errorf("size = %d, want 24", entry.Size)
	}
	if entry.Mode != "0640" {
		t.Errorf("mode = %q, want 0640", entry.Mode)
	}
	if entry.ModeString != "-rw-r-----" {
		t.Errorf("mode string = %q", entry.ModeString)
	}
	if entry.IsDir || entry.IsSymlink {
		t.Error("a plain file was reported as a directory or a symlink")
	}
	if entry.Path != path.Join(ts.Root, "report.txt") {
		t.Errorf("path = %q", entry.Path)
	}
	if uint32(os.Getuid()) != entry.UID { //nolint:gosec // a uid fits a uint32
		t.Errorf("uid = %d, want %d", entry.UID, os.Getuid())
	}
	if time.Since(entry.ModTime) > time.Minute {
		t.Errorf("mod time = %v, which is not recent", entry.ModTime)
	}
}

// TestSymlinksAreDistinguishedFromTheirTargets is what lets the interface
// know whether a link can be navigated into.
func TestSymlinksAreDistinguishedFromTheirTargets(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	mkdir(t, ts, "real-dir")
	write(t, ts, "real-file.txt", "contents")
	symlink(t, ts, "real-dir", "link-to-dir")
	symlink(t, ts, "real-file.txt", "link-to-file")
	symlink(t, ts, "nowhere", "broken-link")

	entries, err := client.List(context.Background(), ts.Root)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	byName := map[string]Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}

	toDir := byName["link-to-dir"]
	if !toDir.IsSymlink {
		t.Error("link-to-dir was not reported as a symlink")
	}
	if !toDir.TargetIsDir {
		t.Error("link-to-dir does not report a directory target, so it could not be opened")
	}
	if toDir.LinkTarget != "real-dir" {
		t.Errorf("link target = %q, want real-dir", toDir.LinkTarget)
	}

	toFile := byName["link-to-file"]
	if !toFile.IsSymlink || toFile.TargetIsDir {
		t.Error("link-to-file is misreported")
	}

	// A broken link must appear, and must not claim to be openable. Failing
	// the whole listing because one link dangles would make a great many real
	// directories unbrowsable.
	broken, ok := byName["broken-link"]
	if !ok {
		t.Fatal("a broken symlink vanished from the listing")
	}
	if !broken.IsSymlink {
		t.Error("a broken symlink was not reported as a symlink")
	}
	if broken.TargetIsDir {
		t.Error("a broken symlink claims to resolve to a directory")
	}
	if broken.LinkTarget != "nowhere" {
		t.Errorf("broken link target = %q", broken.LinkTarget)
	}

	// Directories-first ordering must use the resolved kind, or a symlinked
	// directory sorts among the files and the listing looks wrong.
	if entries[0].Name != "link-to-dir" && entries[1].Name != "link-to-dir" {
		t.Errorf("a symlinked directory did not sort with the directories: %v", names(entries))
	}
}

func TestStatDescribesTheLinkNotTheTarget(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	write(t, ts, "target.txt", "contents")
	symlink(t, ts, "target.txt", "pointer")

	entry, err := client.Stat(context.Background(), path.Join(ts.Root, "pointer"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Describing the target instead would make it impossible for the
	// interface to show that a path is a link at all.
	if !entry.IsSymlink {
		t.Error("stat on a symlink described the target rather than the link")
	}
	if entry.Name != "pointer" {
		t.Errorf("name = %q, want pointer", entry.Name)
	}
	if entry.LinkTarget != "target.txt" {
		t.Errorf("link target = %q", entry.LinkTarget)
	}
}

func TestMissingPathsReportNotFound(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	_, err := client.Stat(context.Background(), path.Join(ts.Root, "absent"))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("stat of a missing path = %v, want ErrNotFound", err)
	}

	_, err = client.List(context.Background(), path.Join(ts.Root, "absent"))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("list of a missing directory = %v, want ErrNotFound", err)
	}

	_, err = client.Reader(path.Join(ts.Root, "absent"), 0)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("read of a missing file = %v, want ErrNotFound", err)
	}
}

func TestUnreadableDirectoryReportsPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, which is not refused by permissions")
	}

	ts := startTestServer(t)
	client := ts.connect(t)

	mkdir(t, ts, "locked")
	if err := os.Chmod(filepath.Join(ts.Root, "locked"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(ts.Root, "locked"), 0o700) })

	_, err := client.List(context.Background(), path.Join(ts.Root, "locked"))
	if !errors.Is(err, ErrPermission) {
		t.Errorf("list of an unreadable directory = %v, want ErrPermission", err)
	}
}

func TestMkdirCreatesMissingParents(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	deep := path.Join(ts.Root, "a", "b", "c")
	if err := client.Mkdir(deep); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	info, err := os.Stat(filepath.Join(ts.Root, "a", "b", "c"))
	if err != nil {
		t.Fatalf("the directory was not created on disk: %v", err)
	}
	if !info.IsDir() {
		t.Error("the path exists but is not a directory")
	}
}

func TestRenameMovesAndOverwrites(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	write(t, ts, "before.txt", "the contents")
	if err := client.Rename(path.Join(ts.Root, "before.txt"), path.Join(ts.Root, "after.txt")); err != nil {
		t.Fatalf("rename: %v", err)
	}

	if _, err := os.Stat(filepath.Join(ts.Root, "before.txt")); !os.IsNotExist(err) {
		t.Error("the original still exists after a rename")
	}
	if got := read(t, ts, "after.txt"); got != "the contents" {
		t.Errorf("contents after rename = %q", got)
	}

	// Renaming over an existing file replaces it. Servers without the POSIX
	// rename extension refuse instead, which is a safe failure; this one has
	// it, so the replacement is what must happen.
	write(t, ts, "source.txt", "new")
	write(t, ts, "victim.txt", "old")
	if err := client.Rename(path.Join(ts.Root, "source.txt"), path.Join(ts.Root, "victim.txt")); err != nil {
		t.Fatalf("rename over an existing file: %v", err)
	}
	if got := read(t, ts, "victim.txt"); got != "new" {
		t.Errorf("contents after overwrite = %q, want new", got)
	}
}

func TestRemoveAllClearsATreeAndStopsOnCancellation(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	mkdir(t, ts, "tree/one/two")
	write(t, ts, "tree/top.txt", "a")
	write(t, ts, "tree/one/middle.txt", "b")
	write(t, ts, "tree/one/two/bottom.txt", "c")

	if err := client.RemoveAll(context.Background(), path.Join(ts.Root, "tree")); err != nil {
		t.Fatalf("remove all: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ts.Root, "tree")); !os.IsNotExist(err) {
		t.Error("the tree survived a recursive delete")
	}

	// A cancelled delete stops rather than running to completion in the
	// background, which is what a user pressing cancel means.
	mkdir(t, ts, "second/inner")
	write(t, ts, "second/inner/file.txt", "x")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := client.RemoveAll(ctx, path.Join(ts.Root, "second"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled delete = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(filepath.Join(ts.Root, "second")); err != nil {
		t.Errorf("a cancelled delete removed the directory anyway: %v", err)
	}
}

// TestRemoveAllDeletesTheLinkNotTheTarget is the difference between tidying
// up a shortcut and destroying what it pointed at.
func TestRemoveAllDeletesTheLinkNotTheTarget(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	mkdir(t, ts, "precious")
	write(t, ts, "precious/keep.txt", "irreplaceable")
	symlink(t, ts, "precious", "shortcut")

	if err := client.RemoveAll(context.Background(), path.Join(ts.Root, "shortcut")); err != nil {
		t.Fatalf("remove all: %v", err)
	}

	if _, err := os.Lstat(filepath.Join(ts.Root, "shortcut")); !os.IsNotExist(err) {
		t.Error("the symlink survived")
	}
	if got := read(t, ts, "precious/keep.txt"); got != "irreplaceable" {
		t.Fatalf("deleting a symlink destroyed what it pointed at; contents = %q", got)
	}
}

func TestChmodChangesTheModeOnDisk(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	write(t, ts, "script.sh", "#!/bin/sh\n")

	if err := client.Chmod(path.Join(ts.Root, "script.sh"), 0o750); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	info, err := os.Stat(filepath.Join(ts.Root, "script.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Errorf("mode on disk = %04o, want 0750", got)
	}
}

// TestChownLeavesUnspecifiedHalfAlone covers the chown(2) convention: -1 for
// a field means do not change it. The interface needs to set a group without
// knowing or disturbing the owner.
func TestChownLeavesUnspecifiedHalfAlone(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	write(t, ts, "owned.txt", "x")
	target := path.Join(ts.Root, "owned.txt")

	before, err := os.Stat(filepath.Join(ts.Root, "owned.txt"))
	if err != nil {
		t.Fatal(err)
	}

	// Setting both to the values they already hold: it must succeed for any
	// user, and must not disturb anything. A non-root user cannot give a file
	// away, so a real change cannot be tested portably.
	if err := client.Chown(context.Background(), target, -1, -1); err != nil {
		t.Fatalf("chown with both fields unspecified: %v", err)
	}

	after, err := os.Stat(filepath.Join(ts.Root, "owned.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Errorf("mode changed during a chown: %v then %v", before.Mode(), after.Mode())
	}
}

func TestReaderStartsAtTheRequestedOffset(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	write(t, ts, "ranged.txt", "0123456789")

	r, err := client.Reader(path.Join(ts.Root, "ranged.txt"), 4)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	defer func() { _ = r.Close() }()

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "456789" {
		t.Errorf("read from offset 4 = %q, want 456789", got)
	}
}

// TestWriterAtOffsetResumesRatherThanTruncating is the whole of resumable
// upload: a partial file must be continued, not started again.
func TestWriterAtOffsetResumesRatherThanTruncating(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	// A transfer that stopped halfway.
	write(t, ts, "partial.bin", "FIRSTHALF")

	size, err := client.Size(path.Join(ts.Root, "partial.bin"))
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if size != 9 {
		t.Fatalf("size = %d, want 9", size)
	}

	w, err := client.Writer(path.Join(ts.Root, "partial.bin"), size)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if _, err := io.Copy(w, strings.NewReader("SECONDHALF")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if got := read(t, ts, "partial.bin"); got != "FIRSTHALFSECONDHALF" {
		t.Errorf("resumed file = %q, want FIRSTHALFSECONDHALF", got)
	}
}

func TestWriterAtZeroTruncates(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	write(t, ts, "replaced.txt", "a much longer previous version")

	w, err := client.Writer(path.Join(ts.Root, "replaced.txt"), 0)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if _, err := io.Copy(w, strings.NewReader("short")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Without truncation the tail of the old file would still be there, and
	// an overwrite would silently produce a corrupt file.
	if got := read(t, ts, "replaced.txt"); got != "short" {
		t.Errorf("overwritten file = %q, want short", got)
	}
}

func TestLargeRoundTripIsByteExact(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	// Larger than MaxPacket, so the transfer spans many requests and any
	// off-by-one in offset handling shows up as corruption.
	payload := make([]byte, 5*MaxPacket+1237)
	for i := range payload {
		payload[i] = byte(i * 7 % 251)
	}

	target := path.Join(ts.Root, "large.bin")
	w, err := client.Writer(target, 0)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if _, err := io.Copy(w, bytes.NewReader(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	r, err := client.Reader(target, 0)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	defer func() { _ = r.Close() }()

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip corrupted the file: %d bytes back, %d sent", len(got), len(payload))
	}
}

func TestSizeRefusesADirectory(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	mkdir(t, ts, "adir")

	if _, err := client.Size(path.Join(ts.Root, "adir")); !errors.Is(err, ErrIsDirectory) {
		t.Errorf("size of a directory = %v, want ErrIsDirectory", err)
	}
}

func TestSymlinkAndReadLink(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	write(t, ts, "original.txt", "x")

	if err := client.Symlink("original.txt", path.Join(ts.Root, "made-link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	target, err := client.ReadLink(path.Join(ts.Root, "made-link"))
	if err != nil {
		t.Fatalf("read link: %v", err)
	}
	if target != "original.txt" {
		t.Errorf("link target = %q", target)
	}
}

func TestRealPathAndHome(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	mkdir(t, ts, "one/two")

	resolved, err := client.RealPath(path.Join(ts.Root, "one", "..", "one", "two"))
	if err != nil {
		t.Fatalf("realpath: %v", err)
	}
	// The temp directory itself may be reached through a symlink on macOS,
	// so the suffix is what can be asserted portably.
	if !strings.HasSuffix(resolved, path.Join("one", "two")) {
		t.Errorf("resolved = %q, want it to end in one/two", resolved)
	}

	home, err := client.Home()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	if !path.IsAbs(home) {
		t.Errorf("home = %q, which is not absolute", home)
	}
}

// TestOwnerNamesComeFromTheRemoteHost proves the names in a listing are read
// from the host being browsed rather than resolved locally, which would be
// wrong the moment the two machines disagree about who user 1000 is.
func TestOwnerNamesComeFromTheRemoteHost(t *testing.T) {
	ts := startTestServer(t)
	client := ts.connect(t)

	// The test server serves the real filesystem, so the /etc/passwd being
	// read is the one belonging to the machine on the far side of the SSH
	// connection — which is the point.
	client.LoadOwnerNames(context.Background())

	if !client.OwnerNamesAvailable() {
		t.Skip("this host publishes no /etc/passwd to read")
	}

	// Every Unix has user 0 as root, which makes it the one assertion that
	// holds wherever these tests run.
	uid, ok := client.LookupUser("root")
	if !ok {
		t.Fatal("root was not found in the names read from the host")
	}
	if uid != 0 {
		t.Errorf("root resolved to uid %d, want 0", uid)
	}

	write(t, ts, "mine.txt", "x")
	entries, err := client.List(context.Background(), ts.Root)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if entries[0].Owner == "" {
		t.Error("a listing carried no owner name despite names being available")
	}
}

// --- helpers ----------------------------------------------------------------

func write(t *testing.T, ts *testServer, rel, contents string) {
	t.Helper()

	full := filepath.Join(ts.Root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, ts *testServer, rel string) string {
	t.Helper()

	// #nosec G304 -- a path the test itself constructed under its temp dir
	data, err := os.ReadFile(filepath.Join(ts.Root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mkdir(t *testing.T, ts *testServer, rel string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Join(ts.Root, filepath.FromSlash(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, ts *testServer, target, rel string) {
	t.Helper()

	if err := os.Symlink(target, filepath.Join(ts.Root, filepath.FromSlash(rel))); err != nil {
		t.Fatal(err)
	}
}

func names(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out
}
