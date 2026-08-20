package terminal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Transcripts, written to a real directory.
//
// The setting for this existed for five phases and nothing read it, so these
// start from "does anything reach the disk" and work outwards to the two
// properties that matter: that a password typed at a prompt is not in the
// file, and that a device printing rubbish forever cannot fill the disk of a
// server that also holds the database and the master key.

func newTestTranscript(t *testing.T, label string) (*Transcript, string) {
	t.Helper()

	dir := t.TempDir()
	transcript, err := NewTranscript(TranscriptConfig{
		Dir: dir, UserID: "user-1", Label: label,
	}, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return transcript, dir
}

func TestATranscriptRecordsWhatWasOnTheScreen(t *testing.T) {
	transcript, _ := newTestTranscript(t, "core-sw-01")
	shell := newFakeShell()
	recorded := WithTranscript(shell, transcript)

	go func() {
		_, _ = shell.fromFarEnd.Write([]byte("switch> show version\r\n"))
		_, _ = shell.fromFarEnd.Write([]byte("IOS 15.2\r\n"))
	}()

	buf := make([]byte, 128)
	seen := ""
	for !strings.Contains(seen, "IOS 15.2") {
		n, err := recorded.Read(buf)
		seen += string(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := recorded.Close(); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(transcript.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)

	for _, want := range []string{"show version", "IOS 15.2", "core-sw-01", "session ended"} {
		if !strings.Contains(text, want) {
			t.Errorf("the transcript does not contain %q:\n%s", want, text)
		}
	}
}

// TestKeystrokesAreNotRecorded is the property that keeps a password out of
// the file without this code having to recognise one.
//
// A password typed at a prompt is not echoed — the device's own doing, by
// WILL ECHO on telnet or by simply not printing it on SSH — so a transcript
// of output contains the session and not the credential, automatically.
// Recording input as well would capture every password anybody typed, in the
// clear, in a file kept for months.
func TestKeystrokesAreNotRecorded(t *testing.T) {
	transcript, _ := newTestTranscript(t, "core-sw-01")
	shell := newFakeShell()
	recorded := WithTranscript(shell, transcript)

	go func() { _, _ = shell.fromFarEnd.Write([]byte("Password: ")) }()

	buf := make([]byte, 64)
	if _, err := recorded.Read(buf); err != nil {
		t.Fatal(err)
	}

	// The device does not echo it, so nothing about it reaches Read.
	if _, err := recorded.Write([]byte("hunter2\r")); err != nil {
		t.Fatal(err)
	}
	if err := recorded.Close(); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(transcript.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "hunter2") {
		t.Fatal("the password reached the transcript")
	}
	if !strings.Contains(string(body), "Password: ") {
		t.Error("the prompt should be there; only the answer should not")
	}
}

// TestATranscriptStopsAtItsCapAndSaysSo.
//
// One `cat /dev/urandom` on one console must not fill the disk of a server
// that also holds the database and the master key. And a transcript that
// simply ends is indistinguishable from a session that ended, so the reason
// is written into the file.
func TestATranscriptStopsAtItsCapAndSaysSo(t *testing.T) {
	transcript, _ := newTestTranscript(t, "noisy")

	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = 'x'
	}
	for range (MaxTranscriptBytes / len(chunk)) + 4 {
		transcript.write(chunk)
	}

	if !transcript.Truncated() {
		t.Fatal("the cap was never reached")
	}
	if got := transcript.Bytes(); got > MaxTranscriptBytes {
		t.Errorf("wrote %d bytes, past the %d cap", got, MaxTranscriptBytes)
	}

	// Writing after the cap is a no-op rather than an error, because the
	// session is still running and must not be interrupted by a full log.
	transcript.write([]byte("more"))

	info, err := os.Stat(transcript.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > MaxTranscriptBytes+1024 {
		t.Errorf("the file is %d bytes", info.Size())
	}

	body, err := os.ReadFile(transcript.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "truncated") {
		t.Error("a truncated transcript must say so, or it reads as a session that ended")
	}
}

// TestATranscriptIsNotReadableByOtherAccounts. It holds whatever scrolled
// past on a production console, which is frequently as sensitive as the
// credentials themselves.
func TestATranscriptIsNotReadableByOtherAccounts(t *testing.T) {
	transcript, dir := newTestTranscript(t, "core-sw-01")
	if err := transcript.Close(time.Now()); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(transcript.Path())
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("transcript mode = %o, want 600", mode)
	}

	parent, err := os.Stat(filepath.Dir(transcript.Path()))
	if err != nil {
		t.Fatal(err)
	}
	if mode := parent.Mode().Perm(); mode != 0o700 {
		t.Errorf("directory mode = %o, want 700", mode)
	}

	// And it landed under the user's own directory rather than loose.
	if !strings.HasPrefix(transcript.Path(), filepath.Join(dir, "user-1")) {
		t.Errorf("path = %q, want it under the user's directory", transcript.Path())
	}
}

// TestAConnectionNameCannotChooseWhereTheFileLands.
//
// Connection names are user-supplied. A name of "../../etc/cron.d/x" would
// otherwise decide where the transcript is written, which turns a logging
// feature into a file-write primitive on a server running as its own user.
func TestAConnectionNameCannotChooseWhereTheFileLands(t *testing.T) {
	dir := t.TempDir()

	transcript, err := NewTranscript(TranscriptConfig{
		Dir: dir, UserID: "user-1", Label: "../../../../etc/cron.d/evil",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transcript.Close(time.Now()) }()

	resolved, err := filepath.Abs(transcript.Path())
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
		t.Fatalf("the transcript escaped its directory: %s", resolved)
	}
	if strings.Contains(filepath.Base(resolved), "/") {
		t.Error("the filename contains a separator")
	}

	// Nothing was created outside the directory either — a check that a name
	// merely being cleaned would not catch, if the cleaning were wrong.
	if _, err := os.Stat(filepath.Join(dir, "..", "etc")); err == nil {
		t.Error("something was written outside the transcript directory")
	}
}

// TestASymbolicLinkCannotRedirectATranscript.
//
// safeName makes a filename safe and is tested above. This checks the second
// layer: the file is opened through a root scoped to the transcript
// directory, so containment holds even where a name that should have been
// rejected was not. A link planted inside the directory — by anything sharing
// the machine — cannot make the write land somewhere else.
func TestASymbolicLinkCannotRedirectATranscript(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere")

	userDir := filepath.Join(dir, "user-1")
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		t.Fatal(err)
	}

	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	name := "20260304-050607-core_sw_01.log"
	if err := os.Symlink(outside, filepath.Join(userDir, name)); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}

	// O_EXCL refuses an existing name, link or not, so this fails over to the
	// suffixed name — and either way nothing is written through the link.
	transcript, err := NewTranscript(TranscriptConfig{
		Dir: dir, UserID: "user-1", Label: "core-sw-01",
	}, at)
	if err == nil {
		transcript.write([]byte("secret output"))
		_ = transcript.Close(at)
	}

	if _, err := os.Stat(outside); err == nil {
		t.Fatal("the transcript was written through a symbolic link, outside its directory")
	}
}

// TestTwoSessionsInTheSameSecondBothGetATranscript.
//
// The obvious naming scheme collides at one-second resolution, and the loser
// of that collision would have its record silently overwritten — the one
// failure a transcript must not have.
func TestTwoSessionsInTheSameSecondBothGetATranscript(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	cfg := TranscriptConfig{Dir: dir, UserID: "user-1", Label: "core-sw-01"}

	first, err := NewTranscript(cfg, at)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTranscript(cfg, at)
	if err != nil {
		t.Fatal(err)
	}

	if first.Path() == second.Path() {
		t.Fatal("two sessions in the same second share a file; one record is being lost")
	}

	first.write([]byte("from the first\n"))
	second.write([]byte("from the second\n"))
	_ = first.Close(at)
	_ = second.Close(at)

	for path, want := range map[string]string{
		first.Path():  "from the first",
		second.Path(): "from the second",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), want) {
			t.Errorf("%s does not contain %q", path, want)
		}
	}
}

// TestTheHeaderSaysWhoseDecisionItWas.
//
// Somebody whose session is recorded by policy should be able to find that
// out from the record itself, not only from a settings page they never open.
func TestTheHeaderSaysWhoseDecisionItWas(t *testing.T) {
	dir := t.TempDir()

	forced, err := NewTranscript(TranscriptConfig{
		Dir: dir, UserID: "u", Label: "sw", Forced: true,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = forced.Close(time.Now())

	body, err := os.ReadFile(forced.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "record_all_sessions") {
		t.Errorf("a forced transcript does not say so:\n%s", body)
	}
	if !strings.Contains(string(body), "keystrokes are not recorded") {
		t.Error("the header should say what is and is not in the file")
	}
}

// TestNoDirectoryMeansNoRecording, whatever a connection asks for.
func TestNoDirectoryMeansNoRecording(t *testing.T) {
	if _, err := NewTranscript(TranscriptConfig{UserID: "u", Label: "x"}, time.Now()); err == nil {
		t.Fatal("recording with nowhere to write must be an error, not a silent no-op")
	}
}

// TestWithTranscriptIsFreeWhenThereIsNothingToRecord.
func TestWithTranscriptIsFreeWhenThereIsNothingToRecord(t *testing.T) {
	shell := newFakeShell()
	if got := WithTranscript(shell, nil); got != Shell(shell) {
		t.Error("a session with no transcript should not be wrapped at all")
	}
}
