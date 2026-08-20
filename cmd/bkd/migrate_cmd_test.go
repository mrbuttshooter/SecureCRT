package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The command line itself, driven the way an administrator drives it.
//
// internal/server covers the migration behind these commands. What is left is
// the part only the binary has: flag parsing, the passphrase arriving through
// the environment, -commit actually being required, and a file appearing on
// disk with the right contents. run() is called directly rather than through a
// subprocess, so a failure points at a line rather than at an exit code.

// deployment writes a self-contained configuration and initialises it.
func deployment(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	config := `
server:
  bind: "127.0.0.1:0"
  external_url: "https://bkd.test"
database:
  driver: sqlite
  dsn: "` + filepath.Join(dir, "bkd.db") + `"
vault:
  master_key_path: "` + filepath.Join(dir, "master.key") + `"
  argon2_time: 1
  argon2_memory_kb: 16384
  argon2_threads: 1
paths:
  data_dir: "` + filepath.Join(dir, "data") + `"
  session_log_dir: "` + filepath.Join(dir, "data", "logs") + `"
  recording_dir: "` + filepath.Join(dir, "data", "recordings") + `"
log:
  level: error
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"gen-master-key", "-config", path}); err != nil {
		t.Fatalf("gen-master-key: %v", err)
	}
	if err := run([]string{"migrate", "-config", path}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return path
}

// account creates a local user through the same command an operator uses.
func account(t *testing.T, config, email string) {
	t.Helper()

	// create-user reads the password from stdin when it is not a terminal,
	// which is the path a provisioning script takes.
	restore := stdinFrom(t, "correct horse battery staple\n")
	defer restore()

	if err := run([]string{"admin", "create-user", "-config", config, "-email", email}); err != nil {
		t.Fatalf("create-user: %v", err)
	}
}

// stdinFrom replaces standard input for the duration of one command.
func stdinFrom(t *testing.T, text string) func() {
	t.Helper()

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := write.WriteString(text); err != nil {
		t.Fatal(err)
	}
	_ = write.Close()

	previous := os.Stdin
	os.Stdin = read
	return func() {
		os.Stdin = previous
		_ = read.Close()
	}
}

// csvOfHosts writes the kind of spreadsheet a network team already has.
func csvOfHosts(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "inventory.csv")
	const sheet = `Device Name,IP Address,User,Port,Site
core-sw-01,10.0.0.1,netops,22,London
core-sw-02,10.0.0.2,netops,22,London
edge-rtr-01,10.1.0.1,admin,2222,Manchester
`
	if err := os.WriteFile(path, []byte(sheet), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestImportWritesNothingWithoutCommit is the promise the command makes in its
// own help text, and the one that matters: an administrator pointing this at
// the wrong account should discover it from a printed plan, not from a tree.
func TestImportWritesNothingWithoutCommit(t *testing.T) {
	config := deployment(t)
	account(t, config, "alice@example.com")
	sheet := csvOfHosts(t, t.TempDir())

	if err := run([]string{
		"import", "-config", config, "-user", "alice@example.com",
		"-source", "csv", "-file", sheet,
	}); err != nil {
		t.Fatalf("preview: %v", err)
	}

	// Exporting is the only way to ask the binary what it holds, so it is
	// also the check: an empty tree exports an empty config.
	out := filepath.Join(t.TempDir(), "check.json")
	if err := run([]string{
		"export", "-config", config, "-user", "alice@example.com",
		"-format", "ssh_config", "-out", out, "-include-secrets=false",
	}); err != nil {
		t.Fatalf("export: %v", err)
	}

	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(written), "core-sw-01") {
		t.Fatal("the preview wrote connections to the database")
	}
}

// TestImportCommitsWhenAsked, and the connections come back out again.
func TestImportCommitsWhenAsked(t *testing.T) {
	config := deployment(t)
	account(t, config, "alice@example.com")
	sheet := csvOfHosts(t, t.TempDir())

	if err := run([]string{
		"import", "-config", config, "-user", "alice@example.com",
		"-source", "csv", "-file", sheet, "-commit",
	}); err != nil {
		t.Fatalf("import: %v", err)
	}

	out := filepath.Join(t.TempDir(), "config")
	if err := run([]string{
		"export", "-config", config, "-user", "alice@example.com",
		"-format", "ssh_config", "-out", out, "-include-secrets=false",
	}); err != nil {
		t.Fatalf("export: %v", err)
	}

	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"core-sw-01", "core-sw-02", "edge-rtr-01"} {
		if !strings.Contains(string(written), host) {
			t.Errorf("%s is missing from the exported config:\n%s", host, written)
		}
	}
	if !strings.Contains(string(written), "10.1.0.1") {
		t.Error("the addresses did not survive")
	}
	if !strings.Contains(string(written), "2222") {
		t.Error("the non-default port did not survive")
	}
}

// TestAnExportRefusesToOverwrite. An export is what somebody just spent an
// hour preparing; clobbering it because two commands shared a filename is
// entirely avoidable data loss.
func TestAnExportRefusesToOverwrite(t *testing.T) {
	config := deployment(t)
	account(t, config, "alice@example.com")

	out := filepath.Join(t.TempDir(), "config")
	args := []string{
		"export", "-config", config, "-user", "alice@example.com",
		"-format", "ssh_config", "-out", out, "-include-secrets=false",
	}

	if err := run(args); err != nil {
		t.Fatalf("first export: %v", err)
	}
	err := run(args)
	if err == nil {
		t.Fatal("the second export overwrote the first")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v, want it to say the file is in the way", err)
	}
}

// TestPuTTYKeysArriveThroughTheBinary: a zip of a .putty directory with a real
// .ppk in it, imported by the command an administrator would actually type.
func TestPuTTYKeysArriveThroughTheBinary(t *testing.T) {
	config := deployment(t)
	account(t, config, "alice@example.com")

	// The account has no vault, so a key cannot be stored — and the command
	// must say that plainly rather than importing the sessions and quietly
	// leaving the key behind.
	archive := puttyZip(t, t.TempDir())

	err := run([]string{
		"import", "-config", config, "-user", "alice@example.com",
		"-source", "putty", "-file", archive, "-commit",
	})
	if err == nil {
		t.Fatal("a key was imported into an account with no vault")
	}
	if !strings.Contains(err.Error(), "no vault yet") {
		t.Errorf("error = %v, want it to explain what is missing", err)
	}

	// With -no-secrets the device tree lands, which is the half of a bulk
	// pre-load that does not need anybody to have signed in yet.
	if err := run([]string{
		"import", "-config", config, "-user", "alice@example.com",
		"-source", "putty", "-file", archive, "-commit", "-no-secrets",
	}); err != nil {
		t.Fatalf("importing connections alone: %v", err)
	}

	out := filepath.Join(t.TempDir(), "config")
	if err := run([]string{
		"export", "-config", config, "-user", "alice@example.com",
		"-format", "ssh_config", "-out", out, "-include-secrets=false",
	}); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "10.0.0.1") {
		t.Errorf("the connection did not arrive:\n%s", written)
	}
}

// TestUnknownFlagsAndMissingArguments are reported rather than assumed.
func TestMissingArgumentsAreReported(t *testing.T) {
	config := deployment(t)

	cases := map[string][]string{
		"no user":   {"import", "-config", config, "-source", "csv", "-file", "x"},
		"no source": {"import", "-config", config, "-user", "a@b.c", "-file", "x"},
		"no file":   {"import", "-config", config, "-user", "a@b.c", "-source", "csv"},
		"no out":    {"export", "-config", config, "-user", "a@b.c"},
		"bad conflict": {"import", "-config", config, "-user", "a@b.c",
			"-source", "csv", "-file", "x", "-on-conflict", "merge"},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := run(args); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func puttyZip(t *testing.T, dir string) string {
	t.Helper()

	key, err := os.ReadFile(filepath.Join(
		"..", "..", "internal", "portability", "ppk", "testdata", "v3-ed25519.ppk"))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)

	files := []struct {
		name string
		data []byte
	}{
		{"putty/core.ppk", key},
		{"putty/sessions/core%20switch", []byte(
			"HostName=10.0.0.1\nPortNumber=22\nUserName=netops\nProtocol=ssh\n" +
				`PublicKeyFile=C:\Users\netops\core.ppk` + "\n")},
	}
	for _, file := range files {
		entry, err := writer.Create(file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "putty.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
