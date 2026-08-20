package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAndLoadMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")

	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatalf("GenerateMasterKeyFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != MasterKeyFileMode {
		t.Fatalf("mode = %04o, want %04o", got, MasterKeyFileMode)
	}

	key, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if len(key) != KeyLen {
		t.Fatalf("key length = %d", len(key))
	}
	if key.IsZero() {
		t.Fatal("loaded key is all zeroes")
	}
}

// TestGenerateMasterKeyRefusesOverwrite guards the single most destructive
// mistake an operator could make: re-running the installer over a live
// deployment and orphaning every shared credential.
func TestGenerateMasterKeyRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")

	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	err = GenerateMasterKeyFile(path)
	if !errors.Is(err, ErrMasterKeyExists) {
		t.Fatalf("want ErrMasterKeyExists, got %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the existing key file was modified")
	}
}

func TestLoadMasterKeyRejectsLoosePermissions(t *testing.T) {
	for name, mode := range map[string]os.FileMode{
		"group readable": 0o440,
		"world readable": 0o444,
		"world writable": 0o666,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "master.key")
			if err := GenerateMasterKeyFile(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}

			if _, err := LoadMasterKey(path); !errors.Is(err, ErrMasterKeyPermissions) {
				t.Fatalf("mode %04o must be refused, got %v", mode, err)
			}
		})
	}
}

func TestLoadMasterKeyRejectsMalformedContent(t *testing.T) {
	cases := map[string]string{
		"empty":      "",
		"whitespace": "   \n",
		"not hex":    "zzzz not hex at all zzzz",
		"too short":  strings.Repeat("ab", KeyLen-1),
		"too long":   strings.Repeat("ab", KeyLen+1),
		"all zeroes": strings.Repeat("00", KeyLen),
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "master.key")
			if err := os.WriteFile(path, []byte(content), MasterKeyFileMode); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadMasterKey(path); err == nil {
				t.Fatalf("%q must be refused", content)
			}
		})
	}
}

func TestLoadMasterKeyToleratesTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatal(err)
	}

	// The generator writes a trailing newline; loading must handle it, and
	// must equally handle a file an operator re-saved without one.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Fatal("generated file should end with a newline")
	}

	trimmed := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(trimmed, []byte(strings.TrimSpace(string(raw))), MasterKeyFileMode); err != nil {
		t.Fatal(err)
	}

	a, err := LoadMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadMasterKey(trimmed)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("newline handling changed the decoded key")
	}
}

func TestLoadMasterKeyMissingFile(t *testing.T) {
	if _, err := LoadMasterKey(filepath.Join(t.TempDir(), "absent.key")); err == nil {
		t.Fatal("a missing key file must be an error")
	}
}

func TestGenerateMasterKeyCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "master.key")
	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatalf("GenerateMasterKeyFile: %v", err)
	}
	if _, err := LoadMasterKey(path); err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
}

// TestMasterKeySealsServerUnlockableCredential covers the unattended-automation
// path: a credential the server can open without any user being logged in.
func TestMasterKeySealsServerUnlockableCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := GenerateMasterKeyFile(path); err != nil {
		t.Fatal(err)
	}
	master, err := LoadMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}

	aad := MasterAAD("automation-cred-1", "private_key")
	secret := []byte("unattended backup job key")

	env, err := Seal(master, aad, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a restart: reload the key from disk and decrypt again.
	reloaded, err := LoadMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(reloaded, aad, env)
	if err != nil {
		t.Fatalf("server-unlockable credential must open after restart: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("got %q", got)
	}

	// A different master key must not open it.
	other := filepath.Join(t.TempDir(), "other.key")
	if err := GenerateMasterKeyFile(other); err != nil {
		t.Fatal(err)
	}
	otherKey, err := LoadMasterKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(otherKey, aad, env); !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}
