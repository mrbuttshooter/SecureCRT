package vault

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// MasterKeyFileMode is the only permission bitmask a master key file may
// carry. Anything broader would expose it to other local accounts.
const MasterKeyFileMode fs.FileMode = 0o400

// ErrMasterKeyPermissions means the key file is readable by users other than
// its owner. This is refused rather than warned about: a master key one `cat`
// away from any local account provides no protection at all.
var ErrMasterKeyPermissions = errors.New("vault: master key file must not be readable by group or others")

// ErrMasterKeyExists means a key file is already present where a new one was
// requested. Overwriting it would render every team key and every
// server-unlockable credential permanently undecryptable.
var ErrMasterKeyExists = errors.New("vault: master key file already exists")

// LoadMasterKey reads the server master key from path.
//
// The master key is the second wrapping layer: it protects team keys and
// credentials explicitly marked as server-unlockable (unattended automation).
// It deliberately does NOT protect ordinary user credentials — those are
// reachable only through a user's passphrase — so possession of this file
// alone does not compromise the fleet.
func LoadMasterKey(path string) (Key, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("vault: stat master key: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("vault: master key path %s is a directory", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o, want 0400", ErrMasterKeyPermissions, path, perm)
	}

	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, fmt.Errorf("vault: read master key: %w", err)
	}

	key, err := decodeMasterKey(raw)
	if err != nil {
		return nil, fmt.Errorf("vault: %s: %w", path, err)
	}
	return key, nil
}

// decodeMasterKey accepts the key as lowercase hex, optionally with
// surrounding whitespace, so the file stays copy-pasteable and diff-friendly
// for operators moving it between hosts.
func decodeMasterKey(raw []byte) (Key, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, errors.New("master key file is empty")
	}

	decoded, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("master key must be %d hex characters: %w", KeyLen*2, err)
	}
	if len(decoded) != KeyLen {
		return nil, fmt.Errorf("master key must decode to %d bytes, got %d", KeyLen, len(decoded))
	}

	key := Key(decoded)
	if key.IsZero() {
		return nil, errors.New("master key is all zeroes")
	}
	return key, nil
}

// GenerateMasterKeyFile creates a new random master key at path with mode
// 0400. It refuses to overwrite an existing file.
//
// Called once by install.sh at first setup. Operators must back the resulting
// file up separately from the database: losing it means losing every shared
// team credential.
func GenerateMasterKeyFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: %s", ErrMasterKeyExists, path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("vault: stat master key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("vault: create master key directory: %w", err)
	}

	key, err := NewKey()
	if err != nil {
		return err
	}
	defer key.Zero()

	encoded := make([]byte, hex.EncodedLen(len(key))+1)
	hex.Encode(encoded, key)
	encoded[len(encoded)-1] = '\n'
	defer func() {
		for i := range encoded {
			encoded[i] = 0
		}
	}()

	// O_EXCL closes the race between the Stat above and this create.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, MasterKeyFileMode) // #nosec G304
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrMasterKeyExists, path)
		}
		return fmt.Errorf("vault: create master key: %w", err)
	}
	defer f.Close() //nolint:errcheck // reported via the explicit Close below

	if _, err := f.Write(encoded); err != nil {
		return fmt.Errorf("vault: write master key: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("vault: sync master key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("vault: close master key: %w", err)
	}

	// Guard against a permissive umask having widened the mode at creation.
	if err := os.Chmod(path, MasterKeyFileMode); err != nil {
		return fmt.Errorf("vault: chmod master key: %w", err)
	}
	return nil
}

// MasterAAD is the binding for a value sealed under the server master key.
func MasterAAD(recordID, field string) AAD {
	return AAD{Scope: "master", OwnerID: "server", RecordID: recordID, FieldName: field}
}
