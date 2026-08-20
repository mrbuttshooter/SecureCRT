// Package auth implements identity: password hashing, TOTP, sessions, OIDC
// against Microsoft Entra, and login throttling.
//
// Two distinct secrets appear in this package and they must not be confused:
//
//   - The *login password* proves who you are. It is hashed with Argon2id and
//     the hash is stored. The server can verify it but never recover it.
//   - The *vault passphrase* decrypts your credentials. It is never stored in
//     any form. See internal/vault.
//
// For a local account these may be the same string typed once. They are still
// processed independently, under different salts, so the stored login hash
// gives an attacker no head start on the vault.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for login password hashing.
//
// Lower than the vault's 64 MiB deliberately. A login hash is verified on
// every sign-in attempt, including an attacker's, so the cost is also a
// denial-of-service surface: 64 MiB per concurrent attempt would let a
// modest flood exhaust server memory. The vault KEK can afford more because
// it is derived once per unlock, not once per attempt.
//
// These are the RFC 9106 first recommended option scaled for that trade-off.
const (
	passwordTime      uint32 = 3
	passwordMemoryKB  uint32 = 19 * 1024
	passwordThreads   uint8  = 4
	passwordSaltLen          = 16
	passwordKeyLen    uint32 = 32
	passwordMaxLength        = 1024
)

// Errors returned by this file. Compare with errors.Is.
var (
	// ErrPasswordMismatch means the password did not match the hash. It is
	// returned for every failure mode a caller is allowed to distinguish —
	// which is to say, only this one.
	ErrPasswordMismatch = errors.New("auth: password does not match")

	// ErrMalformedHash means the stored hash could not be parsed. Distinct
	// from ErrPasswordMismatch because it indicates database corruption or a
	// migration bug, not a user typing the wrong thing, and should page
	// someone rather than count as a failed login.
	ErrMalformedHash = errors.New("auth: stored password hash is malformed")

	// ErrPasswordTooLong guards against a caller passing unbounded input.
	ErrPasswordTooLong = fmt.Errorf("auth: password exceeds %d bytes", passwordMaxLength)
)

// PasswordParams are the Argon2id costs used for a single hash. They are
// encoded into the resulting PHC string, so changing the defaults never
// invalidates existing hashes.
type PasswordParams struct {
	Time     uint32
	MemoryKB uint32
	Threads  uint8
}

// DefaultPasswordParams returns the built-in login-password costs.
func DefaultPasswordParams() PasswordParams {
	return PasswordParams{Time: passwordTime, MemoryKB: passwordMemoryKB, Threads: passwordThreads}
}

// HashPassword hashes a password with Argon2id and returns a PHC string:
//
//	$argon2id$v=19$m=19456,t=3,p=4$<b64 salt>$<b64 hash>
//
// The format is self-describing, so a hash produced under one set of costs
// stays verifiable after the defaults change.
func HashPassword(password []byte, p PasswordParams) (string, error) {
	if len(password) == 0 {
		return "", errors.New("auth: password must not be empty")
	}
	if len(password) > passwordMaxLength {
		return "", ErrPasswordTooLong
	}

	salt := make([]byte, passwordSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}

	hash := argon2.IDKey(password, salt, p.Time, p.MemoryKB, p.Threads, passwordKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks a password against a PHC hash in constant time.
//
// It returns ErrPasswordMismatch on a wrong password and ErrMalformedHash if
// the stored value cannot be parsed — callers should treat those differently,
// since the latter means something is wrong with the data, not the user.
func VerifyPassword(password []byte, encoded string) error {
	if len(password) > passwordMaxLength {
		return ErrPasswordTooLong
	}

	parsed, err := parsePHC(encoded)
	if err != nil {
		return err
	}

	computed := argon2.IDKey(password, parsed.salt,
		parsed.params.Time, parsed.params.MemoryKB, parsed.params.Threads,
		uint32(len(parsed.hash))) // #nosec G115 -- length of a hash we just parsed and bounded

	if subtle.ConstantTimeCompare(computed, parsed.hash) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// NeedsRehash reports whether a stored hash was produced with weaker costs
// than the current parameters.
//
// Call it after a successful verification: that is the only moment the
// plaintext password is available to re-hash with, so it is the only chance
// to upgrade an old hash without asking the user to reset anything.
func NeedsRehash(encoded string, want PasswordParams) (bool, error) {
	parsed, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}
	got := parsed.params
	return got.Time < want.Time ||
		got.MemoryKB < want.MemoryKB ||
		got.Threads < want.Threads, nil
}

type parsedPHC struct {
	params PasswordParams
	salt   []byte
	hash   []byte
}

// parsePHC decodes the PHC string format.
//
// It is strict: an unexpected algorithm, version or field count is rejected
// rather than guessed at. A lenient parser here would be a downgrade vector —
// accepting "$argon2i$" or a lower version would verify against a weaker
// function than the one the password was enrolled with.
func parsePHC(encoded string) (parsedPHC, error) {
	parts := strings.Split(encoded, "$")
	// A well-formed string starts with an empty segment, then five fields.
	if len(parts) != 6 || parts[0] != "" {
		return parsedPHC{}, fmt.Errorf("%w: expected 5 fields, got %d", ErrMalformedHash, len(parts)-1)
	}
	if parts[1] != "argon2id" {
		return parsedPHC{}, fmt.Errorf("%w: algorithm is %q, only argon2id is accepted", ErrMalformedHash, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return parsedPHC{}, fmt.Errorf("%w: unreadable version %q", ErrMalformedHash, parts[2])
	}
	if version != argon2.Version {
		return parsedPHC{}, fmt.Errorf("%w: version is %d, want %d", ErrMalformedHash, version, argon2.Version)
	}

	var p PasswordParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKB, &p.Time, &p.Threads); err != nil {
		return parsedPHC{}, fmt.Errorf("%w: unreadable parameters %q", ErrMalformedHash, parts[3])
	}
	if p.Time == 0 || p.MemoryKB == 0 || p.Threads == 0 {
		return parsedPHC{}, fmt.Errorf("%w: parameters must all be non-zero, got %q", ErrMalformedHash, parts[3])
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return parsedPHC{}, fmt.Errorf("%w: undecodable salt", ErrMalformedHash)
	}
	if len(salt) == 0 {
		return parsedPHC{}, fmt.Errorf("%w: empty salt", ErrMalformedHash)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return parsedPHC{}, fmt.Errorf("%w: undecodable hash", ErrMalformedHash)
	}
	if len(hash) < 16 {
		return parsedPHC{}, fmt.Errorf("%w: hash is only %d bytes", ErrMalformedHash, len(hash))
	}

	return parsedPHC{params: p, salt: salt, hash: hash}, nil
}
