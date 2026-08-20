// Package vault implements the envelope encryption that protects every
// credential bkd stores: SSH private keys, passwords, passphrases and enable
// secrets.
//
// # Threat model
//
// The design assumes an attacker may obtain a full copy of the database, and
// separately may obtain the server's master key file. Neither alone — and in
// the common case, not even both together — is sufficient to recover a user's
// credentials.
//
//	vault passphrase --Argon2id(per-user salt)--> KEK (never stored)
//	                                               |
//	DEK (random 256-bit)  --AES-256-GCM wrapped--> stored in DB
//	                                               |
//	credential plaintext  --AES-256-GCM, AAD-bound-> stored in DB
//
// The user's data-encryption key (DEK) is unwrapped only at login, held in
// process memory for the life of the session, and zeroed on logout. A database
// dump therefore yields only Argon2id-hardened wrapped keys and AEAD
// ciphertexts.
//
// # Why AAD matters
//
// Every credential ciphertext is bound to its owner and record identity via
// GCM additional authenticated data. An attacker with write access to the
// database cannot move Alice's encrypted key into Bob's row and have it
// decrypt, nor swap two of Alice's own credentials, because the AAD would no
// longer match and GCM authentication fails.
//
// # Limits
//
// Zeroing is best-effort. Go's garbage collector may copy a heap allocation
// before we clear it, and without mlock the OS may page it to swap. Operators
// handling especially sensitive fleets should disable swap or run with
// encrypted swap; a future revision may adopt locked, non-GC'd buffers.
package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// KeyLen is the size in bytes of every symmetric key in this package
// (AES-256).
const KeyLen = 32

// SaltLen is the size in bytes of a per-user Argon2id salt.
const SaltLen = 16

// Errors returned by this package. Callers should compare with errors.Is
// rather than inspecting messages.
var (
	// ErrWrongPassphrase means the supplied passphrase did not unwrap the
	// key. It is deliberately indistinguishable from a tampered wrapped key:
	// revealing which occurred would help an attacker probing the database.
	ErrWrongPassphrase = errors.New("vault: wrong passphrase or corrupted key")

	// ErrTampered means an authenticated decryption failed. Either the
	// ciphertext, the nonce, or the bound identity was modified.
	ErrTampered = errors.New("vault: ciphertext failed authentication")

	// ErrBadKeyLength means a key of the wrong size was supplied.
	ErrBadKeyLength = errors.New("vault: key must be 32 bytes")

	// ErrLocked means no unwrapped key is available for this session.
	ErrLocked = errors.New("vault: locked; unlock with a vault passphrase first")
)

// Key is a symmetric key held in memory. It is a distinct type so that a key
// can never be passed where a plaintext or ciphertext is expected, and so
// that Zero has an obvious home.
type Key []byte

// Zero overwrites the key material in place.
//
// Call this as soon as a key is no longer needed — typically via defer at the
// point of derivation. See the package note on the limits of zeroing in Go.
func (k Key) Zero() {
	for i := range k {
		k[i] = 0
	}
}

// IsZero reports whether every byte of the key is zero, in constant time.
// Used by tests to assert that Zero actually ran, and as a cheap guard
// against accidentally encrypting under a cleared key.
func (k Key) IsZero() bool {
	if len(k) == 0 {
		return true
	}
	var acc byte
	for _, b := range k {
		acc |= b
	}
	return subtle.ConstantTimeByteEq(acc, 0) == 1
}

// Equal compares two keys in constant time.
func (k Key) Equal(other Key) bool {
	return subtle.ConstantTimeCompare(k, other) == 1
}

// validate rejects keys that are not exactly KeyLen bytes, or that have been
// zeroed. Encrypting under an all-zero key would silently produce ciphertext
// anybody could read.
func (k Key) validate() error {
	if len(k) != KeyLen {
		return fmt.Errorf("%w: got %d", ErrBadKeyLength, len(k))
	}
	if k.IsZero() {
		return errors.New("vault: refusing to use an all-zero key")
	}
	return nil
}

// NewKey returns a fresh cryptographically random key.
func NewKey() (Key, error) {
	k := make(Key, KeyLen)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("vault: generate key: %w", err)
	}
	return k, nil
}

// NewSalt returns a fresh cryptographically random Argon2id salt.
func NewSalt() ([]byte, error) {
	s := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		return nil, fmt.Errorf("vault: generate salt: %w", err)
	}
	return s, nil
}

// KDFParams records the Argon2id cost parameters and salt used to derive a
// particular key-encryption key.
//
// These are stored alongside each wrapped key rather than read from config at
// unwrap time. That is what allows an operator to raise the costs for new
// users without invalidating every existing vault: each wrapped key remembers
// how it was made.
type KDFParams struct {
	Time     uint32 `json:"time"`
	MemoryKB uint32 `json:"memory_kb"`
	Threads  uint8  `json:"threads"`
	Salt     []byte `json:"salt"`
}

// Default Argon2id costs, following the RFC 9106 second recommended option.
// Operators may raise them in configuration; see NewKDFParams.
const (
	DefaultKDFTime     uint32 = 3
	DefaultKDFMemoryKB uint32 = 64 * 1024
	DefaultKDFThreads  uint8  = 4
)

// DefaultKDFParams returns interactive-grade Argon2id parameters with a fresh
// salt.
func DefaultKDFParams() (KDFParams, error) {
	return NewKDFParams(DefaultKDFTime, DefaultKDFMemoryKB, DefaultKDFThreads)
}

// NewKDFParams returns the given Argon2id costs with a fresh random salt.
//
// This is how an operator's configured costs reach the KDF. Costs are recorded
// alongside each wrapped key rather than read from configuration at unwrap
// time, so raising them affects new and re-keyed vaults while existing ones
// keep working with the parameters they were created under.
func NewKDFParams(time uint32, memoryKB uint32, threads uint8) (KDFParams, error) {
	salt, err := NewSalt()
	if err != nil {
		return KDFParams{}, err
	}
	p := KDFParams{Time: time, MemoryKB: memoryKB, Threads: threads, Salt: salt}
	if err := p.Validate(); err != nil {
		return KDFParams{}, err
	}
	return p, nil
}

// Validate rejects cost parameters too weak to resist offline cracking.
func (p KDFParams) Validate() error {
	switch {
	case p.Time < 1:
		return errors.New("vault: kdf time must be at least 1")
	case p.MemoryKB < 16*1024:
		return fmt.Errorf("vault: kdf memory %d KiB is below the 16384 KiB floor", p.MemoryKB)
	case p.Threads < 1:
		return errors.New("vault: kdf threads must be at least 1")
	case len(p.Salt) < SaltLen:
		return fmt.Errorf("vault: kdf salt must be at least %d bytes, got %d", SaltLen, len(p.Salt))
	}
	return nil
}

// DeriveKEK derives a key-encryption key from a vault passphrase.
//
// The result is never stored. It exists only long enough to unwrap the user's
// DEK, and callers should Zero it immediately afterwards.
func DeriveKEK(passphrase []byte, p KDFParams) (Key, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("vault: passphrase must not be empty")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	k := argon2.IDKey(passphrase, p.Salt, p.Time, p.MemoryKB, p.Threads, KeyLen)
	return Key(k), nil
}

// DeriveSubkey derives an independent 32-byte key from a master key for a
// named purpose, using HKDF-SHA256.
//
// This exists so the service needs exactly one secret on disk. Signing OIDC
// state cookies and CSRF tokens both need a key, and adding a separate secret
// file for each would be one more thing for an operator to generate, protect,
// rotate and back up — and one more thing to get wrong.
//
// Each purpose gets a cryptographically independent key: recovering the CSRF
// subkey tells an attacker nothing about the OIDC subkey or about the master
// key itself. The info string is what separates them, so it must be distinct
// and stable per purpose — changing it invalidates everything signed under the
// old value.
//
// The master key is never used directly for signing, only as HKDF input.
func DeriveSubkey(master Key, info string) (Key, error) {
	if err := master.validate(); err != nil {
		return nil, fmt.Errorf("vault: derive subkey: %w", err)
	}
	if info == "" {
		return nil, errors.New("vault: subkey info must not be empty")
	}

	// The salt is a fixed domain-separation constant rather than a random
	// value: HKDF's salt need not be secret or random, and a stable one keeps
	// derivation reproducible across restarts without storing anything extra.
	r := hkdf.New(sha256.New, master, []byte("bkd/subkey/v1"), []byte(info))

	sub := make(Key, KeyLen)
	if _, err := io.ReadFull(r, sub); err != nil {
		return nil, fmt.Errorf("vault: derive subkey %q: %w", info, err)
	}
	return sub, nil
}

// Subkey purposes. Each is a stable string; changing one invalidates every
// value previously signed or encrypted under it.
const (
	// SubkeyOIDCState signs the short-lived cookie carrying the OIDC state,
	// nonce and PKCE verifier through the Entra redirect.
	SubkeyOIDCState = "oidc-state-cookie"

	// SubkeyCSRF signs double-submit CSRF tokens.
	SubkeyCSRF = "csrf-token"

	// SubkeySessionID derives the lookup hash for opaque session tokens.
	SubkeySessionID = "session-token-hash"
)
