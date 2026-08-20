package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// EnvelopeVersion identifies the wire format of a sealed value. It is bound
// into the AAD, so a downgrade to an older, weaker format cannot be forced by
// editing the stored record.
const EnvelopeVersion uint8 = 1

// Envelope is an AES-256-GCM ciphertext together with its nonce. It is the
// only shape in which secret material is written to the database.
type Envelope struct {
	Version    uint8  `json:"v"`
	Nonce      []byte `json:"n"`
	Ciphertext []byte `json:"c"`
}

// AAD identifies what a ciphertext belongs to. Every field is authenticated
// but not encrypted, which is what prevents an attacker with database write
// access from relocating a ciphertext to a different owner or record.
//
// Scope distinguishes categories of secret (for example "credential",
// "team-dek", "bundle") so that a value sealed for one purpose cannot be
// presented as another.
type AAD struct {
	Scope     string
	OwnerID   string
	RecordID  string
	FieldName string
}

// MaxAADComponent bounds each AAD component.
//
// These are identifiers — a scope name, a UUID, a field name — so 1 KiB is
// generous. The bound is a correctness requirement, not just hygiene: the
// length prefix below is 32 bits, and a component long enough to wrap that
// counter would let two different identities encode identically, which is
// precisely the collision the prefixing exists to prevent.
const MaxAADComponent = 1024

// ErrAADTooLong means an AAD component exceeded MaxAADComponent.
var ErrAADTooLong = errors.New("vault: AAD component exceeds the maximum length")

// bytes serialises the AAD unambiguously.
//
// Each component is length-prefixed rather than delimiter-joined. Naive
// concatenation would let ("ab", "c") and ("a", "bc") produce identical AAD,
// which is exactly the kind of collision an attacker would hunt for.
//
// Callers must have run Validate first, which enforces MaxAADComponent; the
// panic below is unreachable in normal operation and exists so that a future
// code path bypassing Validate fails loudly rather than silently producing a
// forgeable encoding.
func (a AAD) bytes() []byte {
	parts := [...]string{a.Scope, a.OwnerID, a.RecordID, a.FieldName}

	n := 1 // version byte
	for _, p := range parts {
		if len(p) > MaxAADComponent {
			panic("vault: AAD component exceeds MaxAADComponent; Validate was not called")
		}
		n += 4 + len(p)
	}

	buf := make([]byte, 0, n)
	buf = append(buf, EnvelopeVersion)
	for _, p := range parts {
		var l [4]byte
		// Safe: bounded by MaxAADComponent above, far below math.MaxUint32.
		binary.BigEndian.PutUint32(l[:], uint32(len(p))) // #nosec G115
		buf = append(buf, l[:]...)
		buf = append(buf, p...)
	}
	return buf
}

// Validate rejects an AAD that fails to identify anything, which would defeat
// the binding it exists to provide, or whose components are long enough to
// threaten the length-prefix encoding.
func (a AAD) Validate() error {
	if a.Scope == "" {
		return errors.New("vault: AAD scope must not be empty")
	}
	if a.OwnerID == "" {
		return errors.New("vault: AAD owner must not be empty")
	}
	for name, p := range map[string]string{
		"scope": a.Scope, "owner": a.OwnerID,
		"record": a.RecordID, "field": a.FieldName,
	} {
		if len(p) > MaxAADComponent {
			return fmt.Errorf("%w: %s is %d bytes, limit is %d", ErrAADTooLong, name, len(p), MaxAADComponent)
		}
	}
	return nil
}

// newGCM builds an AES-256-GCM AEAD from key.
func newGCM(key Key) (cipher.AEAD, error) {
	if err := key.validate(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	return gcm, nil
}

// Seal encrypts plaintext under key, binding the result to aad.
//
// A fresh random nonce is drawn for every call. GCM nonce reuse under the same
// key is catastrophic — it leaks the authentication subkey — so nonces are
// never derived from a counter or from record identity here.
func Seal(key Key, aad AAD, plaintext []byte) (Envelope, error) {
	if err := aad.Validate(); err != nil {
		return Envelope{}, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return Envelope{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("vault: generate nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, plaintext, aad.bytes())
	return Envelope{Version: EnvelopeVersion, Nonce: nonce, Ciphertext: ct}, nil
}

// Open authenticates and decrypts env under key and aad.
//
// Any mismatch — wrong key, altered ciphertext, altered nonce, or an AAD
// naming a different owner, record, field or scope — returns ErrTampered with
// no further detail. Distinguishing the causes would hand an attacker an
// oracle for probing the database.
func Open(key Key, aad AAD, env Envelope) ([]byte, error) {
	if err := aad.Validate(); err != nil {
		return nil, err
	}
	if env.Version != EnvelopeVersion {
		return nil, fmt.Errorf("vault: unsupported envelope version %d", env.Version)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(env.Nonce) != gcm.NonceSize() {
		return nil, ErrTampered
	}

	pt, err := gcm.Open(nil, env.Nonce, env.Ciphertext, aad.bytes())
	if err != nil {
		return nil, ErrTampered
	}
	return pt, nil
}

// WrappedKey is a DEK encrypted under a key-encryption key, stored with the
// KDF parameters needed to reproduce that KEK from a passphrase.
type WrappedKey struct {
	KDF      KDFParams `json:"kdf"`
	Envelope Envelope  `json:"env"`
}

// wrapAAD is the binding used for a user's own wrapped DEK.
func wrapAAD(ownerID string) AAD {
	return AAD{Scope: "user-dek", OwnerID: ownerID, FieldName: "dek"}
}

// NewUserKey creates a fresh DEK for a user and wraps it under a KEK derived
// from their vault passphrase.
//
// It returns both the plaintext DEK — which the caller should install in the
// session cache and eventually Zero — and the wrapped form to persist.
func NewUserKey(ownerID string, passphrase []byte) (Key, WrappedKey, error) {
	params, err := DefaultKDFParams()
	if err != nil {
		return nil, WrappedKey{}, err
	}

	kek, err := DeriveKEK(passphrase, params)
	if err != nil {
		return nil, WrappedKey{}, err
	}
	defer kek.Zero()

	dek, err := NewKey()
	if err != nil {
		return nil, WrappedKey{}, err
	}

	env, err := Seal(kek, wrapAAD(ownerID), dek)
	if err != nil {
		dek.Zero()
		return nil, WrappedKey{}, err
	}
	return dek, WrappedKey{KDF: params, Envelope: env}, nil
}

// UnwrapUserKey recovers a user's DEK from their passphrase.
//
// A wrong passphrase and a tampered record both yield ErrWrongPassphrase.
func UnwrapUserKey(ownerID string, passphrase []byte, wk WrappedKey) (Key, error) {
	kek, err := DeriveKEK(passphrase, wk.KDF)
	if err != nil {
		return nil, err
	}
	defer kek.Zero()

	dek, err := Open(kek, wrapAAD(ownerID), wk.Envelope)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	if len(dek) != KeyLen {
		return nil, ErrWrongPassphrase
	}
	return Key(dek), nil
}

// RewrapUserKey re-encrypts an existing DEK under a new passphrase.
//
// This is how a passphrase change works: the DEK itself is unchanged, so none
// of the user's credentials need re-encrypting. Only the small wrapped-key
// record is rewritten, which keeps the operation atomic and fast even for a
// user with thousands of saved sessions.
func RewrapUserKey(ownerID string, dek Key, newPassphrase []byte) (WrappedKey, error) {
	if err := dek.validate(); err != nil {
		return WrappedKey{}, err
	}
	params, err := DefaultKDFParams()
	if err != nil {
		return WrappedKey{}, err
	}

	kek, err := DeriveKEK(newPassphrase, params)
	if err != nil {
		return WrappedKey{}, err
	}
	defer kek.Zero()

	env, err := Seal(kek, wrapAAD(ownerID), dek)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{KDF: params, Envelope: env}, nil
}

// SealKeyUnder wraps one key under another. This is the mechanism behind
// shared team credentials: a team's DEK is sealed once per member under that
// member's personal DEK, so revoking a member is a single row delete and no
// plaintext ever leaves the process.
func SealKeyUnder(outer Key, aad AAD, inner Key) (Envelope, error) {
	if err := inner.validate(); err != nil {
		return Envelope{}, err
	}
	return Seal(outer, aad, inner)
}

// OpenKeyFrom unwraps a key sealed by SealKeyUnder.
func OpenKeyFrom(outer Key, aad AAD, env Envelope) (Key, error) {
	raw, err := Open(outer, aad, env)
	if err != nil {
		return nil, err
	}
	k := Key(raw)
	if err := k.validate(); err != nil {
		k.Zero()
		return nil, ErrTampered
	}
	return k, nil
}

// TeamAAD is the binding for a team DEK sealed for one member.
func TeamAAD(teamID, memberID string) AAD {
	return AAD{Scope: "team-dek", OwnerID: memberID, RecordID: teamID, FieldName: "dek"}
}

// CredentialAAD is the binding for one field of one credential.
func CredentialAAD(ownerID, credentialID, field string) AAD {
	return AAD{Scope: "credential", OwnerID: ownerID, RecordID: credentialID, FieldName: field}
}
