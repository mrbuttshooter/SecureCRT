// Package portability moves a user's world in and out of bkd.
//
// It exists because nobody should be locked in — not into SecureCRT, which is
// what this replaces, and not into this either. A team that adopts bkd and
// then decides against it must be able to leave with everything they brought
// and everything they made since.
//
// # The bundle
//
// A .bkbundle is a self-contained, encrypted archive of saved connections,
// folders, credentials and host key decisions. It is sealed under a
// passphrase given at export time, not under the vault key: a bundle is meant
// to survive being emailed, put on a memory stick, or restored onto an
// instance that has never heard of the person who made it.
//
// The header is deliberately in the clear. It has to be — the KDF salt and
// cost parameters cannot be inside the ciphertext they protect — and while it
// is there it may as well say enough for a person with three bundles to tell
// which is which without trying the passphrase on each. What that costs is
// stated plainly in docs/SECURITY.md: a bundle reveals when it was made, by
// which address, and roughly how much is in it.
package portability

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Errors callers distinguish.
var (
	// ErrNotABundle means the file is not in this format at all.
	ErrNotABundle = errors.New("portability: this is not a bkd bundle")

	// ErrUnsupportedVersion means the bundle is from a newer bkd.
	ErrUnsupportedVersion = errors.New("portability: this bundle was made by a newer version")

	// ErrWrongPassphrase means the bundle did not open. Indistinguishable
	// from tampering by design: telling the two apart would hand an attacker
	// an oracle.
	ErrWrongPassphrase = errors.New("portability: that passphrase did not open the bundle")

	// ErrBundleTooLarge means the archive exceeds what will be read into
	// memory.
	ErrBundleTooLarge = errors.New("portability: the bundle is too large")
)

// BundleFormat identifies the format in the clear header.
const BundleFormat = "bkbundle"

// BundleVersion is the format this build writes.
//
// Readers accept anything up to and including it and refuse anything above,
// so an old bkd meeting a new bundle says so rather than misreading it.
const BundleVersion = 1

// MaxBundleBytes bounds what will be read.
//
// Generous: a hundred thousand connections with keys is a few tens of
// megabytes. The limit exists so a malformed or hostile file cannot exhaust
// the process before it is even understood.
const MaxBundleBytes int64 = 256 << 20 // 256 MiB

// maxPayloadBytes bounds the decompressed payload.
//
// Separate from MaxBundleBytes because gzip expands: a small archive can
// decompress to something enormous, and a decompression bomb is the obvious
// way to attack a program that accepts archives.
const maxPayloadBytes = 512 << 20 // 512 MiB

// Header is the clear-text preamble of a bundle.
type Header struct {
	Format  string `json:"format"`
	Version int    `json:"version"`

	CreatedAt time.Time `json:"created_at"`

	// CreatedBy is the exporter's address, so a person can tell one bundle
	// from another. Empty when the exporter chose not to include it.
	CreatedBy string `json:"created_by,omitempty"`

	// Note is whatever the exporter wanted to write on the tin.
	Note string `json:"note,omitempty"`

	// KDF carries the parameters needed to reproduce the key from the
	// passphrase. It cannot be encrypted: it is what the decryption needs.
	KDF KDFHeader `json:"kdf"`

	Cipher string `json:"cipher"`

	// Contents lets an interface describe a bundle before asking for the
	// passphrase. See the package comment for what that reveals.
	Contents Counts `json:"contents"`
}

// KDFHeader is the key derivation in a form that survives JSON.
type KDFHeader struct {
	Algorithm string `json:"algorithm"`
	Time      uint32 `json:"time"`
	MemoryKB  uint32 `json:"memory_kb"`
	Threads   uint8  `json:"threads"`
	Salt      []byte `json:"salt"`
}

// Counts summarises what a bundle holds.
type Counts struct {
	Folders     int `json:"folders"`
	Sessions    int `json:"sessions"`
	Credentials int `json:"credentials"`
	KnownHosts  int `json:"known_hosts"`
}

// Total reports how many records a bundle carries in all.
func (c Counts) Total() int {
	return c.Folders + c.Sessions + c.Credentials + c.KnownHosts
}

// Payload is everything a bundle carries, once decrypted.
type Payload struct {
	Folders     []Folder     `json:"folders"`
	Sessions    []Session    `json:"sessions"`
	Credentials []Credential `json:"credentials"`
	KnownHosts  []KnownHost  `json:"known_hosts"`
}

// Counts summarises a payload.
func (p Payload) Counts() Counts {
	return Counts{
		Folders:     len(p.Folders),
		Sessions:    len(p.Sessions),
		Credentials: len(p.Credentials),
		KnownHosts:  len(p.KnownHosts),
	}
}

// Folder is a folder in the saved-connection tree.
//
// IDs travel with the records so references between them survive. They are
// remapped on import: keeping them would collide with whatever the receiving
// instance already has, and would let a crafted bundle overwrite existing
// rows by naming their identifiers.
type Folder struct {
	ID        string          `json:"id"`
	ParentID  string          `json:"parent_id,omitempty"`
	Name      string          `json:"name"`
	Defaults  json.RawMessage `json:"defaults,omitempty"`
	SortOrder int             `json:"sort_order,omitempty"`
}

// Session is one saved connection.
type Session struct {
	ID           string          `json:"id"`
	FolderID     string          `json:"folder_id,omitempty"`
	Name         string          `json:"name"`
	Protocol     string          `json:"protocol"`
	Hostname     string          `json:"hostname"`
	Port         int             `json:"port,omitempty"`
	Username     string          `json:"username,omitempty"`
	CredentialID string          `json:"credential_id,omitempty"`
	JumpChain    []string        `json:"jump_chain,omitempty"`
	Settings     json.RawMessage `json:"settings,omitempty"`
	SortOrder    int             `json:"sort_order,omitempty"`

	// EffectivePort is Port with folder inheritance applied, and is not part
	// of the bundle.
	//
	// A .bkbundle carries the folders and their defaults, so restoring it
	// reproduces the inheritance — writing a resolved value into the file
	// would pin every connection to whatever its folder said on the day it
	// was exported, and quietly break the "change the folder, change them
	// all" behaviour the export exists to preserve.
	//
	// The other formats have no folder defaults to carry, so for those the
	// resolved value is the only correct thing to write. Hence a field that
	// exists in memory and not on disk.
	EffectivePort int `json:"-"`
}

// DialPort is the port to write into a format that has no folder defaults.
//
// EffectivePort when Gather resolved one, the raw column otherwise. An
// override rather than a requirement, so a Payload assembled by hand — a
// test, or a caller that never had a folder tree — still exports the port it
// was given instead of silently exporting none.
func (s Session) DialPort() int {
	if s.EffectivePort > 0 {
		return s.EffectivePort
	}
	return s.Port
}

// Credential is a key or password, in the clear inside the sealed payload.
//
// This is the whole point of the format and the reason it is encrypted at
// all: a migration that leaves the passwords behind is not a migration.
type Credential struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Username string `json:"username,omitempty"`

	// Secret is the private key or the password.
	Secret string `json:"secret,omitempty"`

	// Extra is a key's passphrase, where it still has one.
	Extra string `json:"extra,omitempty"`

	PublicKey   string `json:"public_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
}

// KnownHost is a host key the exporter had accepted.
//
// Carried so a restored instance does not ask about every host again — which
// sounds like a convenience and is actually a security property: a user
// re-approving three hundred fingerprints in an afternoon is a user who has
// stopped reading them.
type KnownHost struct {
	Hostname    string `json:"hostname"`
	Port        int    `json:"port"`
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
}

// WriteOptions control an export.
type WriteOptions struct {
	Passphrase []byte

	// CreatedBy and Note go in the clear header.
	CreatedBy string
	Note      string

	// KDF overrides the cost parameters. Zero means the defaults, which are
	// deliberately expensive: a bundle is offline material and an attacker
	// who obtains one can attack the passphrase at their leisure.
	KDF vault.KDFParams
}

// MinPassphraseLength is the shortest passphrase a bundle will accept.
//
// A bundle leaves the building. Unlike a login, there is no rate limiter and
// no lockout between an attacker and the passphrase — only the cost of the
// KDF — so the floor is higher than it is for a password.
const MinPassphraseLength = 12

// Write seals a payload into a bundle.
func Write(w io.Writer, payload Payload, opts WriteOptions) error {
	if len(opts.Passphrase) < MinPassphraseLength {
		return fmt.Errorf("portability: a bundle passphrase must be at least %d characters",
			MinPassphraseLength)
	}

	params := opts.KDF
	if params.Time == 0 {
		defaults, err := vault.DefaultKDFParams()
		if err != nil {
			return err
		}
		params = defaults
	}
	if len(params.Salt) == 0 {
		salt, err := vault.NewSalt()
		if err != nil {
			return err
		}
		params.Salt = salt
	}
	if err := params.Validate(); err != nil {
		return err
	}

	header := Header{
		Format:    BundleFormat,
		Version:   BundleVersion,
		CreatedAt: time.Now().UTC(),
		CreatedBy: opts.CreatedBy,
		Note:      opts.Note,
		Cipher:    "aes-256-gcm",
		Contents:  payload.Counts(),
		KDF: KDFHeader{
			Algorithm: "argon2id",
			Time:      params.Time,
			MemoryKB:  params.MemoryKB,
			Threads:   params.Threads,
			Salt:      params.Salt,
		},
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("portability: encode header: %w", err)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("portability: encode payload: %w", err)
	}

	compressed, err := compress(body)
	if err != nil {
		return err
	}

	key, err := vault.DeriveKEK(opts.Passphrase, params)
	if err != nil {
		return err
	}
	defer key.Zero()

	envelope, err := vault.Seal(key, bundleAAD(headerJSON), compressed)
	if err != nil {
		return err
	}

	sealed, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("portability: encode envelope: %w", err)
	}

	// Two lines: the header, then the sealed payload. Line-oriented so the
	// header can be read without parsing — or trusting — anything after it.
	if _, err := w.Write(append(headerJSON, '\n')); err != nil {
		return fmt.Errorf("portability: write header: %w", err)
	}
	if _, err := w.Write(append(sealed, '\n')); err != nil {
		return fmt.Errorf("portability: write payload: %w", err)
	}
	return nil
}

// bundleAAD binds a sealed payload to its exact header.
//
// Without it a header could be swapped between bundles — a smaller record
// count to hide what was taken, a different exporter's name. The KDF fields
// are already protected by the fact that changing them changes the key, but
// binding the whole header costs nothing and covers the rest.
func bundleAAD(headerJSON []byte) vault.AAD {
	sum := sha256.Sum256(headerJSON)
	return vault.AAD{
		Scope:     "bundle",
		OwnerID:   BundleFormat,
		RecordID:  hex.EncodeToString(sum[:]),
		FieldName: "payload",
	}
}

// Bundle is a bundle that has been read but not necessarily opened.
type Bundle struct {
	Header Header

	headerJSON []byte
	envelope   vault.Envelope
}

// Read parses a bundle's header without needing the passphrase.
//
// Separate from Open so an interface can describe a file — when it was made,
// by whom, how much is in it — before asking anybody to type a passphrase at
// it. Being told "wrong passphrase" for a file that was never a bundle is a
// poor way to learn you picked the wrong one.
func Read(r io.Reader) (*Bundle, error) {
	return read(r, MaxBundleBytes)
}

// read is Read with the limit as a parameter, so the size guard can be
// exercised without a test allocating a quarter of a gigabyte to trip it.
func read(r io.Reader, limit int64) (*Bundle, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("portability: read bundle: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, ErrBundleTooLarge
	}

	newline := bytes.IndexByte(data, '\n')
	if newline < 0 {
		return nil, ErrNotABundle
	}

	headerJSON := data[:newline]
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrNotABundle
	}
	if header.Format != BundleFormat {
		return nil, ErrNotABundle
	}
	if header.Version > BundleVersion {
		return nil, fmt.Errorf("%w: this bundle is version %d, this build reads up to %d",
			ErrUnsupportedVersion, header.Version, BundleVersion)
	}
	if header.KDF.Algorithm != "argon2id" {
		return nil, fmt.Errorf("portability: unsupported key derivation %q", header.KDF.Algorithm)
	}

	rest := bytes.TrimSpace(data[newline+1:])
	if len(rest) == 0 {
		return nil, ErrNotABundle
	}

	var envelope vault.Envelope
	if err := json.Unmarshal(rest, &envelope); err != nil {
		return nil, ErrNotABundle
	}

	return &Bundle{Header: header, headerJSON: headerJSON, envelope: envelope}, nil
}

// Open decrypts a bundle's payload.
func (b *Bundle) Open(passphrase []byte) (Payload, error) {
	params := vault.KDFParams{
		Time:     b.Header.KDF.Time,
		MemoryKB: b.Header.KDF.MemoryKB,
		Threads:  b.Header.KDF.Threads,
		Salt:     b.Header.KDF.Salt,
	}
	// Validated rather than trusted: the parameters come from a file someone
	// else wrote, and a memory cost of 64 GiB would be a denial of service
	// dressed as a bundle.
	if err := params.Validate(); err != nil {
		return Payload{}, fmt.Errorf("portability: the bundle's key derivation parameters are unusable: %w", err)
	}

	key, err := vault.DeriveKEK(passphrase, params)
	if err != nil {
		return Payload{}, err
	}
	defer key.Zero()

	compressed, err := vault.Open(key, bundleAAD(b.headerJSON), b.envelope)
	if err != nil {
		// A wrong passphrase and a tampered bundle are the same answer.
		// Distinguishing them would say whether a guess was close.
		return Payload{}, ErrWrongPassphrase
	}

	body, err := decompress(compressed)
	if err != nil {
		return Payload{}, err
	}

	var payload Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		return Payload{}, fmt.Errorf("portability: the bundle's contents are unreadable: %w", err)
	}
	return payload, nil
}

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("portability: compress: %w", err)
	}
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("portability: compress: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("portability: compress: %w", err)
	}
	return buf.Bytes(), nil
}

// decompress expands a payload, refusing a decompression bomb.
func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("portability: the bundle's contents are unreadable: %w", err)
	}
	defer func() { _ = reader.Close() }()

	body, err := io.ReadAll(io.LimitReader(reader, maxPayloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("portability: the bundle's contents are unreadable: %w", err)
	}
	if len(body) > maxPayloadBytes {
		return nil, ErrBundleTooLarge
	}
	return body, nil
}
