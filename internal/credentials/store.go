package credentials

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Kind names a category of secret.
type Kind string

const (
	KindSSHKey       Kind = "ssh_key"
	KindPassword     Kind = "password"
	KindPassphrase   Kind = "passphrase"
	KindEnableSecret Kind = "enable_secret"
)

// Validate rejects an unknown kind.
func (k Kind) Validate() error {
	switch k {
	case KindSSHKey, KindPassword, KindPassphrase, KindEnableSecret:
		return nil
	default:
		return fmt.Errorf("credentials: unknown kind %q", k)
	}
}

// Field names within a credential. These become part of the AAD, so a
// ciphertext cannot be moved from one field to another.
const (
	fieldSecret = "secret"
	fieldExtra  = "secret_extra"
)

// Errors returned by this package.
var (
	ErrNotFound  = errors.New("credentials: no such credential")
	ErrForbidden = errors.New("credentials: this credential belongs to someone else")
	ErrNoSecret  = errors.New("credentials: this credential holds no secret")
)

// Credential is a stored secret, without the secret.
//
// This is what listing and detail views return. The private material is never
// a field here, so it cannot be leaked by a handler that serialises the whole
// struct — the mistake this shape exists to make impossible.
type Credential struct {
	ID       string
	OwnerID  string
	IsTeam   bool
	Name     string
	Kind     Kind
	Username string

	// Safe to store and show in the clear. Keeping these unencrypted is what
	// lets the credential list render without unlocking the vault.
	PublicKey   string
	Fingerprint string
	KeyType     string

	// ServerUnlockable marks a credential wrapped under the server master key
	// for unattended use. Surfaced prominently because it is a deliberate
	// weakening.
	ServerUnlockable bool

	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastUsedAt *time.Time
}

// Store persists credentials.
type Store struct {
	db  *store.DB
	now func() time.Time
}

// NewStore builds a Store.
func NewStore(db *store.DB) *Store {
	return &Store{db: db, now: time.Now}
}

const credentialColumns = `
	id, user_id, team_id, name, kind, username,
	public_key, fingerprint, key_type, server_unlockable,
	created_at, updated_at, last_used_at`

// CreateParams describes a credential to store.
type CreateParams struct {
	OwnerID string
	IsTeam  bool

	Name     string
	Kind     Kind
	Username string

	// Secret is the private key or password. Encrypted before storage.
	Secret string

	// Extra is an optional second secret — a key passphrase, typically.
	Extra string

	// PublicKey, Fingerprint and KeyType are stored in the clear.
	PublicKey   string
	Fingerprint string
	KeyType     string
}

// Create encrypts and stores a credential.
//
// key is the owner's unwrapped vault key. It is used and not retained.
func (s *Store) Create(ctx context.Context, key vault.Key, p CreateParams) (Credential, error) {
	if p.OwnerID == "" {
		return Credential{}, errors.New("credentials: an owner is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return Credential{}, errors.New("credentials: a name is required")
	}
	if err := p.Kind.Validate(); err != nil {
		return Credential{}, err
	}

	now := s.now().UTC()
	c := Credential{
		ID:          uuid.Must(uuid.NewV7()).String(),
		OwnerID:     p.OwnerID,
		IsTeam:      p.IsTeam,
		Name:        strings.TrimSpace(p.Name),
		Kind:        p.Kind,
		Username:    strings.TrimSpace(p.Username),
		PublicKey:   p.PublicKey,
		Fingerprint: p.Fingerprint,
		KeyType:     p.KeyType,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	secretEnc, err := sealField(key, p.OwnerID, c.ID, fieldSecret, p.Secret)
	if err != nil {
		return Credential{}, err
	}
	extraEnc, err := sealField(key, p.OwnerID, c.ID, fieldExtra, p.Extra)
	if err != nil {
		return Credential{}, err
	}

	var userID, teamID any
	if p.IsTeam {
		teamID = p.OwnerID
	} else {
		userID = p.OwnerID
	}

	_, err = s.db.Exec(ctx, `
		INSERT INTO credentials
			(id, user_id, team_id, name, kind, username,
			 secret_enc, secret_extra_enc, public_key, fingerprint, key_type,
			 server_unlockable, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		c.ID, userID, teamID, c.Name, string(c.Kind), c.Username,
		secretEnc, extraEnc, c.PublicKey, c.Fingerprint, c.KeyType,
		formatTime(c.CreatedAt), formatTime(c.UpdatedAt))
	if err != nil {
		return Credential{}, fmt.Errorf("credentials: create: %w", err)
	}
	return c, nil
}

// sealField encrypts one field, returning "" for an empty value so an absent
// secret is stored as NULL rather than as the ciphertext of an empty string.
func sealField(key vault.Key, ownerID, credentialID, field, plaintext string) (any, error) {
	if plaintext == "" {
		return nil, nil
	}
	env, err := vault.Seal(key, vault.CredentialAAD(ownerID, credentialID, field), []byte(plaintext))
	if err != nil {
		return nil, fmt.Errorf("credentials: encrypt %s: %w", field, err)
	}
	encoded, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("credentials: encode %s: %w", field, err)
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

// openField decrypts one field.
func openField(key vault.Key, ownerID, credentialID, field string, stored sql.NullString) (string, error) {
	if !stored.Valid || stored.String == "" {
		return "", nil
	}

	raw, err := base64.StdEncoding.DecodeString(stored.String)
	if err != nil {
		return "", fmt.Errorf("credentials: decode %s: %w", field, err)
	}
	var env vault.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("credentials: parse %s: %w", field, err)
	}

	plaintext, err := vault.Open(key, vault.CredentialAAD(ownerID, credentialID, field), env)
	if err != nil {
		return "", fmt.Errorf("credentials: decrypt %s: %w", field, err)
	}
	return string(plaintext), nil
}

// Get returns a credential's metadata, without its secret.
func (s *Store) Get(ctx context.Context, ownerID, id string) (Credential, error) {
	row := s.db.QueryRow(ctx, `SELECT`+credentialColumns+` FROM credentials WHERE id = ?`, id)
	c, err := scanCredential(row)
	if err != nil {
		return Credential{}, err
	}
	if c.OwnerID != ownerID {
		// Reported as not-found rather than forbidden: confirming that a
		// credential exists but belongs to someone else is itself a small
		// disclosure.
		return Credential{}, ErrNotFound
	}
	return c, nil
}

// Secret describes a decrypted credential.
//
// Returned only by Reveal. Zero it once used.
type Secret struct {
	Value string
	Extra string
}

// Zero overwrites the decrypted strings as far as Go allows.
//
// Strings are immutable, so this cannot scrub the original backing array; it
// drops the references and leaves the rest to the garbage collector. Callers
// holding especially sensitive material for long periods should use []byte.
func (s *Secret) Zero() {
	s.Value = ""
	s.Extra = ""
}

// Reveal decrypts a credential's secret.
//
// The one method that returns private key material. Named so that a reviewer
// scanning call sites can find every place it happens, and expected to be
// paired with an audit event at each of them.
func (s *Store) Reveal(ctx context.Context, key vault.Key, ownerID, id string) (Secret, error) {
	row := s.db.QueryRow(ctx,
		`SELECT user_id, team_id, secret_enc, secret_extra_enc FROM credentials WHERE id = ?`, id)

	var (
		userID, teamID      sql.NullString
		secretEnc, extraEnc sql.NullString
	)
	err := row.Scan(&userID, &teamID, &secretEnc, &extraEnc)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	if err != nil {
		return Secret{}, fmt.Errorf("credentials: read secret: %w", err)
	}

	owner := userID.String
	if teamID.Valid && teamID.String != "" {
		owner = teamID.String
	}
	if owner != ownerID {
		return Secret{}, ErrNotFound
	}

	value, err := openField(key, owner, id, fieldSecret, secretEnc)
	if err != nil {
		return Secret{}, err
	}
	extra, err := openField(key, owner, id, fieldExtra, extraEnc)
	if err != nil {
		return Secret{}, err
	}
	if value == "" && extra == "" {
		return Secret{}, ErrNoSecret
	}

	return Secret{Value: value, Extra: extra}, nil
}

// List returns an owner's credentials, newest first.
//
// Deliberately does not need the vault key: the fields shown in a list are
// stored in the clear, so the credential list renders on a locked vault.
func (s *Store) List(ctx context.Context, ownerID string, isTeam bool) ([]Credential, error) {
	column := "user_id"
	if isTeam {
		column = "team_id"
	}

	// #nosec G201 -- column is one of two literals chosen above, never input
	query := `SELECT` + credentialColumns + ` FROM credentials WHERE ` + column + ` = ? ORDER BY created_at DESC`

	rows, err := s.db.Query(ctx, query, ownerID)
	if err != nil {
		return nil, fmt.Errorf("credentials: list: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("credentials: iterate: %w", err)
	}
	return out, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanCredential(row rowScanner) (Credential, error) {
	var (
		c                Credential
		userID, teamID   sql.NullString
		kind             string
		unlockable       int
		created, updated string
		lastUsed         sql.NullString
	)

	err := row.Scan(&c.ID, &userID, &teamID, &c.Name, &kind, &c.Username,
		&c.PublicKey, &c.Fingerprint, &c.KeyType, &unlockable,
		&created, &updated, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, fmt.Errorf("credentials: read: %w", err)
	}

	c.Kind = Kind(kind)
	c.ServerUnlockable = unlockable != 0
	if teamID.Valid && teamID.String != "" {
		c.OwnerID, c.IsTeam = teamID.String, true
	} else {
		c.OwnerID = userID.String
	}

	if c.CreatedAt, err = parseTime(created); err != nil {
		return Credential{}, err
	}
	if c.UpdatedAt, err = parseTime(updated); err != nil {
		return Credential{}, err
	}
	if lastUsed.Valid && lastUsed.String != "" {
		t, err := parseTime(lastUsed.String)
		if err != nil {
			return Credential{}, err
		}
		c.LastUsedAt = &t
	}

	return c, nil
}

// UpdateParams describes a metadata change. Nil fields are left alone.
type UpdateParams struct {
	Name     *string
	Username *string
}

// Update changes a credential's metadata.
//
// Deliberately cannot change the secret. Replacing key material is a
// create-then-delete, so the audit log shows a new credential appearing
// rather than an existing one silently becoming a different key.
func (s *Store) Update(ctx context.Context, ownerID, id string, p UpdateParams) (Credential, error) {
	existing, err := s.Get(ctx, ownerID, id)
	if err != nil {
		return Credential{}, err
	}

	name := existing.Name
	if p.Name != nil {
		if strings.TrimSpace(*p.Name) == "" {
			return Credential{}, errors.New("credentials: a name is required")
		}
		name = strings.TrimSpace(*p.Name)
	}
	username := existing.Username
	if p.Username != nil {
		username = strings.TrimSpace(*p.Username)
	}

	now := s.now().UTC()
	if _, err := s.db.Exec(ctx,
		`UPDATE credentials SET name = ?, username = ?, updated_at = ? WHERE id = ?`,
		name, username, formatTime(now), id); err != nil {
		return Credential{}, fmt.Errorf("credentials: update: %w", err)
	}

	existing.Name, existing.Username, existing.UpdatedAt = name, username, now
	return existing, nil
}

// Delete removes a credential.
func (s *Store) Delete(ctx context.Context, ownerID, id string) error {
	if _, err := s.Get(ctx, ownerID, id); err != nil {
		return err
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM credentials WHERE id = ?`, id); err != nil {
		return fmt.Errorf("credentials: delete: %w", err)
	}
	return nil
}

// MarkUsed records that a credential was used to open a connection.
func (s *Store) MarkUsed(ctx context.Context, id string) error {
	if _, err := s.db.Exec(ctx, `UPDATE credentials SET last_used_at = ? WHERE id = ?`,
		formatTime(s.now().UTC()), id); err != nil {
		return fmt.Errorf("credentials: mark used: %w", err)
	}
	return nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("credentials: unparseable timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}
