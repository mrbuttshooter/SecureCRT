// Package users owns accounts: local and single-sign-on identity, vault
// enrolment, and the administrative lifecycle.
//
// It is the only package that writes to the users table, so the invariants
// below hold in one place rather than being restated at every call site.
package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/auth"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Errors returned by this package.
var (
	ErrNotFound      = errors.New("users: no such user")
	ErrEmailInUse    = errors.New("users: that email address is already registered")
	ErrDisabled      = errors.New("users: this account is disabled")
	ErrNoPassword    = errors.New("users: this account has no password; sign in with single sign-on")
	ErrVaultNotSetUp = errors.New("users: this account has no vault passphrase set")
	ErrInvalidEmail  = errors.New("users: invalid email address")
)

// UnlockKind is how a user's data-encryption key is wrapped.
type UnlockKind string

const (
	// UnlockUnset means no vault exists yet. Set on first enrolment.
	UnlockUnset UnlockKind = "unset"

	// UnlockDerived wraps the DEK under a key derived from the local login
	// password. A different salt is used from the password hash, so the
	// stored hash gives an attacker no head start on the vault.
	UnlockDerived UnlockKind = "derived"

	// UnlockSeparate wraps the DEK under a distinct vault passphrase.
	// Mandatory for SSO users: Entra returns an identity token, not a secret
	// the server could derive a key from.
	UnlockSeparate UnlockKind = "separate"

	// UnlockServer wraps the DEK under the server master key alone.
	//
	// Strictly weaker, and only reachable when an operator has set
	// sso_unlock_mode to server_managed: it means a stolen database plus the
	// master key opens every credential this user owns. Marked in the UI and
	// recorded in the audit log so the trade-off stays visible.
	UnlockServer UnlockKind = "server"
)

// User is an account.
type User struct {
	ID          string
	Email       string
	DisplayName string

	// PasswordHash is empty for accounts that only sign in via SSO.
	PasswordHash string

	UnlockKind UnlockKind
	WrappedDEK *vault.WrappedKey

	TOTPEnabled bool
	IsAdmin     bool
	IsDisabled  bool

	SSOProvider string
	SSOSubject  string
	SSOTenant   string

	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  *time.Time
	VaultResetAt *time.Time
}

// HasVault reports whether the user has enrolled a vault.
func (u User) HasVault() bool {
	return u.UnlockKind != UnlockUnset && u.UnlockKind != "" && u.WrappedDEK != nil
}

// IsSSO reports whether this account is backed by an external identity.
func (u User) IsSSO() bool { return u.SSOProvider != "" }

// CanSignInLocally reports whether a password sign-in is possible.
func (u User) CanSignInLocally() bool { return u.PasswordHash != "" }

// Store reads and writes accounts.
type Store struct {
	db  *store.DB
	now func() time.Time
}

// NewStore builds a Store.
func NewStore(db *store.DB) *Store {
	return &Store{db: db, now: time.Now}
}

// NormalizeEmail canonicalises an address for comparison.
//
// Lowercasing only. Deliberately not stripping dots or +tags: those rules are
// provider-specific, and applying Gmail's conventions to a corporate directory
// would merge accounts that the directory considers distinct.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ValidateEmail applies a deliberately loose check.
//
// Full RFC 5322 validation rejects addresses that work in practice, and the
// authoritative test is whether the directory recognises it. This catches
// typos and obvious nonsense, nothing more.
func ValidateEmail(email string) error {
	e := NormalizeEmail(email)
	if e == "" {
		return fmt.Errorf("%w: empty", ErrInvalidEmail)
	}
	if len(e) > 320 {
		return fmt.Errorf("%w: too long", ErrInvalidEmail)
	}
	at := strings.Index(e, "@")
	if at <= 0 || at == len(e)-1 {
		return fmt.Errorf("%w: %q must be local@domain", ErrInvalidEmail, email)
	}
	if strings.Count(e, "@") != 1 {
		return fmt.Errorf("%w: %q has more than one @", ErrInvalidEmail, email)
	}
	if strings.ContainsAny(e, " \t\r\n") {
		return fmt.Errorf("%w: %q contains whitespace", ErrInvalidEmail, email)
	}
	if !strings.Contains(e[at+1:], ".") {
		return fmt.Errorf("%w: %q has no domain suffix", ErrInvalidEmail, email)
	}
	return nil
}

const userColumns = `
	id, email, email_normalized, display_name, password_hash,
	wrapped_dek_enc, kdf_params, vault_unlock_kind,
	totp_enabled, is_admin, is_disabled,
	sso_provider, sso_subject, sso_tenant,
	created_at, updated_at, last_login_at, vault_reset_at`

// CreateParams describes a new account.
type CreateParams struct {
	Email       string
	DisplayName string

	// Password is optional. An account created without one can only sign in
	// via SSO, which is the normal case for an auto-provisioned user.
	Password string

	IsAdmin bool

	SSOProvider string
	SSOSubject  string
	SSOTenant   string
}

// Create makes an account.
//
// It does not enrol a vault: that needs a passphrase, which for an SSO user
// arrives after the first sign-in, not during provisioning.
func (s *Store) Create(ctx context.Context, p CreateParams) (User, error) {
	if err := ValidateEmail(p.Email); err != nil {
		return User{}, err
	}

	normalized := NormalizeEmail(p.Email)
	now := s.now().UTC()

	u := User{
		ID:          uuid.Must(uuid.NewV7()).String(),
		Email:       strings.TrimSpace(p.Email),
		DisplayName: strings.TrimSpace(p.DisplayName),
		UnlockKind:  UnlockUnset,
		IsAdmin:     p.IsAdmin,
		SSOProvider: p.SSOProvider,
		SSOSubject:  p.SSOSubject,
		SSOTenant:   p.SSOTenant,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if p.Password != "" {
		hash, err := auth.HashPassword([]byte(p.Password), auth.DefaultPasswordParams())
		if err != nil {
			return User{}, err
		}
		u.PasswordHash = hash
	}

	_, err := s.db.Exec(ctx, `
		INSERT INTO users
			(id, email, email_normalized, display_name, password_hash,
			 vault_unlock_kind, is_admin, sso_provider, sso_subject, sso_tenant,
			 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, normalized, u.DisplayName, u.PasswordHash,
		string(u.UnlockKind), boolToInt(u.IsAdmin),
		nullable(u.SSOProvider), nullable(u.SSOSubject), nullable(u.SSOTenant),
		formatTime(u.CreatedAt), formatTime(u.UpdatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrEmailInUse
		}
		return User{}, fmt.Errorf("users: create: %w", err)
	}
	return u, nil
}

// isUniqueViolation recognises a duplicate-key error from either driver.
//
// Matching on message text rather than a typed error keeps this working
// across both without importing driver-specific packages, at the cost of
// being a little blunt.
func isUniqueViolation(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "constraint failed")
}

// ByID returns a user by ID.
func (s *Store) ByID(ctx context.Context, id string) (User, error) {
	row := s.db.QueryRow(ctx, `SELECT`+userColumns+` FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// ByEmail returns a user by address, matched case-insensitively.
func (s *Store) ByEmail(ctx context.Context, email string) (User, error) {
	row := s.db.QueryRow(ctx, `SELECT`+userColumns+` FROM users WHERE email_normalized = ?`,
		NormalizeEmail(email))
	return scanUser(row)
}

// BySSO returns a user by external identity.
//
// Matching on provider and subject rather than email is deliberate: an email
// address can be reassigned to a new employee, whereas the directory object
// ID cannot. Matching on email would hand a new starter the previous holder's
// stored credentials.
func (s *Store) BySSO(ctx context.Context, provider, subject string) (User, error) {
	row := s.db.QueryRow(ctx,
		`SELECT`+userColumns+` FROM users WHERE sso_provider = ? AND sso_subject = ?`,
		provider, subject)
	return scanUser(row)
}

type rowScanner interface{ Scan(dest ...any) error }

func scanUser(row rowScanner) (User, error) {
	var (
		u                              User
		normalized                     string
		wrappedDEK, kdfParams          sql.NullString
		unlockKind                     string
		totpEnabled, isAdmin, disabled int
		provider, subject, tenant      sql.NullString
		created, updated               string
		lastLogin, vaultReset          sql.NullString
	)

	err := row.Scan(&u.ID, &u.Email, &normalized, &u.DisplayName, &u.PasswordHash,
		&wrappedDEK, &kdfParams, &unlockKind,
		&totpEnabled, &isAdmin, &disabled,
		&provider, &subject, &tenant,
		&created, &updated, &lastLogin, &vaultReset)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("users: read: %w", err)
	}

	u.UnlockKind = UnlockKind(unlockKind)
	u.TOTPEnabled = totpEnabled != 0
	u.IsAdmin = isAdmin != 0
	u.IsDisabled = disabled != 0
	u.SSOProvider = provider.String
	u.SSOSubject = subject.String
	u.SSOTenant = tenant.String

	if u.CreatedAt, err = parseTime(created); err != nil {
		return User{}, err
	}
	if u.UpdatedAt, err = parseTime(updated); err != nil {
		return User{}, err
	}
	if u.LastLoginAt, err = parseNullTime(lastLogin); err != nil {
		return User{}, err
	}
	if u.VaultResetAt, err = parseNullTime(vaultReset); err != nil {
		return User{}, err
	}

	if wrappedDEK.Valid && wrappedDEK.String != "" {
		wk, err := decodeWrappedKey(wrappedDEK.String, kdfParams.String)
		if err != nil {
			return User{}, err
		}
		u.WrappedDEK = &wk
	}

	return u, nil
}

// UpdateLastLogin records a successful sign-in.
func (s *Store) UpdateLastLogin(ctx context.Context, id string) error {
	now := formatTime(s.now().UTC())
	_, err := s.db.Exec(ctx, `UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?`,
		now, now, id)
	if err != nil {
		return fmt.Errorf("users: update last login: %w", err)
	}
	return nil
}

// UpdateProfile refreshes the display name and email from an SSO sign-in.
//
// Directory changes — a marriage, a department rename — should follow through
// rather than leaving a stale name in the interface. Identity itself is keyed
// on the SSO subject, so this never reassigns an account.
func (s *Store) UpdateProfile(ctx context.Context, id, email, displayName string) error {
	now := formatTime(s.now().UTC())

	if email != "" {
		if err := ValidateEmail(email); err != nil {
			return err
		}
		_, err := s.db.Exec(ctx,
			`UPDATE users SET email = ?, email_normalized = ?, display_name = ?, updated_at = ? WHERE id = ?`,
			strings.TrimSpace(email), NormalizeEmail(email), strings.TrimSpace(displayName), now, id)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrEmailInUse
			}
			return fmt.Errorf("users: update profile: %w", err)
		}
		return nil
	}

	_, err := s.db.Exec(ctx, `UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?`,
		strings.TrimSpace(displayName), now, id)
	if err != nil {
		return fmt.Errorf("users: update profile: %w", err)
	}
	return nil
}

// SetPassword sets or replaces the local login password.
func (s *Store) SetPassword(ctx context.Context, id, password string) error {
	if password == "" {
		return errors.New("users: password must not be empty")
	}
	hash, err := auth.HashPassword([]byte(password), auth.DefaultPasswordParams())
	if err != nil {
		return err
	}
	now := formatTime(s.now().UTC())
	if _, err := s.db.Exec(ctx, `UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		hash, now, id); err != nil {
		return fmt.Errorf("users: set password: %w", err)
	}
	return nil
}

// SetVault records a user's wrapped data-encryption key.
//
// The wrapped key and the KDF parameters go into separate columns so the
// parameters stay queryable — an operator raising the Argon2id cost can find
// which accounts are still on the old settings without decrypting anything.
func (s *Store) SetVault(ctx context.Context, id string, kind UnlockKind, wk vault.WrappedKey) error {
	switch kind {
	case UnlockDerived, UnlockSeparate, UnlockServer:
	default:
		return fmt.Errorf("users: %q is not a valid unlock kind for an enrolled vault", kind)
	}

	envelope, params, err := encodeWrappedKey(wk)
	if err != nil {
		return err
	}

	now := formatTime(s.now().UTC())
	_, err = s.db.Exec(ctx,
		`UPDATE users SET wrapped_dek_enc = ?, kdf_params = ?, vault_unlock_kind = ?, updated_at = ?
		 WHERE id = ?`,
		envelope, params, string(kind), now, id)
	if err != nil {
		return fmt.Errorf("users: set vault: %w", err)
	}
	return nil
}

// ResetVault discards a user's vault.
//
// Irreversible and destructive: every credential that user owns becomes
// permanently undecryptable, because the key that opened them is gone. That
// is the unavoidable cost of a design where the server cannot decrypt on its
// own. The credentials are deleted rather than left as unopenable rows, and
// the reset is stamped on the account so the interface can explain why the
// vault is empty instead of appearing to have lost data silently.
func (s *Store) ResetVault(ctx context.Context, id string) error {
	now := formatTime(s.now().UTC())

	return s.db.InTx(ctx, func(tx *store.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM credentials WHERE user_id = ?`, id); err != nil {
			return fmt.Errorf("users: delete credentials during vault reset: %w", err)
		}
		// Team keys were wrapped under the personal DEK, so those memberships
		// must be re-granted by a team admin afterwards.
		if _, err := tx.Exec(ctx, `DELETE FROM team_members WHERE user_id = ?`, id); err != nil {
			return fmt.Errorf("users: clear team memberships during vault reset: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_totp WHERE user_id = ?`, id); err != nil {
			return fmt.Errorf("users: clear TOTP during vault reset: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE users SET wrapped_dek_enc = NULL, kdf_params = NULL,
			                  vault_unlock_kind = ?, totp_enabled = 0,
			                  vault_reset_at = ?, updated_at = ?
			 WHERE id = ?`,
			string(UnlockUnset), now, now, id); err != nil {
			return fmt.Errorf("users: reset vault: %w", err)
		}
		return nil
	})
}

// SetAdmin grants or revokes administrator rights.
func (s *Store) SetAdmin(ctx context.Context, id string, admin bool) error {
	now := formatTime(s.now().UTC())
	if _, err := s.db.Exec(ctx, `UPDATE users SET is_admin = ?, updated_at = ? WHERE id = ?`,
		boolToInt(admin), now, id); err != nil {
		return fmt.Errorf("users: set admin: %w", err)
	}
	return nil
}

// SetDisabled disables or re-enables an account.
//
// Disabling does not delete anything: the user's credentials survive, so a
// suspension can be lifted. The caller must also revoke live sessions and
// purge cached keys — this only closes the front door.
func (s *Store) SetDisabled(ctx context.Context, id string, disabled bool) error {
	now := formatTime(s.now().UTC())
	if _, err := s.db.Exec(ctx, `UPDATE users SET is_disabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(disabled), now, id); err != nil {
		return fmt.Errorf("users: set disabled: %w", err)
	}
	return nil
}

// SetTOTPEnabled records whether TOTP is active.
func (s *Store) SetTOTPEnabled(ctx context.Context, id string, enabled bool) error {
	now := formatTime(s.now().UTC())
	if _, err := s.db.Exec(ctx, `UPDATE users SET totp_enabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled), now, id); err != nil {
		return fmt.Errorf("users: set TOTP state: %w", err)
	}
	return nil
}

// List returns accounts, oldest first.
func (s *Store) List(ctx context.Context, limit int) ([]User, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(ctx, `SELECT`+userColumns+` FROM users ORDER BY created_at ASC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("users: list: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("users: iterate: %w", err)
	}
	return out, nil
}

// CountAdmins returns how many enabled administrators exist.
//
// Used to refuse the last one being removed or disabled, which would leave
// nobody able to administer the system.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE is_admin = 1 AND is_disabled = 0`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("users: count admins: %w", err)
	}
	return n, nil
}

// Delete removes an account and everything it owns.
//
// Audit events survive: audit_events deliberately carries no foreign key on
// actor_id, so deleting an account does not erase what it did.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.Exec(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("users: delete: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}
