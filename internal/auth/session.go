package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
)

// Session token shape and cookie names.
const (
	// SessionTokenBytes is the entropy in a session token. 256 bits makes
	// guessing hopeless, which matters because the token alone identifies a
	// logged-in user.
	SessionTokenBytes = 32

	// SessionCookieName holds the opaque session token.
	SessionCookieName = "bkd_session"

	// CSRFCookieName holds the double-submit CSRF token. Readable by
	// JavaScript by design — that is how the SPA echoes it back in a header,
	// which is the half of the check the browser cannot forge cross-origin.
	CSRFCookieName = "bkd_csrf"

	// CSRFHeaderName is where the SPA echoes the CSRF token.
	CSRFHeaderName = "X-CSRF-Token"
)

// Session errors.
var (
	// ErrSessionNotFound covers an unknown, expired or revoked token alike.
	// Callers must not distinguish them: telling an attacker that a token was
	// "valid but expired" confirms it was once real.
	ErrSessionNotFound = errors.New("auth: session not found or no longer valid")

	// ErrSessionExpired is used internally to decide whether to clean up a
	// row. It is never surfaced to an HTTP client.
	ErrSessionExpired = errors.New("auth: session expired")
)

// AuthMethod records how a session was established.
type AuthMethod string

const (
	// AuthMethodLocal is a username and password held by this system. Used
	// for break-glass admin access when SSO is unavailable.
	AuthMethodLocal AuthMethod = "local"

	// AuthMethodOIDC is a sign-in via Microsoft Entra.
	AuthMethodOIDC AuthMethod = "oidc"
)

// Session is a logged-in browser session.
//
// It carries no key material. The user's data-encryption key lives only in
// vault.Cache, keyed by Session.ID, and never touches the database.
type Session struct {
	ID            string
	UserID        string
	AuthMethod    AuthMethod
	MFASatisfied  bool
	VaultUnlocked bool
	UserAgent     string
	IPAddress     string
	CreatedAt     time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
}

// Active reports whether the session is usable at time now.
func (s Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt) && now.Before(s.IdleExpiresAt)
}

// SessionConfig controls session lifetimes.
type SessionConfig struct {
	// IdleTTL is how long a session survives without activity. Each
	// authenticated request pushes the idle deadline out.
	IdleTTL time.Duration

	// AbsoluteTTL is the hard ceiling. Activity never extends a session past
	// this, so a stolen token cannot be kept alive indefinitely by using it.
	AbsoluteTTL time.Duration

	// SecureCookies should be false only for local HTTP development. In
	// production TLS terminates upstream, so the cookie must still be marked
	// Secure even though bkd itself speaks plain HTTP to the proxy.
	SecureCookies bool
}

// DefaultSessionConfig returns sensible lifetimes.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		IdleTTL:       8 * time.Hour,
		AbsoluteTTL:   7 * 24 * time.Hour,
		SecureCookies: true,
	}
}

// Validate rejects nonsensical lifetimes.
func (c SessionConfig) Validate() error {
	if c.IdleTTL <= 0 {
		return errors.New("auth: session idle TTL must be positive")
	}
	if c.AbsoluteTTL <= 0 {
		return errors.New("auth: session absolute TTL must be positive")
	}
	if c.IdleTTL > c.AbsoluteTTL {
		return fmt.Errorf("auth: idle TTL (%s) must not exceed absolute TTL (%s)", c.IdleTTL, c.AbsoluteTTL)
	}
	return nil
}

// SessionStore persists sessions.
type SessionStore struct {
	db  *store.DB
	cfg SessionConfig
	now func() time.Time
}

// NewSessionStore builds a SessionStore.
func NewSessionStore(db *store.DB, cfg SessionConfig) (*SessionStore, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &SessionStore{db: db, cfg: cfg, now: time.Now}, nil
}

// hashToken is the one-way mapping from a token to its database key.
//
// SHA-256 without a work factor is correct here, unlike for passwords: the
// token is 256 bits of uniform randomness, so there is no dictionary to
// attack and a slow hash would only add latency to every request. What this
// buys is that a database dump yields no usable tokens.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newToken returns a fresh URL-safe session token.
func newToken() (string, error) {
	raw := make([]byte, SessionTokenBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("auth: generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// CreateSessionParams describes a session to create.
type CreateSessionParams struct {
	UserID       string
	AuthMethod   AuthMethod
	MFASatisfied bool
	UserAgent    string
	IPAddress    string
}

// Create issues a new session and returns the plaintext token.
//
// The token is returned exactly once, here. Only its hash is stored, so it
// cannot be recovered afterwards — not by an operator, not by an attacker
// with a database dump.
func (s *SessionStore) Create(ctx context.Context, p CreateSessionParams) (Session, string, error) {
	if p.UserID == "" {
		return Session{}, "", errors.New("auth: session requires a user")
	}
	switch p.AuthMethod {
	case AuthMethodLocal, AuthMethodOIDC:
	default:
		return Session{}, "", fmt.Errorf("auth: unknown auth method %q", p.AuthMethod)
	}

	token, err := newToken()
	if err != nil {
		return Session{}, "", err
	}

	now := s.now().UTC()
	sess := Session{
		ID:            uuid.Must(uuid.NewV7()).String(),
		UserID:        p.UserID,
		AuthMethod:    p.AuthMethod,
		MFASatisfied:  p.MFASatisfied,
		UserAgent:     truncate(p.UserAgent, 512),
		IPAddress:     truncate(p.IPAddress, 64),
		CreatedAt:     now,
		IdleExpiresAt: now.Add(s.cfg.IdleTTL),
		ExpiresAt:     now.Add(s.cfg.AbsoluteTTL),
	}

	_, err = s.db.Exec(ctx, `
		INSERT INTO auth_sessions
			(id, user_id, refresh_token_hash, user_agent, ip_address,
			 vault_unlocked, mfa_satisfied, auth_method,
			 created_at, idle_expires_at, expires_at)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, hashToken(token), sess.UserAgent, sess.IPAddress,
		boolToInt(sess.MFASatisfied), string(sess.AuthMethod),
		formatTime(sess.CreatedAt), formatTime(sess.IdleExpiresAt), formatTime(sess.ExpiresAt),
	)
	if err != nil {
		return Session{}, "", fmt.Errorf("auth: create session: %w", err)
	}

	return sess, token, nil
}

// Lookup resolves a token to its session and refreshes the idle deadline.
//
// Refreshing on read is what keeps a working user signed in while still
// expiring an abandoned session on schedule. The refresh is clamped to
// ExpiresAt, so activity can never extend a session past its hard ceiling.
func (s *SessionStore) Lookup(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, ErrSessionNotFound
	}

	sess, err := s.byTokenHash(ctx, hashToken(token))
	if err != nil {
		return Session{}, err
	}

	now := s.now().UTC()
	if !sess.Active(now) {
		// Expired or revoked sessions are removed on discovery, so the table
		// does not accumulate rows for logins nobody ever returns to.
		if sess.RevokedAt == nil {
			_ = s.deleteByID(ctx, sess.ID)
		}
		return Session{}, ErrSessionNotFound
	}

	newIdle := now.Add(s.cfg.IdleTTL)
	if newIdle.After(sess.ExpiresAt) {
		newIdle = sess.ExpiresAt
	}
	if _, err := s.db.Exec(ctx,
		`UPDATE auth_sessions SET idle_expires_at = ? WHERE id = ?`,
		formatTime(newIdle), sess.ID); err != nil {
		return Session{}, fmt.Errorf("auth: refresh session: %w", err)
	}
	sess.IdleExpiresAt = newIdle

	return sess, nil
}

func (s *SessionStore) byTokenHash(ctx context.Context, hash string) (Session, error) {
	row := s.db.QueryRow(ctx, `
		SELECT id, user_id, auth_method, mfa_satisfied, vault_unlocked,
		       user_agent, ip_address, created_at, idle_expires_at, expires_at, revoked_at
		FROM auth_sessions WHERE refresh_token_hash = ?`, hash)
	return scanSession(row)
}

// Get returns a session by ID without refreshing it.
func (s *SessionStore) Get(ctx context.Context, id string) (Session, error) {
	row := s.db.QueryRow(ctx, `
		SELECT id, user_id, auth_method, mfa_satisfied, vault_unlocked,
		       user_agent, ip_address, created_at, idle_expires_at, expires_at, revoked_at
		FROM auth_sessions WHERE id = ?`, id)
	return scanSession(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSession(row rowScanner) (Session, error) {
	var (
		sess          Session
		method        string
		mfa, unlocked int
		idle          sql.NullString
		created, exp  string
		revoked       sql.NullString
	)

	err := row.Scan(&sess.ID, &sess.UserID, &method, &mfa, &unlocked,
		&sess.UserAgent, &sess.IPAddress, &created, &idle, &exp, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("auth: read session: %w", err)
	}

	sess.AuthMethod = AuthMethod(method)
	sess.MFASatisfied = mfa != 0
	sess.VaultUnlocked = unlocked != 0

	if sess.CreatedAt, err = parseTime(created); err != nil {
		return Session{}, err
	}
	if sess.ExpiresAt, err = parseTime(exp); err != nil {
		return Session{}, err
	}

	// idle_expires_at was added in migration 0002 and is nullable, so a row
	// written before it existed falls back to the absolute deadline rather
	// than being treated as already expired.
	sess.IdleExpiresAt = sess.ExpiresAt
	if idle.Valid && idle.String != "" {
		if sess.IdleExpiresAt, err = parseTime(idle.String); err != nil {
			return Session{}, err
		}
	}

	if revoked.Valid && revoked.String != "" {
		t, err := parseTime(revoked.String)
		if err != nil {
			return Session{}, err
		}
		sess.RevokedAt = &t
	}

	return sess, nil
}

// SetVaultUnlocked records whether the vault is open for this session.
//
// This column is a UI hint only. The key itself lives in vault.Cache; nothing
// here can decrypt anything.
func (s *SessionStore) SetVaultUnlocked(ctx context.Context, id string, unlocked bool) error {
	_, err := s.db.Exec(ctx,
		`UPDATE auth_sessions SET vault_unlocked = ? WHERE id = ?`,
		boolToInt(unlocked), id)
	if err != nil {
		return fmt.Errorf("auth: update vault state: %w", err)
	}
	return nil
}

// SetMFASatisfied marks a second factor as completed for this session.
func (s *SessionStore) SetMFASatisfied(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `UPDATE auth_sessions SET mfa_satisfied = 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("auth: update MFA state: %w", err)
	}
	return nil
}

// Revoke marks a single session as revoked. Used on logout.
func (s *SessionStore) Revoke(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		formatTime(s.now().UTC()), id)
	if err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	return nil
}

// RevokeAllForUser revokes every live session belonging to a user and returns
// how many were affected.
//
// Called on password change, vault passphrase change, MFA changes and admin
// disable. The caller must also purge that user's keys from vault.Cache —
// revoking the row does not by itself clear the decrypted key from memory.
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) (int, error) {
	res, err := s.db.Exec(ctx,
		`UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		formatTime(s.now().UTC()), userID)
	if err != nil {
		return 0, fmt.Errorf("auth: revoke user sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil // not all drivers report this; the revocation still happened
	}
	return int(n), nil
}

// RevokeAllForUserExcept revokes a user's sessions apart from one.
//
// This is the "sign out everywhere else" action, and the shape wanted after a
// password change made by the user themselves: every other device is cut off
// while the device they are holding stays usable.
func (s *SessionStore) RevokeAllForUserExcept(ctx context.Context, userID, keepSessionID string) (int, error) {
	res, err := s.db.Exec(ctx,
		`UPDATE auth_sessions SET revoked_at = ?
		 WHERE user_id = ? AND id <> ? AND revoked_at IS NULL`,
		formatTime(s.now().UTC()), userID, keepSessionID)
	if err != nil {
		return 0, fmt.Errorf("auth: revoke other sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return int(n), nil
}

// ListForUser returns a user's live sessions, newest first, for the "where am
// I signed in" screen.
func (s *SessionStore) ListForUser(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, user_id, auth_method, mfa_satisfied, vault_unlocked,
		       user_agent, ip_address, created_at, idle_expires_at, expires_at, revoked_at
		FROM auth_sessions
		WHERE user_id = ? AND revoked_at IS NULL
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: list sessions: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	now := s.now().UTC()
	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		if sess.Active(now) {
			out = append(out, sess)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: iterate sessions: %w", err)
	}
	return out, nil
}

func (s *SessionStore) deleteByID(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM auth_sessions WHERE id = ?`, id)
	return err
}

// PurgeExpired deletes sessions past their absolute deadline, and revoked
// sessions older than a grace period.
//
// Revoked rows are kept briefly rather than deleted immediately so that an
// investigation into a compromised account can still see them.
func (s *SessionStore) PurgeExpired(ctx context.Context, revokedGrace time.Duration) (int, error) {
	now := s.now().UTC()

	res, err := s.db.Exec(ctx,
		`DELETE FROM auth_sessions
		 WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)`,
		formatTime(now), formatTime(now.Add(-revokedGrace)))
	if err != nil {
		return 0, fmt.Errorf("auth: purge sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return int(n), nil
}

// SessionCookie builds the Set-Cookie for a freshly issued token.
//
// SameSite=Strict is deliberate. It means a link from a chat client into this
// app lands the user on a signed-out page until they navigate once — a small
// annoyance in exchange for closing the cross-site request forgery class
// almost entirely, before the CSRF token is even considered.
func (c SessionConfig) SessionCookie(token string) *http.Cookie {
	// #nosec G124 -- Secure is set from configuration rather than a literal,
	// which static analysis cannot follow. It defaults to true and the only
	// supported reason to disable it is local development over plain HTTP,
	// where a Secure cookie would simply never be sent. Startup logs a
	// warning when it is off.
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.SecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(c.AbsoluteTTL.Seconds()),
	}
}

// ClearSessionCookie builds the Set-Cookie that removes the session cookie.
func (c SessionConfig) ClearSessionCookie() *http.Cookie {
	// #nosec G124 -- see SessionCookie. The clearing cookie must carry the
	// same attributes as the one it replaces, or some browsers ignore it.
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   c.SecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
}

// Helpers shared across this package.

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("auth: unparseable timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
