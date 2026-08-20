package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testDB returns a freshly migrated database.
//
// The backend is chosen by BKD_TEST_POSTGRES_DSN: unset gives SQLite, set
// gives PostgreSQL. `make test` runs the suite both ways rather than picking
// one, because the two drivers differ in exactly the places that bite —
// placeholder syntax, type affinity and foreign key enforcement.
func testDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()

	var db *store.DB
	var err error

	if dsn := os.Getenv("BKD_TEST_POSTGRES_DSN"); dsn != "" {
		db, err = store.Open(ctx, store.Options{Driver: store.DriverPostgres, DSN: dsn})
		if err != nil {
			t.Fatalf("open postgres: %v", err)
		}
		// Postgres instances are reused across tests, unlike the per-test
		// SQLite temp file, so each test starts from a clean schema.
		if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
			t.Fatalf("reset schema: %v", err)
		}
	} else {
		db, err = store.Open(ctx, store.Options{
			Driver: store.DriverSQLite,
			DSN:    filepath.Join(t.TempDir(), "test.db"),
		})
		if err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
	}

	if err := store.Migrate(ctx, db, quietLogger()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// testUser inserts a user and returns its ID.
func testUser(t *testing.T, db *store.DB, email string) string {
	t.Helper()

	id := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.Exec(context.Background(),
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, email, email, now, now)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

// clock is a controllable time source so expiry is tested deterministically
// rather than by sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)}
}
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newStore(t *testing.T, db *store.DB, cfg SessionConfig) (*SessionStore, *clock) {
	t.Helper()
	s, err := NewSessionStore(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := newClock()
	s.now = c.Now
	return s, c
}

func TestSessionCreateAndLookup(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	sess, token, err := ss.Create(ctx, CreateSessionParams{
		UserID:     userID,
		AuthMethod: AuthMethodOIDC,
		UserAgent:  "Mozilla/5.0",
		IPAddress:  "203.0.113.5",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if token == "" {
		t.Fatal("no token returned")
	}

	got, err := ss.Lookup(ctx, token)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.ID != sess.ID || got.UserID != userID {
		t.Fatalf("looked up the wrong session: %+v", got)
	}
	if got.AuthMethod != AuthMethodOIDC {
		t.Errorf("auth method = %q", got.AuthMethod)
	}
	if got.UserAgent != "Mozilla/5.0" || got.IPAddress != "203.0.113.5" {
		t.Errorf("client details not persisted: %+v", got)
	}
}

// TestSessionTokenIsNotStored is the guarantee that a database dump yields no
// usable sessions.
func TestSessionTokenIsNotStored(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	_, token, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}

	var stored string
	if err := db.QueryRow(ctx, `SELECT refresh_token_hash FROM auth_sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token {
		t.Fatal("the raw token was written to the database")
	}
	if stored != hashToken(token) {
		t.Fatal("stored value is not the token hash")
	}
	if len(stored) != 64 {
		t.Fatalf("stored hash is %d characters, want 64 hex", len(stored))
	}
}

func TestSessionTokensAreUnique(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	seen := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		_, token, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[token]; dup {
			t.Fatalf("token repeated after %d sessions", i)
		}
		seen[token] = struct{}{}
	}
}

func TestLookupRejectsUnknownToken(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()

	for name, token := range map[string]string{
		"empty":     "",
		"garbage":   "not-a-real-token",
		"lookalike": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ss.Lookup(ctx, token); !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("want ErrSessionNotFound, got %v", err)
			}
		})
	}
}

// TestIdleExpiry covers a session abandoned mid-afternoon.
func TestIdleExpiry(t *testing.T) {
	db := testDB(t)
	cfg := SessionConfig{IdleTTL: 30 * time.Minute, AbsoluteTTL: 24 * time.Hour, SecureCookies: true}
	ss, clk := newStore(t, db, cfg)
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	_, token, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}

	clk.Advance(31 * time.Minute)

	if _, err := ss.Lookup(ctx, token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("an idle session must expire, got %v", err)
	}
}

// TestActivityExtendsIdleDeadline keeps someone working all day signed in.
func TestActivityExtendsIdleDeadline(t *testing.T) {
	db := testDB(t)
	cfg := SessionConfig{IdleTTL: 30 * time.Minute, AbsoluteTTL: 24 * time.Hour, SecureCookies: true}
	ss, clk := newStore(t, db, cfg)
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	_, token, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}

	// Work steadily for six hours, well past the 30-minute idle window.
	for i := 0; i < 12; i++ {
		clk.Advance(25 * time.Minute)
		if _, err := ss.Lookup(ctx, token); err != nil {
			t.Fatalf("active session expired at step %d: %v", i, err)
		}
	}

	// Then walk away.
	clk.Advance(31 * time.Minute)
	if _, err := ss.Lookup(ctx, token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("session must expire once idle, got %v", err)
	}
}

// TestAbsoluteExpiryCannotBeExtended is the important half: a stolen token
// must not be keepable alive forever simply by using it.
func TestAbsoluteExpiryCannotBeExtended(t *testing.T) {
	db := testDB(t)
	cfg := SessionConfig{IdleTTL: time.Hour, AbsoluteTTL: 4 * time.Hour, SecureCookies: true}
	ss, clk := newStore(t, db, cfg)
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	sess, token, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}
	absolute := sess.ExpiresAt

	// Constant activity, every half hour.
	for i := 0; i < 7; i++ {
		clk.Advance(30 * time.Minute)
		got, err := ss.Lookup(ctx, token)
		if err != nil {
			break
		}
		if got.IdleExpiresAt.After(absolute) {
			t.Fatalf("idle deadline %v pushed past the absolute deadline %v", got.IdleExpiresAt, absolute)
		}
		if !got.ExpiresAt.Equal(absolute) {
			t.Fatalf("absolute deadline moved: %v then %v", absolute, got.ExpiresAt)
		}
	}

	// Past four hours the session must be gone regardless of activity.
	clk.Advance(time.Hour)
	if _, err := ss.Lookup(ctx, token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("session outlived its absolute TTL, got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	sess, token, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ss.Lookup(ctx, token); err != nil {
		t.Fatal(err)
	}

	if err := ss.Revoke(ctx, sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := ss.Lookup(ctx, token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("a revoked session must not resolve, got %v", err)
	}

	// Revoked rows are retained for investigation rather than deleted.
	var n int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM auth_sessions WHERE id = ?`, sess.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("the revoked row should be retained for audit, not deleted immediately")
	}
}

func TestRevokeAllForUser(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()
	alice := testUser(t, db, "alice@example.com")
	bob := testUser(t, db, "bob@example.com")

	var aliceTokens []string
	for i := 0; i < 3; i++ {
		_, token, err := ss.Create(ctx, CreateSessionParams{UserID: alice, AuthMethod: AuthMethodLocal})
		if err != nil {
			t.Fatal(err)
		}
		aliceTokens = append(aliceTokens, token)
	}
	_, bobToken, err := ss.Create(ctx, CreateSessionParams{UserID: bob, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}

	n, err := ss.RevokeAllForUser(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("revoked %d sessions, want 3", n)
	}

	for i, token := range aliceTokens {
		if _, err := ss.Lookup(ctx, token); !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("alice session %d survived: %v", i, err)
		}
	}
	if _, err := ss.Lookup(ctx, bobToken); err != nil {
		t.Errorf("another user's session must be untouched: %v", err)
	}
}

// TestRevokeAllForUserExcept is the "sign out everywhere else" behaviour.
func TestRevokeAllForUserExcept(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()
	alice := testUser(t, db, "alice@example.com")

	keep, keepToken, err := ss.Create(ctx, CreateSessionParams{UserID: alice, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}
	var others []string
	for i := 0; i < 3; i++ {
		_, token, err := ss.Create(ctx, CreateSessionParams{UserID: alice, AuthMethod: AuthMethodLocal})
		if err != nil {
			t.Fatal(err)
		}
		others = append(others, token)
	}

	n, err := ss.RevokeAllForUserExcept(ctx, alice, keep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("revoked %d, want 3", n)
	}

	if _, err := ss.Lookup(ctx, keepToken); err != nil {
		t.Errorf("the current session must survive: %v", err)
	}
	for i, token := range others {
		if _, err := ss.Lookup(ctx, token); !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("session %d survived: %v", i, err)
		}
	}
}

func TestListForUser(t *testing.T) {
	db := testDB(t)
	ss, clk := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()
	alice := testUser(t, db, "alice@example.com")
	bob := testUser(t, db, "bob@example.com")

	for i := 0; i < 3; i++ {
		if _, _, err := ss.Create(ctx, CreateSessionParams{UserID: alice, AuthMethod: AuthMethodLocal}); err != nil {
			t.Fatal(err)
		}
		clk.Advance(time.Second)
	}
	revoked, _, err := ss.Create(ctx, CreateSessionParams{UserID: alice, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Revoke(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ss.Create(ctx, CreateSessionParams{UserID: bob, AuthMethod: AuthMethodLocal}); err != nil {
		t.Fatal(err)
	}

	list, err := ss.ListForUser(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("listed %d sessions, want 3 (revoked and other users excluded)", len(list))
	}
	for _, s := range list {
		if s.UserID != alice {
			t.Errorf("another user's session leaked into the list: %s", s.UserID)
		}
		if s.RevokedAt != nil {
			t.Error("a revoked session appeared in the list")
		}
	}
}

func TestSetVaultUnlockedAndMFA(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	sess, token, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}
	if sess.VaultUnlocked || sess.MFASatisfied {
		t.Fatal("a new session must start locked and without MFA")
	}

	if err := ss.SetVaultUnlocked(ctx, sess.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := ss.SetMFASatisfied(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}

	got, err := ss.Lookup(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if !got.VaultUnlocked {
		t.Error("vault_unlocked was not persisted")
	}
	if !got.MFASatisfied {
		t.Error("mfa_satisfied was not persisted")
	}

	if err := ss.SetVaultUnlocked(ctx, sess.ID, false); err != nil {
		t.Fatal(err)
	}
	got, err = ss.Lookup(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if got.VaultUnlocked {
		t.Error("locking the vault was not persisted")
	}
}

func TestPurgeExpired(t *testing.T) {
	db := testDB(t)
	cfg := SessionConfig{IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour, SecureCookies: true}
	ss, clk := newStore(t, db, cfg)
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	if _, _, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal}); err != nil {
		t.Fatal(err)
	}
	stale, _, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Revoke(ctx, stale.ID); err != nil {
		t.Fatal(err)
	}

	clk.Advance(3 * time.Hour)

	// A fresh session, created after the clock moved.
	if _, _, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal}); err != nil {
		t.Fatal(err)
	}

	n, err := ss.PurgeExpired(ctx, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("purged %d rows, want 2", n)
	}

	var remaining int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM auth_sessions`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Errorf("%d sessions remain, want 1", remaining)
	}
}

// TestPurgeKeepsRecentlyRevoked confirms the investigation grace period.
func TestPurgeKeepsRecentlyRevoked(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	sess, _, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Revoke(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := ss.PurgeExpired(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM auth_sessions WHERE id = ?`, sess.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("a just-revoked session was purged inside the grace period, losing audit trail")
	}
}

func TestCreateRejectsBadParams(t *testing.T) {
	db := testDB(t)
	ss, _ := newStore(t, db, DefaultSessionConfig())
	ctx := context.Background()

	t.Run("no user", func(t *testing.T) {
		if _, _, err := ss.Create(ctx, CreateSessionParams{AuthMethod: AuthMethodLocal}); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("unknown auth method", func(t *testing.T) {
		userID := testUser(t, db, "alice@example.com")
		if _, _, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: "carrier-pigeon"}); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestSessionConfigValidate(t *testing.T) {
	if err := DefaultSessionConfig().Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}

	for name, cfg := range map[string]SessionConfig{
		"zero idle":        {IdleTTL: 0, AbsoluteTTL: time.Hour},
		"zero absolute":    {IdleTTL: time.Hour, AbsoluteTTL: 0},
		"idle exceeds abs": {IdleTTL: 2 * time.Hour, AbsoluteTTL: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected rejection")
			}
			if _, err := NewSessionStore(nil, cfg); err == nil {
				t.Fatal("NewSessionStore must reject an invalid config")
			}
		})
	}
}

// TestSessionCookieFlags checks the attributes that carry the security
// properties. These are easy to weaken by accident and hard to notice.
func TestSessionCookieFlags(t *testing.T) {
	cfg := DefaultSessionConfig()
	c := cfg.SessionCookie("token-value")

	if c.Name != SessionCookieName {
		t.Errorf("name = %q", c.Name)
	}
	if !c.HttpOnly {
		t.Error("session cookie must be HttpOnly so script cannot read it")
	}
	if !c.Secure {
		t.Error("session cookie must be Secure")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("path = %q", c.Path)
	}

	cleared := cfg.ClearSessionCookie()
	if cleared.Value != "" || cleared.MaxAge != -1 {
		t.Errorf("clearing cookie is wrong: value=%q maxage=%d", cleared.Value, cleared.MaxAge)
	}
	if !cleared.HttpOnly || !cleared.Secure {
		t.Error("the clearing cookie must carry the same flags, or some browsers ignore it")
	}
}

// TestConcurrentLookups runs under -race: many tabs hitting the API at once
// is the normal case for this application, not an edge case.
func TestConcurrentLookups(t *testing.T) {
	db := testDB(t)
	ss, err := NewSessionStore(db, DefaultSessionConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	userID := testUser(t, db, "alice@example.com")

	_, token, err := ss.Create(ctx, CreateSessionParams{UserID: userID, AuthMethod: AuthMethodLocal})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := ss.Lookup(ctx, token); err != nil {
					t.Errorf("concurrent lookup failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
