package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
)

// ErrRateLimited means too many attempts have been made. RetryAfter reports
// how long the caller should wait.
type ErrRateLimited struct {
	RetryAfter time.Duration
	Scope      string // "account" or "address"
}

func (e *ErrRateLimited) Error() string {
	return fmt.Sprintf("auth: too many attempts for this %s; retry in %s",
		e.Scope, e.RetryAfter.Round(time.Second))
}

// IsRateLimited reports whether err is a rate-limit rejection.
func IsRateLimited(err error) bool {
	var rl *ErrRateLimited
	return errors.As(err, &rl)
}

// ThrottleConfig bounds authentication attempts.
//
// Two independent limits, because they defend against different things. The
// per-account limit stops one account being brute-forced from a botnet; the
// per-address limit stops one host spraying a common password across many
// accounts, which the per-account limit would never notice.
type ThrottleConfig struct {
	MaxPerAccount int
	MaxPerAddress int
	Window        time.Duration

	// LockoutDuration is how long an account stays locked after exceeding its
	// limit. Long enough to make brute force impractical, short enough that a
	// legitimate user is not calling the help desk — and it never applies to
	// an address, because a shared office NAT would lock out a whole floor.
	LockoutDuration time.Duration
}

// DefaultThrottleConfig returns sensible limits.
func DefaultThrottleConfig() ThrottleConfig {
	return ThrottleConfig{
		MaxPerAccount:   5,
		MaxPerAddress:   30,
		Window:          15 * time.Minute,
		LockoutDuration: 15 * time.Minute,
	}
}

// Validate rejects a configuration that would disable throttling.
func (c ThrottleConfig) Validate() error {
	var errs []error
	if c.MaxPerAccount < 1 {
		errs = append(errs, errors.New("auth: max attempts per account must be at least 1"))
	}
	if c.MaxPerAddress < c.MaxPerAccount {
		errs = append(errs, fmt.Errorf(
			"auth: max attempts per address (%d) must be at least the per-account limit (%d), "+
				"or one user's own retries would lock out their whole office",
			c.MaxPerAddress, c.MaxPerAccount))
	}
	if c.Window <= 0 {
		errs = append(errs, errors.New("auth: throttle window must be positive"))
	}
	if c.LockoutDuration <= 0 {
		errs = append(errs, errors.New("auth: lockout duration must be positive"))
	}
	return errors.Join(errs...)
}

// AttemptKind distinguishes the two counters.
type AttemptKind string

const (
	AttemptAccount AttemptKind = "account"
	AttemptAddress AttemptKind = "ip"
)

// Throttle records and limits authentication attempts.
//
// Attempts are persisted rather than held in memory: a counter that resets on
// restart is a counter an attacker can clear by causing a crash, and an
// in-memory one cannot be shared across nodes. An in-process cache sits in
// front so the common case — a successful login — does not pay for a database
// round trip on every request.
type Throttle struct {
	db  *store.DB
	cfg ThrottleConfig
	now func() time.Time

	mu     sync.Mutex
	recent map[string][]time.Time
}

// NewThrottle builds a Throttle.
func NewThrottle(db *store.DB, cfg ThrottleConfig) (*Throttle, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Throttle{
		db:     db,
		cfg:    cfg,
		now:    time.Now,
		recent: make(map[string][]time.Time),
	}, nil
}

func cacheKey(kind AttemptKind, identifier string) string {
	return string(kind) + "\x00" + identifier
}

// Check reports whether an attempt may proceed.
//
// Call it before verifying a credential, so a locked-out attacker never
// reaches the expensive Argon2id verification at all — which is what stops
// the throttle itself becoming a denial-of-service amplifier.
func (t *Throttle) Check(ctx context.Context, kind AttemptKind, identifier string) error {
	if identifier == "" {
		return nil
	}

	limit := t.cfg.MaxPerAccount
	scope := "account"
	if kind == AttemptAddress {
		limit = t.cfg.MaxPerAddress
		scope = "address"
	}

	failures, oldest, err := t.countFailures(ctx, kind, identifier)
	if err != nil {
		return err
	}
	if failures < limit {
		return nil
	}

	// The lockout runs from the oldest failure still inside the window, so it
	// decays naturally rather than resetting on every fresh attempt. An
	// attacker cannot extend their own lockout indefinitely by continuing to
	// try, and a legitimate user's wait only ever shortens.
	retry := oldest.Add(t.cfg.LockoutDuration).Sub(t.now())
	if retry <= 0 {
		return nil
	}
	return &ErrRateLimited{RetryAfter: retry, Scope: scope}
}

// countFailures returns how many failures are inside the window and when the
// oldest of them happened.
func (t *Throttle) countFailures(ctx context.Context, kind AttemptKind, identifier string) (int, time.Time, error) {
	cutoff := t.now().Add(-t.cfg.Window)

	// Serve from cache when it is populated, which it is for any identifier
	// that has failed recently in this process.
	t.mu.Lock()
	cached, ok := t.recent[cacheKey(kind, identifier)]
	t.mu.Unlock()

	if ok {
		var oldest time.Time
		n := 0
		for _, at := range cached {
			if at.After(cutoff) {
				n++
				if oldest.IsZero() || at.Before(oldest) {
					oldest = at
				}
			}
		}
		if n > 0 {
			return n, oldest, nil
		}
	}

	var (
		count  int
		oldest string
	)
	err := t.db.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(MIN(attempted_at), '')
		FROM login_attempts
		WHERE identifier = ? AND kind = ? AND outcome = 'failure' AND attempted_at > ?`,
		identifier, string(kind), formatTime(cutoff)).Scan(&count, &oldest)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("auth: count login attempts: %w", err)
	}
	if count == 0 || oldest == "" {
		return 0, time.Time{}, nil
	}

	at, err := parseTime(oldest)
	if err != nil {
		return 0, time.Time{}, err
	}
	return count, at, nil
}

// RecordFailure notes a failed attempt.
func (t *Throttle) RecordFailure(ctx context.Context, kind AttemptKind, identifier string) error {
	if identifier == "" {
		return nil
	}
	now := t.now().UTC()

	t.mu.Lock()
	key := cacheKey(kind, identifier)
	t.recent[key] = append(t.recent[key], now)
	t.mu.Unlock()

	_, err := t.db.Exec(ctx,
		`INSERT INTO login_attempts (id, identifier, kind, attempted_at, outcome)
		 VALUES (?, ?, ?, ?, 'failure')`,
		uuid.Must(uuid.NewV7()).String(), identifier, string(kind), formatTime(now))
	if err != nil {
		return fmt.Errorf("auth: record failed attempt: %w", err)
	}
	return nil
}

// RecordSuccess notes a successful attempt and clears the identifier's
// failures.
//
// Clearing on success is deliberate: someone who mistyped their password four
// times and then got it right should not be one slip away from a lockout for
// the next quarter of an hour.
func (t *Throttle) RecordSuccess(ctx context.Context, kind AttemptKind, identifier string) error {
	if identifier == "" {
		return nil
	}
	now := t.now().UTC()

	t.mu.Lock()
	delete(t.recent, cacheKey(kind, identifier))
	t.mu.Unlock()

	return t.db.InTx(ctx, func(tx *store.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM login_attempts WHERE identifier = ? AND kind = ? AND outcome = 'failure'`,
			identifier, string(kind)); err != nil {
			return fmt.Errorf("auth: clear failed attempts: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO login_attempts (id, identifier, kind, attempted_at, outcome)
			 VALUES (?, ?, ?, ?, 'success')`,
			uuid.Must(uuid.NewV7()).String(), identifier, string(kind), formatTime(now)); err != nil {
			return fmt.Errorf("auth: record successful attempt: %w", err)
		}
		return nil
	})
}

// Purge deletes attempt records older than retain, and prunes the in-memory
// cache. Successful attempts are kept longer than the throttle window because
// they are useful in an audit; the caller chooses how long.
func (t *Throttle) Purge(ctx context.Context, retain time.Duration) (int, error) {
	cutoff := t.now().Add(-retain)

	t.mu.Lock()
	for key, times := range t.recent {
		kept := times[:0]
		for _, at := range times {
			if at.After(cutoff) {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(t.recent, key)
		} else {
			t.recent[key] = kept
		}
	}
	t.mu.Unlock()

	res, err := t.db.Exec(ctx, `DELETE FROM login_attempts WHERE attempted_at < ?`, formatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("auth: purge login attempts: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return int(n), nil
}
