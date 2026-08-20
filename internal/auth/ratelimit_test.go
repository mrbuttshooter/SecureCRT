package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/store"
)

func newThrottle(t *testing.T, db *store.DB, cfg ThrottleConfig) (*Throttle, *clock) {
	t.Helper()
	th, err := NewThrottle(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := newClock()
	th.now = c.Now
	return th, c
}

func TestThrottleAllowsUpToLimit(t *testing.T) {
	th, _ := newThrottle(t, testDB(t), DefaultThrottleConfig())
	ctx := context.Background()

	for i := 0; i < DefaultThrottleConfig().MaxPerAccount; i++ {
		if err := th.Check(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatalf("attempt %d must be allowed: %v", i+1, err)
		}
		if err := th.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}

	err := th.Check(ctx, AttemptAccount, "alice@example.com")
	if !IsRateLimited(err) {
		t.Fatalf("the attempt after the limit must be refused, got %v", err)
	}

	var rl *ErrRateLimited
	if !errors.As(err, &rl) {
		t.Fatal("error should be *ErrRateLimited")
	}
	if rl.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v, want positive", rl.RetryAfter)
	}
	if rl.Scope != "account" {
		t.Errorf("scope = %q", rl.Scope)
	}
}

// TestThrottleIsPerIdentifier confirms one user's failures cannot lock out
// another.
func TestThrottleIsPerIdentifier(t *testing.T) {
	th, _ := newThrottle(t, testDB(t), DefaultThrottleConfig())
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if err := th.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}

	if err := th.Check(ctx, AttemptAccount, "alice@example.com"); !IsRateLimited(err) {
		t.Fatal("alice should be locked out")
	}
	if err := th.Check(ctx, AttemptAccount, "bob@example.com"); err != nil {
		t.Fatalf("bob must be unaffected: %v", err)
	}
}

// TestThrottleAccountAndAddressAreIndependent covers the reason there are two
// counters: password spraying hits many accounts from one address, so the
// per-account counter never trips.
func TestThrottleAccountAndAddressAreIndependent(t *testing.T) {
	cfg := ThrottleConfig{MaxPerAccount: 5, MaxPerAddress: 8, Window: 15 * time.Minute, LockoutDuration: 15 * time.Minute}
	th, _ := newThrottle(t, testDB(t), cfg)
	ctx := context.Background()

	// One address trying a common password against nine different accounts:
	// no account exceeds its own limit.
	for i := 0; i < 9; i++ {
		account := fmt.Sprintf("user%d@example.com", i)
		if err := th.RecordFailure(ctx, AttemptAccount, account); err != nil {
			t.Fatal(err)
		}
		if err := th.RecordFailure(ctx, AttemptAddress, "198.51.100.7"); err != nil {
			t.Fatal(err)
		}
		if err := th.Check(ctx, AttemptAccount, account); err != nil {
			t.Fatalf("account %s should not be limited by a single failure: %v", account, err)
		}
	}

	// But the address counter catches it.
	err := th.Check(ctx, AttemptAddress, "198.51.100.7")
	if !IsRateLimited(err) {
		t.Fatal("password spraying from one address must be caught by the address limit")
	}
	var rl *ErrRateLimited
	if errors.As(err, &rl) && rl.Scope != "address" {
		t.Errorf("scope = %q, want address", rl.Scope)
	}
}

// TestThrottleWindowExpires confirms a lockout lifts on its own.
func TestThrottleWindowExpires(t *testing.T) {
	cfg := ThrottleConfig{MaxPerAccount: 3, MaxPerAddress: 30, Window: 15 * time.Minute, LockoutDuration: 15 * time.Minute}
	th, clk := newThrottle(t, testDB(t), cfg)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := th.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if err := th.Check(ctx, AttemptAccount, "alice@example.com"); !IsRateLimited(err) {
		t.Fatal("should be locked out")
	}

	clk.Advance(16 * time.Minute)

	if err := th.Check(ctx, AttemptAccount, "alice@example.com"); err != nil {
		t.Fatalf("the lockout must lift once the window passes: %v", err)
	}
}

// TestThrottleLockoutDoesNotExtendIndefinitely is the property that stops an
// attacker keeping a legitimate user locked out by continuing to try.
func TestThrottleLockoutDoesNotExtendIndefinitely(t *testing.T) {
	cfg := ThrottleConfig{MaxPerAccount: 3, MaxPerAddress: 100, Window: 15 * time.Minute, LockoutDuration: 15 * time.Minute}
	th, clk := newThrottle(t, testDB(t), cfg)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := th.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}

	// An attacker keeps hammering for the whole lockout period.
	for i := 0; i < 14; i++ {
		clk.Advance(time.Minute)
		if err := th.Check(ctx, AttemptAccount, "alice@example.com"); !IsRateLimited(err) {
			t.Fatalf("still expected to be locked at minute %d", i+1)
		}
		if err := th.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}

	// Once the original failures age out of the window, the user gets back in
	// regardless of how much noise the attacker made.
	clk.Advance(16 * time.Minute)
	if err := th.Check(ctx, AttemptAccount, "alice@example.com"); err != nil {
		t.Fatalf("the legitimate user must not be locked out forever: %v", err)
	}
}

// TestThrottleRetryAfterShrinks confirms the reported wait counts down rather
// than resetting.
func TestThrottleRetryAfterShrinks(t *testing.T) {
	cfg := ThrottleConfig{MaxPerAccount: 2, MaxPerAddress: 30, Window: 15 * time.Minute, LockoutDuration: 15 * time.Minute}
	th, clk := newThrottle(t, testDB(t), cfg)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := th.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}

	var previous time.Duration
	for i := 0; i < 5; i++ {
		err := th.Check(ctx, AttemptAccount, "alice@example.com")
		var rl *ErrRateLimited
		if !errors.As(err, &rl) {
			t.Fatalf("expected a rate limit at step %d, got %v", i, err)
		}
		if previous != 0 && rl.RetryAfter >= previous {
			t.Fatalf("RetryAfter did not shrink: %v then %v", previous, rl.RetryAfter)
		}
		previous = rl.RetryAfter
		clk.Advance(time.Minute)
	}
}

// TestThrottleSuccessClearsFailures keeps someone who mistyped their password
// a few times from being one slip from a lockout.
func TestThrottleSuccessClearsFailures(t *testing.T) {
	cfg := ThrottleConfig{MaxPerAccount: 5, MaxPerAddress: 30, Window: 15 * time.Minute, LockoutDuration: 15 * time.Minute}
	th, _ := newThrottle(t, testDB(t), cfg)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if err := th.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if err := th.RecordSuccess(ctx, AttemptAccount, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	// The slate is clean: four more failures must still be allowed.
	for i := 0; i < 4; i++ {
		if err := th.Check(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatalf("failure %d after a success should be allowed: %v", i+1, err)
		}
		if err := th.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
}

// TestThrottleSurvivesRestart is why attempts are persisted: an in-memory
// counter is one an attacker can clear by causing a crash.
func TestThrottleSurvivesRestart(t *testing.T) {
	db := testDB(t)
	cfg := ThrottleConfig{MaxPerAccount: 3, MaxPerAddress: 30, Window: 15 * time.Minute, LockoutDuration: 15 * time.Minute}
	ctx := context.Background()

	first, clk := newThrottle(t, db, cfg)
	for i := 0; i < 3; i++ {
		if err := first.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}

	// A completely fresh Throttle, as after a process restart: no cache, same
	// database.
	second, err := NewThrottle(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second.now = clk.Now

	if err := second.Check(ctx, AttemptAccount, "alice@example.com"); !IsRateLimited(err) {
		t.Fatalf("the lockout must survive a restart, got %v", err)
	}
}

func TestThrottlePurge(t *testing.T) {
	db := testDB(t)
	cfg := ThrottleConfig{MaxPerAccount: 3, MaxPerAddress: 30, Window: 15 * time.Minute, LockoutDuration: 15 * time.Minute}
	th, clk := newThrottle(t, db, cfg)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := th.RecordFailure(ctx, AttemptAccount, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	clk.Advance(48 * time.Hour)
	if err := th.RecordFailure(ctx, AttemptAccount, "bob@example.com"); err != nil {
		t.Fatal(err)
	}

	n, err := th.Purge(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("purged %d rows, want 5", n)
	}

	var remaining int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM login_attempts`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Errorf("%d rows remain, want 1", remaining)
	}

	// Purging must also drop the in-memory cache, or a restart-free process
	// would keep enforcing a lockout whose evidence is gone.
	if err := th.Check(ctx, AttemptAccount, "alice@example.com"); err != nil {
		t.Fatalf("alice should be clear after the purge: %v", err)
	}
}

func TestThrottleIgnoresEmptyIdentifier(t *testing.T) {
	th, _ := newThrottle(t, testDB(t), DefaultThrottleConfig())
	ctx := context.Background()

	if err := th.Check(ctx, AttemptAccount, ""); err != nil {
		t.Errorf("an empty identifier must not be limited: %v", err)
	}
	if err := th.RecordFailure(ctx, AttemptAccount, ""); err != nil {
		t.Errorf("recording an empty identifier must be a no-op: %v", err)
	}
	if err := th.RecordSuccess(ctx, AttemptAccount, ""); err != nil {
		t.Errorf("recording an empty identifier must be a no-op: %v", err)
	}

	var n int
	if err := th.db.QueryRow(ctx, `SELECT COUNT(*) FROM login_attempts`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d rows written for an empty identifier", n)
	}
}

func TestThrottleConfigValidate(t *testing.T) {
	if err := DefaultThrottleConfig().Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}

	for name, cfg := range map[string]ThrottleConfig{
		"zero account limit": {MaxPerAccount: 0, MaxPerAddress: 30, Window: time.Minute, LockoutDuration: time.Minute},
		"zero window":        {MaxPerAccount: 5, MaxPerAddress: 30, Window: 0, LockoutDuration: time.Minute},
		"zero lockout":       {MaxPerAccount: 5, MaxPerAddress: 30, Window: time.Minute, LockoutDuration: 0},
		// An address limit below the account limit would mean one user's own
		// retries lock out everyone behind their office NAT.
		"address below account": {MaxPerAccount: 10, MaxPerAddress: 3, Window: time.Minute, LockoutDuration: time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected rejection")
			}
			if _, err := NewThrottle(nil, cfg); err == nil {
				t.Fatal("NewThrottle must reject an invalid config")
			}
		})
	}
}

// TestThrottleConcurrent runs under -race. Login is exactly where concurrent
// attempts arrive.
func TestThrottleConcurrent(t *testing.T) {
	th, err := NewThrottle(testDB(t), DefaultThrottleConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		account := fmt.Sprintf("user%d@example.com", i)
		wg.Add(2)

		go func() {
			defer wg.Done()
			for j := 0; j < 15; j++ {
				if err := th.RecordFailure(ctx, AttemptAccount, account); err != nil {
					t.Errorf("RecordFailure: %v", err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 15; j++ {
				//nolint:errcheck // being limited is a valid outcome here
				_ = th.Check(ctx, AttemptAccount, account)
			}
		}()
	}
	wg.Wait()

	// Every account exceeded its limit, so all must now be locked.
	for i := 0; i < 8; i++ {
		account := fmt.Sprintf("user%d@example.com", i)
		if err := th.Check(ctx, AttemptAccount, account); !IsRateLimited(err) {
			t.Errorf("%s should be locked out, got %v", account, err)
		}
	}
}
