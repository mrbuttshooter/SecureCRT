package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock lets expiry be tested deterministically instead of by sleeping.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestCachePutGet(t *testing.T) {
	c := newCache(time.Hour, newFakeClock().Now)
	defer c.Close()

	key := mustKey(t)
	want := bytes.Clone(key)
	c.Put("session-1", key)

	got, err := c.Get("session-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Equal(Key(want)) {
		t.Fatal("cache returned a different key")
	}
}

func TestCacheGetUnknownSessionIsLocked(t *testing.T) {
	c := newCache(time.Hour, newFakeClock().Now)
	defer c.Close()

	if _, err := c.Get("never-unlocked"); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

// TestCacheForgetZeroesKey is the logout guarantee: the key material must be
// cleared, not merely dereferenced and left for the garbage collector.
func TestCacheForgetZeroesKey(t *testing.T) {
	c := newCache(time.Hour, newFakeClock().Now)
	defer c.Close()

	key := mustKey(t)
	c.Put("session-1", key)
	c.Forget("session-1")

	if !key.IsZero() {
		t.Fatal("Forget did not zero the key material")
	}
	if _, err := c.Get("session-1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked after Forget, got %v", err)
	}
}

func TestCachePutReplacesAndZeroesPrevious(t *testing.T) {
	c := newCache(time.Hour, newFakeClock().Now)
	defer c.Close()

	first := mustKey(t)
	c.Put("session-1", first)

	second := mustKey(t)
	c.Put("session-1", second)

	if !first.IsZero() {
		t.Fatal("replacing an entry must zero the key it displaced")
	}
	got, err := c.Get("session-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(second) {
		t.Fatal("cache did not return the replacement key")
	}
}

func TestCacheExpiryZeroesKey(t *testing.T) {
	clock := newFakeClock()
	c := newCache(30*time.Minute, clock.Now)
	defer c.Close()

	key := mustKey(t)
	c.Put("session-1", key)

	clock.Advance(31 * time.Minute)

	if _, err := c.Get("session-1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked after expiry, got %v", err)
	}
	if !key.IsZero() {
		t.Fatal("expiry did not zero the key material")
	}
}

// TestCacheGetRefreshesExpiry keeps an actively-working user logged in while
// still expiring idle sessions on schedule.
func TestCacheGetRefreshesExpiry(t *testing.T) {
	clock := newFakeClock()
	c := newCache(30*time.Minute, clock.Now)
	defer c.Close()

	c.Put("session-1", mustKey(t))

	// Touch the entry every 20 minutes across a span far longer than the TTL.
	for i := 0; i < 5; i++ {
		clock.Advance(20 * time.Minute)
		if _, err := c.Get("session-1"); err != nil {
			t.Fatalf("active session expired at step %d: %v", i, err)
		}
	}

	// Then go idle past the TTL.
	clock.Advance(31 * time.Minute)
	if _, err := c.Get("session-1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("idle session must expire, got %v", err)
	}
}

func TestCacheEvictExpired(t *testing.T) {
	clock := newFakeClock()
	c := newCache(30*time.Minute, clock.Now)
	defer c.Close()

	expiring := mustKey(t)
	c.Put("old", expiring)

	clock.Advance(31 * time.Minute)
	c.Put("new", mustKey(t))

	if n := c.EvictExpired(); n != 1 {
		t.Fatalf("evicted %d entries, want 1", n)
	}
	if !expiring.IsZero() {
		t.Fatal("evicted key was not zeroed")
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}
}

// TestCacheForgetFunc covers revoking every session belonging to one user,
// as happens on password change or admin disable.
func TestCacheForgetFunc(t *testing.T) {
	c := newCache(time.Hour, newFakeClock().Now)
	defer c.Close()

	aliceKeys := []Key{mustKey(t), mustKey(t)}
	c.Put("alice:sess-1", aliceKeys[0])
	c.Put("alice:sess-2", aliceKeys[1])

	bobKey := mustKey(t)
	c.Put("bob:sess-1", bobKey)

	n := c.ForgetFunc(func(id string) bool { return strings.HasPrefix(id, "alice:") })
	if n != 2 {
		t.Fatalf("forgot %d entries, want 2", n)
	}
	for i, k := range aliceKeys {
		if !k.IsZero() {
			t.Fatalf("alice key %d was not zeroed", i)
		}
	}
	if bobKey.IsZero() {
		t.Fatal("another user's key must be left alone")
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}
}

// TestCacheCloseZeroesEverything is the shutdown guarantee: no key material
// survives into a post-shutdown core dump.
func TestCacheCloseZeroesEverything(t *testing.T) {
	c := newCache(time.Hour, newFakeClock().Now)

	keys := make([]Key, 10)
	for i := range keys {
		keys[i] = mustKey(t)
		c.Put(fmt.Sprintf("session-%d", i), keys[i])
	}

	c.Close()

	for i, k := range keys {
		if !k.IsZero() {
			t.Fatalf("key %d survived Close un-zeroed", i)
		}
	}
	if c.Len() != 0 {
		t.Fatalf("Len = %d after Close", c.Len())
	}
}

func TestCacheCloseIsIdempotent(t *testing.T) {
	c := NewCache(time.Hour)
	c.Close()
	c.Close() // must not panic on a double close of the stop channel
}

func TestCacheShutdownHonoursContext(t *testing.T) {
	c := NewCache(time.Hour)
	c.Put("session-1", mustKey(t))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if c.Len() != 0 {
		t.Fatal("Shutdown left entries behind")
	}
}

// TestCacheConcurrentAccess runs under -race in CI and is the guard against a
// data race in the janitor/reader/writer interleaving.
func TestCacheConcurrentAccess(t *testing.T) {
	c := NewCache(time.Hour)
	defer c.Close()

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers * 3)

	for i := 0; i < workers; i++ {
		id := fmt.Sprintf("session-%d", i)

		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				k, err := NewKey()
				if err != nil {
					t.Error(err)
					return
				}
				c.Put(id, k)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				//nolint:errcheck // a miss is a valid outcome here
				_, _ = c.Get(id)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.EvictExpired()
			}
		}()
	}
	wg.Wait()
}

// TestCacheEndToEnd walks the real login lifecycle: unlock, use, log out.
func TestCacheEndToEnd(t *testing.T) {
	clock := newFakeClock()
	c := newCache(12*time.Hour, clock.Now)
	defer c.Close()

	pass := []byte("correct horse battery staple")
	secret := []byte("ssh private key material")
	aad := CredentialAAD("alice", "cred-1", "private_key")

	// Registration.
	dek, wrapped, err := NewUserKey("alice", pass)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(dek, aad, secret)
	if err != nil {
		t.Fatal(err)
	}
	dek.Zero()

	// Login: unwrap once, cache for the session.
	unlocked, err := UnwrapUserKey("alice", pass, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	c.Put("alice:sess-1", unlocked)

	// Each subsequent connection reads the credential without touching the
	// passphrase again.
	for i := 0; i < 3; i++ {
		clock.Advance(time.Hour)
		k, err := c.Get("alice:sess-1")
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		got, err := Open(k, aad, env)
		if err != nil {
			t.Fatalf("connection %d decrypt: %v", i, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("connection %d: wrong plaintext", i)
		}
	}

	// Logout.
	c.Forget("alice:sess-1")
	if !unlocked.IsZero() {
		t.Fatal("logout did not zero the DEK")
	}
	if _, err := c.Get("alice:sess-1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked after logout, got %v", err)
	}
}
