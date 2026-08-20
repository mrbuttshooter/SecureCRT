package vault

import (
	"context"
	"sync"
	"time"
)

// Cache holds unwrapped data-encryption keys for the lifetime of a logged-in
// session, and nothing longer.
//
// This is the component that makes the whole scheme usable: without it, every
// keystroke that needed a credential would require re-deriving Argon2id at
// 64 MiB. With it, a user unlocks once at login and their DEK stays in
// process memory until they log out, their session expires, or the process
// restarts.
//
// It is deliberately memory-only. Persisting these keys anywhere — disk,
// Redis, a database — would reintroduce exactly the "server can always
// decrypt" property the vault design exists to avoid.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*entry
	ttl     time.Duration
	now     func() time.Time // injectable for tests

	stopOnce sync.Once
	stop     chan struct{}
}

type entry struct {
	key       Key
	expiresAt time.Time
}

// NewCache returns a Cache whose entries expire after ttl, and starts a
// janitor goroutine that evicts and zeroes expired keys.
//
// The janitor matters for more than tidiness: without it, the DEK of a user
// who closed their laptop rather than logging out would linger in memory
// indefinitely.
func NewCache(ttl time.Duration) *Cache {
	c := newCache(ttl, time.Now)
	go c.janitor(ttl)
	return c
}

// newCache builds a Cache without starting the janitor, and with an
// injectable clock. Tests use it to drive expiry deterministically instead of
// sleeping.
func newCache(ttl time.Duration, now func() time.Time) *Cache {
	return &Cache{
		entries: make(map[string]*entry),
		ttl:     ttl,
		now:     now,
		stop:    make(chan struct{}),
	}
}

func (c *Cache) janitor(ttl time.Duration) {
	interval := ttl / 10
	if interval < time.Second {
		interval = time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.EvictExpired()
		case <-c.stop:
			return
		}
	}
}

// Put installs a DEK for sessionID. Any key already held under that ID is
// zeroed first, so re-unlocking never leaves an orphaned copy behind.
//
// The Cache takes ownership of key: callers must not zero or reuse it
// afterwards.
func (c *Cache) Put(sessionID string, key Key) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.entries[sessionID]; ok {
		old.key.Zero()
	}
	c.entries[sessionID] = &entry{key: key, expiresAt: c.now().Add(c.ttl)}
}

// Get returns the DEK for sessionID, refreshing its expiry.
//
// Activity extends the lease, so a user working continuously is not logged
// out mid-session, while an idle session still expires on schedule.
func (c *Cache) Get(sessionID string) (Key, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[sessionID]
	if !ok {
		return nil, ErrLocked
	}
	if c.now().After(e.expiresAt) {
		e.key.Zero()
		delete(c.entries, sessionID)
		return nil, ErrLocked
	}

	e.expiresAt = c.now().Add(c.ttl)
	return e.key, nil
}

// Forget zeroes and removes the DEK for sessionID. Called on logout and on
// any forced revocation.
func (c *Cache) Forget(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[sessionID]; ok {
		e.key.Zero()
		delete(c.entries, sessionID)
	}
}

// ForgetFunc zeroes and removes every entry whose session ID matches pred.
// Used to revoke all of one user's sessions when their password changes or an
// admin disables the account.
func (c *Cache) ForgetFunc(pred func(sessionID string) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0
	for id, e := range c.entries {
		if pred(id) {
			e.key.Zero()
			delete(c.entries, id)
			n++
		}
	}
	return n
}

// EvictExpired zeroes and removes every entry past its expiry, returning how
// many were evicted.
func (c *Cache) EvictExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	n := 0
	for id, e := range c.entries {
		if now.After(e.expiresAt) {
			e.key.Zero()
			delete(c.entries, id)
			n++
		}
	}
	return n
}

// Len reports how many sessions currently hold an unwrapped key.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Close stops the janitor and zeroes every key still held.
//
// This runs during graceful shutdown so that a core dump or crash-handler
// snapshot taken after shutdown contains no key material.
func (c *Cache) Close() {
	c.stopOnce.Do(func() { close(c.stop) })

	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.entries {
		e.key.Zero()
		delete(c.entries, id)
	}
}

// Shutdown stops the janitor and zeroes all keys, honouring ctx for symmetry
// with the rest of the service's lifecycle hooks.
func (c *Cache) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
