// Package hostkeys records which SSH host keys are trusted, and decides what
// to do when one is presented.
//
// This is the defence against someone sitting between this server and the
// hosts your team administers. It is also the part of an SSH client that is
// most often quietly weakened — an "accept anything" option, a warning the
// user learns to click through — so the behaviour here is deliberately
// unforgiving:
//
//   - A host nobody has seen before produces a decision the user must make,
//     with the fingerprint in front of them. It never connects silently.
//   - A host whose key has CHANGED is refused outright. There is no override,
//     no checkbox. Clearing the record is an explicit, audited action taken
//     away from the connection attempt, so nobody does it reflexively while
//     staring at a stalled terminal.
//
// An administrator may publish an org-wide entry, which is consulted before
// any personal one. That is how a fleet rebuild is handled: the admin updates
// the record once instead of two hundred engineers each being confronted with
// a warning they cannot evaluate.
package hostkeys

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"golang.org/x/crypto/ssh"
)

// Verdict is the outcome of checking a presented host key.
type Verdict string

const (
	// VerdictTrusted means this exact key is already recorded.
	VerdictTrusted Verdict = "trusted"

	// VerdictUnknown means no key is recorded for this host. The user must
	// decide, having seen the fingerprint.
	VerdictUnknown Verdict = "unknown"

	// VerdictChanged means a different key is recorded for this host. The
	// connection is refused.
	//
	// The benign explanations — a rebuilt host, a replaced appliance — are
	// indistinguishable from an attack at this point, which is exactly why
	// the decision belongs to a person acting deliberately rather than to
	// someone dismissing a dialog.
	VerdictChanged Verdict = "changed"
)

// ErrKeyChanged is returned when a host presents a key different from the one
// on record.
var ErrKeyChanged = errors.New("hostkeys: the host key has changed")

// ErrNotFound means no record exists.
var ErrNotFound = errors.New("hostkeys: no record for that host")

// Entry is a recorded host key.
type Entry struct {
	ID          string
	UserID      string // empty for an org-wide entry published by an admin
	Hostname    string
	Port        int
	KeyType     string
	PublicKey   string // authorized_keys form
	Fingerprint string // SHA256:...
	CreatedAt   time.Time
}

// IsOrgWide reports whether this entry applies to everyone.
func (e Entry) IsOrgWide() bool { return e.UserID == "" }

// Check is the result of verifying a presented key.
type Check struct {
	Verdict Verdict

	// Presented describes the key the host actually offered.
	Presented Presented

	// Existing is the recorded entry, set when the verdict is trusted or
	// changed. For a changed key this is what the interface shows alongside
	// the new fingerprint, so the difference is visible.
	Existing *Entry
}

// Presented describes a key offered by a host.
type Presented struct {
	KeyType     string
	PublicKey   string
	Fingerprint string
}

// Store records and consults trusted host keys.
type Store struct {
	db  *store.DB
	now func() time.Time
}

// NewStore builds a Store.
func NewStore(db *store.DB) *Store {
	return &Store{db: db, now: time.Now}
}

// NormalizeHost canonicalises a hostname for comparison.
//
// Lowercased, with a trailing dot stripped and IPv6 brackets removed, so
// "Router1.Example.com." and "router1.example.com" are the same host rather
// than two records that disagree about which key is right.
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return h
}

// Describe renders a host and port the way a person writes it.
func Describe(host string, port int) string {
	if port == 22 {
		return host
	}
	if strings.Contains(host, ":") { // IPv6 literal
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return host + ":" + strconv.Itoa(port)
}

// DescribeKey renders a presented key for display.
func DescribeKey(key ssh.PublicKey) Presented {
	return Presented{
		KeyType:     key.Type(),
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		Fingerprint: ssh.FingerprintSHA256(key),
	}
}

// Verify checks a presented key against what is recorded.
//
// Org-wide entries are consulted first. An org-wide entry that matches means
// the connection proceeds even if the user has a stale personal record;
// an org-wide entry that does NOT match means the connection is refused even
// if the user's personal record would have allowed it. Administrators are the
// authority on what a fleet's keys are.
func (s *Store) Verify(ctx context.Context, userID, hostname string, port int, key ssh.PublicKey) (Check, error) {
	presented := DescribeKey(key)
	host := NormalizeHost(hostname)

	orgEntry, err := s.lookup(ctx, "", host, port, presented.KeyType)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Check{}, err
	}
	if orgEntry != nil {
		if orgEntry.Fingerprint == presented.Fingerprint {
			return Check{Verdict: VerdictTrusted, Presented: presented, Existing: orgEntry}, nil
		}
		return Check{Verdict: VerdictChanged, Presented: presented, Existing: orgEntry}, nil
	}

	userEntry, err := s.lookup(ctx, userID, host, port, presented.KeyType)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Check{}, err
	}
	if userEntry == nil {
		return Check{Verdict: VerdictUnknown, Presented: presented}, nil
	}
	if userEntry.Fingerprint == presented.Fingerprint {
		return Check{Verdict: VerdictTrusted, Presented: presented, Existing: userEntry}, nil
	}
	return Check{Verdict: VerdictChanged, Presented: presented, Existing: userEntry}, nil
}

func (s *Store) lookup(ctx context.Context, userID, host string, port int, keyType string) (*Entry, error) {
	var (
		row *sql.Row
	)
	if userID == "" {
		row = s.db.QueryRow(ctx, `
			SELECT id, user_id, hostname, port, key_type, public_key, fingerprint, created_at
			FROM known_hosts
			WHERE user_id IS NULL AND hostname = ? AND port = ? AND key_type = ?`,
			host, port, keyType)
	} else {
		row = s.db.QueryRow(ctx, `
			SELECT id, user_id, hostname, port, key_type, public_key, fingerprint, created_at
			FROM known_hosts
			WHERE user_id = ? AND hostname = ? AND port = ? AND key_type = ?`,
			userID, host, port, keyType)
	}

	var (
		e       Entry
		owner   sql.NullString
		created string
	)
	err := row.Scan(&e.ID, &owner, &e.Hostname, &e.Port, &e.KeyType,
		&e.PublicKey, &e.Fingerprint, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("hostkeys: read: %w", err)
	}

	e.UserID = owner.String
	if e.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	return &e, nil
}

// Trust records a key as trusted for a user.
//
// Refuses to overwrite a differing record: replacing a key that has changed is
// Replace, which is a separate and audited operation. Making that a distinct
// call means a connection handler cannot accidentally paper over a changed key
// by reusing the ordinary accept path.
func (s *Store) Trust(ctx context.Context, userID, hostname string, port int, presented Presented) (Entry, error) {
	if userID == "" {
		return Entry{}, errors.New("hostkeys: Trust needs a user; use TrustOrgWide for a published entry")
	}
	return s.insert(ctx, userID, hostname, port, presented)
}

// TrustOrgWide records a key trusted for everyone. Administrators only.
func (s *Store) TrustOrgWide(ctx context.Context, hostname string, port int, presented Presented) (Entry, error) {
	return s.insert(ctx, "", hostname, port, presented)
}

func (s *Store) insert(ctx context.Context, userID, hostname string, port int, presented Presented) (Entry, error) {
	host := NormalizeHost(hostname)
	if host == "" {
		return Entry{}, errors.New("hostkeys: hostname must not be empty")
	}
	if port < 1 || port > 65535 {
		return Entry{}, fmt.Errorf("hostkeys: port %d is out of range", port)
	}
	if presented.Fingerprint == "" || presented.PublicKey == "" {
		return Entry{}, errors.New("hostkeys: a key is required")
	}

	existing, err := s.lookup(ctx, userID, host, port, presented.KeyType)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Entry{}, err
	}
	if existing != nil {
		if existing.Fingerprint == presented.Fingerprint {
			return *existing, nil // already trusted; nothing to do
		}
		return Entry{}, fmt.Errorf("%w: %s already has a different key on record", ErrKeyChanged, Describe(host, port))
	}

	e := Entry{
		ID:          uuid.Must(uuid.NewV7()).String(),
		UserID:      userID,
		Hostname:    host,
		Port:        port,
		KeyType:     presented.KeyType,
		PublicKey:   presented.PublicKey,
		Fingerprint: presented.Fingerprint,
		CreatedAt:   s.now().UTC(),
	}

	var owner any
	if userID != "" {
		owner = userID
	}

	if _, err := s.db.Exec(ctx, `
		INSERT INTO known_hosts (id, user_id, hostname, port, key_type, public_key, fingerprint, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, owner, e.Hostname, e.Port, e.KeyType, e.PublicKey, e.Fingerprint,
		e.CreatedAt.Format(time.RFC3339Nano)); err != nil {
		return Entry{}, fmt.Errorf("hostkeys: record: %w", err)
	}
	return e, nil
}

// Replace overwrites a recorded key after a deliberate decision.
//
// The only path by which a changed key becomes trusted. Separate from Trust so
// that accepting a changed key is always an explicit act — and so the audit
// log can distinguish "trusted a new host" from "overrode a changed key",
// which are very different events during an investigation.
func (s *Store) Replace(ctx context.Context, userID, hostname string, port int, presented Presented) (Entry, error) {
	host := NormalizeHost(hostname)

	var owner any
	if userID != "" {
		owner = userID
	}

	if err := s.db.InTx(ctx, func(tx *store.Tx) error {
		var err error
		if userID == "" {
			_, err = tx.Exec(ctx,
				`DELETE FROM known_hosts WHERE user_id IS NULL AND hostname = ? AND port = ? AND key_type = ?`,
				host, port, presented.KeyType)
		} else {
			_, err = tx.Exec(ctx,
				`DELETE FROM known_hosts WHERE user_id = ? AND hostname = ? AND port = ? AND key_type = ?`,
				userID, host, port, presented.KeyType)
		}
		if err != nil {
			return fmt.Errorf("hostkeys: clear previous key: %w", err)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO known_hosts (id, user_id, hostname, port, key_type, public_key, fingerprint, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			uuid.Must(uuid.NewV7()).String(), owner, host, port, presented.KeyType,
			presented.PublicKey, presented.Fingerprint,
			s.now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("hostkeys: record replacement: %w", err)
		}
		return nil
	}); err != nil {
		return Entry{}, err
	}

	entry, err := s.lookup(ctx, userID, host, port, presented.KeyType)
	if err != nil {
		return Entry{}, err
	}
	return *entry, nil
}

// Forget removes a user's record for a host.
func (s *Store) Forget(ctx context.Context, userID, hostname string, port int) (int, error) {
	res, err := s.db.Exec(ctx,
		`DELETE FROM known_hosts WHERE user_id = ? AND hostname = ? AND port = ?`,
		userID, NormalizeHost(hostname), port)
	if err != nil {
		return 0, fmt.Errorf("hostkeys: forget: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return int(n), nil
}

// ListForUser returns a user's recorded hosts plus every org-wide entry,
// so the interface can show what is trusted and where it came from.
func (s *Store) ListForUser(ctx context.Context, userID string) ([]Entry, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, user_id, hostname, port, key_type, public_key, fingerprint, created_at
		FROM known_hosts
		WHERE user_id = ? OR user_id IS NULL
		ORDER BY hostname ASC, port ASC, key_type ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("hostkeys: list: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []Entry
	for rows.Next() {
		var (
			e       Entry
			owner   sql.NullString
			created string
		)
		if err := rows.Scan(&e.ID, &owner, &e.Hostname, &e.Port, &e.KeyType,
			&e.PublicKey, &e.Fingerprint, &created); err != nil {
			return nil, fmt.Errorf("hostkeys: scan: %w", err)
		}
		e.UserID = owner.String
		if e.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("hostkeys: unparseable timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}
