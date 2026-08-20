package hostkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

// newHostKey returns a fresh SSH public key, as a host would present.
func newHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func fixture(t *testing.T) (*Store, *store.DB, string) {
	t.Helper()
	db := storetest.New(t)

	userID := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		userID, "alice@example.com", "alice@example.com", now, now); err != nil {
		t.Fatal(err)
	}
	return NewStore(db), db, userID
}

func TestFirstContactIsUnknown(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()
	key := newHostKey(t)

	check, err := s.Verify(ctx, userID, "router1.example.com", 22, key)
	if err != nil {
		t.Fatal(err)
	}
	if check.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %q, want unknown", check.Verdict)
	}
	// The fingerprint must be available, because that is what the user is
	// being asked to compare against.
	if check.Presented.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Errorf("fingerprint = %q", check.Presented.Fingerprint)
	}
	if check.Existing != nil {
		t.Error("there should be no existing entry on first contact")
	}
}

func TestTrustThenTrusted(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()
	key := newHostKey(t)

	check, err := s.Verify(ctx, userID, "router1.example.com", 22, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(ctx, userID, "router1.example.com", 22, check.Presented); err != nil {
		t.Fatalf("Trust: %v", err)
	}

	again, err := s.Verify(ctx, userID, "router1.example.com", 22, key)
	if err != nil {
		t.Fatal(err)
	}
	if again.Verdict != VerdictTrusted {
		t.Fatalf("verdict = %q, want trusted", again.Verdict)
	}
	if again.Existing == nil {
		t.Fatal("the recorded entry should be returned")
	}
}

// TestChangedKeyIsRefused is the property this package exists for.
func TestChangedKeyIsRefused(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	original := newHostKey(t)
	check, err := s.Verify(ctx, userID, "router1.example.com", 22, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(ctx, userID, "router1.example.com", 22, check.Presented); err != nil {
		t.Fatal(err)
	}

	// The same host now presents a different key.
	impostor := newHostKey(t)
	changed, err := s.Verify(ctx, userID, "router1.example.com", 22, impostor)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Verdict != VerdictChanged {
		t.Fatalf("verdict = %q, want changed", changed.Verdict)
	}

	// Both fingerprints must be available, so the interface can show the
	// difference rather than just asserting one exists.
	if changed.Existing == nil {
		t.Fatal("the previously recorded key should be returned for comparison")
	}
	if changed.Existing.Fingerprint == changed.Presented.Fingerprint {
		t.Fatal("the two fingerprints should differ")
	}

	// And the ordinary accept path must refuse to paper over it.
	if _, err := s.Trust(ctx, userID, "router1.example.com", 22, changed.Presented); !errors.Is(err, ErrKeyChanged) {
		t.Fatalf("Trust on a changed key must fail with ErrKeyChanged, got %v", err)
	}
}

// TestReplaceIsTheOnlyWayToAcceptAChangedKey covers a deliberate override,
// such as a genuinely rebuilt host.
func TestReplaceIsTheOnlyWayToAcceptAChangedKey(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	original := newHostKey(t)
	first, err := s.Verify(ctx, userID, "router1.example.com", 22, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(ctx, userID, "router1.example.com", 22, first.Presented); err != nil {
		t.Fatal(err)
	}

	rebuilt := newHostKey(t)
	changed, err := s.Verify(ctx, userID, "router1.example.com", 22, rebuilt)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Replace(ctx, userID, "router1.example.com", 22, changed.Presented); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	after, err := s.Verify(ctx, userID, "router1.example.com", 22, rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	if after.Verdict != VerdictTrusted {
		t.Fatalf("verdict = %q after replacing, want trusted", after.Verdict)
	}

	// The old key must no longer be accepted.
	old, err := s.Verify(ctx, userID, "router1.example.com", 22, original)
	if err != nil {
		t.Fatal(err)
	}
	if old.Verdict != VerdictChanged {
		t.Fatalf("the superseded key should now read as changed, got %q", old.Verdict)
	}
}

// TestOrgWideEntryOverridesPersonal is how a fleet rebuild is handled without
// confronting every engineer with a warning they cannot evaluate.
func TestOrgWideEntryOverridesPersonal(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	stale := newHostKey(t)
	staleCheck, err := s.Verify(ctx, userID, "core-switch.example.com", 22, stale)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(ctx, userID, "core-switch.example.com", 22, staleCheck.Presented); err != nil {
		t.Fatal(err)
	}

	// An administrator publishes the fleet's new key.
	current := newHostKey(t)
	if _, err := s.TrustOrgWide(ctx, "core-switch.example.com", 22, DescribeKey(current)); err != nil {
		t.Fatal(err)
	}

	t.Run("the published key is accepted despite the stale personal record", func(t *testing.T) {
		check, err := s.Verify(ctx, userID, "core-switch.example.com", 22, current)
		if err != nil {
			t.Fatal(err)
		}
		if check.Verdict != VerdictTrusted {
			t.Fatalf("verdict = %q, want trusted", check.Verdict)
		}
		if check.Existing == nil || !check.Existing.IsOrgWide() {
			t.Error("the org-wide entry should be the one that matched")
		}
	})

	t.Run("the old key is refused even though the user personally trusted it", func(t *testing.T) {
		// Administrators are the authority: a personal record cannot
		// re-authorise a key the organisation has superseded.
		check, err := s.Verify(ctx, userID, "core-switch.example.com", 22, stale)
		if err != nil {
			t.Fatal(err)
		}
		if check.Verdict != VerdictChanged {
			t.Fatalf("verdict = %q, want changed", check.Verdict)
		}
	})
}

func TestTrustIsPerUser(t *testing.T) {
	s, db, alice := fixture(t)
	ctx := context.Background()

	bob := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		bob, "bob@example.com", "bob@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	key := newHostKey(t)
	check, err := s.Verify(ctx, alice, "router1.example.com", 22, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(ctx, alice, "router1.example.com", 22, check.Presented); err != nil {
		t.Fatal(err)
	}

	// Bob has made no decision about this host, so he must still be asked.
	bobCheck, err := s.Verify(ctx, bob, "router1.example.com", 22, key)
	if err != nil {
		t.Fatal(err)
	}
	if bobCheck.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %q for a different user, want unknown", bobCheck.Verdict)
	}
}

// TestHostsAreDistinguishedByPort stops a record for one service being applied
// to a different one on the same address — a real case with port-forwarded
// console servers, where each port is a different device entirely.
func TestHostsAreDistinguishedByPort(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	deviceA := newHostKey(t)
	checkA, err := s.Verify(ctx, userID, "console.example.com", 2001, deviceA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(ctx, userID, "console.example.com", 2001, checkA.Presented); err != nil {
		t.Fatal(err)
	}

	deviceB := newHostKey(t)
	checkB, err := s.Verify(ctx, userID, "console.example.com", 2002, deviceB)
	if err != nil {
		t.Fatal(err)
	}
	if checkB.Verdict != VerdictUnknown {
		t.Fatalf("a different port must be a different host, got %q", checkB.Verdict)
	}
}

func TestHostnamesAreNormalized(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()
	key := newHostKey(t)

	check, err := s.Verify(ctx, userID, "Router1.Example.COM", 22, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust(ctx, userID, "Router1.Example.COM", 22, check.Presented); err != nil {
		t.Fatal(err)
	}

	// Every spelling of the same host must resolve to the same record, or a
	// user would be re-prompted for a host they have already approved.
	for _, variant := range []string{
		"router1.example.com", "ROUTER1.EXAMPLE.COM", "Router1.Example.com.", "  router1.example.com  ",
	} {
		got, err := s.Verify(ctx, userID, variant, 22, key)
		if err != nil {
			t.Fatal(err)
		}
		if got.Verdict != VerdictTrusted {
			t.Errorf("%q: verdict = %q, want trusted", variant, got.Verdict)
		}
	}
}

func TestTrustIsIdempotent(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()
	key := newHostKey(t)
	presented := DescribeKey(key)

	first, err := s.Trust(ctx, userID, "router1.example.com", 22, presented)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Trust(ctx, userID, "router1.example.com", 22, presented)
	if err != nil {
		t.Fatalf("trusting the same key twice must not fail: %v", err)
	}
	if first.ID != second.ID {
		t.Error("a duplicate trust should return the existing record, not create another")
	}
}

func TestForget(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()
	key := newHostKey(t)

	if _, err := s.Trust(ctx, userID, "router1.example.com", 22, DescribeKey(key)); err != nil {
		t.Fatal(err)
	}

	n, err := s.Forget(ctx, userID, "router1.example.com", 22)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("forgot %d entries, want 1", n)
	}

	check, err := s.Verify(ctx, userID, "router1.example.com", 22, key)
	if err != nil {
		t.Fatal(err)
	}
	if check.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %q after forgetting, want unknown", check.Verdict)
	}
}

func TestListForUserIncludesOrgWide(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	if _, err := s.Trust(ctx, userID, "personal.example.com", 22, DescribeKey(newHostKey(t))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TrustOrgWide(ctx, "published.example.com", 22, DescribeKey(newHostKey(t))); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListForUser(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("listed %d entries, want 2", len(list))
	}

	var sawOrgWide, sawPersonal bool
	for _, e := range list {
		if e.IsOrgWide() {
			sawOrgWide = true
		} else {
			sawPersonal = true
		}
	}
	if !sawOrgWide || !sawPersonal {
		t.Error("the list should show both personal and published entries, and which is which")
	}
}

func TestInsertValidation(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()
	presented := DescribeKey(newHostKey(t))

	cases := map[string]func() error{
		"empty hostname": func() error {
			_, err := s.Trust(ctx, userID, "", 22, presented)
			return err
		},
		"port too low": func() error {
			_, err := s.Trust(ctx, userID, "h.example.com", 0, presented)
			return err
		},
		"port too high": func() error {
			_, err := s.Trust(ctx, userID, "h.example.com", 70000, presented)
			return err
		},
		"no key": func() error {
			_, err := s.Trust(ctx, userID, "h.example.com", 22, Presented{})
			return err
		},
		"no user": func() error {
			_, err := s.Trust(ctx, "", "h.example.com", 22, presented)
			return err
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestDescribe(t *testing.T) {
	cases := map[string]string{
		"router1.example.com|22":   "router1.example.com",
		"router1.example.com|2222": "router1.example.com:2222",
		"2001:db8::1|22":           "2001:db8::1",
		"2001:db8::1|2222":         "[2001:db8::1]:2222",
	}
	for input, want := range cases {
		var host string
		var port int
		if _, err := fmtSscan(input, &host, &port); err != nil {
			t.Fatal(err)
		}
		if got := Describe(host, port); got != want {
			t.Errorf("Describe(%q, %d) = %q, want %q", host, port, got, want)
		}
	}
}

// fmtSscan splits "host|port" without pulling fmt into the test's imports for
// one call.
func fmtSscan(s string, host *string, port *int) (int, error) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '|' {
			*host = s[:i]
			p := 0
			for _, c := range s[i+1:] {
				p = p*10 + int(c-'0')
			}
			*port = p
			return 2, nil
		}
	}
	return 0, errors.New("no separator")
}
