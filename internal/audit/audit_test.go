package audit

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
)

func quietLogger() *slog.Logger { return storetest.QuietLogger() }

func testDB(t *testing.T) *store.DB { return storetest.New(t) }

// TestMain drops this process's PostgreSQL schema when the run finishes.
func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

func TestRecordAndList(t *testing.T) {
	r := NewRecorder(testDB(t), quietLogger())
	ctx := context.Background()

	if err := r.RecordErr(ctx, Event{
		ActorID:     "user-1",
		ActorEmail:  "alice@example.com",
		IPAddress:   "203.0.113.5",
		Action:      ActionLoginSucceeded,
		TargetType:  "session",
		TargetID:    "sess-1",
		TargetLabel: "Chrome on macOS",
		Detail:      map[string]any{"method": "oidc", "tenant": "contoso"},
	}); err != nil {
		t.Fatalf("RecordErr: %v", err)
	}

	events, err := r.List(ctx, Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("listed %d events, want 1", len(events))
	}

	e := events[0]
	if e.ID == "" {
		t.Error("no ID assigned")
	}
	if e.ActorEmail != "alice@example.com" || e.Action != ActionLoginSucceeded {
		t.Errorf("event did not round-trip: %+v", e)
	}
	if e.Outcome != OutcomeSuccess {
		t.Errorf("outcome = %q, want the success default", e.Outcome)
	}
	if e.Detail["method"] != "oidc" {
		t.Errorf("detail did not round-trip: %+v", e.Detail)
	}
	if e.OccurredAt.IsZero() {
		t.Error("no timestamp assigned")
	}
}

// TestSecretsAreRefused is the guard that matters most in this package. An
// audit record is retained for the retention period and forwarded to whatever
// log collector consumes it, so a secret landing here is the worst case.
func TestSecretsAreRefused(t *testing.T) {
	r := NewRecorder(testDB(t), quietLogger())
	ctx := context.Background()

	forbidden := []string{
		"password", "Password", "PASSWORD",
		"passphrase", "vault_passphrase",
		"secret", "client_secret", "totp_secret",
		"private_key", "privateKey", "PrivateKey",
		"token", "refresh_token", "session_token",
		"recovery_code", "master_key", "api_key", "apiKey",
		"dek", "kek",
	}

	for _, key := range forbidden {
		t.Run(key, func(t *testing.T) {
			err := r.RecordErr(ctx, Event{
				Action: ActionLoginSucceeded,
				Detail: map[string]any{key: "the actual secret value"},
			})
			if err == nil {
				t.Fatalf("a detail key named %q must be refused", key)
			}
			if !strings.Contains(err.Error(), "secret material") {
				t.Errorf("the error should explain why, got: %v", err)
			}
		})
	}

	// Nothing may have been written.
	events, err := r.List(ctx, Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("%d events were written despite being refused", len(events))
	}
}

func TestBenignDetailKeysAreAllowed(t *testing.T) {
	r := NewRecorder(testDB(t), quietLogger())
	ctx := context.Background()

	// These read adjacent to secrets but carry no secret material, and
	// refusing them would push callers towards logging nothing at all.
	allowed := map[string]any{
		"credential_id":    "cred-1",
		"credential_kind":  "ssh_key",
		"credential_count": 12,
		"fingerprint":      "SHA256:abc123",
		"key_type":         "ed25519",
		"reason":           "wrong passphrase",
		"session_id":       "sess-1",
		"mfa_method":       "totp",
	}

	if err := r.RecordErr(ctx, Event{Action: ActionCredentialCreated, Detail: allowed}); err != nil {
		t.Fatalf("benign keys must be accepted: %v", err)
	}
}

// TestSeverityFloorIsEnforced covers the events that must never be filed as
// routine, whatever the caller passed.
func TestSeverityFloorIsEnforced(t *testing.T) {
	r := NewRecorder(testDB(t), quietLogger())
	ctx := context.Background()

	cases := map[Action]Severity{
		ActionExportedPlaintext: SeverityCritical,
		ActionVaultReset:        SeverityCritical,
		ActionUserDeleted:       SeverityWarning,
		ActionRoleChanged:       SeverityWarning,
		ActionPolicyChanged:     SeverityWarning,
		ActionExported:          SeverityNotice,
		ActionRecoveryCodeUsed:  SeverityNotice,
	}

	for action, want := range cases {
		t.Run(string(action), func(t *testing.T) {
			// Deliberately understated by the caller.
			if err := r.RecordErr(ctx, Event{Action: action, Severity: SeverityInfo}); err != nil {
				t.Fatal(err)
			}

			events, err := r.List(ctx, Query{Action: action})
			if err != nil {
				t.Fatal(err)
			}
			if len(events) == 0 {
				t.Fatal("event was not written")
			}
			if events[0].Severity != want {
				t.Errorf("severity = %q, want it raised to %q", events[0].Severity, want)
			}
		})
	}
}

// TestSeverityIsNeverLowered confirms the floor raises but does not clamp: a
// caller who knows an event is worse than the floor keeps their severity.
func TestSeverityIsNeverLowered(t *testing.T) {
	r := NewRecorder(testDB(t), quietLogger())
	ctx := context.Background()

	if err := r.RecordErr(ctx, Event{
		Action:   ActionExported,
		Severity: SeverityCritical, // above the notice floor
	}); err != nil {
		t.Fatal(err)
	}

	events, err := r.List(ctx, Query{Action: ActionExported})
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Severity != SeverityCritical {
		t.Errorf("severity = %q; the floor must not lower a caller's severity", events[0].Severity)
	}
}

func TestRecordRequiresAction(t *testing.T) {
	r := NewRecorder(testDB(t), quietLogger())
	if err := r.RecordErr(context.Background(), Event{ActorID: "user-1"}); err == nil {
		t.Fatal("an event without an action must be refused")
	}
}

// TestRecordDoesNotBlockCallerOnFailure confirms Record swallows write errors.
// A broken audit table must not stop a user logging out.
func TestRecordDoesNotBlockCallerOnFailure(t *testing.T) {
	db := testDB(t)
	r := NewRecorder(db, quietLogger())
	ctx := context.Background()

	if _, err := db.Exec(ctx, `DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}

	// Must not panic and must return normally.
	r.Record(ctx, Event{Action: ActionLogout, ActorID: "user-1"})
}

// TestUnauthenticatedEventsHaveNullActor keeps failed logins — where there is
// no authenticated actor yet — from carrying a meaningless empty ID.
func TestUnauthenticatedEventsHaveNullActor(t *testing.T) {
	db := testDB(t)
	r := NewRecorder(db, quietLogger())
	ctx := context.Background()

	if err := r.RecordErr(ctx, Event{
		Action:     ActionLoginFailed,
		ActorEmail: "someone@example.com",
		Outcome:    OutcomeFailure,
		IPAddress:  "198.51.100.7",
	}); err != nil {
		t.Fatal(err)
	}

	var actorID *string
	if err := db.QueryRow(ctx, `SELECT actor_id FROM audit_events`).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	if actorID != nil {
		t.Errorf("actor_id = %q, want NULL for an unauthenticated event", *actorID)
	}
}

// TestEventsOutliveDeletedUsers is why audit_events carries no foreign key on
// actor_id: deleting an account must not erase what it did.
func TestEventsOutliveDeletedUsers(t *testing.T) {
	db := testDB(t)
	r := NewRecorder(db, quietLogger())
	ctx := context.Background()

	const ts = "2026-01-01T00:00:00Z"
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"user-1", "alice@example.com", "alice@example.com", ts, ts); err != nil {
		t.Fatal(err)
	}

	if err := r.RecordErr(ctx, Event{
		ActorID: "user-1", ActorEmail: "alice@example.com", Action: ActionCredentialCreated,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(ctx, `DELETE FROM users WHERE id = ?`, "user-1"); err != nil {
		t.Fatal(err)
	}

	events, err := r.List(ctx, Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("deleting the user erased %d audit events", 1-len(events))
	}
	if events[0].ActorEmail != "alice@example.com" {
		t.Error("the actor's identity was not preserved on the event")
	}
}

func TestListFilters(t *testing.T) {
	db := testDB(t)
	r := NewRecorder(db, quietLogger())
	ctx := context.Background()

	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	seed := []struct {
		actor  string
		action Action
		at     time.Time
	}{
		{"alice", ActionLoginSucceeded, base},
		{"alice", ActionCredentialCreated, base.Add(time.Hour)},
		{"bob", ActionLoginSucceeded, base.Add(2 * time.Hour)},
		{"bob", ActionExported, base.Add(3 * time.Hour)},
	}
	for _, s := range seed {
		if err := r.RecordErr(ctx, Event{ActorID: s.actor, Action: s.action, OccurredAt: s.at}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("by actor", func(t *testing.T) {
		events, err := r.List(ctx, Query{ActorID: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 2 {
			t.Fatalf("got %d events, want 2", len(events))
		}
		for _, e := range events {
			if e.ActorID != "alice" {
				t.Errorf("another actor leaked in: %s", e.ActorID)
			}
		}
	})

	t.Run("by action", func(t *testing.T) {
		events, err := r.List(ctx, Query{Action: ActionLoginSucceeded})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 2 {
			t.Fatalf("got %d events, want 2", len(events))
		}
	})

	t.Run("by time range", func(t *testing.T) {
		events, err := r.List(ctx, Query{
			Since: base.Add(90 * time.Minute),
			Until: base.Add(150 * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 {
			t.Fatalf("got %d events, want 1", len(events))
		}
		if events[0].ActorID != "bob" || events[0].Action != ActionLoginSucceeded {
			t.Errorf("wrong event returned: %+v", events[0])
		}
	})

	t.Run("newest first", func(t *testing.T) {
		events, err := r.List(ctx, Query{})
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(events); i++ {
			if events[i-1].OccurredAt.Before(events[i].OccurredAt) {
				t.Fatal("events are not ordered newest first")
			}
		}
	})

	t.Run("limit is bounded", func(t *testing.T) {
		events, err := r.List(ctx, Query{Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 2 {
			t.Fatalf("got %d events, want 2", len(events))
		}

		// An absurd limit must be clamped rather than dumping the table.
		events, err = r.List(ctx, Query{Limit: 1_000_000})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) > 1000 {
			t.Fatalf("limit was not clamped: %d rows", len(events))
		}
	})
}

// TestNoMutationPath is a structural assertion: this package must expose no
// way to alter or delete an event. An audit log the application can rewrite
// is not an audit log.
func TestNoMutationPath(t *testing.T) {
	body, err := os.ReadFile("audit.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)

	for _, forbidden := range []string{"UPDATE audit_events", "DELETE FROM audit_events"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("audit.go contains %q; the log must be append-only", forbidden)
		}
	}
}
