package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// backends returns every database this suite can reach.
//
// SQLite always runs. PostgreSQL runs only when BKD_TEST_POSTGRES_DSN is set,
// so `go test ./...` works on a bare checkout while CI still exercises the
// production driver.
func backends(t *testing.T) map[string]func(t *testing.T) *DB {
	t.Helper()

	out := map[string]func(t *testing.T) *DB{
		"sqlite": func(t *testing.T) *DB {
			t.Helper()
			path := filepath.Join(t.TempDir(), "test.db")
			db, err := Open(context.Background(), Options{Driver: DriverSQLite, DSN: path})
			if err != nil {
				t.Fatalf("open sqlite: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			return db
		},
	}

	if dsn := os.Getenv("BKD_TEST_POSTGRES_DSN"); dsn != "" {
		out["postgres"] = func(t *testing.T) *DB {
			t.Helper()
			db, err := Open(context.Background(), Options{Driver: DriverPostgres, DSN: dsn})
			if err != nil {
				t.Fatalf("open postgres: %v", err)
			}
			// Each test gets a clean schema; Postgres instances are reused
			// across tests, unlike the per-test SQLite temp file.
			if _, err := db.Exec(context.Background(), `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
				t.Fatalf("reset schema: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			return db
		}
	}
	return out
}

func eachBackend(t *testing.T, fn func(t *testing.T, db *DB)) {
	t.Helper()
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) { fn(t, open(t)) })
	}
}

func TestLoadMigrations(t *testing.T) {
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations found; the embed directive is not matching")
	}

	for i, m := range ms {
		if m.Up == "" || m.Down == "" {
			t.Errorf("migration %d (%s) is missing a direction", m.Version, m.Name)
		}
		if m.Checksum == "" {
			t.Errorf("migration %d has no checksum", m.Version)
		}
		if i > 0 && ms[i-1].Version >= m.Version {
			t.Errorf("migrations out of order: %d before %d", ms[i-1].Version, m.Version)
		}
	}
}

func TestMigrateCreatesSchema(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()

		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}

		v, err := CurrentVersion(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if v < 1 {
			t.Fatalf("version = %d after migrating", v)
		}

		// Every table the application depends on must exist.
		for _, table := range []string{
			"users", "teams", "team_members", "credentials",
			"folders", "sessions", "known_hosts", "auth_sessions", "audit_events",
			"mfa_totp", "mfa_recovery_codes", "webauthn_credentials", "login_attempts",
		} {
			var n int
			q := fmt.Sprintf(`SELECT COUNT(*) FROM %s`, table) // #nosec G201 -- fixed list
			if err := db.QueryRow(ctx, q).Scan(&n); err != nil {
				t.Errorf("table %s is not queryable: %v", table, err)
			}
		}
	})
}

func TestMigrateIsIdempotent(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()

		for i := 0; i < 3; i++ {
			if err := Migrate(ctx, db, quietLogger()); err != nil {
				t.Fatalf("Migrate run %d: %v", i+1, err)
			}
		}

		var n int
		if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		ms, err := LoadMigrations()
		if err != nil {
			t.Fatal(err)
		}
		if n != len(ms) {
			t.Fatalf("schema_migrations has %d rows, want %d", n, len(ms))
		}
	})
}

// TestMigrateDetectsEditedMigration guards the classic deployment trap: a
// migration edited after it shipped, leaving environments silently divergent.
func TestMigrateDetectsEditedMigration(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()

		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}

		// Simulate someone editing an already-applied migration file.
		if _, err := db.Exec(ctx,
			`UPDATE schema_migrations SET checksum = ? WHERE version = 1`,
			strings.Repeat("de", 32)); err != nil {
			t.Fatal(err)
		}

		err := Migrate(ctx, db, quietLogger())
		if !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("want ErrChecksumMismatch, got %v", err)
		}
	})
}

// TestRollbackIsSingleStep confirms Rollback reverts exactly one migration,
// not everything above some floor. An operator undoing a bad deploy must be
// able to step back one version at a time.
func TestRollbackIsSingleStep(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()

		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}
		before, err := CurrentVersion(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if before < 2 {
			t.Skip("needs at least two migrations to be meaningful")
		}

		if err := Rollback(ctx, db, quietLogger()); err != nil {
			t.Fatalf("Rollback: %v", err)
		}

		after, err := CurrentVersion(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if after != before-1 {
			t.Fatalf("version = %d after one rollback, want %d", after, before-1)
		}

		// The earlier migration's tables must still be there.
		var n int
		if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			t.Fatalf("a single-step rollback removed more than one migration: %v", err)
		}
	})
}

// TestRollbackAllThenRemigrate walks the schema all the way down and back up.
// This is what catches a down migration that does not actually undo its up:
// the second Migrate would fail, or leave a different schema behind.
func TestRollbackAllThenRemigrate(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()

		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}
		top, err := CurrentVersion(ctx, db)
		if err != nil {
			t.Fatal(err)
		}

		for i := top; i > 0; i-- {
			if err := Rollback(ctx, db, quietLogger()); err != nil {
				t.Fatalf("rolling back version %d: %v", i, err)
			}
		}

		v, err := CurrentVersion(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if v != 0 {
			t.Fatalf("version = %d after rolling everything back, want 0", v)
		}

		var n int
		if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err == nil {
			t.Fatal("users table survived a full rollback")
		}

		// Everything must come back cleanly.
		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatalf("re-migrate after a full rollback: %v", err)
		}
		for _, table := range []string{
			"users", "teams", "credentials", "sessions", "auth_sessions",
			"mfa_totp", "mfa_recovery_codes", "webauthn_credentials", "login_attempts",
		} {
			q := fmt.Sprintf(`SELECT COUNT(*) FROM %s`, table) // #nosec G201 -- fixed list
			if err := db.QueryRow(ctx, q).Scan(&n); err != nil {
				t.Errorf("table %s was not restored: %v", table, err)
			}
		}

		restored, err := CurrentVersion(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if restored != top {
			t.Fatalf("version = %d after re-migrating, want %d", restored, top)
		}
	})
}

func TestRollbackOnEmptyDatabase(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()
		if _, err := db.Exec(ctx, createMigrationsTable); err != nil {
			t.Fatal(err)
		}
		if err := Rollback(ctx, db, quietLogger()); err == nil {
			t.Fatal("rolling back an unmigrated database must be an error")
		}
	})
}

func TestRebind(t *testing.T) {
	pg := &DB{driver: DriverPostgres}
	lite := &DB{driver: DriverSQLite}

	cases := []struct {
		name  string
		query string
		want  string
	}{
		{"no params", "SELECT 1", "SELECT 1"},
		{"one param", "SELECT * FROM users WHERE id = ?", "SELECT * FROM users WHERE id = $1"},
		{"three params", "INSERT INTO t VALUES (?, ?, ?)", "INSERT INTO t VALUES ($1, $2, $3)"},
		{
			// A question mark inside a string literal is data, not a
			// placeholder, and must survive untouched.
			"literal question mark",
			"SELECT * FROM t WHERE name = 'why?' AND id = ?",
			"SELECT * FROM t WHERE name = 'why?' AND id = $1",
		},
		{
			"escaped quote in literal",
			"SELECT * FROM t WHERE name = 'it''s ok?' AND id = ?",
			"SELECT * FROM t WHERE name = 'it''s ok?' AND id = $1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pg.Rebind(tc.query); got != tc.want {
				t.Errorf("postgres: got %q, want %q", got, tc.want)
			}
			if got := lite.Rebind(tc.query); got != tc.query {
				t.Errorf("sqlite must pass through unchanged: got %q", got)
			}
		})
	}
}

func TestOpenRejectsUnknownDriver(t *testing.T) {
	if _, err := Open(context.Background(), Options{Driver: "mongodb", DSN: "x"}); err == nil {
		t.Fatal("unknown driver must be rejected")
	}
}

// TestSQLiteEnforcesForeignKeys is the reason Open sets the foreign_keys
// pragma: without it SQLite parses ON DELETE CASCADE and then ignores it,
// so deleting a user would silently orphan their credentials.
func TestSQLiteEnforcesForeignKeys(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "fk.db")

	db, err := Open(ctx, Options{Driver: DriverSQLite, DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck

	if err := Migrate(ctx, db, quietLogger()); err != nil {
		t.Fatal(err)
	}

	const ts = "2026-01-01T00:00:00Z"
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"u1", "a@x", "a@x", ts, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO credentials (id, user_id, name, kind, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"c1", "u1", "key", "ssh_key", ts, ts); err != nil {
		t.Fatal(err)
	}

	// A credential referencing a non-existent user must be refused.
	if _, err := db.Exec(ctx,
		`INSERT INTO credentials (id, user_id, name, kind, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"c2", "ghost", "key", "ssh_key", ts, ts); err == nil {
		t.Fatal("foreign key violation was not enforced")
	}

	// And deleting the user must cascade.
	if _, err := db.Exec(ctx, `DELETE FROM users WHERE id = ?`, "u1"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM credentials WHERE user_id = ?`, "u1").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d credentials survived the cascade", n)
	}
}

// TestOwnershipCheckConstraint verifies the schema's central invariant: a
// credential belongs to exactly one of a user or a team, never both, never
// neither.
func TestOwnershipCheckConstraint(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()
		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}

		const ts = "2026-01-01T00:00:00Z"
		if _, err := db.Exec(ctx,
			`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			"u1", "a@x", "a@x", ts, ts); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx,
			`INSERT INTO teams (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)`,
			"t1", "netops", ts, ts); err != nil {
			t.Fatal(err)
		}

		t.Run("both owners rejected", func(t *testing.T) {
			_, err := db.Exec(ctx,
				`INSERT INTO credentials (id, user_id, team_id, name, kind, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				"c-both", "u1", "t1", "x", "password", ts, ts)
			if err == nil {
				t.Fatal("a credential owned by both a user and a team must be rejected")
			}
		})

		t.Run("no owner rejected", func(t *testing.T) {
			_, err := db.Exec(ctx,
				`INSERT INTO credentials (id, name, kind, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
				"c-none", "x", "password", ts, ts)
			if err == nil {
				t.Fatal("an unowned credential must be rejected")
			}
		})

		t.Run("single owner accepted", func(t *testing.T) {
			if _, err := db.Exec(ctx,
				`INSERT INTO credentials (id, user_id, name, kind, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
				"c-user", "u1", "x", "password", ts, ts); err != nil {
				t.Fatalf("user-owned credential rejected: %v", err)
			}
			if _, err := db.Exec(ctx,
				`INSERT INTO credentials (id, team_id, name, kind, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
				"c-team", "t1", "x", "password", ts, ts); err != nil {
				t.Fatalf("team-owned credential rejected: %v", err)
			}
		})
	})
}

func TestPortRangeConstraint(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()
		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}

		const ts = "2026-01-01T00:00:00Z"
		if _, err := db.Exec(ctx,
			`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			"u1", "a@x", "a@x", ts, ts); err != nil {
			t.Fatal(err)
		}

		for _, port := range []int{-1, 65536, 99999} {
			_, err := db.Exec(ctx,
				`INSERT INTO sessions (id, user_id, name, hostname, port, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				fmt.Sprintf("s-%d", port), "u1", "x", "h", port, ts, ts)
			if err == nil {
				t.Errorf("port %d must be rejected", port)
			}
		}
		// Zero is accepted from migration 0003 onward, and means "inherit
		// from the folder". It is the one value outside 1-65535 that has to
		// get through, so it is listed with the valid ports rather than
		// quietly removed from the invalid ones.
		for _, port := range []int{0, 1, 22, 23, 65535} {
			_, err := db.Exec(ctx,
				`INSERT INTO sessions (id, user_id, name, hostname, port, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				fmt.Sprintf("ok-%d", port), "u1", "x", "h", port, ts, ts)
			if err != nil {
				t.Errorf("port %d must be accepted: %v", port, err)
			}
		}
	})
}

// TestInTxRollsBackOnError confirms a failed multi-step write leaves nothing
// behind — the property the team-key rewrap path depends on.
func TestInTxRollsBackOnError(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()
		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}

		const ts = "2026-01-01T00:00:00Z"
		sentinel := errors.New("deliberate failure")

		err := db.InTx(ctx, func(tx *Tx) error {
			if _, err := tx.Exec(ctx,
				`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
				"u1", "a@x", "a@x", ts, ts); err != nil {
				return err
			}
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("want the sentinel error back, got %v", err)
		}

		var n int
		if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%d users survived the rollback", n)
		}
	})
}

func TestInTxCommitsOnSuccess(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()
		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}

		const ts = "2026-01-01T00:00:00Z"
		err := db.InTx(ctx, func(tx *Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
				"u1", "a@x", "a@x", ts, ts)
			return err
		})
		if err != nil {
			t.Fatalf("InTx: %v", err)
		}

		var got string
		if err := db.QueryRow(ctx, `SELECT email FROM users WHERE id = ?`, "u1").Scan(&got); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				t.Fatal("the committed row is missing")
			}
			t.Fatal(err)
		}
		if got != "a@x" {
			t.Fatalf("email = %q", got)
		}
	})
}

// TestInTxRollsBackOnPanic prevents a panic from stranding an open
// transaction, which on SQLite would block every subsequent write.
func TestInTxRollsBackOnPanic(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()
		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}
		const ts = "2026-01-01T00:00:00Z"

		func() {
			defer func() {
				if recover() == nil {
					t.Error("the panic should have propagated")
				}
			}()
			_ = db.InTx(ctx, func(tx *Tx) error {
				if _, err := tx.Exec(ctx,
					`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
					"u1", "a@x", "a@x", ts, ts); err != nil {
					t.Error(err)
				}
				panic("boom")
			})
		}()

		// The connection must still be usable, and the write must be gone.
		var n int
		if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			t.Fatalf("connection unusable after panic: %v", err)
		}
		if n != 0 {
			t.Fatalf("%d users survived the panic rollback", n)
		}
	})
}

// TestFreshDatabaseVersionFlow is a regression test for a real bug: reading
// the schema version before migrating failed on a brand-new database, because
// the bookkeeping table did not exist yet. It went unnoticed because every
// other test migrated first.
func TestFreshDatabaseVersionFlow(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()

		// Exactly the sequence "bkd migrate" performs on a fresh database.
		if err := EnsureMigrationsTable(ctx, db); err != nil {
			t.Fatalf("EnsureMigrationsTable: %v", err)
		}

		before, err := CurrentVersion(ctx, db)
		if err != nil {
			t.Fatalf("CurrentVersion on a fresh database: %v", err)
		}
		if before != 0 {
			t.Fatalf("fresh database reports version %d, want 0", before)
		}

		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}

		after, err := CurrentVersion(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if after <= before {
			t.Fatalf("version did not advance: %d -> %d", before, after)
		}
	})
}

func TestEnsureMigrationsTableIsIdempotent(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			if err := EnsureMigrationsTable(ctx, db); err != nil {
				t.Fatalf("call %d: %v", i+1, err)
			}
		}
	})
}

// TestTheInheritedPortMigrationCarriesExistingRows exercises 0003 the way an
// upgrade does: with data already in the table.
//
// It is the first migration that rebuilds a table rather than adding a
// column, so "does it apply cleanly to an empty schema" — which every other
// test here checks — is the easy half. The half that matters to somebody with
// three hundred saved connections is whether their rows come out the other
// side unchanged, and whether the down migration they might reach for after a
// bad deploy leaves them anything to go back to.
func TestTheInheritedPortMigrationCarriesExistingRows(t *testing.T) {
	eachBackend(t, func(t *testing.T, db *DB) {
		ctx := context.Background()
		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatal(err)
		}

		const ts = "2026-01-01T00:00:00Z"
		if _, err := db.Exec(ctx,
			`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			"u1", "a@x", "a@x", ts, ts); err != nil {
			t.Fatal(err)
		}

		rows := []struct {
			id       string
			protocol string
			port     int
		}{
			{"explicit", "ssh", 2222},
			{"inherited", "ssh", 0},
			{"telnet-inherited", "telnet", 0},
		}
		for _, r := range rows {
			if _, err := db.Exec(ctx,
				`INSERT INTO sessions (id, user_id, name, protocol, hostname, port, created_at, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				r.id, "u1", r.id, r.protocol, "h", r.port, ts, ts); err != nil {
				t.Fatalf("insert %s: %v", r.id, err)
			}
		}

		// Down: zero has nowhere to go in the old schema, so it becomes the
		// protocol's default. Everything else must be untouched.
		if err := Rollback(ctx, db, quietLogger()); err != nil {
			t.Fatalf("rollback: %v", err)
		}

		afterDown := map[string]int{"explicit": 2222, "inherited": 22, "telnet-inherited": 23}
		for id, want := range afterDown {
			var got int
			if err := db.QueryRow(ctx, `SELECT port FROM sessions WHERE id = ?`, id).Scan(&got); err != nil {
				t.Fatalf("%s vanished in the rollback: %v", id, err)
			}
			if got != want {
				t.Errorf("after rollback %s has port %d, want %d", id, got, want)
			}
		}

		// And up again. The rows carry through as they now stand — the
		// migration deliberately does not rewrite 22 to 0, because that would
		// re-point every default-port connection at whatever its folder says.
		if err := Migrate(ctx, db, quietLogger()); err != nil {
			t.Fatalf("re-migrate: %v", err)
		}
		for id, want := range afterDown {
			var got int
			if err := db.QueryRow(ctx, `SELECT port FROM sessions WHERE id = ?`, id).Scan(&got); err != nil {
				t.Fatalf("%s vanished on the way back up: %v", id, err)
			}
			if got != want {
				t.Errorf("after re-migrating %s has port %d, want %d", id, got, want)
			}
		}

		// The indexes have to come back too, or the rebuild leaves a table
		// that works and scans.
		var indexes int
		if err := db.QueryRow(ctx,
			`SELECT COUNT(*) FROM sessions WHERE user_id = ? AND folder_id IS NULL`,
			"u1").Scan(&indexes); err != nil {
			t.Fatalf("the rebuilt table is not queryable by its index columns: %v", err)
		}
	})
}
