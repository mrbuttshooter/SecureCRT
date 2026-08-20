package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migration is one versioned schema change, read from the embedded
// migrations directory.
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
	// Checksum of the Up body. Recorded at apply time so that editing an
	// already-applied migration is detected rather than silently ignored —
	// the usual cause of "works on my machine, broken in production".
	Checksum string
}

// LoadMigrations parses the embedded migrations directory.
//
// Files are named NNNN_description.up.sql and NNNN_description.down.sql.
// Every up migration must have a matching down migration: an irreversible
// schema change should be a deliberate, documented decision, not an
// oversight.
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}

	byVersion := make(map[int]*Migration)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()

		var direction string
		switch {
		case strings.HasSuffix(name, ".up.sql"):
			direction = "up"
		case strings.HasSuffix(name, ".down.sql"):
			direction = "down"
		default:
			return nil, fmt.Errorf("store: migration %s must end in .up.sql or .down.sql", name)
		}

		base := strings.TrimSuffix(name, "."+direction+".sql")
		idx := strings.Index(base, "_")
		if idx <= 0 {
			return nil, fmt.Errorf("store: migration %s must be named NNNN_description", name)
		}
		version, err := strconv.Atoi(base[:idx])
		if err != nil {
			return nil, fmt.Errorf("store: migration %s has a non-numeric version: %w", name, err)
		}

		body, err := migrationFS.ReadFile(path.Join("migrations", name))
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", name, err)
		}

		m, ok := byVersion[version]
		if !ok {
			m = &Migration{Version: version, Name: base[idx+1:]}
			byVersion[version] = m
		}
		if direction == "up" {
			m.Up = string(body)
			sum := sha256.Sum256(body)
			m.Checksum = hex.EncodeToString(sum[:])
		} else {
			m.Down = string(body)
		}
	}

	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.Up == "" {
			return nil, fmt.Errorf("store: migration %d (%s) has no up file", m.Version, m.Name)
		}
		if m.Down == "" {
			return nil, fmt.Errorf("store: migration %d (%s) has no down file", m.Version, m.Name)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// ErrChecksumMismatch means an already-applied migration's contents changed
// since it ran. Continuing would leave the schema in a state nobody can
// reproduce, so this is fatal rather than a warning.
var ErrChecksumMismatch = errors.New("store: applied migration has been modified")

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL
)`

// EnsureMigrationsTable creates the bookkeeping table if it is absent.
//
// Exported because callers that inspect the schema version before migrating —
// the "bkd migrate" command, which reports the before/after versions — would
// otherwise query a table that does not yet exist on a fresh database.
func EnsureMigrationsTable(ctx context.Context, db *DB) error {
	if _, err := db.Exec(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	return nil
}

// Migrate brings the database up to the latest schema version.
//
// Each migration runs inside its own transaction, so a failure leaves the
// database at the last complete version rather than half-migrated. Both
// PostgreSQL and SQLite support transactional DDL, which is what makes this
// safe.
func Migrate(ctx context.Context, db *DB, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}

	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}

	if err := EnsureMigrationsTable(ctx, db); err != nil {
		return err
	}

	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if prev, ok := applied[m.Version]; ok {
			if prev != m.Checksum {
				return fmt.Errorf("%w: version %d (%s): recorded %s, found %s",
					ErrChecksumMismatch, m.Version, m.Name, prev[:12], m.Checksum[:12])
			}
			continue
		}

		if err := applyMigration(ctx, db, m); err != nil {
			return err
		}
		log.Info("applied migration", "version", m.Version, "name", m.Name)
	}
	return nil
}

func appliedMigrations(ctx context.Context, db *DB) (map[int]string, error) {
	rows, err := db.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: read schema_migrations: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	out := make(map[int]string)
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return nil, fmt.Errorf("store: scan schema_migrations: %w", err)
		}
		out[v] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate schema_migrations: %w", err)
	}
	return out, nil
}

func applyMigration(ctx context.Context, db *DB, m Migration) error {
	return db.InTx(ctx, func(tx *Tx) error {
		if _, err := tx.Exec(ctx, m.Up); err != nil {
			return fmt.Errorf("store: apply migration %d (%s): %w", m.Version, m.Name, err)
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
			m.Version, m.Name, m.Checksum, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("store: record migration %d: %w", m.Version, err)
		}
		return nil
	})
}

// Rollback reverts the single most recently applied migration.
//
// Deliberately one step at a time: an operator undoing a bad deploy should
// have to consider each schema change individually rather than issuing one
// command that discards several.
func Rollback(ctx context.Context, db *DB, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}

	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}

	if err := EnsureMigrationsTable(ctx, db); err != nil {
		return err
	}

	var current int
	err = db.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current)
	if err != nil {
		return fmt.Errorf("store: read current version: %w", err)
	}
	if current == 0 {
		return errors.New("store: nothing to roll back")
	}

	var target *Migration
	for i := range migrations {
		if migrations[i].Version == current {
			target = &migrations[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("store: applied version %d has no migration file; refusing to roll back blind", current)
	}

	err = db.InTx(ctx, func(tx *Tx) error {
		if _, err := tx.Exec(ctx, target.Down); err != nil {
			return fmt.Errorf("store: roll back migration %d (%s): %w", target.Version, target.Name, err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version = ?`, target.Version); err != nil {
			return fmt.Errorf("store: clear migration record %d: %w", target.Version, err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	log.Info("rolled back migration", "version", target.Version, "name", target.Name)
	return nil
}

// CurrentVersion reports the highest applied schema version, or 0 for a fresh
// database.
//
// The caller must have run Migrate or EnsureMigrationsTable first; this does
// not create the bookkeeping table itself, so that a genuine "table is
// missing" fault is reported rather than masked as version 0.
func CurrentVersion(ctx context.Context, db *DB) (int, error) {
	var v int
	err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: read current version: %w", err)
	}
	return v, nil
}
