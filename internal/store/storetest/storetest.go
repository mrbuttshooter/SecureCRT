// Package storetest provides a database for tests.
//
// It exists to solve two problems that bit once already. First, every package
// that touches the database was growing its own near-identical copy of this
// setup. Second, and worse: `go test ./...` runs packages in parallel against
// one PostgreSQL database, so a naive "DROP SCHEMA public CASCADE" per test
// destroys the tables another package is midway through using. That failure
// only appears in the full run, never when the failing package is run alone,
// which makes it exactly the kind of thing that gets dismissed as a flake.
//
// Each process therefore gets its own uniquely named PostgreSQL schema,
// created up front and dropped at exit, with search_path pointed at it. SQLite
// needs none of this: every test already gets its own temporary file.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mrbuttshooter/securecrt/internal/store"
)

// EnvPostgresDSN selects the PostgreSQL backend. Unset means SQLite.
const EnvPostgresDSN = "BKD_TEST_POSTGRES_DSN"

var (
	schemaOnce sync.Once
	schemaName string
	schemaErr  error
)

// QuietLogger returns a logger that discards output, so test runs are not
// buried in migration chatter.
func QuietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// UsingPostgres reports which backend the suite is running against.
func UsingPostgres() bool {
	return os.Getenv(EnvPostgresDSN) != ""
}

// New returns a migrated, isolated database, registering cleanup on t.
func New(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()

	db, err := open(ctx, t)
	if err != nil {
		t.Fatalf("storetest: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := store.Migrate(ctx, db, QuietLogger()); err != nil {
		t.Fatalf("storetest: migrate: %v", err)
	}
	return db
}

func open(ctx context.Context, t *testing.T) (*store.DB, error) {
	dsn := os.Getenv(EnvPostgresDSN)
	if dsn == "" {
		return store.Open(ctx, store.Options{
			Driver: store.DriverSQLite,
			DSN:    filepath.Join(t.TempDir(), "test.db"),
		})
	}

	schemaOnce.Do(func() { schemaName, schemaErr = createSchema(ctx, dsn) })
	if schemaErr != nil {
		return nil, schemaErr
	}

	scoped, err := withSearchPath(dsn, schemaName)
	if err != nil {
		return nil, err
	}

	db, err := store.Open(ctx, store.Options{Driver: store.DriverPostgres, DSN: scoped})
	if err != nil {
		return nil, err
	}

	// Each test starts from an empty schema. Safe to do here, unlike against
	// the shared public schema, because this schema belongs to this process
	// alone.
	if _, err := db.Exec(ctx, fmt.Sprintf(
		`DROP SCHEMA IF EXISTS %s CASCADE; CREATE SCHEMA %s;`, schemaName, schemaName)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("reset schema %s: %w", schemaName, err)
	}
	return db, nil
}

// createSchema makes this process's private schema.
func createSchema(ctx context.Context, dsn string) (string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", fmt.Errorf("generate schema name: %w", err)
	}
	name := "bkd_test_" + hex.EncodeToString(suffix)

	db, err := store.Open(ctx, store.Options{Driver: store.DriverPostgres, DSN: dsn})
	if err != nil {
		return "", fmt.Errorf("connect to create schema: %w", err)
	}
	defer db.Close() //nolint:errcheck

	if _, err := db.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, name)); err != nil {
		return "", fmt.Errorf("create schema %s: %w", name, err)
	}
	return name, nil
}

// withSearchPath points a DSN at a specific schema.
//
// It has to go in the connection string rather than a SET statement, because
// database/sql pools connections and a SET would apply only to whichever one
// happened to run it.
func withSearchPath(dsn, schema string) (string, error) {
	opt := "-c search_path=" + schema

	// Key/value DSNs ("host=... dbname=...") and URL DSNs need different
	// treatment.
	if !strings.Contains(dsn, "://") {
		return dsn + " options='" + opt + "'", nil
	}

	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse DSN: %w", err)
	}
	q := u.Query()
	q.Set("options", opt)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// DropSchema removes this process's schema. Call it from TestMain after
// m.Run() so a long CI run does not leave schemas behind.
func DropSchema() {
	dsn := os.Getenv(EnvPostgresDSN)
	if dsn == "" || schemaName == "" {
		return
	}

	ctx := context.Background()
	db, err := store.Open(ctx, store.Options{Driver: store.DriverPostgres, DSN: dsn})
	if err != nil {
		return
	}
	defer db.Close() //nolint:errcheck

	_, _ = db.Exec(ctx, fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, schemaName))
}
