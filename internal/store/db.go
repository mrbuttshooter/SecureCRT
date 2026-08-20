// Package store owns the database schema, migrations, and data access.
//
// One schema serves both PostgreSQL (the company deployment) and SQLite (a
// single-user or lab install). The only place the two genuinely differ is
// bind-parameter syntax — Postgres wants $1, SQLite wants ? — which Rebind
// normalises so that every query in this package can be written once, in the
// portable ? form.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
	_ "modernc.org/sqlite"             // pure-Go SQLite; keeps CGO_ENABLED=0
)

// Driver names accepted in configuration.
const (
	DriverPostgres = "postgres"
	DriverSQLite   = "sqlite"
)

// DB wraps *sql.DB with the driver identity needed to rewrite bind
// parameters.
type DB struct {
	*sql.DB
	driver string
}

// Driver reports which backend this connection speaks.
func (db *DB) Driver() string { return db.driver }

// Options configures a database connection.
type Options struct {
	Driver          string
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// Open connects to the database and verifies the connection.
//
// SQLite gets three pragmas that are not optional for this workload: WAL so
// readers do not block the writer, a busy timeout so concurrent terminal
// sessions retry instead of failing outright, and foreign_keys because SQLite
// otherwise ignores every ON DELETE CASCADE in the schema.
func Open(ctx context.Context, opts Options) (*DB, error) {
	var driverName, dsn string

	switch opts.Driver {
	case DriverPostgres:
		driverName, dsn = "pgx", opts.DSN
	case DriverSQLite:
		driverName = "sqlite"
		dsn = opts.DSN
		if !strings.Contains(dsn, "_pragma=") {
			sep := "?"
			if strings.Contains(dsn, "?") {
				sep = "&"
			}
			dsn += sep + "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
		}
	default:
		return nil, fmt.Errorf("store: unsupported driver %q", opts.Driver)
	}

	sqlDB, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", opts.Driver, err)
	}

	if opts.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(opts.MaxOpenConns)
	}
	if opts.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(opts.MaxIdleConns)
	}
	if opts.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(opts.ConnMaxLifetime)
	}

	// SQLite writes are serialised by a single file lock. Allowing several
	// connections buys nothing and turns lock contention into SQLITE_BUSY
	// errors under load.
	if opts.Driver == DriverSQLite {
		sqlDB.SetMaxOpenConns(1)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("store: connect to %s: %w", opts.Driver, err)
	}

	return &DB{DB: sqlDB, driver: opts.Driver}, nil
}

// Rebind rewrites portable ? placeholders into the driver's own syntax.
//
// Single-quoted string literals are skipped so a query containing a literal
// question mark is not mangled. Doubled quotes (” inside a literal) are the
// SQL escape for one quote, and are handled by simply toggling twice.
func (db *DB) Rebind(query string) string {
	if db.driver != DriverPostgres {
		return query
	}

	var b strings.Builder
	b.Grow(len(query) + 8)

	n := 0
	inLiteral := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\'':
			inLiteral = !inLiteral
			b.WriteByte(c)
		case c == '?' && !inLiteral:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Exec runs a statement, rebinding placeholders first.
func (db *DB) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.ExecContext(ctx, db.Rebind(query), args...)
}

// Query runs a query, rebinding placeholders first.
func (db *DB) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return db.QueryContext(ctx, db.Rebind(query), args...)
}

// QueryRow runs a single-row query, rebinding placeholders first.
func (db *DB) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return db.QueryRowContext(ctx, db.Rebind(query), args...)
}

// InTx runs fn inside a transaction, committing on success and rolling back
// on error or panic.
//
// The panic path matters: without it, a panic mid-transaction would leave the
// connection holding an open transaction until its lifetime expired, which on
// SQLite means every other write blocks.
func (db *DB) InTx(ctx context.Context, fn func(tx *Tx) error) (err error) {
	sqlTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin transaction: %w", err)
	}

	tx := &Tx{Tx: sqlTx, db: db}
	defer func() {
		if p := recover(); p != nil {
			_ = sqlTx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = sqlTx.Rollback()
		}
	}()

	if err = fn(tx); err != nil {
		return err
	}
	if err = sqlTx.Commit(); err != nil {
		return fmt.Errorf("store: commit transaction: %w", err)
	}
	return nil
}

// Tx is a transaction with the same placeholder rewriting as DB.
type Tx struct {
	*sql.Tx
	db *DB
}

// Exec runs a statement inside the transaction.
func (t *Tx) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.ExecContext(ctx, t.db.Rebind(query), args...)
}

// Query runs a query inside the transaction.
func (t *Tx) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.QueryContext(ctx, t.db.Rebind(query), args...)
}

// QueryRow runs a single-row query inside the transaction.
func (t *Tx) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return t.QueryRowContext(ctx, t.db.Rebind(query), args...)
}
