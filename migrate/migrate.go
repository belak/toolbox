// Package migrate provides a minimal database migration runner.
// Migrations are read from an fs.FS (typically embed.FS) and applied in
// lexicographic order. Applied versions are tracked in a configurable
// table.
//
// Database access and dialect differences are abstracted through the DB
// interface. Use NewDriver to wrap a *sql.DB with a Dialect, or the
// pgxmigrate sub-package for native pgx support.
package migrate

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// DB abstracts database operations and dialect-specific SQL. Use
// NewDriver to create one from a *sql.DB and Dialect, or implement
// this interface for other database libraries such as pgx.
type DB interface {
	Exec(ctx context.Context, query string, args ...any) error
	Query(ctx context.Context, query string, args ...any) (Rows, error)
	Begin(ctx context.Context) (Tx, error)

	CreateTableSQL(table string) string
	InsertVersionSQL(table string) string
	QueryVersionsSQL(table string) string
}

// Rows abstracts result set iteration.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// Tx abstracts a database transaction.
type Tx interface {
	Exec(ctx context.Context, query string, args ...any) error
	Rollback(ctx context.Context) error
	Commit(ctx context.Context) error
}

// Dialect abstracts dialect-specific SQL differences.
type Dialect interface {
	CreateTableSQL(table string) string
	InsertVersionSQL(table string) string
	QueryVersionsSQL(table string) string
}

// Migrator runs migrations against a database.
type Migrator struct {
	db    DB
	fs    fs.FS
	dir   string // subdirectory within fs to read migrations from
	table string
}

// Option configures a Migrator.
type Option func(*Migrator)

// WithTable sets the migrations tracking table name (default:
// "schema_migrations").
func WithTable(name string) Option {
	return func(m *Migrator) { m.table = name }
}

// WithDirectory sets the subdirectory within the fs.FS to read migration
// files from (default: "migrations"). Use "." to read from the root.
func WithDirectory(dir string) Option {
	return func(m *Migrator) { m.dir = dir }
}

// New creates a Migrator. The fs should contain .sql files named with a
// sortable prefix (e.g. 0001_initial.sql, 0002_add_users.sql).
func New(db DB, fsys fs.FS, opts ...Option) *Migrator {
	m := &Migrator{
		db:    db,
		fs:    fsys,
		dir:   "migrations",
		table: "schema_migrations",
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// MigrateResult contains information about a migration run.
type MigrateResult struct {
	Applied []string // versions that were applied in this run
	Total   int      // total migrations (applied + already present)
}

// Migrate applies all pending migrations in lexicographic order. Each
// migration runs in its own transaction. Returns the list of newly
// applied versions.
func (m *Migrator) Migrate(ctx context.Context) (*MigrateResult, error) {
	// Create tracking table.
	if err := m.db.Exec(ctx, m.db.CreateTableSQL(m.table)); err != nil {
		return nil, fmt.Errorf("creating migrations table: %w", err)
	}

	// Load applied versions.
	applied, err := m.loadApplied(ctx)
	if err != nil {
		return nil, err
	}

	// Discover migration files.
	all, err := m.discoverMigrations()
	if err != nil {
		return nil, err
	}

	// Find pending.
	var pending []string
	for _, name := range all {
		version := strings.TrimSuffix(name, ".sql")
		if !applied[version] {
			pending = append(pending, name)
		}
	}

	result := &MigrateResult{Total: len(all)}

	if len(pending) == 0 {
		return result, nil
	}

	// Apply pending migrations.
	for _, name := range pending {
		version := strings.TrimSuffix(name, ".sql")
		if err := m.applyMigration(ctx, name, version); err != nil {
			return result, err
		}
		result.Applied = append(result.Applied, version)
	}

	return result, nil
}

// Pending returns the list of migration versions that have not yet been
// applied.
func (m *Migrator) Pending(ctx context.Context) ([]string, error) {
	// Ensure table exists for the query.
	if err := m.db.Exec(ctx, m.db.CreateTableSQL(m.table)); err != nil {
		return nil, fmt.Errorf("creating migrations table: %w", err)
	}

	applied, err := m.loadApplied(ctx)
	if err != nil {
		return nil, err
	}

	all, err := m.discoverMigrations()
	if err != nil {
		return nil, err
	}

	var pending []string
	for _, name := range all {
		version := strings.TrimSuffix(name, ".sql")
		if !applied[version] {
			pending = append(pending, version)
		}
	}
	return pending, nil
}

func (m *Migrator) loadApplied(ctx context.Context) (map[string]bool, error) {
	rows, err := m.db.Query(ctx, m.db.QueryVersionsSQL(m.table))
	if err != nil {
		return nil, fmt.Errorf("querying applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scanning migration version: %w", err)
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func (m *Migrator) discoverMigrations() ([]string, error) {
	entries, err := fs.ReadDir(m.fs, m.dir)
	if err != nil {
		return nil, fmt.Errorf("reading migrations from %q: %w", m.dir, err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (m *Migrator) applyMigration(ctx context.Context, filename, version string) error {
	path := m.dir + "/" + filename
	content, err := fs.ReadFile(m.fs, path)
	if err != nil {
		return fmt.Errorf("reading migration %s: %w", filename, err)
	}

	tx, err := m.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction for %s: %w", filename, err)
	}

	if err := tx.Exec(ctx, string(content)); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("executing migration %s: %w", filename, err)
	}

	if err := tx.Exec(ctx, m.db.InsertVersionSQL(m.table), version); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("recording migration %s: %w", filename, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing migration %s: %w", filename, err)
	}

	return nil
}
