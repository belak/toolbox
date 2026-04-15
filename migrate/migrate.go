// Package migrate provides a minimal database migration runner using
// database/sql. Migrations are read from an fs.FS (typically embed.FS)
// and applied in lexicographic order. Applied versions are tracked in a
// configurable table.
//
// The package abstracts dialect differences through a small Driver
// interface so the same migration runner works with SQLite, PostgreSQL,
// or any other database/sql-compatible database.
package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// Driver abstracts dialect-specific SQL differences. Implementations for
// common databases are provided by the sqlite and postgres sub-packages,
// or callers can implement their own.
type Driver interface {
	// CreateTableSQL returns the DDL to create the migrations tracking
	// table if it does not exist.
	CreateTableSQL(table string) string

	// InsertVersionSQL returns an INSERT statement for recording a
	// migration version. It must use a single placeholder for the
	// version string.
	InsertVersionSQL(table string) string

	// QueryVersionsSQL returns a SELECT statement that returns all
	// applied version strings.
	QueryVersionsSQL(table string) string
}

// Migrator runs migrations against a database.
type Migrator struct {
	db     *sql.DB
	driver Driver
	fs     fs.FS
	dir    string // subdirectory within fs to read migrations from
	table  string
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
func New(db *sql.DB, driver Driver, fsys fs.FS, opts ...Option) *Migrator {
	m := &Migrator{
		db:     db,
		driver: driver,
		fs:     fsys,
		dir:    "migrations",
		table:  "schema_migrations",
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
	if _, err := m.db.ExecContext(ctx, m.driver.CreateTableSQL(m.table)); err != nil {
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
	if _, err := m.db.ExecContext(ctx, m.driver.CreateTableSQL(m.table)); err != nil {
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
	rows, err := m.db.QueryContext(ctx, m.driver.QueryVersionsSQL(m.table))
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

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction for %s: %w", filename, err)
	}

	if _, err := tx.ExecContext(ctx, string(content)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("executing migration %s: %w", filename, err)
	}

	if _, err := tx.ExecContext(ctx, m.driver.InsertVersionSQL(m.table), version); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("recording migration %s: %w", filename, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing migration %s: %w", filename, err)
	}

	return nil
}
