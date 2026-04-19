package migrate

import "fmt"

// SQLiteDialect implements Dialect for SQLite databases.
type SQLiteDialect struct{}

func (SQLiteDialect) CreateTableSQL(table string) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`, table)
}

func (SQLiteDialect) InsertVersionSQL(table string) string {
	return fmt.Sprintf("INSERT INTO %s (version) VALUES (?)", table)
}

func (SQLiteDialect) QueryVersionsSQL(table string) string {
	return fmt.Sprintf("SELECT version FROM %s", table)
}

// PostgresDialect implements Dialect for PostgreSQL databases.
type PostgresDialect struct{}

func (PostgresDialect) CreateTableSQL(table string) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`, table)
}

func (PostgresDialect) InsertVersionSQL(table string) string {
	return fmt.Sprintf("INSERT INTO %s (version) VALUES ($1)", table)
}

func (PostgresDialect) QueryVersionsSQL(table string) string {
	return fmt.Sprintf("SELECT version FROM %s", table)
}
