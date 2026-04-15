package migrate

import "fmt"

// SQLiteDriver implements Driver for SQLite databases.
type SQLiteDriver struct{}

func (SQLiteDriver) CreateTableSQL(table string) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`, table)
}

func (SQLiteDriver) InsertVersionSQL(table string) string {
	return fmt.Sprintf("INSERT INTO %s (version) VALUES (?)", table)
}

func (SQLiteDriver) QueryVersionsSQL(table string) string {
	return fmt.Sprintf("SELECT version FROM %s", table)
}

// PostgresDriver implements Driver for PostgreSQL databases.
type PostgresDriver struct{}

func (PostgresDriver) CreateTableSQL(table string) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`, table)
}

func (PostgresDriver) InsertVersionSQL(table string) string {
	return fmt.Sprintf("INSERT INTO %s (version) VALUES ($1)", table)
}

func (PostgresDriver) QueryVersionsSQL(table string) string {
	return fmt.Sprintf("SELECT version FROM %s", table)
}
