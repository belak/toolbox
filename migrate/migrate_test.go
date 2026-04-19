package migrate

import (
	"context"
	"database/sql"
	"testing"
	"testing/fstest"

	"github.com/alecthomas/assert/v2"
	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) (*sql.DB, DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	assert.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db, NewDriver(db, SQLiteDialect{})
}

func TestMigrateAppliesInOrder(t *testing.T) {
	raw, db := openTestDB(t)

	fsys := fstest.MapFS{
		"migrations/0002_second.sql": {Data: []byte("CREATE TABLE b (id INTEGER);")},
		"migrations/0001_first.sql":  {Data: []byte("CREATE TABLE a (id INTEGER);")},
		"migrations/0003_third.sql":  {Data: []byte("CREATE TABLE c (id INTEGER);")},
	}

	m := New(db, fsys)
	result, err := m.Migrate(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 3, len(result.Applied))
	assert.Equal(t, 3, result.Total)

	// Verify order.
	assert.Equal(t, "0001_first", result.Applied[0])
	assert.Equal(t, "0002_second", result.Applied[1])
	assert.Equal(t, "0003_third", result.Applied[2])

	// Tables should exist.
	for _, table := range []string{"a", "b", "c"} {
		_, err := raw.Exec("SELECT 1 FROM " + table) //nolint:gosec // test-only, table names are hardcoded
		assert.NoError(t, err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	_, db := openTestDB(t)

	fsys := fstest.MapFS{
		"migrations/0001_init.sql": {Data: []byte("CREATE TABLE t (id INTEGER);")},
	}

	m := New(db, fsys)

	r1, err := m.Migrate(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(r1.Applied))

	// Second run should apply nothing.
	r2, err := m.Migrate(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 0, len(r2.Applied))
	assert.Equal(t, 1, r2.Total)
}

func TestMigrateIncremental(t *testing.T) {
	_, db := openTestDB(t)

	// First run with one migration.
	fsys1 := fstest.MapFS{
		"migrations/0001_init.sql": {Data: []byte("CREATE TABLE a (id INTEGER);")},
	}

	m1 := New(db, fsys1)
	r1, err := m1.Migrate(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(r1.Applied))

	// Second run with two migrations; only new one should apply.
	fsys2 := fstest.MapFS{
		"migrations/0001_init.sql":  {Data: []byte("CREATE TABLE a (id INTEGER);")},
		"migrations/0002_add_b.sql": {Data: []byte("CREATE TABLE b (id INTEGER);")},
	}

	m2 := New(db, fsys2)
	r2, err := m2.Migrate(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(r2.Applied))
	assert.Equal(t, "0002_add_b", r2.Applied[0])
	assert.Equal(t, 2, r2.Total)
}

func TestMigrateRollsBackOnError(t *testing.T) {
	raw, db := openTestDB(t)

	fsys := fstest.MapFS{
		"migrations/0001_good.sql": {Data: []byte("CREATE TABLE good (id INTEGER);")},
		"migrations/0002_bad.sql":  {Data: []byte("INVALID SQL SYNTAX HERE;")},
	}

	m := New(db, fsys)
	result, err := m.Migrate(context.Background())
	assert.Error(t, err)

	// First migration should have succeeded.
	assert.Equal(t, 1, len(result.Applied))

	// "good" table should exist.
	_, err = raw.Exec("SELECT 1 FROM good")
	assert.NoError(t, err)

	// Bad migration should not be recorded.
	pending, err := m.Pending(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(pending))
	assert.Equal(t, "0002_bad", pending[0])
}

func TestPending(t *testing.T) {
	_, db := openTestDB(t)

	fsys := fstest.MapFS{
		"migrations/0001_a.sql": {Data: []byte("CREATE TABLE a (id INTEGER);")},
		"migrations/0002_b.sql": {Data: []byte("CREATE TABLE b (id INTEGER);")},
	}

	m := New(db, fsys)

	pending, err := m.Pending(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 2, len(pending))

	// Apply all.
	_, err = m.Migrate(context.Background())
	assert.NoError(t, err)

	pending, err = m.Pending(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 0, len(pending))
}

func TestCustomTableAndDirectory(t *testing.T) {
	raw, db := openTestDB(t)

	fsys := fstest.MapFS{
		"db/0001_init.sql": {Data: []byte("CREATE TABLE x (id INTEGER);")},
	}

	m := New(db, fsys,
		WithTable("my_migrations"),
		WithDirectory("db"),
	)

	result, err := m.Migrate(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(result.Applied))

	// Custom table should exist.
	var count int
	err = raw.QueryRow("SELECT COUNT(*) FROM my_migrations").Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestEmptyMigrations(t *testing.T) {
	_, db := openTestDB(t)

	fsys := fstest.MapFS{
		"migrations/.gitkeep": {Data: []byte("")},
	}

	m := New(db, fsys)
	result, err := m.Migrate(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 0, len(result.Applied))
	assert.Equal(t, 0, result.Total)
}
