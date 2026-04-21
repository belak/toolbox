package migrate

import (
	"context"
	"database/sql"
)

type sqlDB struct {
	Dialect
	db *sql.DB
}

// NewDriver wraps a *sql.DB and Dialect to satisfy the DB interface.
func NewDriver(db *sql.DB, dialect Dialect) DB {
	return &sqlDB{Dialect: dialect, db: db}
}

func (s *sqlDB) Exec(ctx context.Context, query string, args ...any) error {
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *sqlDB) Query(ctx context.Context, query string, args ...any) (Rows, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return &sqlRows{rows: rows}, nil
}

func (s *sqlDB) Begin(ctx context.Context) (Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &sqlTx{tx: tx}, nil
}

type sqlRows struct{ rows *sql.Rows }

func (r *sqlRows) Next() bool             { return r.rows.Next() }
func (r *sqlRows) Scan(dest ...any) error { return r.rows.Scan(dest...) }
func (r *sqlRows) Err() error             { return r.rows.Err() }
func (r *sqlRows) Close()                 { r.rows.Close() }

type sqlTx struct{ tx *sql.Tx }

func (t *sqlTx) Exec(ctx context.Context, query string, args ...any) error {
	_, err := t.tx.ExecContext(ctx, query, args...)
	return err
}

func (t *sqlTx) Rollback(_ context.Context) error { return t.tx.Rollback() }
func (t *sqlTx) Commit(_ context.Context) error   { return t.tx.Commit() }
