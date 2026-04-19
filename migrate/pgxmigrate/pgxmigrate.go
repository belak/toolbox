// Package pgxmigrate provides a migrate.DB adapter for pgx.
package pgxmigrate

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/belak/toolbox/migrate"
)

// Querier is the subset of pgx methods used by the migrator. Both
// *pgxpool.Pool and *pgx.Conn satisfy this interface.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

type pgxDB struct {
	migrate.PostgresDialect
	q Querier
}

// NewDriver wraps a pgx Querier (typically *pgxpool.Pool or *pgx.Conn)
// to satisfy the migrate.DB interface.
func NewDriver(q Querier) migrate.DB { return &pgxDB{q: q} }

func (p *pgxDB) Exec(ctx context.Context, query string, args ...any) error {
	_, err := p.q.Exec(ctx, query, args...)
	return err
}

func (p *pgxDB) Query(ctx context.Context, query string, args ...any) (migrate.Rows, error) {
	rows, err := p.q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (p *pgxDB) Begin(ctx context.Context) (migrate.Tx, error) {
	tx, err := p.q.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &pgxTx{tx: tx}, nil
}

type pgxTx struct{ tx pgx.Tx }

func (t *pgxTx) Exec(ctx context.Context, query string, args ...any) error {
	_, err := t.tx.Exec(ctx, query, args...)
	return err
}

func (t *pgxTx) Rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }
func (t *pgxTx) Commit(ctx context.Context) error   { return t.tx.Commit(ctx) }
