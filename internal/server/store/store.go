// Package store is the PostgreSQL/TimescaleDB persistence layer.
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/makhammatovb/fleetguard/migrations"
)

// TimescaleImage is the single source of truth for the database image. The
// test harness uses it directly and deploy/docker-compose.yml must carry the
// same tag.
const TimescaleImage = "timescale/timescaledb:2.17.2-pg16"

// Store owns the connection pool to the database.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to the database at dsn and verifies the connection.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping database: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Pool exposes the underlying pool for the query methods in this package's
// callers and for tests.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// Migrate applies every pending embedded migration. It is safe to call
// repeatedly.
func (s *Store) Migrate(ctx context.Context) error {
	db := stdlib.OpenDBFromPool(s.pool)
	defer func() { _ = db.Close() }()

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("store: create migration provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("store: apply migrations: %w", err)
	}
	return nil
}
