// Package store owns the Postgres connection pool and the migration runner.
// It holds no domain logic: every domain package receives a *pgxpool.Pool.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Default pool sizing. Embedders that need different limits can build their own
// pool and inject it with dilion.WithPool.
const (
	defaultMaxConns        = 10
	defaultMinConns        = 0
	defaultMaxConnLifetime = time.Hour
	defaultMaxConnIdleTime = 30 * time.Minute
	defaultConnectTimeout  = 10 * time.Second
)

// Connect opens a pgx pool for dsn and verifies it with a Ping. The caller owns
// the returned pool and must Close it.
func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	if dsn == "" {
		return nil, fmt.Errorf("store: empty dsn")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	// Only fill in what the DSN did not already specify.
	if cfg.MaxConns == 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if cfg.MinConns == 0 {
		cfg.MinConns = defaultMinConns
	}
	if cfg.MaxConnLifetime == 0 {
		cfg.MaxConnLifetime = defaultMaxConnLifetime
	}
	if cfg.MaxConnIdleTime == 0 {
		cfg.MaxConnIdleTime = defaultMaxConnIdleTime
	}
	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = defaultConnectTimeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return pool, nil
}
