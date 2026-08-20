package iam

// Pool resolution. Every database access in this package goes through a
// PoolFunc so that a multi-instance deployment can route it to the database of
// the instance selected on the request context (ports.ContextWithInstance,
// internal/instances). The single-instance default wraps one fixed pool.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolFunc resolves the database pool for a request. It is structurally
// identical to instances.PoolFunc, which is what production wires in; the type
// is declared locally so this package stays free of an instances import.
type PoolFunc func(context.Context) (*pgxpool.Pool, error)

// StaticPool is the single-instance PoolFunc: it always answers with pool.
// A nil pool yields an error at use time (spec generation constructs services
// with a nil pool and never calls them).
func StaticPool(pool *pgxpool.Pool) PoolFunc {
	return func(context.Context) (*pgxpool.Pool, error) {
		if pool == nil {
			return nil, fmt.Errorf("iam: nil pool")
		}
		return pool, nil
	}
}

func resolvePool(ctx context.Context, f PoolFunc) (*pgxpool.Pool, error) {
	if f == nil {
		return nil, fmt.Errorf("iam: nil pool")
	}
	pool, err := f(ctx)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, fmt.Errorf("iam: nil pool")
	}
	return pool, nil
}
