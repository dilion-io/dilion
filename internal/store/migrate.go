package store

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-project/dilion/migrations"
)

// migrationsTable tracks which files have been applied.
const migrationsTable = "public.schema_migrations"

// advisoryLockKey serialises migration runs across processes. Arbitrary but
// stable constant ("dilion" hashed by hand); never change it.
const advisoryLockKey int64 = 7264121035148

// Migrate applies every embedded migration that has not been applied yet, in
// lexicographic filename order, each file in its own transaction. Applied files
// are recorded in public.schema_migrations. It is safe to call concurrently:
// runs are serialised with a Postgres advisory lock.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return migrateFS(ctx, pool, migrations.FS, migrationsTable)
}

// migrateFS is the testable core of Migrate. table must be a schema-qualified,
// trusted identifier (it is interpolated into DDL).
func migrateFS(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS, table string) error {
	if pool == nil {
		return fmt.Errorf("store: migrate: nil pool")
	}
	files, err := sqlFiles(fsys)
	if err != nil {
		return err
	}

	// A single dedicated connection holds the advisory lock for the whole run.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: migrate: acquire conn: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "select pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return fmt.Errorf("store: migrate: advisory lock: %w", err)
	}
	defer func() {
		// Best effort: the lock is also released when the session ends.
		if _, err := conn.Exec(context.WithoutCancel(ctx), "select pg_advisory_unlock($1)", advisoryLockKey); err != nil {
			slog.Warn("store: advisory unlock failed", "error", err)
		}
	}()

	if err := ensureMigrationsTable(ctx, conn, table); err != nil {
		return err
	}
	applied, err := appliedMigrations(ctx, conn, table)
	if err != nil {
		return err
	}

	for _, name := range files {
		if _, ok := applied[name]; ok {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("store: migrate: read %s: %w", name, err)
		}
		if err := applyOne(ctx, conn, table, name, string(body)); err != nil {
			return err
		}
		slog.Info("migration applied", "file", name)
	}
	return nil
}

// sqlFiles returns the *.sql files at the root of fsys, sorted by filename.
func sqlFiles(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("store: migrate: read dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		names = append(names, path.Base(e.Name()))
	}
	sort.Strings(names)
	return names, nil
}

func ensureMigrationsTable(ctx context.Context, conn pgxConn, table string) error {
	const q = `create table if not exists %s (
	filename   text primary key,
	applied_at timestamptz not null default now()
)`
	if _, err := conn.Exec(ctx, fmt.Sprintf(q, table)); err != nil {
		return fmt.Errorf("store: migrate: create %s: %w", table, err)
	}
	return nil
}

func appliedMigrations(ctx context.Context, conn pgxConn, table string) (map[string]struct{}, error) {
	rows, err := conn.Query(ctx, fmt.Sprintf("select filename from %s", table))
	if err != nil {
		return nil, fmt.Errorf("store: migrate: list applied: %w", err)
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: migrate: scan applied: %w", err)
		}
		out[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: migrate: list applied: %w", err)
	}
	return out, nil
}

// applyOne runs a single migration file and records it, atomically.
func applyOne(ctx context.Context, conn pgxConn, table, name, body string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: migrate: begin %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if strings.TrimSpace(body) != "" {
		// No arguments => pgx uses the simple protocol, so a file may contain
		// several statements.
		if _, err := tx.Exec(ctx, body); err != nil {
			return fmt.Errorf("store: migrate: apply %s: %w", name, err)
		}
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf("insert into %s (filename) values ($1)", table), name); err != nil {
		return fmt.Errorf("store: migrate: record %s: %w", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: migrate: commit %s: %w", name, err)
	}
	return nil
}

// pgxConn is the subset of *pgxpool.Conn the runner needs (also satisfied by
// *pgx.Conn, which keeps the helpers usable from tests).
type pgxConn interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}
