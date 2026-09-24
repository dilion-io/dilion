package store

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool connects to $DILION_TEST_DB, skipping when it is unset.
//
//	docker exec dilion-pg createdb -U dilion dilion_test_a
//	DILION_TEST_DB='postgres://dilion:dilion@localhost:55432/dilion_test_a' go test ./internal/store/...
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DILION_TEST_DB")
	if dsn == "" {
		t.Skip("DILION_TEST_DB not set")
	}
	pool, err := Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// throwawaySchema creates an empty schema dropped at the end of the test, so
// runner tests never touch public.schema_migrations or a domain schema.
func throwawaySchema(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("store_migtest_%d", os.Getpid()%100000)
	if _, err := pool.Exec(ctx, "drop schema if exists "+name+" cascade"); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := pool.Exec(ctx, "create schema "+name); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "drop schema if exists "+name+" cascade"); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
	return name
}

// orderedFS builds migrations that each append their name to <schema>.applied,
// letting the test observe the order the runner used.
func orderedFS(schema string, names ...string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for _, n := range names {
		fsys[n] = &fstest.MapFile{Data: []byte(fmt.Sprintf(
			"insert into %s.applied (name) values ('%s');", schema, n))}
	}
	return fsys
}

func appliedOrder(t *testing.T, pool *pgxpool.Pool, schema string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), "select name from "+schema+".applied order by seq")
	if err != nil {
		t.Fatalf("query order: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMigrateAppliesInLexicographicOrderOnce(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	schema := throwawaySchema(t, pool)
	table := schema + ".schema_migrations"

	if _, err := pool.Exec(ctx, "create table "+schema+".applied (seq bigserial primary key, name text not null)"); err != nil {
		t.Fatalf("create applied: %v", err)
	}

	fsys := orderedFS(schema, "2_a.sql", "10_c.sql", "1_b.sql")
	fsys["notes.txt"] = &fstest.MapFile{Data: []byte("ignored")}

	if err := migrateFS(ctx, pool, fsys, table); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	want := []string{"10_c.sql", "1_b.sql", "2_a.sql"}
	if got := appliedOrder(t, pool, schema); !reflect.DeepEqual(got, want) {
		t.Fatalf("apply order = %v, want %v", got, want)
	}

	// Re-running must be a no-op.
	if err := migrateFS(ctx, pool, fsys, table); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	if got := appliedOrder(t, pool, schema); !reflect.DeepEqual(got, want) {
		t.Fatalf("after rerun order = %v, want %v", got, want)
	}

	// Only the newly added file is applied on the next run.
	fsys["3_d.sql"] = &fstest.MapFile{Data: []byte(fmt.Sprintf(
		"insert into %s.applied (name) values ('3_d.sql');", schema))}
	if err := migrateFS(ctx, pool, fsys, table); err != nil {
		t.Fatalf("migrate incremental: %v", err)
	}
	want = append(want, "3_d.sql")
	if got := appliedOrder(t, pool, schema); !reflect.DeepEqual(got, want) {
		t.Fatalf("after incremental order = %v, want %v", got, want)
	}

	var n int
	if err := pool.QueryRow(ctx, "select count(*) from "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("%s rows = %d, want 4", table, n)
	}
}

func TestMigrateFailedFileRollsBackAndStopsRun(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	schema := throwawaySchema(t, pool)
	table := schema + ".schema_migrations"

	fsys := fstest.MapFS{
		"0001_ok.sql": &fstest.MapFile{Data: []byte(
			"create table " + schema + ".t1 (id int);")},
		"0002_bad.sql": &fstest.MapFile{Data: []byte(
			"create table " + schema + ".t2 (id int); this is not sql;")},
		"0003_never.sql": &fstest.MapFile{Data: []byte(
			"create table " + schema + ".t3 (id int);")},
	}
	if err := migrateFS(ctx, pool, fsys, table); err == nil {
		t.Fatal("migrate succeeded, want failure")
	}

	applied := map[string]bool{}
	rows, err := pool.Query(ctx, "select filename from "+table)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		applied[s] = true
	}
	rows.Close()
	if !applied["0001_ok.sql"] || applied["0002_bad.sql"] || applied["0003_never.sql"] {
		t.Fatalf("applied set = %v", applied)
	}

	// The failing file's first statement must have been rolled back, and the
	// run must have stopped before the following file.
	for tbl, want := range map[string]bool{"t1": true, "t2": false, "t3": false} {
		var exists bool
		if err := pool.QueryRow(ctx,
			"select exists (select 1 from information_schema.tables where table_schema = $1 and table_name = $2)",
			schema, tbl).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != want {
			t.Fatalf("table %s exists = %v, want %v", tbl, exists, want)
		}
	}

	// After fixing the file the run resumes from where it stopped.
	fsys["0002_bad.sql"] = &fstest.MapFile{Data: []byte("create table " + schema + ".t2 (id int);")}
	if err := migrateFS(ctx, pool, fsys, table); err != nil {
		t.Fatalf("migrate after fix: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, "select count(*) from "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("%s rows = %d, want 3", table, n)
	}
}

// TestMigrateEmbedded applies the real migration set against the test database.
func TestMigrateEmbedded(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate (idempotent run): %v", err)
	}
	for _, s := range []string{"auth", "dilion_auth", "dilion_privacy", "dilion_pii", "dilion_authz", "dilion_audit"} {
		var exists bool
		if err := pool.QueryRow(ctx,
			"select exists (select 1 from information_schema.schemata where schema_name = $1)", s).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("schema %s missing", s)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, "select count(*) from public.schema_migrations where filename = '0001_core.sql'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("0001_core.sql recorded %d times, want 1", n)
	}
}
