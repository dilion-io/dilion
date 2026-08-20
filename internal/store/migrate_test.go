package store

import (
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/dilion-io/dilion/migrations"
)

func TestSQLFilesLexicographicOrder(t *testing.T) {
	fsys := fstest.MapFS{
		"0010_c.sql":     {Data: []byte("select 1")},
		"0002_a.sql":     {Data: []byte("select 1")},
		"0001_b.sql":     {Data: []byte("select 1")},
		"0002_a.sql.bak": {Data: []byte("select 1")},
		"README.md":      {Data: []byte("not sql")},
		"sub/0000_x.sql": {Data: []byte("select 1")}, // nested files are ignored
	}
	got, err := sqlFiles(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"0001_b.sql", "0002_a.sql", "0010_c.sql"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sqlFiles = %v, want %v", got, want)
	}
}

// Lexicographic ordering differs from numeric ordering for unpadded names; the
// runner must follow the filenames, not the numbers.
func TestSQLFilesOrderIsByteWise(t *testing.T) {
	fsys := fstest.MapFS{
		"2_a.sql":  {Data: []byte("")},
		"10_c.sql": {Data: []byte("")},
		"1_b.sql":  {Data: []byte("")},
	}
	got, err := sqlFiles(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10_c.sql", "1_b.sql", "2_a.sql"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sqlFiles = %v, want %v", got, want)
	}
}

func TestEmbeddedMigrationsPresent(t *testing.T) {
	got, err := sqlFiles(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no embedded migrations")
	}
	if got[0] != "0001_core.sql" {
		t.Fatalf("first migration = %q, want 0001_core.sql", got[0])
	}
}
