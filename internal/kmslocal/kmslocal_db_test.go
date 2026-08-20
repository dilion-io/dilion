package kmslocal

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-project/dilion/ports"
)

// testPool connects to $DILION_TEST_DB, skipping when it is unset.
//
//	docker exec dilion-pg createdb -U dilion dilion_test_a
//	DILION_TEST_DB='postgres://dilion:dilion@localhost:55432/dilion_test_a' go test ./internal/kmslocal/...
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DILION_TEST_DB")
	if dsn == "" {
		t.Skip("DILION_TEST_DB not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	// dilion_pii.subject_keys is created by agent C's 02xx migration; the shape
	// below mirrors that contract so this package can be tested standalone.
	ddl := []string{
		`create schema if not exists dilion_pii`,
		`create table if not exists dilion_pii.subject_keys (
			user_id     uuid not null,
			scope       text not null check (scope in ('DEFAULT','CONSENT')),
			wrapped_dek bytea,
			shred_after timestamptz,
			shredded_at timestamptz,
			created_at  timestamptz not null default now(),
			primary key (user_id, scope)
		)`,
	}
	for _, q := range ddl {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	return pool
}

func newTestKMS(t *testing.T) (*KMS, string) {
	t.Helper()
	pool := testPool(t)
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	subject := uuid.NewString()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `delete from dilion_pii.subject_keys where user_id = $1`, subject)
	})
	return New(pool, key), subject
}

func TestKMSRoundTrip(t *testing.T) {
	ctx := context.Background()
	k, subject := newTestKMS(t)
	plaintext := []byte("서울시 강남구 ...")

	blob, err := k.Encrypt(ctx, subject, ports.KeyScopeDefault, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if blob[0] != Version {
		t.Fatalf("version byte = 0x%02x", blob[0])
	}
	got, err := k.Decrypt(ctx, subject, ports.KeyScopeDefault, blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}

	// A second Encrypt must reuse the stored DEK, not mint a new one.
	blob2, err := k.Encrypt(ctx, subject, ports.KeyScopeDefault, plaintext)
	if err != nil {
		t.Fatalf("encrypt 2: %v", err)
	}
	if _, err := k.Decrypt(ctx, subject, ports.KeyScopeDefault, blob2); err != nil {
		t.Fatalf("decrypt 2: %v", err)
	}
	var n int
	if err := k.pool.QueryRow(ctx, `select count(*) from dilion_pii.subject_keys where user_id = $1`, subject).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("subject_keys rows = %d, want 1", n)
	}
}

func TestKMSEmptyPlaintext(t *testing.T) {
	ctx := context.Background()
	k, subject := newTestKMS(t)
	blob, err := k.Encrypt(ctx, subject, ports.KeyScopeDefault, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := k.Decrypt(ctx, subject, ports.KeyScopeDefault, blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestKMSScopesAreIsolated(t *testing.T) {
	ctx := context.Background()
	k, subject := newTestKMS(t)

	def, err := k.Encrypt(ctx, subject, ports.KeyScopeDefault, []byte("profile"))
	if err != nil {
		t.Fatal(err)
	}
	con, err := k.Encrypt(ctx, subject, ports.KeyScopeConsent, []byte("consent evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Decrypt(ctx, subject, ports.KeyScopeConsent, def); err == nil {
		t.Fatal("DEFAULT ciphertext decrypted under CONSENT scope")
	}
	if _, err := k.Decrypt(ctx, subject, ports.KeyScopeDefault, con); err == nil {
		t.Fatal("CONSENT ciphertext decrypted under DEFAULT scope")
	}

	// Shredding DEFAULT (account erasure) must leave CONSENT evidence readable
	// until its own shred_after arrives (§2.7).
	if err := k.DestroyDEK(ctx, subject, ports.KeyScopeDefault); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Decrypt(ctx, subject, ports.KeyScopeDefault, def); !errors.Is(err, ErrShredded) {
		t.Fatalf("err = %v, want ErrShredded", err)
	}
	if _, err := k.Decrypt(ctx, subject, ports.KeyScopeConsent, con); err != nil {
		t.Fatalf("consent scope broke after DEFAULT shred: %v", err)
	}
}

func TestKMSDestroyDEK(t *testing.T) {
	ctx := context.Background()
	k, subject := newTestKMS(t)

	blob, err := k.Encrypt(ctx, subject, ports.KeyScopeDefault, []byte("pii"))
	if err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err := k.pool.QueryRow(ctx,
		`select wrapped_dek from dilion_pii.subject_keys where user_id = $1 and scope = 'DEFAULT'`,
		subject).Scan(&before); err != nil {
		t.Fatal(err)
	}

	if err := k.DestroyDEK(ctx, subject, ports.KeyScopeDefault); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	var after []byte
	var shredded bool
	if err := k.pool.QueryRow(ctx,
		`select wrapped_dek, shredded_at is not null from dilion_pii.subject_keys where user_id = $1 and scope = 'DEFAULT'`,
		subject).Scan(&after, &shredded); err != nil {
		t.Fatal(err)
	}
	if !shredded {
		t.Fatal("shredded_at not set")
	}
	if bytes.Equal(before, after) {
		t.Fatal("wrapped_dek was not overwritten")
	}

	if _, err := k.Decrypt(ctx, subject, ports.KeyScopeDefault, blob); !errors.Is(err, ErrShredded) {
		t.Fatalf("decrypt after shred: err = %v, want ErrShredded", err)
	}
	// Encrypt must not resurrect an erased subject with a fresh key.
	if _, err := k.Encrypt(ctx, subject, ports.KeyScopeDefault, []byte("pii again")); !errors.Is(err, ErrShredded) {
		t.Fatalf("encrypt after shred: err = %v, want ErrShredded", err)
	}

	// Idempotent, and the shred timestamp must not move.
	var stamp1, stamp2 any
	if err := k.pool.QueryRow(ctx,
		`select shredded_at from dilion_pii.subject_keys where user_id = $1 and scope = 'DEFAULT'`,
		subject).Scan(&stamp1); err != nil {
		t.Fatal(err)
	}
	if err := k.DestroyDEK(ctx, subject, ports.KeyScopeDefault); err != nil {
		t.Fatalf("destroy again: %v", err)
	}
	if err := k.pool.QueryRow(ctx,
		`select shredded_at from dilion_pii.subject_keys where user_id = $1 and scope = 'DEFAULT'`,
		subject).Scan(&stamp2); err != nil {
		t.Fatal(err)
	}
	if stamp1 != stamp2 {
		t.Fatalf("shredded_at moved: %v -> %v", stamp1, stamp2)
	}
}

func TestKMSDestroyUnknownSubjectLeavesTombstone(t *testing.T) {
	ctx := context.Background()
	k, subject := newTestKMS(t)

	if err := k.DestroyDEK(ctx, subject, ports.KeyScopeConsent); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := k.Encrypt(ctx, subject, ports.KeyScopeConsent, []byte("x")); !errors.Is(err, ErrShredded) {
		t.Fatalf("err = %v, want ErrShredded", err)
	}
}

// Platform pseudo-subjects (e.g. the "system" subject holding webhook secrets)
// are not UUIDs; they must still work and stay isolated from data subjects.
func TestKMSNonUUIDSubject(t *testing.T) {
	ctx := context.Background()
	k, _ := newTestKMS(t)
	t.Cleanup(func() {
		_, _ = k.pool.Exec(context.Background(),
			`delete from dilion_pii.subject_keys where user_id = $1`, SubjectUUID("system"))
	})

	blob, err := k.Encrypt(ctx, "system", ports.KeyScopeDefault, []byte("webhook secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := k.Decrypt(ctx, "system", ports.KeyScopeDefault, blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != "webhook secret" {
		t.Fatalf("got %q", got)
	}
	if SubjectUUID("system") == SubjectUUID("other") {
		t.Fatal("distinct subjects collided")
	}
	if u := uuid.New(); SubjectUUID(u.String()) != u {
		t.Fatal("uuid subject was not mapped to itself")
	}
}

func TestKMSDecryptWithoutKey(t *testing.T) {
	ctx := context.Background()
	k, subject := newTestKMS(t)
	blob := make([]byte, 1+nonceSize+gcmTagSize+4)
	blob[0] = Version
	if _, err := k.Decrypt(ctx, subject, ports.KeyScopeDefault, blob); !errors.Is(err, ErrNoKey) {
		t.Fatalf("err = %v, want ErrNoKey", err)
	}
}

func TestKMSRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	k, subject := newTestKMS(t)

	if _, err := k.Encrypt(ctx, "", ports.KeyScopeDefault, []byte("x")); err == nil {
		t.Fatal("empty subject accepted")
	}
	if _, err := k.Encrypt(ctx, subject, ports.KeyScope("BOGUS"), []byte("x")); err == nil {
		t.Fatal("unknown scope accepted")
	}
	if err := k.DestroyDEK(ctx, subject, ports.KeyScope("BOGUS")); err == nil {
		t.Fatal("unknown scope accepted by DestroyDEK")
	}
}

func TestKMSWrongMasterKeyCannotDecrypt(t *testing.T) {
	ctx := context.Background()
	k, subject := newTestKMS(t)
	blob, err := k.Encrypt(ctx, subject, ports.KeyScopeDefault, []byte("pii"))
	if err != nil {
		t.Fatal(err)
	}
	other := New(k.pool, mustKey(t))
	if _, err := other.Decrypt(ctx, subject, ports.KeyScopeDefault, blob); err == nil {
		t.Fatal("decrypted with a different master key")
	}
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}
