package dilion

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A misconfigured KMS fails where it is built, not on the first encryption,
// so an embedder's per-instance resolver cannot hand out a KMS that only
// errors later.
func TestNewLocalKMSRejectsBadInput(t *testing.T) {
	// A pool that is never dialled: pgxpool connects lazily, and these cases
	// must fail before any connection is attempted.
	pool, err := pgxpool.New(context.Background(), "postgres://unused@127.0.0.1:1/none")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	for name, tc := range map[string]struct {
		pool *pgxpool.Pool
		kek  []byte
		want string
	}{
		"nil pool":  {nil, make([]byte, LocalKMSKeySize), "nil pool"},
		"short kek": {pool, make([]byte, LocalKMSKeySize-1), "must be 32 bytes, got 31"},
		"long kek":  {pool, make([]byte, LocalKMSKeySize+1), "must be 32 bytes, got 33"},
		"no kek":    {pool, nil, "must be 32 bytes, got 0"},
	} {
		k, err := NewLocalKMS(tc.pool, tc.kek)
		if err == nil || k != nil {
			t.Errorf("%s: NewLocalKMS = (%v, %v), want an error", name, k, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %q, want it to mention %q", name, err, tc.want)
		}
	}

	if k, err := NewLocalKMS(pool, make([]byte, LocalKMSKeySize)); err != nil || k == nil {
		t.Errorf("valid input: NewLocalKMS = (%v, %v), want a KMS", k, err)
	}
}
