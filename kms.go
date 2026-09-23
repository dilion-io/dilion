package dilion

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/kmslocal"
	"github.com/dilion-io/dilion/ports"
)

// LocalKMSKeySize is the key-encryption-key length NewLocalKMS requires, in
// bytes.
const LocalKMSKeySize = kmslocal.KeySize

// NewLocalKMS builds the default ports.KMS over one database: AES-256-GCM
// envelope encryption with a data key per (subject, scope) stored in
// dilion_pii.subject_keys, wrapped by kek. It is the KMS a server builds for
// itself from WithMasterKey; this constructor exists so an embedder can build
// one per instance, for ports.InstanceResolver.KMS, without writing its own.
//
//	func (r *myResolver) KMS(ctx context.Context, id string) (ports.KMS, error) {
//		return dilion.NewLocalKMS(r.pools[id], r.keks[id])
//	}
//
// The kek never leaves this process, so the KMS is only as well protected as
// the host; a deployment with a real key manager should implement ports.KMS
// against it instead. Instances may share a kek or have their own — each one's
// data keys live in its own database either way — but a lost kek makes every
// data key it wrapped unreadable, and replacing it is not a key rotation (see
// docs/master-key.md).
//
// A nil pool or a kek of the wrong length is reported here rather than on the
// first encryption, so a misconfigured instance fails where it is built.
func NewLocalKMS(pool *pgxpool.Pool, kek []byte) (ports.KMS, error) {
	if pool == nil {
		return nil, errors.New("dilion: NewLocalKMS: nil pool")
	}
	if len(kek) != LocalKMSKeySize {
		return nil, fmt.Errorf("dilion: NewLocalKMS: key-encryption key must be %d bytes, got %d",
			LocalKMSKeySize, len(kek))
	}
	return kmslocal.New(pool, kek), nil
}
