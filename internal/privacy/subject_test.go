package privacy

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/kmslocal"
)

// The UUID the local KMS keeps the webhook secrets under cannot be named as a
// data subject: a deletion request for it would shred them all.
func TestSystemSubjectUUIDIsNotADataSubject(t *testing.T) {
	e, err := NewEngine(EngineDeps{Pool: &pgxpool.Pool{}, KMS: &fakeKMS{}, TombstoneKey: []byte("test-key")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.CreateRequest(context.Background(), CreateRequestInput{
		UserID: kmslocal.SubjectUUID(systemSubjectID).String(), Type: RequestDeletion, Immediate: true,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CreateRequest for the system subject = %v, want ErrInvalidInput", err)
	}
}
