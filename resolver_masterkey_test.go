package dilion

import (
	"strings"
	"testing"

	"github.com/dilion-io/dilion/internal/instances"
	"github.com/dilion-io/dilion/ports"
)

// With a resolver, the master key only derives the tombstone and search keys —
// which must survive restarts, so an ephemeral one is refused.
func TestResolverNeedsAMasterKey(t *testing.T) {
	res := instances.NewStaticResolver(ports.DefaultInstanceID, nil, nil, ports.JWTKeys{}, nil, nil)
	_, err := NewServer(WithInstanceResolver(res), WithJWTSecret([]byte("test-secret-test-secret-test-sec")))
	if err == nil || !strings.Contains(err.Error(), "WithMasterKey") {
		t.Fatalf("NewServer without a master key = %v, want an error naming WithMasterKey", err)
	}
}
