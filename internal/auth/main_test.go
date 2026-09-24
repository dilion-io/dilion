package auth

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/dilion-io/dilion/internal/netguard"
)

func TestMain(m *testing.M) {
	// bcrypt at gotrue's cost 10 is slow on purpose, and slower still under
	// -race. These tests hash and check hundreds of passwords, and at that
	// cost the hashing took most of the suite's time. A hash records its own
	// cost, so comparing is unaffected. TestHashPasswordUsesUpstreamCost checks
	// the production cost.
	hashCost = bcrypt.MinCost
	// The fake providers, IdPs and webhook receivers listen on loopback,
	// which guarded outbound calls refuse by default. Tests of the guard
	// itself take this back (withoutOutboundAllowance).
	defaultOutboundNetworks = netguard.MustParseNetworks("127.0.0.0/8,::1")
	os.Exit(m.Run())
}

// withoutOutboundAllowance makes the mounts a test creates refuse loopback
// again, as production mounts without Deps.OutboundNetworks do.
func withoutOutboundAllowance(t *testing.T) {
	t.Helper()
	prev := defaultOutboundNetworks
	defaultOutboundNetworks = netguard.Networks{}
	t.Cleanup(func() { defaultOutboundNetworks = prev })
}
