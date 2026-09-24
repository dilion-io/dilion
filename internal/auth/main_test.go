package auth

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	// bcrypt at gotrue's cost 10 is slow on purpose, and slower still under
	// -race. These tests hash and check hundreds of passwords, and at that
	// cost the hashing took most of the suite's time. A hash records its own
	// cost, so comparing is unaffected. TestHashPasswordUsesUpstreamCost checks
	// the production cost.
	hashCost = bcrypt.MinCost
	os.Exit(m.Run())
}
