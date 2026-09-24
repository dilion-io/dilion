// Command check-compliance-policies loads internal/privacy/builtin_policies.yaml
// the way the server does at startup and exits non-zero if it is rejected.
// scripts/review-compliance-policies.mjs runs it against every proposed edit.
package main

import (
	"fmt"
	"os"

	"github.com/dilion-io/dilion/internal/privacy"
)

func main() {
	if _, err := privacy.LoadPolicies(nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("built-in compliance policies load")
}
