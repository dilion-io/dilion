// Package parity is Dilion's differential parity + coverage test harness: it
// runs the Dilion /auth/v1 surface side-by-side against the real upstream
// github.com/supabase/auth (GoTrue) and asserts behavioural equivalence,
// excluding the documented intentional deviations (deviations.yaml).
//
// The harness itself lives in files guarded by the `//go:build parity` tag
// (normalize.go, coverage.go, deviations.go, harness_test.go), so it is compiled
// and run ONLY with `-tags parity` and never by the normal `go test ./...`. This
// untagged file exists solely so the package is a valid, empty build target in
// the normal suite instead of a "no Go files" error.
//
// See README.md for how to bring both servers up and run the suite.
package parity
