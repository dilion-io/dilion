// Package httpapi implements the API conventions from docs/api-conventions.md:
// resource IDs, cursor pagination envelope, and problem-details error codes.
// All /privacy/v1 and /iam/v1 handlers must use these helpers.
package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
)

// ---- Resource identifiers ----

var idPattern = regexp.MustCompile(`^[a-z]{2,4}_[0-9a-f]{32}$`)

// NewID returns "<prefix>_<32 hex>". Prefixes: pr, dst, hold, role, key, evt.
func NewID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("httpapi: rand failed: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func ValidID(id string) bool { return idPattern.MatchString(id) }

// ---- Pagination (cursor-based) ----

const (
	DefaultLimit = 20
	MaxLimit     = 100
)

// Page is the list envelope: {"items":[...],"next_cursor":"..."|null}.
type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// ListParams is the canonical list input. Cursor is opaque to clients.
type ListParams struct {
	Limit  int
	Cursor string
	Sort   string // "field" | "-field", comma-separated
}

func (p ListParams) Norm() ListParams {
	if p.Limit <= 0 {
		p.Limit = DefaultLimit
	}
	if p.Limit > MaxLimit {
		p.Limit = MaxLimit
	}
	return p
}

// ---- Machine-readable error codes (problem+json "code" extension) ----

const (
	CodeValidationFailed    = "validation_failed"
	CodeUnauthenticated     = "unauthenticated"
	CodePermissionDenied    = "permission_denied"
	CodeNotFound            = "not_found"
	CodeConflict            = "conflict"
	CodeIdempotencyConflict = "idempotency_conflict"
	CodeLegalHoldActive     = "legal_hold_active"
	CodePolicyViolation     = "policy_violation"
	CodeRateLimited         = "rate_limited"
	// CodeReauthenticationNeeded: the action needs a sign-in more recent than
	// the one the token carries.
	CodeReauthenticationNeeded = "reauthentication_needed"
	CodeInternal               = "internal"
)
