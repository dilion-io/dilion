// Package privacy: engine implementation of the Service contract in service.go.
//
// Layout:
//
//	policy.go      policy data model, built-in policies, merge/validate/resolve
//	requests.go    DSR create/get/list/cancel (§2.9 grace, idempotency)
//	consent.go     append-only consent ledger + reconfirm scanner (§2.8, §4)
//	destinations.go, holds.go   management-plane CRUD
//	pipeline.go    erasure pipeline steps 100–1000 (§2.9)
//	tasks.go       webhook/connector delivery with HMAC signing (§3.2)
//	outbox.go      transactional outbox dispatcher (§2.5)
//	retention.go   retention scanner (§2.8)
//	workers.go     pollers
package privacy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/hooks"
	"github.com/dilion-io/dilion/ports"
)

// systemSubjectID is the KMS subject used for platform secrets that do not
// belong to a data subject (webhook secrets). It must never be crypto-shredded
// by a subject erasure.
const systemSubjectID = "system"

// defaultProjectID — wave 1 is single-tenant (PLAN.md §3.5).
const defaultProjectID = "default"

// EngineDeps is the injection surface of the compliance engine. Every field is
// instance-scoped: one Engine serves exactly one instance (one database), and
// internal/instances constructs one Engine per instance id.
type EngineDeps struct {
	Pool       *pgxpool.Pool
	KMS        ports.KMS
	Hooks      *hooks.Registry
	Clock      ports.Clock
	PolicyYAML []byte
	// PIIFieldsYAML pins the instance's PII field definitions:
	//
	//	pii-fields:
	//	  email: {hint: EMAIL}
	//	  full_name: {hint: NAME}
	//
	// When set, profile writes may only use the defined keys and the stored
	// masking hint always comes from the definition. nil = free-form fields
	// (the single-instance default).
	PIIFieldsYAML []byte
	Connectors    map[string]ports.Connector
	TombstoneKey  []byte
}

// Engine implements Service.
type Engine struct {
	pool         *pgxpool.Pool
	kms          ports.KMS
	hooks        *hooks.Registry
	clock        ports.Clock
	policies     *PolicySet
	piiFields    map[string]FieldHint // nil = free-form fields
	connectors   map[string]ports.Connector
	tombstoneKey []byte
	http         *http.Client
	log          *slog.Logger
}

var _ Service = (*Engine)(nil)

// NewEngine validates dependencies and loads/validates the policy data.
// Invalid policy data is a startup failure (§2.8).
func NewEngine(d EngineDeps) (*Engine, error) {
	if d.Pool == nil {
		return nil, errors.New("privacy: EngineDeps.Pool is required")
	}
	if d.KMS == nil {
		return nil, errors.New("privacy: EngineDeps.KMS is required")
	}
	if len(d.TombstoneKey) == 0 {
		return nil, errors.New("privacy: EngineDeps.TombstoneKey is required (erasure registry tombstones)")
	}
	set, err := LoadPolicies(d.PolicyYAML)
	if err != nil {
		return nil, err
	}
	// Instance-fixed PII field definitions are validated at construction: a
	// malformed definition must not become a per-request surprise.
	fields, err := ParsePIIFields(d.PIIFieldsYAML)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		pool:         d.Pool,
		kms:          d.KMS,
		hooks:        d.Hooks,
		clock:        d.Clock,
		policies:     set,
		piiFields:    fields,
		connectors:   d.Connectors,
		tombstoneKey: append([]byte(nil), d.TombstoneKey...),
		http:         &http.Client{Timeout: 15 * time.Second},
		log:          slog.Default().With("component", "privacy"),
	}
	if e.clock == nil {
		e.clock = ports.SystemClock{}
	}
	if e.hooks == nil {
		e.hooks = hooks.NewRegistry()
	}
	if e.connectors == nil {
		e.connectors = map[string]ports.Connector{}
	}
	return e, nil
}

// Policies exposes the loaded policy set (read-only; used by tests and by the
// API layer to render effective policy).
func (e *Engine) Policies() *PolicySet { return e.policies }

func (e *Engine) now() time.Time { return e.clock.Now().UTC() }

func (e *Engine) runHook(ctx context.Context, p ports.HookPoint, payload map[string]any) error {
	if e.hooks == nil {
		return nil
	}
	_, err := e.hooks.Run(ctx, p, payload)
	return err
}

// ---- small helpers ---------------------------------------------------------

func normProject(p string) string {
	if strings.TrimSpace(p) == "" {
		return defaultProjectID
	}
	return p
}

func validUUID(s string) (string, error) {
	u, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("%w: user_id must be a UUID", ErrInvalidInput)
	}
	return u.String(), nil
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// tableExists guards steps that touch tables owned by other agents (auth.*):
// wave-1 migrations may not create every optional table yet.
func (e *Engine) tableExists(ctx context.Context, qualified string) bool {
	var ok bool
	if err := e.pool.QueryRow(ctx, `select to_regclass($1) is not null`, qualified).Scan(&ok); err != nil {
		e.log.Warn("table existence check failed", "table", qualified, "err", err)
		return false
	}
	return ok
}

// ---- cursor pagination (opaque "<ts>|<id>") --------------------------------

func encodeCursor(ts time.Time, id string) *string {
	s := base64.RawURLEncoding.EncodeToString([]byte(ts.UTC().Format(time.RFC3339Nano) + "|" + id))
	return &s
}

func decodeCursor(c string) (time.Time, string, error) {
	if c == "" {
		return time.Time{}, "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: bad cursor", ErrInvalidInput)
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("%w: bad cursor", ErrInvalidInput)
	}
	ts, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: bad cursor", ErrInvalidInput)
	}
	return ts, parts[1], nil
}

// encodeIDCursor is the cursor form for resources paged by their (random,
// stable) id: destinations, holds.
func encodeIDCursor(id string) *string {
	s := base64.RawURLEncoding.EncodeToString([]byte(id))
	return &s
}

func decodeIDCursor(c string) (string, error) {
	if c == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", fmt.Errorf("%w: bad cursor", ErrInvalidInput)
	}
	return string(raw), nil
}

// page assembles a Page[T] from an over-fetched slice (len == limit+1 means
// there is a next page).
func page[T any](items []T, limit int, cursorOf func(T) *string) httpapi.Page[T] {
	var next *string
	if len(items) > limit {
		items = items[:limit]
		next = cursorOf(items[len(items)-1])
	}
	if items == nil {
		items = []T{}
	}
	return httpapi.Page[T]{Items: items, NextCursor: next}
}

// ---- legal hold gate (§2.9 — shared by pipeline and retention scanner) -----

// activeHoldFor reports whether an un-released hold blocks the subject. A hold
// with domain NULL blocks everything; a domain-scoped hold blocks that domain.
// Passing domain == "" asks "is any hold active for this subject?".
func (e *Engine) activeHoldFor(ctx context.Context, userID, domain string) (bool, error) {
	const q = `select exists (
		select 1 from dilion_privacy.legal_holds
		where user_id = $1::uuid and released_at is null
		  and ($2 = '' or domain is null or domain = $2))`
	var ok bool
	if err := e.pool.QueryRow(ctx, q, userID, domain).Scan(&ok); err != nil {
		return false, fmt.Errorf("privacy: legal hold lookup: %w", err)
	}
	return ok, nil
}
