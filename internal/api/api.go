// Package api implements the Dilion management-plane HTTP surface
// (/privacy/v1 and /iam/v1) with huma v2, following docs/api-conventions.md.
//
// Every operation is guarded by the same pipeline: Bearer authentication
// (service_role JWT, scoped API key, or a user access token) → permission
// check → handler → audit event. Route registration itself never dereferences Deps, so the spec can be
// generated without a database (see cmd/openapi).
package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/auth"
	"github.com/dilion-io/dilion/ports"
)

// PoolFunc resolves the database pool for a request: in a multi-instance
// deployment the database of the instance selected on the context
// (ports.ContextWithInstance, internal/instances), otherwise the one configured
// pool. Structurally identical to instances.PoolFunc.
type PoolFunc func(context.Context) (*pgxpool.Pool, error)

// Deps are the platform dependencies injected by dilion.go.
type Deps struct {
	// Pool is the fixed database of a single-instance deployment. Registration
	// never dereferences it, so a zero Deps describes every route.
	Pool *pgxpool.Pool
	// Pools resolves the database per request and takes precedence over Pool.
	// Multi-instance deployments set it to instances.Registry.Pool.
	Pools    PoolFunc
	Verifier ports.TokenVerifier
	Authz    ports.Authorizer
	Audit    ports.AuditSink

	// DeletionReauthWindow is how recent a user's sign-in must be for them to
	// request their own deletion through /privacy/v1/me/requests; 0 turns the
	// recency check off (the session and MFA checks remain). The server fills
	// it from auth's Security.DeletionReauthWindow.
	DeletionReauthWindow time.Duration

	// SessionLookup reads the assurance of a user token's session. nil means
	// auth.LookupSessionAssurance on the request's database.
	SessionLookup func(ctx context.Context, userID, sessionID string) (auth.SessionAssurance, error)

	// AdminMFADisabled lets a user token act on the management plane without
	// an aal2 session (dilion.WithoutAdminMFA). Development only.
	AdminMFADisabled bool
}

// pools returns the effective pool provider (Pools, else a static Pool).
func (d Deps) pools() PoolFunc {
	if d.Pools != nil {
		return d.Pools
	}
	pool := d.Pool
	return func(context.Context) (*pgxpool.Pool, error) {
		if pool == nil {
			return nil, errNoPool
		}
		return pool, nil
	}
}

var errNoPool = errors.New("api: no database configured")

// API metadata (docs/api-conventions.md consumers generate clients from this).
const (
	APITitle   = "Dilion Platform API"
	APIVersion = "0.1.0"
	DefaultURL = "http://localhost:8787"

	securitySchemeName = "bearerAuth"
)

// NewConfig returns the huma configuration for the Dilion platform API. Use it
// both for the running server and for `cmd/openapi` so the generated spec and
// the served API cannot drift.
func NewConfig() huma.Config {
	installErrorModel()

	cfg := huma.DefaultConfig(APITitle, APIVersion)
	cfg.DocsPath = "/docs"
	cfg.OpenAPIPath = "/openapi"
	// Drop huma's schema-link transformer: it injects a `$schema` member into
	// every response body, which breaks the snake_case-only field rule and
	// confuses generated clients.
	cfg.SchemasPath = ""
	cfg.CreateHooks = nil
	cfg.OpenAPI.Servers = []*huma.Server{{URL: DefaultURL, Description: "Local development"}}
	if cfg.OpenAPI.Components == nil {
		cfg.OpenAPI.Components = &huma.Components{}
	}
	cfg.OpenAPI.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		securitySchemeName: {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT or dk_ API key",
			Description: "Management plane credential: a `service_role` JWT, a scoped API key (`dk_...`), " +
				"or a user access token (`role=authenticated`) whose RBAC role assignments grant the " +
				"permission the operation requires (deny-by-default).",
		},
	}
	cfg.OpenAPI.Security = []map[string][]string{{securitySchemeName: {}}}
	return cfg
}

// ---- Per-request context ----

type ctxKey struct{}

// requestInfo carries the authenticated actor and the access-log metadata
// required by §5.1 ("누가, 언제, 어디서, 어떤 권한으로").
type requestInfo struct {
	Actor     ports.Actor
	Scopes    []string // API key scopes, nil for JWT actors
	RequestID string
	IP        string
	UserAgent string
	// SessionID is the self-service caller's session (the token's session_id
	// claim), whose assurance deletion checks in the database.
	SessionID string
}

func requestInfoFrom(ctx context.Context) *requestInfo {
	ri, _ := ctx.Value(ctxKey{}).(*requestInfo)
	if ri == nil {
		return &requestInfo{}
	}
	return ri
}

// ActorFrom returns the authenticated actor for the current request. It is
// exported so embedders' custom handlers can reuse the same identity.
func ActorFrom(ctx context.Context) (ports.Actor, bool) {
	ri, ok := ctx.Value(ctxKey{}).(*requestInfo)
	if !ok || ri == nil {
		return ports.Actor{}, false
	}
	return ri.Actor, true
}

// ---- Audit ----

// auditOpts describes the parts of an audit event a handler decides.
type auditOpts struct {
	Action      string
	Resource    string
	AccessLevel string
	ResultCount int
	SubjectIDs  []string
	// Reason is the operator-supplied justification for a privileged access
	// (PII reveal 사유, §5.2). Never a personal-data value.
	Reason string
}

// emit appends an audit event, filling in actor/request metadata from the
// request context. Audit failures never fail the request but are logged loudly
// — a missing access record is a compliance defect (§5.4).
func (d Deps) emit(ctx context.Context, o auditOpts) {
	if d.Audit == nil {
		return
	}
	ri := requestInfoFrom(ctx)
	level := o.AccessLevel
	if level == "" {
		level = audit.AccessNA
	}
	ev := ports.AuditEvent{
		ActorID:     ri.Actor.ID,
		ActorType:   ri.Actor.Type,
		Action:      o.Action,
		Resource:    o.Resource,
		AccessLevel: level,
		RequestID:   ri.RequestID,
		ResultCount: o.ResultCount,
		SubjectIDs:  o.SubjectIDs,
		Reason:      o.Reason,
		IP:          ri.IP,
		UserAgent:   ri.UserAgent,
		OccurredAt:  time.Now().UTC(),
	}
	if err := d.Audit.Append(ctx, ev); err != nil {
		slog.ErrorContext(ctx, "audit append failed",
			"action", o.Action, "actor_id", ri.Actor.ID, "request_id", ri.RequestID, "error", err)
	}
}

// ---- small helpers ----

func listParams(limit int, cursor, sort string) httpapi.ListParams {
	return httpapi.ListParams{Limit: limit, Cursor: cursor, Sort: sort}.Norm()
}

// catalogListParams is listParams for a catalog list (httpapi.MaxCatalogLimit).
func catalogListParams(limit int, cursor string) httpapi.ListParams {
	return httpapi.ListParams{Limit: limit, Cursor: cursor, Max: httpapi.MaxCatalogLimit}.Norm()
}

func clientIP(remoteAddr, forwardedFor string) string {
	if forwardedFor != "" {
		first, _, _ := strings.Cut(forwardedFor, ",")
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
