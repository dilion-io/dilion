package api

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/ports"
)

// guard authenticates the caller and enforces one permission. It is installed
// as operation middleware (not API middleware) so it applies to exactly the
// operations registered here and nothing else the embedder mounts.
type guard struct {
	api  huma.API
	d    Deps
	keys *iam.Service
	perm string
}

// guardFor builds the per-operation middleware chain for a required permission.
func (r *registrar) guardFor(perm string) huma.Middlewares {
	g := guard{api: r.api, d: r.d, keys: r.keys, perm: perm}
	return huma.Middlewares{g.handle}
}

func (g guard) handle(ctx huma.Context, next func(huma.Context)) {
	ri := &requestInfo{
		RequestID: firstNonEmpty(ctx.Header("X-Request-Id"), httpapi.NewID("req")),
		IP:        clientIP(ctx.RemoteAddr(), ctx.Header("X-Forwarded-For")),
		UserAgent: ctx.Header("User-Agent"),
	}
	resource := ctx.Operation().Method + " " + ctx.Operation().Path

	token, ok := bearerToken(ctx.Header("Authorization"))
	if !ok {
		g.unauthenticated(ctx, "missing bearer credentials")
		return
	}

	// ---- authentication ----
	switch {
	case strings.HasPrefix(token, iam.TokenPrefix):
		if g.keys == nil {
			g.unauthenticated(ctx, "API key authentication is not available")
			return
		}
		actor, scopes, err := g.keys.VerifyKey(ctx.Context(), token)
		if err != nil {
			g.unauthenticated(ctx, "invalid API key")
			return
		}
		ri.Actor, ri.Scopes = *actor, scopes

	default:
		if g.d.Verifier == nil {
			g.unauthenticated(ctx, "invalid bearer credentials")
			return
		}
		claims, err := g.d.Verifier.Verify(ctx.Context(), token)
		if err != nil || claims == nil {
			g.unauthenticated(ctx, "invalid bearer credentials")
			return
		}
		switch claims.Role {
		case iam.ActorTypeServiceRole:
			ri.Actor = ports.Actor{
				ID:   firstNonEmpty(claims.Subject, iam.ActorTypeServiceRole),
				Type: iam.ActorTypeServiceRole,
			}
		case iam.RoleAuthenticated:
			// A regular end-user token may act on the management plane, but only
			// through RBAC: deny-by-default, decided from role_assignments keyed
			// by the user's UUID (§2.11).
			ri.Actor = ports.Actor{ID: claims.Subject, Type: iam.ActorTypeUser}
		default:
			// Any other compatibility-plane JWT (anon, ...) carries no management
			// plane authority at all.
			ri.Actor = ports.Actor{ID: claims.Subject, Type: claims.Role}
			gctx := huma.WithValue(ctx, ctxKey{}, ri)
			g.d.emit(gctx.Context(), auditOpts{
				Action: audit.ActionPermissionDenied, Resource: resource, AccessLevel: audit.AccessNA,
			})
			huma.WriteErr(g.api, ctx, http.StatusForbidden,
				"the management plane requires a service_role token, a scoped API key, "+
					"or a user token holding the required permission")
			return
		}
	}

	gctx := huma.WithValue(ctx, ctxKey{}, ri)
	rctx := gctx.Context()

	// ---- authorization ----
	if ri.Actor.Type == iam.ActorTypeServiceRole {
		// All-powerful key: allowed, but its use is a "매우 민감" audit event
		// (§2.11). Once per request — this middleware runs once per operation.
		g.d.emit(rctx, auditOpts{
			Action: audit.ActionServiceRoleUse, Resource: resource, AccessLevel: audit.AccessNA,
		})
		next(gctx)
		return
	}

	if g.perm != "" {
		// A scoped API key can never exceed its own scopes, independent of the
		// installed Authorizer (least privilege, §2.11 Machine key).
		if !scopesAllow(ri.Actor, ri.Scopes, g.perm) {
			g.denied(gctx, resource)
			return
		}
		allowed := false
		if g.d.Authz != nil {
			var err error
			allowed, err = g.d.Authz.Can(rctx, ri.Actor, g.perm, resource)
			if err != nil {
				huma.WriteErr(g.api, ctx, http.StatusInternalServerError, "authorization check failed")
				return
			}
		}
		if !allowed {
			// Deny by default: a missing Authorizer denies everything.
			g.denied(gctx, resource)
			return
		}
	}

	next(gctx)
}

func (g guard) unauthenticated(ctx huma.Context, detail string) {
	ctx.SetHeader("WWW-Authenticate", `Bearer realm="dilion"`)
	huma.WriteErr(g.api, ctx, http.StatusUnauthorized, detail)
}

func (g guard) denied(ctx huma.Context, resource string) {
	g.d.emit(ctx.Context(), auditOpts{
		Action:      audit.ActionPermissionDenied,
		Resource:    resource + " (" + g.perm + ")",
		AccessLevel: audit.AccessNA,
	})
	huma.WriteErr(g.api, ctx, http.StatusForbidden, "requires permission "+g.perm)
}

// scopesAllow reports whether an actor's credential itself permits the
// operation. Only API keys are scope-limited; other actor types are decided by
// the Authorizer alone.
func scopesAllow(actor ports.Actor, scopes []string, perm string) bool {
	if actor.Type != iam.ActorTypeAPIKey {
		return true
	}
	return slices.Contains(scopes, perm)
}

// bearerToken extracts the credential from an Authorization header.
func bearerToken(header string) (string, bool) {
	scheme, rest, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(rest)
	return token, token != ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// errorStatuses documents the error responses every guarded operation may
// return, so codegen produces the full union.
var errorStatuses = []int{
	http.StatusBadRequest,
	http.StatusUnauthorized,
	http.StatusForbidden,
	http.StatusNotFound,
	http.StatusConflict,
	http.StatusUnprocessableEntity,
	http.StatusInternalServerError,
}

// authorize checks an ADDITIONAL permission from inside a handler, for a
// request option that widens what an operation returns beyond what its own
// permission covers. The operation's guard has already authenticated the
// caller and enforced its base permission; this adds a second, narrower gate
// on top, with the same rules: a service_role token passes, an API key can
// never exceed its own scopes, and a missing Authorizer denies. A denial is
// recorded as PERMISSION_DENIED and returned as 403, exactly as the guard
// would have.
func (d Deps) authorize(ctx context.Context, perm, resource string) error {
	ri := requestInfoFrom(ctx)
	if ri.Actor.Type == iam.ActorTypeServiceRole {
		return nil
	}
	allowed := false
	if scopesAllow(ri.Actor, ri.Scopes, perm) && d.Authz != nil {
		var err error
		allowed, err = d.Authz.Can(ctx, ri.Actor, perm, resource)
		if err != nil {
			return NewProblem(http.StatusInternalServerError, httpapi.CodeInternal,
				"authorization check failed")
		}
	}
	if !allowed {
		d.emit(ctx, auditOpts{
			Action:      audit.ActionPermissionDenied,
			Resource:    resource + " (" + perm + ")",
			AccessLevel: audit.AccessNA,
		})
		return NewProblem(http.StatusForbidden, httpapi.CodePermissionDenied,
			"requires permission "+perm)
	}
	return nil
}
