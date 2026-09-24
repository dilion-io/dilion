package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/auth"
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
			// by the user's UUID (§2.11) — and only from the user's own, still
			// open, second-factor-verified sign-in.
			ri.Actor = ports.Actor{ID: claims.Subject, Type: iam.ActorTypeUser}
			sid, _ := claims.Extra["session_id"].(string)
			if p := g.d.userSessionProblem(ctx.Context(), claims.Subject, sid, !g.d.AdminMFADisabled); p != nil {
				writeProblem(ctx, p)
				return
			}
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

// userSessionProblem checks the session behind a user access token, from the
// database rather than the token's claims (which hooks may rewrite): it must
// still exist and be the user's, the account must be active, the session must
// be the user's own sign-in rather than an OAuth application's, and, when
// needAAL2, it must have verified a second factor. A token passing every
// check yields nil.
func (d Deps) userSessionProblem(ctx context.Context, userID, sessionID string, needAAL2 bool) *Problem {
	as, err := d.lookupSession(ctx, userID, sessionID)
	switch {
	case errors.Is(err, auth.ErrSessionNotFound):
		return NewProblem(http.StatusUnauthorized, httpapi.CodeUnauthenticated,
			"this token's session has ended; sign in again")
	case err != nil:
		slog.ErrorContext(ctx, "session lookup failed", "error", err)
		return NewProblem(http.StatusInternalServerError, httpapi.CodeInternal, "internal error")
	case !as.Active:
		return NewProblem(http.StatusForbidden, httpapi.CodePermissionDenied, "the account is banned or deleted")
	case as.OAuthClient:
		return NewProblem(http.StatusForbidden, httpapi.CodePermissionDenied,
			"an OAuth application's token cannot act for the user here")
	case needAAL2 && as.AAL != auth.AAL2:
		return NewProblem(http.StatusForbidden, httpapi.CodeInsufficientAAL,
			"the management plane needs a session verified with a second factor (aal2)")
	}
	return nil
}

func (d Deps) lookupSession(ctx context.Context, userID, sessionID string) (auth.SessionAssurance, error) {
	if d.SessionLookup != nil {
		return d.SessionLookup(ctx, userID, sessionID)
	}
	pool, err := d.pools()(ctx)
	if err != nil {
		return auth.SessionAssurance{}, err
	}
	return auth.LookupSessionAssurance(ctx, pool, userID, sessionID)
}

// writeProblem answers a middleware refusal with a problem of its own code,
// which huma.WriteErr cannot carry.
func writeProblem(ctx huma.Context, p *Problem) {
	if p.Status == http.StatusUnauthorized {
		ctx.SetHeader("WWW-Authenticate", `Bearer realm="dilion"`)
	}
	ctx.SetHeader("Content-Type", "application/problem+json")
	ctx.SetStatus(p.Status)
	_ = json.NewEncoder(ctx.BodyWriter()).Encode(p)
}

// grantCeiling refuses to let the caller hand out a permission it does not
// hold itself — in an API key's scopes, a role's definition, or a role
// assignment. Without it, the permission to administer grants was a way to
// every other permission: a holder of it could assign itself `owner`. The
// check uses the same rules as the guard: service_role holds everything, and
// an API key holds only what is both in its scopes and granted to it. The
// refusal names every missing permission and is recorded as
// PERMISSION_DENIED.
func (d Deps) grantCeiling(ctx context.Context, perms []string, resource string) error {
	ri := requestInfoFrom(ctx)
	if ri.Actor.Type == iam.ActorTypeServiceRole {
		return nil
	}
	var missing []string
	for _, perm := range perms {
		if slices.Contains(missing, perm) {
			continue
		}
		held := false
		if scopesAllow(ri.Actor, ri.Scopes, perm) && d.Authz != nil {
			var err error
			held, err = d.Authz.Can(ctx, ri.Actor, perm, resource)
			if err != nil {
				return NewProblem(http.StatusInternalServerError, httpapi.CodeInternal,
					"authorization check failed")
			}
		}
		if !held {
			missing = append(missing, perm)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	d.emit(ctx, auditOpts{
		Action:      audit.ActionPermissionDenied,
		Resource:    resource + " (grant ceiling: " + strings.Join(missing, ",") + ")",
		AccessLevel: audit.AccessNA,
	})
	return NewProblem(http.StatusForbidden, httpapi.CodePermissionDenied,
		"cannot grant permissions you do not hold: "+strings.Join(missing, ", "))
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
