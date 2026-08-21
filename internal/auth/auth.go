// Package auth implements the Supabase Auth (gotrue) compatible surface mounted
// at /auth/v1 (project.md §2.2, §2.3).
//
// The wire contract — request/response JSON, HTTP statuses, error bodies, JWT
// claims and refresh-token semantics — follows github.com/supabase/auth master.
// Compatibility beats internal elegance here: json tags, field order and error
// strings are deliberately copied. Deviations are called out in comments.
//
// The package deliberately does NOT use huma: the /auth/v1 surface must match
// upstream byte-for-byte, and its OpenAPI contract is upstream's openapi.yaml.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/hooks"
	"github.com/dilion-io/dilion/ports"
)

// Version is reported by GET /health.
const Version = "0.1.0"

// maxRequestBody caps request bodies (gotrue applies a similar limit).
const maxRequestBody = 1 << 20 // 1 MiB

// DefaultProjectID is the wave-1 single-tenant project (PLAN.md §3.5).
const DefaultProjectID = "default"

// PoolFunc resolves the database pool for a request. In a multi-instance
// deployment it returns the database of the instance selected on the context
// (ports.ContextWithInstance, internal/instances); the single-instance default
// always answers with the one configured pool. It is structurally identical to
// instances.PoolFunc — declared here so this package keeps its narrow imports.
type PoolFunc func(context.Context) (*pgxpool.Pool, error)

// StaticPool is the single-instance PoolFunc over one fixed pool.
func StaticPool(pool *pgxpool.Pool) PoolFunc {
	return func(context.Context) (*pgxpool.Pool, error) {
		if pool == nil {
			return nil, errors.New("auth: nil pool")
		}
		return pool, nil
	}
}

// Deps are the collaborators injected by the embedder. One of Pool / Pools and
// Tokens are required; Mailer, Hooks and Logger are optional and default to
// no-ops.
type Deps struct {
	// Pool is the fixed database of a single-instance deployment.
	Pool *pgxpool.Pool
	// Pools resolves the database per request and takes precedence over Pool.
	// Multi-instance deployments set it to instances.Registry.Pool.
	Pools  PoolFunc
	Tokens *TokenService
	Mailer ports.Mailer
	Hooks  *hooks.Registry

	// Config is the /auth/v1 configuration (conf.go). It is optional: when nil
	// DefaultConfig() is used, which keeps every embedder that predates the
	// configuration surface working unchanged. Handlers must treat it as
	// read-only — it is shared by every request.
	Config *Config

	// Authz is optional. When set, /admin/* additionally accepts a regular user
	// access token (role=authenticated) that holds the `users.admin` permission
	// (project.md §2.11). When nil the surface stays service_role-only, which is
	// the historical behaviour embedders may rely on.
	Authz ports.Authorizer

	// Audit is optional. When set, the /admin/users surface records an access
	// event per request (안전성 확보조치 기준 제8조 접속기록, project.md §5). When nil
	// nothing is recorded — embedders that mount this package standalone keep
	// working. Auditing here is deliberately FAIL-OPEN: an audit sink is an
	// observability dependency, so a sink failure is logged at WARN and the
	// request still succeeds (see emitAudit).
	Audit ports.AuditSink

	// Logger is optional; slog.Default() is used when nil.
	Logger *slog.Logger
	// Clock is optional; ports.SystemClock is used when nil.
	Clock ports.Clock
}

type api struct {
	cfg    *Config
	pools  PoolFunc
	tokens *TokenService
	mailer ports.Mailer
	hooks  *hooks.Registry
	authz  ports.Authorizer
	audit  ports.AuditSink
	log    *slog.Logger
	clock  ports.Clock

	// limiters are the named per-IP rate limiters of this mount (middleware.go).
	limiters map[string]*rateLimiter
}

func newAPI(d Deps) *api {
	pools := d.Pools
	if pools == nil {
		pools = StaticPool(d.Pool)
	}
	cfg := d.Config
	if cfg == nil {
		cfg = DefaultConfig()
	} else if err := cfg.Validate(); err != nil {
		// A caller-supplied Config is validated here so a bad allow-list or
		// captcha setting fails at mount time, not on the first request.
		panic(err)
	}
	a := &api{
		cfg:    cfg,
		pools:  pools,
		tokens: d.Tokens,
		mailer: d.Mailer,
		hooks:  d.Hooks,
		authz:  d.Authz,
		audit:  d.Audit,
		log:    d.Logger,
		clock:  d.Clock,
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.clock == nil {
		a.clock = ports.SystemClock{}
	}
	a.limiters = buildLimiters(cfg)
	return a
}

func (a *api) now() time.Time { return a.clock.Now().UTC() }

// db resolves the database of the instance selected on ctx. The error is
// already in the gotrue error envelope, so handlers can return it as-is.
func (a *api) db(ctx context.Context) (*pgxpool.Pool, error) {
	if a.pools == nil {
		return nil, internalServerError("Database error: no database configured")
	}
	pool, err := a.pools(ctx)
	if err != nil {
		return nil, internalServerError("Database error: no database configured").withInternal(err)
	}
	if pool == nil {
		return nil, internalServerError("Database error: no database configured")
	}
	return pool, nil
}

// ---- feature registry -----------------------------------------------------

// featureMount is one feature package's route contribution.
type featureMount struct {
	name  string
	mount func(a *api, r chi.Router)
}

// featureMounts is the registry filled by registerFeature. It exists so that a
// new /auth/v1 feature NEVER has to edit this file: the feature's own file
// calls registerFeature from its init(), and Register picks it up.
var featureMounts []featureMount

// registerFeature adds a feature's routes to the /auth/v1 surface. Call it from
// a package-level init():
//
//	func init() {
//		registerFeature("settings", func(a *api, r chi.Router) {
//			r.Get("/settings", a.handle(a.settings))
//		})
//	}
//
// name identifies the feature and fixes the mount order: Register sorts the
// registry by name, so the route table does not depend on Go's file
// initialisation order. Registering the same name twice is a programming error
// and panics.
func registerFeature(name string, mount func(a *api, r chi.Router)) {
	if name == "" || mount == nil {
		panic("auth: registerFeature requires a name and a mount function")
	}
	for _, m := range featureMounts {
		if m.name == name {
			panic("auth: duplicate feature registration: " + name)
		}
	}
	featureMounts = append(featureMounts, featureMount{name: name, mount: mount})
}

// sortedFeatureMounts returns the registry in a stable order.
func sortedFeatureMounts() []featureMount {
	out := append([]featureMount(nil), featureMounts...)
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// Register mounts the gotrue-compatible routes on r. The caller is responsible
// for mounting r at /auth/v1.
//
// Middleware order matches upstream's (internal/api/api.go NewAPIWithVersion):
// CORS outermost, then client-IP resolution, then the request timeout. Rate
// limiting is per route (a.limit / a.limitCheck), as upstream does it.
//
// Routes are mounted in two phases: the core surface below, then every feature
// registered with registerFeature, in name order.
//
// The returned Mount carries the background work of this mount; embedders that
// only need the HTTP surface can ignore it.
func Register(r chi.Router, d Deps) *Mount {
	a := newAPI(d)

	r.Use(corsMiddleware(a.cfg))
	r.Use(clientIPMiddleware)
	r.Use(timeoutMiddleware(a, a.cfg.APIMaxRequestDuration))

	r.Get("/health", a.handle(a.health))
	r.Get("/.well-known/jwks.json", a.handle(a.jwks))

	// Both endpoints pick their limiter from the request: /signup between the
	// signup and the anonymous limit, /token per grant type.
	r.Post("/signup", a.handle(a.signup))
	r.Post("/token", a.handle(a.token))

	r.Group(func(r chi.Router) {
		r.Use(a.requireAuthentication)
		r.Get("/user", a.handle(a.getUser))
		r.With(a.limit(LimiterUser)).Put("/user", a.handle(a.updateUser))
		r.Post("/logout", a.handle(a.logout))
	})

	r.Route("/admin/users", func(r chi.Router) {
		r.Use(a.requireAdmin)
		r.Get("/", a.handle(a.adminListUsers))
		r.Post("/", a.handle(a.adminCreateUser))
		r.Get("/{user_id}", a.handle(a.adminGetUser))
		r.Put("/{user_id}", a.handle(a.adminUpdateUser))
		r.Delete("/{user_id}", a.handle(a.adminDeleteUser))
	})

	for _, m := range sortedFeatureMounts() {
		m.mount(a, r)
	}

	return &Mount{a: a}
}

// Mount is the handle to one mounted /auth/v1 surface. It exposes the parts of
// the package that live outside the request path.
type Mount struct{ a *api }

// RunCleanup runs the periodic deletion of expired auth rows until ctx is
// cancelled (cleanup.go). It is a no-op when Config.CleanupEnabled is false, and
// it operates on the database of the instance selected on ctx
// (ports.ContextWithInstance), so a multi-instance deployment starts one worker
// per instance.
func (m *Mount) RunCleanup(ctx context.Context) { m.a.RunCleanup(ctx) }

// Config returns the configuration this mount was built with.
func (m *Mount) Config() *Config { return m.a.cfg }

// ---- health ---------------------------------------------------------------

// health returns gotrue's healthcheck body. The `name` stays "GoTrue" on
// purpose: supabase-js and the Supabase CLI probe this endpoint and match on it.
func (a *api) health(w http.ResponseWriter, _ *http.Request) error {
	return sendJSON(w, http.StatusOK, HealthCheckResponse{
		Version:     Version,
		Name:        "GoTrue",
		Description: "GoTrue is a user registration and authentication API",
	})
}

// jwks serves /.well-known/jwks.json: the PUBLIC half of every ES256 key in
// Config.JWT.Keys (upstream api.WellKnownJwks).
//
// A symmetric-only deployment (HS256 with JWT_SECRET, the zero-config developer
// path) legitimately publishes an EMPTY key set — the shared secret must never
// leave the server, and that is the same answer upstream gives. Private key
// material is structurally impossible to leak here: TokenService.PublicJWKS
// returns PublicJWK values, which have no field for the private scalar `d`.
func (a *api) jwks(w http.ResponseWriter, _ *http.Request) error {
	keys := []PublicJWK{}
	if a.tokens != nil {
		keys = a.tokens.PublicJWKS()
	}
	// Upstream's cache header, verbatim.
	w.Header().Set("Cache-Control", "public, max-age=600")
	return sendJSON(w, http.StatusOK, JwksResponse{Keys: keys})
}

// JwksResponse is the GET /.well-known/jwks.json body (upstream api.JwksResponse).
type JwksResponse struct {
	Keys []PublicJWK `json:"keys"`
}

// ---- request context ------------------------------------------------------

type ctxKey int

const (
	ctxKeyClaims ctxKey = iota
	ctxKeyUser
	ctxKeyActor
)

func withClaims(ctx context.Context, c *ports.Claims) context.Context {
	return context.WithValue(ctx, ctxKeyClaims, c)
}

func claimsFrom(ctx context.Context) *ports.Claims {
	c, _ := ctx.Value(ctxKeyClaims).(*ports.Claims)
	return c
}

func withUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ctxKeyUser, u)
}

func userFrom(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKeyUser).(*User)
	return u
}

// withActor carries the actor the admin gate established, so handlers record
// the same identity the gate authorized instead of re-parsing the token.
func withActor(ctx context.Context, a ports.Actor) context.Context {
	return context.WithValue(ctx, ctxKeyActor, a)
}

func actorFrom(ctx context.Context) ports.Actor {
	a, _ := ctx.Value(ctxKeyActor).(ports.Actor)
	return a
}

// sessionIDFrom reads the `session_id` custom claim, if present and well-formed.
func sessionIDFrom(c *ports.Claims) string {
	if c == nil {
		return ""
	}
	s, _ := c.Extra["session_id"].(string)
	if s == "" {
		return ""
	}
	if _, err := uuid.Parse(s); err != nil {
		return ""
	}
	return s
}

// ---- middleware -----------------------------------------------------------

func extractBearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", unauthorizedError(ErrorCodeNoAuthorization, "This endpoint requires a valid Bearer token")
	}
	return strings.TrimSpace(parts[1]), nil
}

// requireAuthentication verifies the Bearer JWT and loads the user it names.
func (a *api) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearerToken(r)
		if err != nil {
			a.writeError(r, w, err)
			return
		}
		claims, verr := a.tokens.Verify(r.Context(), token)
		if verr != nil {
			a.writeError(r, w, forbiddenError(ErrorCodeBadJWT,
				"invalid JWT: unable to parse or verify signature, %v", verr))
			return
		}
		if _, perr := uuid.Parse(claims.Subject); perr != nil {
			a.writeError(r, w, badRequestError(ErrorCodeBadJWT, "invalid claim: sub claim must be a UUID"))
			return
		}

		pool, perr := a.db(r.Context())
		if perr != nil {
			a.writeError(r, w, perr)
			return
		}
		u, derr := a.loadUserWithIdentities(r.Context(), pool, claims.Subject)
		if derr != nil {
			if isNoRows(derr) {
				a.writeError(r, w, forbiddenError(ErrorCodeUserNotFound, "User from sub claim in JWT does not exist"))
				return
			}
			a.writeError(r, w, internalServerError("Database error loading user").withInternal(derr))
			return
		}
		if u.DeletedAt != nil {
			a.writeError(r, w, forbiddenError(ErrorCodeUserNotFound, "User from sub claim in JWT does not exist"))
			return
		}
		if u.IsBanned(a.now()) {
			a.writeError(r, w, forbiddenError(ErrorCodeUserBanned, "User is banned"))
			return
		}

		ctx := withUser(withClaims(r.Context(), claims), u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAdmin gates the /admin/* endpoints. A `service_role` JWT is admitted
// unconditionally (upstream behaviour). In addition — when an Authorizer is
// installed — a regular user access token (`role=authenticated`) is admitted if
// RBAC grants it the `users.admin` permission (project.md §2.11). Every other
// credential gets gotrue's 403 not_admin, byte-identical to upstream.
func (a *api) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearerToken(r)
		if err != nil {
			a.writeError(r, w, err)
			return
		}
		claims, verr := a.tokens.Verify(r.Context(), token)
		if verr != nil {
			a.writeError(r, w, forbiddenError(ErrorCodeBadJWT,
				"invalid JWT: unable to parse or verify signature, %v", verr))
			return
		}
		if claims.Role != RoleServiceRole && !a.userIsAdmin(r, claims) {
			a.writeError(r, w, forbiddenError(ErrorCodeNotAdmin, "User not allowed"))
			return
		}
		// The audited actor is exactly the credential the gate admitted: a
		// service_role JWT acts as "service_role", an RBAC-admitted access
		// token as "user" with the user's UUID.
		actor := ports.Actor{ID: claims.Subject, Type: ActorTypeUser, ProjectID: DefaultProjectID}
		if claims.Role == RoleServiceRole {
			actor.Type = ActorTypeServiceRole
		}
		ctx := withActor(withClaims(r.Context(), claims), actor)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// userIsAdmin reports whether a regular user token holds `users.admin`. A nil
// Authorizer denies (service_role-only, the pre-RBAC behaviour), and so does an
// Authorizer error — this gate is fail-closed.
func (a *api) userIsAdmin(r *http.Request, claims *ports.Claims) bool {
	if a.authz == nil || claims == nil || claims.Role != RoleAuthenticated || claims.Subject == "" {
		return false
	}
	ok, err := a.authz.Can(r.Context(), ports.Actor{
		ID:        claims.Subject,
		Type:      ActorTypeUser,
		ProjectID: DefaultProjectID,
	}, PermUsersAdmin, "auth/admin")
	if err != nil {
		a.log.ErrorContext(r.Context(), "auth: admin authorization check failed",
			slog.String("actor_id", claims.Subject), slog.String("error", err.Error()))
		return false
	}
	return ok
}

// ---- helpers --------------------------------------------------------------

// decodeBody reads a JSON body into dst. An empty body is accepted (some gotrue
// endpoints, e.g. DELETE /admin/users/{id}, treat it as "all defaults").
func decodeBody(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		return badRequestError(ErrorCodeBadJSON, "Could not read body")
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return badRequestError(ErrorCodeBadJSON, "Could not parse request body as JSON: %v", err)
	}
	return nil
}

// requestAud is gotrue's requestAud: the X-JWT-AUD header or the configured
// default audience.
func requestAud(r *http.Request) string {
	if aud := r.Header.Get("X-JWT-AUD"); aud != "" {
		return aud
	}
	return AudienceAuthenticated
}

func (a *api) loadUserWithIdentities(ctx context.Context, q querier, id string) (*User, error) {
	u, err := findUserByID(ctx, q, id)
	if err != nil {
		return nil, err
	}
	ids, err := findIdentitiesByUserID(ctx, q, u.ID)
	if err != nil {
		return nil, err
	}
	u.Identities = ids
	return u, nil
}

// runHook executes a hook point, tolerating a nil registry. Validating hook
// points are fail-closed: an error from the registry aborts the request.
func (a *api) runHook(ctx context.Context, point ports.HookPoint, payload map[string]any) (map[string]any, error) {
	if a.hooks == nil {
		return payload, nil
	}
	out, err := a.hooks.Run(ctx, point, payload)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return payload, nil
	}
	return out, nil
}

// observeHook runs an observing hook point; failures are logged, never returned,
// so an observer cannot break the compatibility surface (project.md §2.4).
func (a *api) observeHook(ctx context.Context, point ports.HookPoint, payload map[string]any) {
	if _, err := a.runHook(ctx, point, payload); err != nil {
		a.log.WarnContext(ctx, "auth: observing hook failed",
			slog.String("hook", string(point)), slog.String("error", err.Error()))
	}
}

// notify sends a best-effort transactional email. Delivery failures are logged
// but never fail the request.
func (a *api) notify(ctx context.Context, to, subject, body string) {
	if a.mailer == nil || to == "" {
		return
	}
	if err := a.mailer.Send(ctx, to, subject, body, ""); err != nil {
		a.log.WarnContext(ctx, "auth: mail delivery failed",
			slog.String("subject", subject), slog.String("error", err.Error()))
	}
}

// ---- session issuance -----------------------------------------------------

// issueAccessToken signs the access token for a user/session pair, giving the
// ports.TokenClaims hook a chance to inject custom claims first.
//
// The `aal` and `amr` claims are NOT parameters: they are derived from the
// session's rows in auth.mfa_amr_claims (mfa_models.go, upstream
// models.Session.CalculateAALAndAMR), so a token always reports the assurance
// level the session has actually reached — aal2 only after an MFA factor was
// verified against it. q must be able to read that table; it is the caller's
// transaction wherever one is open.
func (a *api) issueAccessToken(ctx context.Context, q querier, u *User, sessionID string) (string, time.Time, error) {
	now := a.now()
	expiresAt := now.Add(a.tokens.TTL())

	extra := map[string]any{
		"phone":         u.Phone,
		"app_metadata":  map[string]any(u.AppMetaData),
		"user_metadata": map[string]any(u.UserMetaData),
		"is_anonymous":  u.IsAnonymous,
	}
	if sessionID != "" {
		claims, cerr := findAMRClaims(ctx, q, sessionID)
		if cerr != nil {
			return "", time.Time{}, internalServerError("Database error loading AMR claims").withInternal(cerr)
		}
		aal, amr := computeAAL(claims)
		extra["session_id"] = sessionID
		extra["aal"] = aal
		extra["amr"] = amr
	}

	// TokenClaims is a mutating hook point: the returned map replaces `extra`.
	extra, err := a.runHook(ctx, ports.TokenClaims, extra)
	if err != nil {
		return "", time.Time{}, internalServerError("Error running token claims hook").withInternal(err)
	}

	role := u.Role
	if role == "" {
		role = RoleAuthenticated
	}
	aud := u.Aud
	if aud == "" {
		aud = AudienceAuthenticated
	}

	// custom_access_token (external hook). It runs AFTER the in-process
	// ports.TokenClaims hook. Claim precedence, in order of application:
	//
	//  1. the base gotrue claims assembled into `extra` above
	//     (phone, app_metadata, user_metadata, is_anonymous, and — for a session
	//     token — session_id, aal, amr);
	//  2. the in-process ports.TokenClaims hook, which may rewrite `extra`;
	//  3. this external hook, which receives the FULL claim view (the reserved
	//     JWT claims plus everything in `extra`) and whose returned `claims` map
	//     REPLACES `extra` wholesale — upstream's semantics
	//     (gotrueClaims = jwt.MapClaims(output.Claims));
	//  4. TokenService.Sign, which writes the reserved claims
	//     (sub/aud/exp/iat/iss/role/email) on top.
	//
	// DEVIATION: upstream lets custom_access_token overwrite ANY claim, including
	// role. Dilion keeps its reservedClaims protection (token.go): the external
	// hook can add and rewrite custom claims but cannot forge identity, role,
	// audience or lifetime — Sign always re-asserts those. The hook is invoked in
	// the token-issuance transaction (`q`) so a pg-functions hook sees the same
	// uncommitted state the request is building.
	if cfg := a.cfg.Hooks.CustomAccessToken; cfg.Enabled {
		claims := map[string]any{
			"sub":   u.ID,
			"aud":   aud,
			"role":  role,
			"email": u.Email,
			"iat":   now.Unix(),
			"exp":   expiresAt.Unix(),
		}
		for k, v := range extra {
			claims[k] = v
		}
		in := &CustomAccessTokenInput{
			Metadata: newHookMetadata(nil, HookNameCustomAccessToken),
			UserID:   u.ID,
			Claims:   claims,
			// authentication_method is not threaded into issueAccessToken;
			// upstream fills it from the grant. Left empty (documented).
			AuthenticationMethod: "",
		}
		out := &CustomAccessTokenOutput{}
		if herr := a.runExtHook(ctx, cfg, q, in, out); herr != nil {
			return "", time.Time{}, herr
		}
		extra = out.Claims
	}

	token, err := a.tokens.Sign(ctx, ports.Claims{
		Subject:   u.ID,
		Role:      role,
		Email:     u.Email,
		Audience:  aud,
		ExpiresAt: expiresAt,
		Extra:     extra,
	})
	if err != nil {
		return "", time.Time{}, internalServerError("Error generating access token").withInternal(err)
	}
	return token, expiresAt, nil
}

// grantSession creates a session + first refresh token and returns the gotrue
// session envelope. Must run inside the caller's transaction.
func (a *api) grantSession(ctx context.Context, tx querier, u *User, r *http.Request, amrMethod string) (*AccessTokenResponse, error) {
	now := a.now()
	sessionID := uuid.NewString()

	if err := insertSession(ctx, tx, sessionID, u.ID, r.UserAgent(), clientIPInet(r), now); err != nil {
		return nil, internalServerError("Error creating session").withInternal(err)
	}

	// The sign-in method is recorded as this session's first AMR claim, which
	// is what the `amr` array of every token issued for the session is built
	// from (upstream models.AddClaimToSession). It never raises `aal` above
	// aal1 — only a verified MFA factor does that.
	if err := addAMRClaimToSession(ctx, tx, sessionID, amrMethod, now); err != nil {
		return nil, internalServerError("Error recording authentication method").withInternal(err)
	}

	refresh, err := newRefreshToken()
	if err != nil {
		return nil, internalServerError("Error generating refresh token").withInternal(err)
	}
	if err := insertRefreshToken(ctx, tx, refresh, u.ID, "", sessionID, now); err != nil {
		return nil, internalServerError("Error creating refresh token").withInternal(err)
	}

	if _, err := updateUserFields(ctx, tx, u.ID, now, map[string]any{"last_sign_in_at": now}); err != nil {
		return nil, internalServerError("Error updating user").withInternal(err)
	}
	u.LastSignInAt = &now
	u.UpdatedAt = now

	return a.buildSessionResponse(ctx, tx, u, sessionID, refresh)
}

// buildSessionResponse renders the gotrue session envelope for an EXISTING
// session. q is used to read the session's AMR claims; pass the open
// transaction whenever the caller has one, so a claim written moments ago is
// visible to the token being signed.
func (a *api) buildSessionResponse(ctx context.Context, q querier, u *User, sessionID, refresh string) (*AccessTokenResponse, error) {
	accessToken, expiresAt, err := a.issueAccessToken(ctx, q, u, sessionID)
	if err != nil {
		return nil, err
	}
	return &AccessTokenResponse{
		Token:        accessToken,
		TokenType:    "bearer",
		ExpiresIn:    int(a.tokens.TTL().Seconds()),
		ExpiresAt:    expiresAt.Unix(),
		RefreshToken: refresh,
		User:         u,
	}, nil
}

// commitWithError makes a transaction commit even though the request fails.
// It is gotrue's storage.NewCommitWithError and exists for exactly one case:
// refresh-token reuse detection, where the punitive revocation MUST persist
// while the caller still receives an error.
type commitWithError struct{ err error }

func (c *commitWithError) Error() string { return c.err.Error() }
func (c *commitWithError) Unwrap() error { return c.err }

// commitAndFail wraps err so inTx commits the work done so far and then returns
// err to the caller.
func commitAndFail(err error) error { return &commitWithError{err: err} }

// inTx runs fn in a transaction, rolling back on error — unless fn returns a
// commitWithError, in which case the work is committed and the wrapped error
// is returned.
func (a *api) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return internalServerError("Database error starting transaction").withInternal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx); err != nil {
		var cwe *commitWithError
		if errors.As(err, &cwe) {
			if cerr := tx.Commit(ctx); cerr != nil {
				return internalServerError("Database error committing transaction").withInternal(cerr)
			}
			return cwe.err
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return internalServerError("Database error committing transaction").withInternal(err)
	}
	return nil
}
