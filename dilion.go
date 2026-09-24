// Package dilion assembles the Dilion server: an embeddable, Supabase Auth
// compatible authentication engine with a built-in privacy/compliance plane.
//
// Everything replaceable is injected through functional options (project.md
// §2.4). With no options beyond a database, every component falls back to a
// working default:
//
//	srv, err := dilion.NewServer(dilion.WithDSN(os.Getenv("DILION_DSN")))
//	if err != nil { ... }
//	if err := srv.Migrate(ctx); err != nil { ... }
//	log.Fatal(srv.Start(ctx))
//
// API surfaces mounted by Handler:
//
//	/auth/v1/*      Supabase Auth compatible (chi, hand-written JSON contract)
//	/privacy/v1/*   compliance API (huma, OpenAPI 3.1 generated)
//	/iam/v1/*       management-plane RBAC API (huma)
//	/healthz        liveness; /readyz database readiness
//
// # Multiple database instances
//
// A Dilion "instance" is a whole isolated database (auth.* + dilion_*). The
// built-in daemon runs exactly one. Embedders that need several inject a
// ports.InstanceResolver and select the instance per request themselves —
// Dilion ships no routing rule. Tokens are bound to their instance by key
// material: the resolver hands every instance its own JWT keys, so a token of
// one instance is rejected by every other (and by any PostgREST or resource
// server that trusts the other's JWKS):
//
//	srv, _ := dilion.NewServer(dilion.WithInstanceResolver(myResolver))
//	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		id := myTenantLookup(r) // subdomain, header, session, ...
//		r = r.WithContext(ports.ContextWithInstance(r.Context(), id))
//		srv.Handler().ServeHTTP(w, r)
//	})
//
// Migrate then migrates every instance the resolver lists, and Start runs the
// compliance workers per instance.
package dilion

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/api"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/auth"
	"github.com/dilion-io/dilion/internal/devmail"
	"github.com/dilion-io/dilion/internal/hooks"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/instances"
	"github.com/dilion-io/dilion/internal/kmslocal"
	"github.com/dilion-io/dilion/internal/store"
	"github.com/dilion-io/dilion/ports"
)

// Version is reported in the generated OpenAPI document.
const Version = "0.1.0"

// DefaultAddr is the listen address used when WithAddr is not given.
const DefaultAddr = ":8787"

const shutdownGrace = 15 * time.Second

// Hook points are re-exported so embedders need not import ports directly.
type HookPoint = ports.HookPoint

// The identity-federation contracts are re-exported for the same reason; see
// WithProviderSource and WithOAuthClientResolver.
type (
	OIDCProvider        = ports.OIDCProvider
	ProviderSource      = ports.ProviderSource
	OAuthClient         = ports.OAuthClient
	OAuthClientResolver = ports.OAuthClientResolver
	AuthSettings        = ports.AuthSettings
	AuthSettingsSource  = ports.AuthSettingsSource
)

const (
	BeforeSignup      = ports.BeforeSignup
	AfterSignup       = ports.AfterSignup
	TokenClaims       = ports.TokenClaims
	BeforeUserDelete  = ports.BeforeUserDelete
	AfterUserDelete   = ports.AfterUserDelete
	BeforeErasureStep = ports.BeforeErasureStep
	AfterErasure      = ports.AfterErasure
	ConsentChanged    = ports.ConsentChanged
	ConsentReconfirm  = ports.ConsentReconfirm
	AuthHookSetting   = ports.AuthHookSetting
	PIIReveal         = ports.PIIReveal
)

// ---- options ----

type config struct {
	dsn           string
	pool          *pgxpool.Pool
	kms           ports.KMS
	mailer        ports.Mailer
	sms           ports.SMSSender
	authz         ports.Authorizer
	auditSink     ports.AuditSink
	connectors    map[string]ports.Connector
	hooks         []hookReg
	jwtSecret     []byte
	masterKey     []byte
	policyYAML    []byte
	piiFieldsYAML []byte
	resolver      ports.InstanceResolver
	providers     ports.ProviderSource
	oauthClients  ports.OAuthClientResolver
	authSettings  ports.AuthSettingsSource
	authConfig    *auth.Config
	addr          string
	clock         ports.Clock
	log           *slog.Logger

	adminMFADisabled bool
}

type hookReg struct {
	point ports.HookPoint
	fn    ports.HookFunc
}

// Option customises the server. Options are applied in order.
type Option func(*config)

// WithDSN connects a pool from a Postgres connection string. Ignored when
// WithPool is also given.
func WithDSN(dsn string) Option { return func(c *config) { c.dsn = dsn } }

// WithPool injects an existing pool. The caller keeps ownership: Close does not
// close a pool it did not create.
func WithPool(p *pgxpool.Pool) Option { return func(c *config) { c.pool = p } }

// WithKMS replaces the default AES-256-GCM local KMS (AWS KMS, Vault, HSM...).
func WithKMS(k ports.KMS) Option { return func(c *config) { c.kms = k } }

// WithMailer replaces the dev logging mailer.
func WithMailer(m ports.Mailer) Option { return func(c *config) { c.mailer = m } }

// WithSMS replaces the dev logging SMS sender.
func WithSMS(s ports.SMSSender) Option { return func(c *config) { c.sms = s } }

// WithAuthorizer replaces the built-in management-plane RBAC decision point.
func WithAuthorizer(a ports.Authorizer) Option { return func(c *config) { c.authz = a } }

// WithAuditSink replaces the Postgres audit sink.
func WithAuditSink(s ports.AuditSink) Option { return func(c *config) { c.auditSink = s } }

// WithHook installs a lifecycle hook (§2.4). Hooks run in registration order.
func WithHook(p ports.HookPoint, fn ports.HookFunc) Option {
	return func(c *config) { c.hooks = append(c.hooks, hookReg{p, fn}) }
}

// WithConnector registers an external-system connector under name; privacy
// destinations of type CONNECTOR reference it by that name (§3.1).
func WithConnector(name string, conn ports.Connector) Option {
	return func(c *config) {
		if c.connectors == nil {
			c.connectors = map[string]ports.Connector{}
		}
		c.connectors[name] = conn
	}
}

// WithJWTSecret sets the HS256 signing secret for the compat auth surface.
// Without it an ephemeral secret is generated and all tokens die on restart.
func WithJWTSecret(secret []byte) Option {
	return func(c *config) { c.jwtSecret = append([]byte(nil), secret...) }
}

// WithMasterKey sets the 32-byte KEK for the default local KMS. Without it an
// ephemeral key is generated and stored PII becomes unreadable on restart.
func WithMasterKey(key []byte) Option {
	return func(c *config) { c.masterKey = append([]byte(nil), key...) }
}

// WithPolicyYAML supplies compliance policy overrides merged onto the built-in
// policies (§2.8). Invalid policy data fails NewServer.
func WithPolicyYAML(b []byte) Option {
	return func(c *config) { c.policyYAML = append([]byte(nil), b...) }
}

// WithPIIFieldsYAML pins the PII vault's field definitions:
//
//	pii-fields:
//	  email:     {hint: EMAIL}
//	  full_name: {hint: NAME}
//
// With definitions in place a profile write may only use the defined keys, its
// `hint` may be omitted, and a supplied hint must equal the defined one; the
// stored hint always comes from the definition. Without them (the default)
// fields stay free-form. Invalid definitions fail NewServer.
func WithPIIFieldsYAML(b []byte) Option {
	return func(c *config) { c.piiFieldsYAML = append([]byte(nil), b...) }
}

// WithInstanceResolver turns the server multi-instance: every request resolves
// its database, KMS, JWT keys, policy and PII field definitions from r, keyed
// by the instance id the embedder puts on the context with
// ports.ContextWithInstance (typically in its own middleware). Dilion provides
// no HTTP routing — choosing the instance for a request is the embedder's
// responsibility — but it does bind tokens to instances: each instance signs
// and verifies with the keys r returns for it, so those keys must differ per
// instance (a shared key is logged as a warning).
//
// Without this option the server is single-instance: WithPool/WithDSN,
// WithKMS, the JWT settings of the auth configuration, WithPolicyYAML and
// WithPIIFieldsYAML are wrapped in a static resolver under
// ports.DefaultInstanceID and nothing else changes.
//
// A resolver must return stable results per instance id: constructed
// per-instance objects are cached for the lifetime of the server.
func WithInstanceResolver(r ports.InstanceResolver) Option {
	return func(c *config) { c.resolver = r }
}

// WithProviderSource defines external OpenID Connect providers in code, per
// instance. A sign-in through GET /auth/v1/authorize?provider=<name> asks src
// first — before the built-in providers and before the instance's
// auth.custom_oauth_providers — and uses the provider it returns; (nil, nil)
// moves on to those. This is how a platform gives every tenant instance its own
// registration at a shared IdP without storing it in each tenant database:
//
//	dilion.WithProviderSource(func(ctx context.Context, instanceID, name string) (*dilion.OIDCProvider, error) {
//		if name != "platform" {
//			return nil, nil
//		}
//		t := tenants.Get(instanceID)
//		return &dilion.OIDCProvider{
//			Issuer:        "https://platform.example.com/auth/v1",
//			ClientID:      t.ClientID,
//			ClientSecret:  t.ClientSecret,
//			LinkBySubject: true, // the platform's user ids ARE this instance's
//		}, nil
//	})
//
// With RedirectURI left empty the callback is derived from the request — the
// host the authorize request arrived on — so one definition serves every
// tenant host. See ports.OIDCProvider for LinkBySubject, which hands the
// provider authority over every account in the instance.
func WithProviderSource(src ports.ProviderSource) Option {
	return func(c *config) { c.providers = src }
}

// WithAuthSettingsSource sets, per instance, the parts of the /auth/v1
// configuration that name the instance's application — its site URL and
// redirect allow list — from embedder code, the way WithProviderSource does
// for providers. A platform that serves one workspace per instance already
// knows each workspace's address; fn returns it, and (nil, nil) keeps the
// server-wide DILION_AUTH_SITE_URL and URI_ALLOW_LIST.
//
//	dilion.WithAuthSettingsSource(func(ctx context.Context, instanceID string) (*dilion.AuthSettings, error) {
//		ws, err := workspaces.Get(ctx, instanceID)
//		if err != nil {
//			return nil, err
//		}
//		return &dilion.AuthSettings{
//			SiteURL:      "https://" + ws.Domain,
//			URIAllowList: []string{"https://" + ws.Domain + "/**"},
//		}, nil
//	})
func WithAuthSettingsSource(fn ports.AuthSettingsSource) Option {
	return func(c *config) { c.authSettings = fn }
}

// WithOAuthClientResolver decides the clients of each instance's OAuth 2.1
// server in code. Every authorize, token and consent request asks fn first and
// falls back to auth.oauth_clients only when it returns (nil, nil). A returned
// client's redirect targets, secret and consent rule come from fn's answer,
// never from a stored row; a FirstParty client skips the consent screen:
//
//	dilion.WithOAuthClientResolver(func(ctx context.Context, instanceID, clientID string) (*dilion.OAuthClient, error) {
//		if clientID != workspaceClientID {
//			return nil, nil
//		}
//		return &dilion.OAuthClient{
//			ID:           workspaceClientID,
//			Name:         "Workspace",
//			VerifySecret: func(s string) bool { return subtle.ConstantTimeCompare([]byte(s), secret) == 1 },
//			AllowRedirectURI: func(uri string) bool {
//				ref, ok := workspaceCallbackRef(uri) // exact https://{ref}.api.example.com/auth/v1/callback
//				return ok && workspaces.Exists(ref)
//			},
//			FirstParty: true,
//		}, nil
//	})
//
// The client id must be a UUID. Such a client is kept out of the admin client
// API; see internal/auth/oauthserver_code_clients.go for how it satisfies the
// schema's foreign keys without becoming a stored client.
func WithOAuthClientResolver(fn ports.OAuthClientResolver) Option {
	return func(c *config) { c.oauthClients = fn }
}

// WithAuthConfig pins the /auth/v1 configuration (internal/auth.Config).
// Without it the configuration is read from the environment with
// auth.LoadConfig — DILION_AUTH_* first, the upstream GOTRUE_* names as a
// fallback — and an invalid value fails NewServer.
func WithAuthConfig(c *auth.Config) Option { return func(cfg *config) { cfg.authConfig = c } }

// WithAddr sets the listen address used by Start (default ":8787").
func WithAddr(addr string) Option { return func(c *config) { c.addr = addr } }

// WithClock replaces the time source used by the compliance engine (tests).
func WithClock(cl ports.Clock) Option { return func(c *config) { c.clock = cl } }

// WithLogger sets the base slog logger (default slog.Default()).
func WithLogger(l *slog.Logger) Option { return func(c *config) { c.log = l } }

// WithoutAdminMFA disables the MFA requirement on the management plane.
// Development only — it removes a control required by the security baselines in
// project.md §8; a warning is logged at startup whenever it is set.
func WithoutAdminMFA() Option { return func(c *config) { c.adminMFADisabled = true } }

// ---- server ----

// Server is a fully wired Dilion deployment. It serves one instance by default
// and any number of them when WithInstanceResolver is given.
type Server struct {
	cfg      config
	log      *slog.Logger
	pool     *pgxpool.Pool // default instance pool; nil when only a resolver was given
	ownsPool bool

	router    *chi.Mux
	authMount *auth.Mount
	hooks     *hooks.Registry
	mailer    ports.Mailer
	sms       ports.SMSSender
	kms       ports.KMS
	instances *instances.Registry
	authz     ports.Authorizer
	audit     ports.AuditSink
}

// NewServer wires the server. It connects the database (unless WithPool was
// given), fills in defaults for every injectable component, validates the
// policy data and builds the HTTP surface.
func NewServer(opts ...Option) (*Server, error) {
	cfg := config{addr: DefaultAddr}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	log := cfg.log
	if log == nil {
		log = slog.Default()
	}
	if cfg.clock == nil {
		cfg.clock = ports.SystemClock{}
	}

	s := &Server{cfg: cfg, log: log}

	// Database. With an instance resolver the per-instance pools come from it,
	// so a server-wide pool is optional.
	switch {
	case cfg.pool != nil:
		s.pool = cfg.pool
	case cfg.dsn != "":
		pool, err := store.Connect(context.Background(), cfg.dsn)
		if err != nil {
			return nil, err
		}
		s.pool, s.ownsPool = pool, true
	case cfg.resolver != nil:
		// Resolver-only deployment: nothing to connect here.
	default:
		return nil, errors.New("dilion: WithDSN or WithPool is required")
	}

	// Secrets. Ephemeral fallbacks keep the zero-config path working but are
	// never acceptable in production, so they are loud.
	masterKey := cfg.masterKey
	if len(masterKey) == 0 {
		k, err := randomKey()
		if err != nil {
			s.closeOwnedPool()
			return nil, err
		}
		masterKey = k
		log.Warn("dilion: no master key configured; generated an ephemeral one — PII encrypted now cannot be read after restart (set WithMasterKey / DILION_MASTER_KEY)")
	}
	if len(masterKey) != kmslocal.KeySize {
		s.closeOwnedPool()
		return nil, fmt.Errorf("dilion: master key must be %d bytes, got %d", kmslocal.KeySize, len(masterKey))
	}
	// /auth/v1 configuration. It is resolved here, before the token service, because
	// the signing keys live in it (auth.Config.JWT).
	if cfg.authConfig == nil {
		authCfg, err := auth.LoadConfig()
		if err != nil {
			s.closeOwnedPool()
			return nil, err
		}
		s.cfg.authConfig = authCfg
	} else if err := cfg.authConfig.Validate(); err != nil {
		s.closeOwnedPool()
		return nil, err
	}
	authCfg := s.cfg.authConfig

	// WithJWTSecret / DILION_JWT_SECRET is the server-level spelling of
	// auth.Config.JWT.Secret and wins over it; the ephemeral fallback only
	// applies when no HS256 secret AND no ES256 signing key exists at all.
	if len(cfg.jwtSecret) > 0 {
		authCfg.JWT.Secret = string(cfg.jwtSecret)
	}
	if _, hasSigningKey := authCfg.JWT.Keys.SigningKey(); !hasSigningKey && authCfg.JWT.Secret == "" {
		k, err := randomKey()
		if err != nil {
			s.closeOwnedPool()
			return nil, err
		}
		authCfg.JWT.Secret = string(k)
		log.Warn("dilion: no JWT signing key configured; generated an ephemeral HS256 secret — issued tokens stop verifying after restart (set DILION_AUTH_JWT_KEYS for ES256, or WithJWTSecret / DILION_JWT_SECRET)")
	}
	if cfg.adminMFADisabled {
		log.Warn("dilion: admin MFA requirement disabled (WithoutAdminMFA) — development only")
	}

	// Hooks.
	s.hooks = hooks.NewRegistry()
	for _, h := range cfg.hooks {
		s.hooks.Register(h.point, h.fn)
	}

	// Replaceable components.
	s.kms = cfg.kms
	if s.kms == nil && s.pool != nil {
		s.kms = kmslocal.New(s.pool, masterKey)
	}
	s.mailer = cfg.mailer
	if s.mailer == nil {
		s.mailer = devmail.NewMailer(log)
		log.Warn("dilion: no mailer configured; using the dev logger (no mail is delivered)")
	}
	// The SMS sender feeds the phone auth surface via auth.Config.SMS.Sender.
	// Precedence: an embedder-set Config.SMS.Sender wins; otherwise WithSMS;
	// otherwise the dev logger.
	s.sms = cfg.sms
	if s.sms == nil {
		s.sms = devmail.NewSMS(log)
	}
	if authCfg.SMS.Sender == nil {
		authCfg.SMS.Sender = s.sms
	}
	// The JWT key material is validated up front so a bad key set fails
	// NewServer rather than the first request. Per instance, ES256 with a
	// published JWKS when the key set carries a signing key, HS256 with the
	// secret otherwise (internal/auth.NewTokenService).
	if _, err := auth.NewTokenService(authCfg); err != nil {
		s.closeOwnedPool()
		return nil, err
	}

	// Tombstone identifiers must not be derivable without the deployment key,
	// and must not be the KEK itself (§2.10).
	tombstoneKey, err := hkdf.Key(sha256.New, masterKey, nil, "dilion:erasure-registry:tombstone:v1", 32)
	if err != nil {
		s.closeOwnedPool()
		return nil, fmt.Errorf("dilion: derive tombstone key: %w", err)
	}

	// Instance resolution. Without WithInstanceResolver the whole configuration
	// becomes one static instance under ports.DefaultInstanceID, which is
	// exactly the pre-multi-instance behaviour.
	resolver := cfg.resolver
	if resolver == nil {
		resolver = instances.NewStaticResolver(ports.DefaultInstanceID,
			s.pool, s.kms, ports.JWTKeys{
				Keys:   authCfg.JWT.Keys.JSON(),
				Secret: authCfg.JWT.Secret,
				Issuer: authCfg.JWT.Issuer,
			}, cfg.policyYAML, cfg.piiFieldsYAML)
	}
	registry, err := instances.New(instances.Config{
		Resolver:     resolver,
		AuthConfig:   authCfg,
		Hooks:        s.hooks,
		Clock:        cfg.clock,
		Connectors:   cfg.connectors,
		TombstoneKey: tombstoneKey,
		Logger:       log,
	})
	if err != nil {
		s.closeOwnedPool()
		return nil, err
	}
	s.instances = registry

	// Everything on the request path resolves its database from the context.
	s.authz = cfg.authz
	if s.authz == nil {
		s.authz = iam.NewAuthorizerFor(registry.Pool)
	}
	s.audit = cfg.auditSink
	if s.audit == nil {
		s.audit = audit.NewSinkFor(registry.Pool)
	}

	if cfg.resolver == nil {
		// Single instance: build its engine eagerly so invalid policy or PII
		// field data still fails NewServer (§2.8) instead of the first request.
		if _, err := registry.Engine(context.Background()); err != nil {
			s.closeOwnedPool()
			return nil, err
		}
	}

	s.router = s.buildRouter()
	return s, nil
}

// buildRouter mounts the compat surface (chi) and the Dilion APIs (huma).
func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "application/json")
		// Readiness is per instance: it probes the database of the instance
		// selected on the request (the only one, by default).
		pool, err := s.instances.Pool(ctx)
		if err == nil {
			err = pool.Ping(ctx)
		}
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Supabase Auth compatible surface: byte-level upstream contract, so it is
	// hand-written on chi rather than generated by huma.
	r.Route("/auth/v1", func(r chi.Router) {
		s.authMount = auth.Register(r, auth.Deps{
			// Per-request database: the instance selected with
			// ports.ContextWithInstance, or the only one.
			Pools: auth.PoolFunc(s.instances.Pool),
			// Per-request token service: the selected instance's own keys.
			TokensFor: s.instances.Tokens,
			Mailer:    s.mailer,
			Hooks:     s.hooks,
			// Site URL, allow list, rate limits, session policy, ... (§2.2).
			Config: s.cfg.authConfig,
			// Lets /auth/v1/admin/* accept a user token carrying `users.admin`
			// in addition to service_role (§2.11).
			Authz: s.authz,
			// Access records for /admin/users (§5, 제8조 접속기록).
			Audit: s.audit,
			// Code-defined identity federation, consulted before the
			// instance database (WithProviderSource, WithOAuthClientResolver).
			Providers:    s.cfg.providers,
			OAuthClients: s.cfg.oauthClients,
			// Per-instance site URL and redirect allow list.
			Settings: s.cfg.authSettings,
			// Admin user tokens need aal2 unless WithoutAdminMFA.
			AdminMFADisabled: s.cfg.adminMFADisabled,
		})
	})

	// Dilion's own APIs: huma generates the OpenAPI 3.1 document consumed by
	// the frontend codegen (docs/api-conventions.md).
	humaAPI := humachi.New(r, s.humaConfig())
	deps := api.Deps{
		Pools:    api.PoolFunc(s.instances.Pool),
		Verifier: s.instances,
		Authz:    s.authz,
		Audit:    s.audit,

		DeletionReauthWindow: s.cfg.authConfig.Security.DeletionReauthWindow,
		AdminMFADisabled:     s.cfg.adminMFADisabled,
	}
	api.RegisterPrivacyAPI(humaAPI, s.instances.PrivacyService, deps)
	api.RegisterIAMAPI(humaAPI, deps)

	return r
}

func (s *Server) humaConfig() huma.Config {
	cfg := huma.DefaultConfig("Dilion", Version)
	cfg.Info.Description = "Dilion privacy and management-plane API. " +
		"The Supabase Auth compatible surface under /auth/v1 is documented upstream."
	cfg.DocsPath = "/docs"
	cfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearer": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
			Description: "Management plane credential: a service_role JWT, a scoped API key (dk_...), " +
				"or a user access token (role=authenticated) whose RBAC roles grant the required permission.",
		},
	}
	return cfg
}

// Handler returns the HTTP handler, for embedding into an existing server.
func (s *Server) Handler() http.Handler { return s.router }

// WithOpaqueSessionKey lends the shared OPAQUE key to a short, synchronous
// operation after checking the bearer, live session, MFA and key lifetime.
// Select the trusted instance on ctx just as for HTTP requests. fn must not
// retain the slice, perform network I/O, or recursively update auth state:
// account/session locks remain held, and the slice is wiped on return.
func (s *Server) WithOpaqueSessionKey(ctx context.Context, bearer, keyID string, fn func([]byte) error) error {
	if s.authMount == nil {
		return fmt.Errorf("dilion: auth is not initialized")
	}
	return s.authMount.WithOpaqueSessionKey(ctx, bearer, keyID, fn)
}

// Pool exposes the database pool for embedders sharing it with their app. It is
// the pool given with WithPool/WithDSN and is nil in a deployment configured
// with WithInstanceResolver alone — use PoolFor there.
func (s *Server) Pool() *pgxpool.Pool { return s.pool }

// PoolFor returns the pool of the instance selected on ctx.
func (s *Server) PoolFor(ctx context.Context) (*pgxpool.Pool, error) {
	return s.instances.Pool(ctx)
}

// MigrateInstance applies pending schema migrations to ONE instance, which is
// what provisioning a newly added instance needs: Migrate would otherwise walk
// every instance the resolver lists just to reach the new one. Safe to run
// concurrently with other processes and with Migrate itself, because the run is
// serialised by a Postgres advisory lock on that database.
//
// The instance does not have to appear in List yet — only Pool has to resolve
// it — so a resolver may publish an instance to List only once its schema is in
// place. Background workers need no separate step either: Start re-scans the
// instance list periodically and picks the instance up on its own.
func (s *Server) MigrateInstance(ctx context.Context, id string) error {
	pool, err := s.instances.PoolFor(ctx, id)
	if err != nil {
		return fmt.Errorf("dilion: migrate instance %q: %w", id, err)
	}
	if err := store.Migrate(ports.ContextWithInstance(ctx, id), pool); err != nil {
		return fmt.Errorf("dilion: migrate instance %q: %w", id, err)
	}
	return nil
}

// Migrate applies pending schema migrations to every instance the resolver
// lists. Safe to run concurrently with other processes and on every boot: each
// database's run is serialised by a Postgres advisory lock. Use MigrateInstance
// to provision a single instance without walking the others.
func (s *Server) Migrate(ctx context.Context) error {
	ids, err := s.instances.List(ctx)
	if err != nil {
		return fmt.Errorf("dilion: list instances: %w", err)
	}
	for _, id := range ids {
		if err := s.MigrateInstance(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// Start serves HTTP and runs the compliance background workers until ctx is
// cancelled, then shuts down gracefully. It returns nil on a clean shutdown.
func (s *Server) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	srv := &http.Server{
		Addr:              s.cfg.addr,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		// No BaseContext from ctx on purpose: cancelling ctx must start a
		// graceful drain, not kill in-flight requests.
	}

	workersDone := make(chan struct{})
	go func() {
		defer close(workersDone)
		s.runWorkers(ctx)
	}()

	serveErr := make(chan error, 1)
	go func() {
		s.log.Info("dilion: listening", "addr", s.cfg.addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	var err error
	select {
	case err = <-serveErr:
		cancel() // listener died: stop the workers too
	case <-ctx.Done():
		s.log.Info("dilion: shutting down")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer shutdownCancel()
	if serr := srv.Shutdown(shutdownCtx); serr != nil && err == nil {
		err = serr
	}
	<-workersDone
	return err
}

// instanceRescanInterval is how often Start looks for instances that appeared
// after boot.
const instanceRescanInterval = 60 * time.Second

// runWorkers runs the compliance background workers of every instance until ctx
// is cancelled. The instance list is re-scanned periodically so instances added
// to a dynamic resolver after boot get their workers.
//
// Known limitation: an instance that disappears from List keeps its workers
// running (they are only stopped by ctx). Removing an instance from a live
// deployment therefore needs a restart; the disappearance is logged.
func (s *Server) runWorkers(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()

	started := map[string]bool{}
	gone := map[string]bool{}
	scan := func() {
		ids, err := s.instances.List(ctx)
		if err != nil {
			s.log.Error("dilion: listing instances for workers failed", "error", err)
			return
		}
		seen := make(map[string]bool, len(ids))
		for _, id := range ids {
			seen[id] = true
			if started[id] {
				continue
			}
			ictx := ports.ContextWithInstance(ctx, id)
			engine, err := s.instances.EngineFor(ictx, id)
			if err != nil {
				s.log.Error("dilion: starting workers failed", "instance", id, "error", err)
				continue
			}
			started[id] = true
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				s.log.Info("dilion: privacy workers started", "instance", id)
				engine.RunWorkers(ictx)
			}(id)

			// Expired auth rows (sessions, refresh tokens) are cleaned per
			// instance alongside the privacy engine.
			if s.authMount != nil {
				wg.Add(1)
				go func(id string) {
					defer wg.Done()
					s.log.Info("dilion: auth cleanup worker started", "instance", id)
					s.authMount.RunCleanup(ictx)
				}(id)
			}
		}
		for id := range started {
			if !seen[id] && !gone[id] {
				gone[id] = true
				s.log.Warn("dilion: instance disappeared from the resolver; "+
					"its workers keep running until shutdown", "instance", id)
			}
		}
	}

	scan()
	ticker := time.NewTicker(instanceRescanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}

// Close releases resources owned by the server (the pool, when NewServer
// created it). A pool passed with WithPool is left alone.
func (s *Server) Close() error {
	s.closeOwnedPool()
	return nil
}

func (s *Server) closeOwnedPool() {
	if s.ownsPool && s.pool != nil {
		s.pool.Close()
		s.pool = nil
		s.ownsPool = false
	}
}

func randomKey() ([]byte, error) {
	k := make([]byte, kmslocal.KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("dilion: rand: %w", err)
	}
	return k, nil
}
