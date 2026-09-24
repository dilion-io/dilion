// Package ports defines the shared interfaces (contracts) between Dilion
// domains and embedder-injectable components. Do not add domain logic here.
package ports

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ---- KMS (PII Vault envelope encryption, §2.7) ----

type KeyScope string

const (
	KeyScopeDefault KeyScope = "DEFAULT" // general PII — shredded immediately on erasure
	KeyScopeConsent KeyScope = "CONSENT" // consent evidence — shredded at shred_after
)

type KMS interface {
	Encrypt(ctx context.Context, subjectID string, scope KeyScope, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, subjectID string, scope KeyScope, ciphertext []byte) ([]byte, error)
	// DestroyDEK irreversibly destroys the subject-scoped DEK (crypto-shred).
	// Decrypt must fail afterwards. Idempotent.
	DestroyDEK(ctx context.Context, subjectID string, scope KeyScope) error
}

// ---- Messaging ----

type Mailer interface {
	Send(ctx context.Context, to, subject, textBody, htmlBody string) error
}

type SMSSender interface {
	Send(ctx context.Context, to, body string) error
}

// ---- Tokens (implemented by internal/auth, consumed by internal/api) ----

type Claims struct {
	Subject   string // canonical user_id (UUID) or actor id
	Role      string // anon | authenticated | service_role
	Email     string
	Audience  string
	ExpiresAt time.Time
	Extra     map[string]any // custom claims injected via TokenClaims hook
}

type TokenSigner interface {
	Sign(ctx context.Context, c Claims) (string, error)
}

type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*Claims, error)
}

// ---- Authorization (management plane RBAC, §2.11) ----

type Actor struct {
	ID   string
	Type string // admin | api_key | service_role | user
}

// Authorizer decides only; audit logging and masked-by-default behavior are
// enforced by callers regardless of the implementation.
type Authorizer interface {
	Can(ctx context.Context, actor Actor, permission string, resource string) (bool, error)
}

// ---- Audit (§5) ----

type AuditEvent struct {
	ActorID     string
	ActorType   string // admin | api_key | service_role | user | system
	Action      string // e.g. USER_LIST_READ, PII_FULL_READ, ROLE_GRANTED
	Resource    string
	AccessLevel string // masked | full | n/a
	RequestID   string
	ResultCount int
	SubjectIDs  []string // written to dilion_audit.subjects (manifest)
	Reason      string   // operator-supplied justification (PII reveal 등); optional
	IP          string
	UserAgent   string
	OccurredAt  time.Time
}

type AuditSink interface {
	Append(ctx context.Context, e AuditEvent) error
}

// ---- Hooks (§2.4) ----

type HookPoint string

const (
	BeforeSignup      HookPoint = "before_signup"       // validating (may reject)
	AfterSignup       HookPoint = "after_signup"        // observing
	TokenClaims       HookPoint = "token_claims"        // mutating (rewrites the access token's claims)
	BeforeUserDelete  HookPoint = "before_user_delete"  // validating
	AfterUserDelete   HookPoint = "after_user_delete"   // observing
	BeforeErasureStep HookPoint = "before_erasure_step" // validating
	AfterErasure      HookPoint = "after_erasure"       // observing
	ConsentChanged    HookPoint = "consent_changed"     // observing
	ConsentReconfirm  HookPoint = "consent_reconfirm"   // observing (확인 고지 이벤트)
	PIIReveal         HookPoint = "pii_reveal"          // validating
	AuthHookSetting   HookPoint = "auth_hook_setting"   // validating + mutating (see below)
)

// HookFunc receives a mutable payload. Validating hooks reject by returning an
// error; mutating hooks return a replacement payload (nil = unchanged).
//
// Hooks are registered once and run for every instance: ctx carries the
// instance the event happened in, as ports.InstanceFromContext(ctx).
//
// TokenClaims is the one point with a fixed payload shape, shared with the
// external custom_access_token hook so that both see the same thing:
//
//	{
//	  "user_id":               "<uuid>",
//	  "claims":                {...},   // the FULL claim view about to be signed
//	  "authentication_method": "password" | "otp" | "oauth" | ...
//	}
//
// The hook returns that envelope and its `claims` member becomes the token's
// claims; a payload with no `claims` object fails token issuance rather than
// silently dropping every custom claim. The reserved claims (sub, aud, exp,
// iat, iss, role, email) are visible but not writable: signing re-asserts them,
// so a hook cannot forge identity, role, audience or lifetime.
//
// AuthHookSetting is the operator's policy for the auth hooks an instance admin
// configures for their own instance (/auth/v1/admin/hooks). It runs when a
// setting is saved and again before every call made with it, so a policy
// change applies to settings already stored. The payload is
//
//	{
//	  "hook":            "send_email" | "before_user_created" | ...,
//	  "uri":             "https://..." | "pg-functions://...",
//	  "ssrf_protection": true
//	}
//
// Returning an error rejects the setting (a 400 on save, a failed hook call
// afterwards). ssrf_protection arrives true for an http(s) URI and false for a
// pg-functions one; while it is true the call refuses to connect to loopback,
// private, link-local and other non-public addresses. A hook returns the
// payload with "ssrf_protection": false to exempt a URI it trusts, such as a
// receiver inside the operator's own network. The server-wide hooks set by
// configuration are the operator's own and never pass through this point.
type HookFunc func(ctx context.Context, payload map[string]any) (map[string]any, error)

// ---- Connectors (§3.1) ----

type ConnectorTask struct {
	// InstanceID is the instance the task belongs to. Connectors are
	// registered once and shared by every instance's compliance engine, so a
	// connector serving several instances tells them apart by this.
	InstanceID    string
	TaskID        string
	RequestID     string
	UserID        string
	DestinationID string
	Action        string // DELETE | ANONYMIZE | EXPORT
	Config        map[string]any
}

type ConnectorReceipt struct {
	TaskID      string
	Status      string // completed | failed
	ResultCode  string
	Detail      string
	CompletedAt time.Time
}

type Connector interface {
	Execute(ctx context.Context, t ConnectorTask) (ConnectorReceipt, error)
}

// ---- Instances (multi-DB customization) ----

// DefaultInstanceID is the sole instance of the built-in daemon and examples.
// Multi-instance is an embedder customization, not a default-daemon feature.
const DefaultInstanceID = "default"

// InstanceResolver provides per-instance resources dynamically. Each instance
// is a fully isolated database (auth.* + dilion_*). The built-in daemon uses a
// single static instance; embedders
// inject their own resolver via dilion.WithInstanceResolver and select the
// instance per request with ContextWithInstance. There is NO built-in HTTP
// routing — how an instance is chosen for a request is the embedder's
// responsibility. Tokens, however, ARE bound to their instance: every instance
// signs and verifies with its own JWT key material (see JWT), so an access
// token minted for one instance is rejected by every other one, including
// third-party verifiers such as PostgREST that trust that instance's JWKS.
//
// Results for the same instanceID should be stable; Dilion may cache
// per-instance resources (engines, workers, token services) keyed by instanceID.
type InstanceResolver interface {
	Pool(ctx context.Context, instanceID string) (*pgxpool.Pool, error)
	KMS(ctx context.Context, instanceID string) (KMS, error)
	// PolicyYAML returns the instance's compliance policy document
	// (project.md §2.8). nil = built-in defaults only.
	PolicyYAML(ctx context.Context, instanceID string) ([]byte, error)
	// PIIFields returns the instance's fixed PII field definitions (YAML:
	// pii-fields: {<key>: {hint: NAME|EMAIL|PHONE|ADDRESS|GENERIC}}).
	// Writes of undefined keys are rejected and the stored hint always comes
	// from the definition. nil = free-form fields (single-instance default).
	PIIFields(ctx context.Context, instanceID string) ([]byte, error)
	// JWT returns the instance's access-token key material. Every instance
	// MUST have its own: sharing a secret or key set between instances lets a
	// token issued by one instance pass verification at the other.
	JWT(ctx context.Context, instanceID string) (JWTKeys, error)
	// List enumerates known instance ids (background worker scheduling).
	List(ctx context.Context) ([]string, error)
}

// JWTKeys is one instance's access-token key material, in the same shape as
// the /auth/v1 environment: Keys is the GOTRUE_JWT_KEYS JSON array of private
// JWKs (ES256 with a published JWKS), Secret the GOTRUE_JWT_SECRET HS256 secret
// (the developer path, and the verify-only legacy key during a rotation), and
// Issuer the `iss` claim minted into and required of this instance's tokens.
// At least one of Keys/Secret must be set.
type JWTKeys struct {
	Keys   json.RawMessage
	Secret string
	Issuer string
}

type instanceCtxKey struct{}

// ContextWithInstance selects the instance for downstream Dilion calls.
func ContextWithInstance(ctx context.Context, instanceID string) context.Context {
	return context.WithValue(ctx, instanceCtxKey{}, instanceID)
}

// InstanceFromContext returns the selected instance, or DefaultInstanceID.
func InstanceFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(instanceCtxKey{}).(string); ok && v != "" {
		return v
	}
	return DefaultInstanceID
}

// ---- Identity federation defined in code ----
//
// Two directions, both resolved per request and per instance, both consulted
// BEFORE anything stored in the instance database:
//
//   - As a relying party, an instance signs users in through external OpenID
//     Connect providers. ProviderSource defines those providers in code.
//   - As an identity provider (the OAuth 2.1 server), an instance issues codes
//     to OAuth clients. OAuthClientResolver decides those clients in code.
//
// Both exist for platforms that already know, in their own data, which
// providers and clients each tenant has, and should not have to copy that into
// every instance database and keep it in sync.

// OIDCProvider is an external OpenID Connect provider an instance signs users
// in with, defined by embedder code rather than stored in
// auth.custom_oauth_providers. It is reached at
// GET /auth/v1/authorize?provider=<name> exactly like a stored one.
//
// Toward the provider the instance behaves as an OAuth 2.1 client: every
// authorization request carries a PKCE S256 challenge, and the token request
// authenticates by HTTP Basic, retrying once with the credentials in the body
// if the provider refuses Basic. That is what Dilion's own OAuth server, as the
// provider, requires.
type OIDCProvider struct {
	// Issuer is the provider's issuer identifier. Its endpoints and signing
	// keys come from Issuer + "/.well-known/openid-configuration", and every
	// id_token must carry exactly this `iss`. Required.
	Issuer string
	// DiscoveryURL overrides where the metadata is fetched from, for a
	// provider that does not publish it under the issuer. Optional.
	DiscoveryURL string
	// ClientID and ClientSecret are this instance's registration at the
	// provider. The id_token audience must include ClientID. Required.
	ClientID     string
	ClientSecret string
	// RedirectURI is the callback registered at the provider. Empty derives it
	// from the request: the scheme and Host the authorize request arrived on,
	// with the path's last segment replaced by "callback" — e.g.
	// https://{ref}.api.example.com/auth/v1/callback. Set it when a proxy
	// rewrites the host or path on the way in.
	RedirectURI string
	// Scopes requested at the provider. Empty means openid, email and profile.
	Scopes []string
	// LinkBySubject makes the provider's `sub` claim the local user id. A
	// sign-in then resolves to the user whose id equals `sub` — linking the
	// identity to that user if it exists, creating the user under that id if
	// it does not — and never matches on email. That is only correct when the
	// provider and this instance share one user id space, as a platform's own
	// SSO does; `sub` must then be a UUID, and a sign-in whose `sub` is not
	// one is refused. It also means the provider can sign in as ANY local
	// user, which is why it is only available to providers defined in code.
	LinkBySubject bool
}

// ProviderSource returns the code-defined provider called name for an
// instance, or (nil, nil) when it defines none by that name — the lookup then
// continues with the built-in providers and auth.custom_oauth_providers. An
// error fails the request. It runs on every authorize and callback request, so
// it should answer from memory or a cache.
type ProviderSource func(ctx context.Context, instanceID, name string) (*OIDCProvider, error)

// OAuthClient is an OAuth client of an instance's OAuth 2.1 server, decided by
// embedder code rather than registered in auth.oauth_clients.
type OAuthClient struct {
	// ID is the client_id, and must be a UUID: client identifiers in this
	// server ARE uuids (upstream parity), and authorizations, consents and
	// sessions reference the client by it.
	ID string
	// Name, URI and LogoURI describe the client on the consent screen.
	Name    string
	URI     string
	LogoURI string
	// Public clients hold no secret and authenticate the code exchange with
	// PKCE alone (token_endpoint_auth_method "none"). Confidential clients
	// present a secret, by HTTP Basic or in the form body.
	Public bool
	// VerifySecret checks a confidential client's secret and must compare in
	// constant time (crypto/subtle). Required unless Public; a confidential
	// client without it can never authenticate.
	VerifySecret func(secret string) bool
	// RedirectURIs are the redirect targets this client may receive codes at,
	// matched exactly — no prefix or wildcard matching, per OAuth 2.1.
	RedirectURIs []string
	// AllowRedirectURI, when set, decides redirect targets instead of
	// RedirectURIs, for a client whose targets are not a fixed list (one per
	// tenant, say). It is the only thing standing between an authorization
	// code and an attacker's host: it must accept exactly the URIs the client
	// owns, compared as whole strings, never by prefix or pattern.
	AllowRedirectURI func(uri string) bool
	// FirstParty skips the consent step. The signed-in user is still required
	// — authorization is granted as soon as the consent page learns who they
	// are — but they are not asked to approve, and no consent is recorded.
	// Only for the operator's own applications.
	FirstParty bool
}

// OAuthClientResolver returns the code-defined client with clientID for an
// instance, or (nil, nil) when it defines none — the client is then looked up
// in auth.oauth_clients. An error fails the request. It runs on every
// authorize, token and consent request.
type OAuthClientResolver func(ctx context.Context, instanceID, clientID string) (*OAuthClient, error)

// ---- Clock (no naked time.Now in domain logic; injectable for tests) ----

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }
