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
)

// HookFunc receives a mutable payload. Validating hooks reject by returning an
// error; mutating hooks return a replacement payload (nil = unchanged).
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
type HookFunc func(ctx context.Context, payload map[string]any) (map[string]any, error)

// ---- Connectors (§3.1) ----

type ConnectorTask struct {
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

// ---- Clock (no naked time.Now in domain logic; injectable for tests) ----

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }
