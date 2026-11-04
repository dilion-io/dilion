package auth

// Wire types, constants and storage for the OAuth 2.1 authorization-server
// surface (Dilion acting as an identity provider).
//
// Everything here mirrors github.com/supabase/auth master:
//
//	internal/api/oauthserver/{server,handlers,authorize,service,client_auth,auth}.go
//	internal/models/{oauth_client,oauth_authorization,oauth_consent,oauth_scope}.go
//
// The tables live in migrations/0116_auth_oauth_server.sql. Note that upstream
// dropped the public `client_id` text column: the client identifier IS the uuid
// primary key of auth.oauth_clients.

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/ports"
)

// ---- scopes ----------------------------------------------------------------

// OAuth/OIDC scope constants (upstream models/oauth_scope.go).
const (
	ScopeOpenID        = "openid"
	ScopeEmail         = "email"
	ScopeProfile       = "profile"
	ScopePhone         = "phone"
	ScopeOfflineAccess = "offline_access"
)

// supportedOAuthScopes (wellknown.go) is upstream's models.SupportedOAuthScopes
// and is the allow-list every authorization request is validated against.

// parseScopeString splits a space-separated scope string, never returning nil
// (upstream models.ParseScopeString).
func parseScopeString(scopeString string) []string {
	out := []string{}
	for _, s := range strings.Fields(strings.TrimSpace(scopeString)) {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// hasScope reports whether scopes contains scope.
func hasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// hasAllScopes reports whether granted covers every scope in requested.
func hasAllScopes(granted, requested []string) bool {
	set := make(map[string]bool, len(granted))
	for _, s := range granted {
		set[s] = true
	}
	for _, s := range requested {
		if !set[s] {
			return false
		}
	}
	return true
}

func isSupportedScope(scope string) bool { return hasScope(supportedOAuthScopes, scope) }

// ---- client / authorization constants --------------------------------------

// Client types (auth.oauth_client_type).
const (
	OAuthClientTypePublic       = "public"
	OAuthClientTypeConfidential = "confidential"
)

// Token endpoint authentication methods (auth.oauth_clients.token_endpoint_auth_method).
const (
	TokenEndpointAuthMethodNone              = "none"
	TokenEndpointAuthMethodClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthMethodClientSecretPost  = "client_secret_post"
)

// Registration types (auth.oauth_registration_type).
const (
	OAuthRegistrationDynamic = "dynamic"
	OAuthRegistrationManual  = "manual"
)

// Authorization statuses (auth.oauth_authorization_status).
const (
	OAuthAuthorizationPending  = "pending"
	OAuthAuthorizationApproved = "approved"
	OAuthAuthorizationDenied   = "denied"
	OAuthAuthorizationExpired  = "expired"
)

// OAuth 2.1 grant types accepted by POST /oauth/token.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

// oauthResponseTypeCode is the only response_type OAuth 2.1 defines.
const oauthResponseTypeCode = "code"

// oauthAMRMethod is the `amr` method recorded on a session minted by the
// authorization-code grant (upstream models.OAuthProviderAuthorizationCode).
const oauthAMRMethod = "oauth_provider/authorization_code"

// ---- gotrue error codes (upstream apierrors/errorcode.go) ------------------

const (
	// ErrorCodeOAuthClientNotFound is an unknown or soft-deleted client.
	ErrorCodeOAuthClientNotFound = "oauth_client_not_found"
	// ErrorCodeOAuthAuthorizationNotFound is an unknown, expired or foreign
	// authorization request.
	ErrorCodeOAuthAuthorizationNotFound = "oauth_authorization_not_found"
	// ErrorCodeOAuthConsentNotFound is DELETE /user/oauth/grants for a client
	// the user never consented to.
	ErrorCodeOAuthConsentNotFound = "oauth_consent_not_found"
	// ErrorCodeOAuthDynamicClientRegistrationDisabled is POST
	// /oauth/clients/register while dynamic registration is off.
	ErrorCodeOAuthDynamicClientRegistrationDisabled = "oauth_dynamic_client_registration_disabled"
	// ErrorCodeFeatureDisabled is the 404 every route of a disabled feature
	// answers with (upstream requireOAuthServerEnabled).
	ErrorCodeFeatureDisabled = "feature_disabled"
)

// ---- RFC 6749 error bodies -------------------------------------------------

// OAuth2 error codes per RFC 6749 §4.1.2.1 / §5.2.
const (
	oAuth2ErrorInvalidRequest       = "invalid_request"
	oAuth2ErrorInvalidClient        = "invalid_client"
	oAuth2ErrorInvalidGrant         = "invalid_grant"
	oAuth2ErrorUnsupportedGrantType = "unsupported_grant_type"
	oAuth2ErrorServerError          = "server_error"
	oAuth2ErrorAccessDenied         = "access_denied"
)

// OAuthError is the RFC 6749 error body of POST /oauth/token. It is
// DELIBERATELY NOT the gotrue {code,error_code,msg} envelope: an OAuth client
// library parses `error` / `error_description`, and upstream answers this
// endpoint the same way (apierrors.OAuthError, always with HTTP 400).
type OAuthError struct {
	Err         string `json:"error"`
	Description string `json:"error_description,omitempty"`

	// internal is never serialized; it carries the cause for server-side logs.
	internal error
}

func (e *OAuthError) Error() string {
	if e.internal != nil {
		return e.Err + ": " + e.Description + ": " + e.internal.Error()
	}
	return e.Err + ": " + e.Description
}

func (e *OAuthError) Unwrap() error { return e.internal }

// withInternal attaches a cause that is logged but never returned to the client.
func (e *OAuthError) withInternal(err error) *OAuthError {
	e.internal = err
	return e
}

// oauthError builds an RFC 6749 error body. Upstream renders every OAuthError
// with HTTP 400, whatever the error code — reproduced by writeOAuthError.
func oauthError(code, format string, args ...any) *OAuthError {
	return &OAuthError{Err: code, Description: fmt.Sprintf(format, args...)}
}

// errCodeVerifierRequired is upstream's message for a PKCE-protected
// authorization redeemed without a code_verifier.
var errCodeVerifierRequired = errors.New("code_verifier is required when PKCE challenge is present")

// ---- random identifiers ----------------------------------------------------

// secureAlphanumeric reproduces upstream crypto.SecureAlphanumeric: lowercase
// base32 over cryptographically random bytes, truncated to length.
func secureAlphanumeric(length int) string {
	if length < 8 {
		length = 8
	}
	numBytes := (length*5 + 7) / 8
	b := make([]byte, numBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// crypto/rand never fails on a supported platform; a failure here must
		// not silently produce a guessable identifier.
		panic("auth: crypto/rand failed: " + err.Error())
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))[:length]
}

// ---- auth.oauth_clients ----------------------------------------------------

// oauthClient is one auth.oauth_clients row. redirect_uris and grant_types are
// COMMA-SEPARATED text columns upstream, not arrays.
type oauthClient struct {
	ID                      string
	ClientSecretHash        string
	RegistrationType        string
	ClientType              string
	TokenEndpointAuthMethod string
	RedirectURIs            string
	GrantTypes              string
	ClientName              *string
	ClientURI               *string
	LogoURI                 *string
	CreatedAt               time.Time
	UpdatedAt               time.Time
	DeletedAt               *time.Time

	// code is set for a client decided by embedder code
	// (oauthserver_code_clients.go); its rules replace the stored columns
	// wherever a client is judged. nil for a stored client.
	code *ports.OAuthClient
}

func (c *oauthClient) IsPublic() bool       { return c.ClientType == OAuthClientTypePublic }
func (c *oauthClient) IsConfidential() bool { return c.ClientType == OAuthClientTypeConfidential }

// GetRedirectURIs splits the stored comma-separated list.
func (c *oauthClient) GetRedirectURIs() []string {
	if c.RedirectURIs == "" {
		return []string{}
	}
	return strings.Split(c.RedirectURIs, ",")
}

// GetGrantTypes splits the stored comma-separated list.
func (c *oauthClient) GetGrantTypes() []string {
	if c.GrantTypes == "" {
		return []string{}
	}
	return strings.Split(c.GrantTypes, ",")
}

// IsGrantTypeAllowed reports whether the client may use grantType.
func (c *oauthClient) IsGrantTypeAllowed(grantType string) bool {
	for _, t := range c.GetGrantTypes() {
		if strings.TrimSpace(t) == grantType {
			return true
		}
	}
	return false
}

const oauthClientColumns = `id::text, coalesce(client_secret_hash, ''), registration_type::text,
	client_type::text, token_endpoint_auth_method, redirect_uris, grant_types,
	client_name, client_uri, logo_uri, created_at, updated_at, deleted_at`

func scanOAuthClient(row pgx.Row) (*oauthClient, error) {
	var (
		c                    oauthClient
		createdAt, updatedAt *time.Time
	)
	if err := row.Scan(&c.ID, &c.ClientSecretHash, &c.RegistrationType, &c.ClientType,
		&c.TokenEndpointAuthMethod, &c.RedirectURIs, &c.GrantTypes,
		&c.ClientName, &c.ClientURI, &c.LogoURI, &createdAt, &updatedAt, &c.DeletedAt); err != nil {
		return nil, err
	}
	if createdAt != nil {
		c.CreatedAt = createdAt.UTC()
	}
	if updatedAt != nil {
		c.UpdatedAt = updatedAt.UTC()
	}
	c.DeletedAt = utc(c.DeletedAt)
	return &c, nil
}

// findOAuthClientByID is upstream's models.FindOAuthServerClientByID: a
// soft-deleted client does not exist.
func findOAuthClientByID(ctx context.Context, q querier, id string) (*oauthClient, error) {
	return scanOAuthClient(q.QueryRow(ctx,
		`select `+oauthClientColumns+` from auth.oauth_clients
		 where id = $1::uuid and deleted_at is null`, id))
}

func listOAuthClients(ctx context.Context, q querier) ([]*oauthClient, error) {
	rows, err := q.Query(ctx,
		`select `+oauthClientColumns+` from auth.oauth_clients
		 where deleted_at is null order by created_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*oauthClient{}
	for rows.Next() {
		c, err := scanOAuthClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func insertOAuthClient(ctx context.Context, q querier, c *oauthClient, now time.Time) (*oauthClient, error) {
	return scanOAuthClient(q.QueryRow(ctx, `
		insert into auth.oauth_clients (
			id, client_secret_hash, registration_type, client_type,
			token_endpoint_auth_method, redirect_uris, grant_types,
			client_name, client_uri, logo_uri, created_at, updated_at
		) values (
			$1::uuid, nullif($2, ''), $3::auth.oauth_registration_type, $4::auth.oauth_client_type,
			$5, $6, $7, nullif($8, ''), nullif($9, ''), nullif($10, ''), $11, $11
		)
		returning `+oauthClientColumns,
		c.ID, c.ClientSecretHash, c.RegistrationType, c.ClientType,
		c.TokenEndpointAuthMethod, c.RedirectURIs, c.GrantTypes,
		deref(c.ClientName), deref(c.ClientURI), deref(c.LogoURI), now))
}

// updateOAuthClient writes the mutable columns of an existing client.
func updateOAuthClient(ctx context.Context, q querier, c *oauthClient, now time.Time) (*oauthClient, error) {
	return scanOAuthClient(q.QueryRow(ctx, `
		update auth.oauth_clients set
			client_secret_hash = nullif($2, ''),
			token_endpoint_auth_method = $3,
			redirect_uris = $4,
			grant_types = $5,
			client_name = nullif($6, ''),
			client_uri = nullif($7, ''),
			logo_uri = nullif($8, ''),
			updated_at = $9
		where id = $1::uuid and deleted_at is null
		returning `+oauthClientColumns,
		c.ID, c.ClientSecretHash, c.TokenEndpointAuthMethod, c.RedirectURIs, c.GrantTypes,
		deref(c.ClientName), deref(c.ClientURI), deref(c.LogoURI), now))
}

// softDeleteOAuthClient is upstream's deleteOAuthServerClient: deleted_at is
// set, the row survives so existing sessions keep their FK.
func softDeleteOAuthClient(ctx context.Context, q querier, id string, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.oauth_clients set deleted_at = $2, updated_at = $2
		 where id = $1::uuid and deleted_at is null`, id, now)
	return err
}

// ---- auth.oauth_authorizations ---------------------------------------------

// oauthAuthorization is one auth.oauth_authorizations row.
type oauthAuthorization struct {
	ID                  string
	AuthorizationID     string
	ClientID            string
	UserID              *string
	RedirectURI         string
	Scope               string
	State               *string
	Resource            *string
	CodeChallenge       *string
	CodeChallengeMethod *string
	Nonce               *string
	ResponseType        string
	Status              string
	AuthorizationCode   *string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	ApprovedAt          *time.Time
}

// IsExpired reports whether the 3-minute window has passed.
func (o *oauthAuthorization) IsExpired(now time.Time) bool { return now.After(o.ExpiresAt) }

// GetScopeList returns the requested scopes.
func (o *oauthAuthorization) GetScopeList() []string { return parseScopeString(o.Scope) }

// VerifyPKCE checks a code verifier against the stored challenge (upstream
// models.OAuthServerAuthorization.VerifyPKCE, which reuses the same
// security.VerifyPKCEChallenge as the email flows — pkce.go here).
func (o *oauthAuthorization) VerifyPKCE(codeVerifier string) error {
	if o.CodeChallenge == nil || *o.CodeChallenge == "" {
		return nil
	}
	if codeVerifier == "" {
		return errCodeVerifierRequired
	}
	method := ""
	if o.CodeChallengeMethod != nil {
		method = *o.CodeChallengeMethod
	}
	return verifyPKCEChallenge(*o.CodeChallenge, method, codeVerifier)
}

const oauthAuthorizationColumns = `id::text, authorization_id, client_id::text, user_id::text,
	redirect_uri, scope, state, resource, code_challenge, code_challenge_method::text,
	nonce, response_type::text, status::text, authorization_code,
	created_at, expires_at, approved_at`

func scanOAuthAuthorization(row pgx.Row) (*oauthAuthorization, error) {
	var (
		o                    oauthAuthorization
		createdAt, expiresAt *time.Time
	)
	if err := row.Scan(&o.ID, &o.AuthorizationID, &o.ClientID, &o.UserID,
		&o.RedirectURI, &o.Scope, &o.State, &o.Resource, &o.CodeChallenge, &o.CodeChallengeMethod,
		&o.Nonce, &o.ResponseType, &o.Status, &o.AuthorizationCode,
		&createdAt, &expiresAt, &o.ApprovedAt); err != nil {
		return nil, err
	}
	if createdAt != nil {
		o.CreatedAt = createdAt.UTC()
	}
	if expiresAt != nil {
		o.ExpiresAt = expiresAt.UTC()
	}
	o.ApprovedAt = utc(o.ApprovedAt)
	return &o, nil
}

// insertOAuthAuthorization creates a pending authorization request. created_at
// and expires_at are written explicitly (rather than left to the column
// defaults) so a stubbed clock — and a future TTL knob — control the window;
// the value equals the migration's own default of now() + 3 minutes.
func insertOAuthAuthorization(ctx context.Context, q querier, o *oauthAuthorization, now time.Time, ttl time.Duration) (*oauthAuthorization, error) {
	return scanOAuthAuthorization(q.QueryRow(ctx, `
		insert into auth.oauth_authorizations (
			id, authorization_id, client_id, redirect_uri, scope, state, resource,
			code_challenge, code_challenge_method, nonce, response_type, status,
			created_at, expires_at
		) values (
			$1::uuid, $2, $3::uuid, $4, $5, $6, $7,
			$8, $9::auth.code_challenge_method, $10, $11::auth.oauth_response_type,
			'pending'::auth.oauth_authorization_status, $12, $13
		)
		returning `+oauthAuthorizationColumns,
		o.ID, o.AuthorizationID, o.ClientID, o.RedirectURI, o.Scope, o.State, o.Resource,
		o.CodeChallenge, o.CodeChallengeMethod, o.Nonce, oauthResponseTypeCode,
		now, now.Add(ttl)))
}

// findOAuthAuthorizationForUpdate locks the row: two concurrent callers must not
// both claim the same pending authorization (upstream
// FindOAuthServerAuthorizationByIDForUpdate, FOR UPDATE SKIP LOCKED).
func findOAuthAuthorizationForUpdate(ctx context.Context, q querier, authorizationID string) (*oauthAuthorization, error) {
	return scanOAuthAuthorization(q.QueryRow(ctx,
		`select `+oauthAuthorizationColumns+` from auth.oauth_authorizations
		 where authorization_id = $1 limit 1 for update skip locked`, authorizationID))
}

// findOAuthAuthorizationByCode resolves an APPROVED authorization by its
// single-use authorization code.
func findOAuthAuthorizationByCode(ctx context.Context, q querier, code string) (*oauthAuthorization, error) {
	return scanOAuthAuthorization(q.QueryRow(ctx,
		`select `+oauthAuthorizationColumns+` from auth.oauth_authorizations
		 where authorization_code = $1 and status = 'approved'::auth.oauth_authorization_status`, code))
}

func setOAuthAuthorizationUser(ctx context.Context, q querier, id, userID string) error {
	_, err := q.Exec(ctx,
		`update auth.oauth_authorizations set user_id = $2::uuid where id = $1::uuid`, id, userID)
	return err
}

// approveOAuthAuthorization flips a pending row to approved and mints its
// single-use authorization code.
func approveOAuthAuthorization(ctx context.Context, q querier, o *oauthAuthorization, now time.Time) error {
	code := uuid.NewString()
	tag, err := q.Exec(ctx, `
		update auth.oauth_authorizations
		set status = 'approved'::auth.oauth_authorization_status, approved_at = $2, authorization_code = $3
		where id = $1::uuid and status = 'pending'::auth.oauth_authorization_status`, o.ID, now, code)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	o.Status = OAuthAuthorizationApproved
	o.ApprovedAt = &now
	o.AuthorizationCode = &code
	return nil
}

// setOAuthAuthorizationStatus moves a pending row to denied or expired.
func setOAuthAuthorizationStatus(ctx context.Context, q querier, id, status string) error {
	_, err := q.Exec(ctx, `
		update auth.oauth_authorizations set status = $2::auth.oauth_authorization_status
		where id = $1::uuid and status = 'pending'::auth.oauth_authorization_status`, id, status)
	return err
}

// deleteOAuthAuthorization consumes an authorization code: upstream destroys the
// row as the tokens are issued, so a code is strictly single use.
func deleteOAuthAuthorization(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `delete from auth.oauth_authorizations where id = $1::uuid`, id)
	return err
}

// ---- auth.oauth_consents ---------------------------------------------------

// oauthConsent is one auth.oauth_consents row.
type oauthConsent struct {
	ID        string
	UserID    string
	ClientID  string
	Scopes    string
	GrantedAt time.Time
	RevokedAt *time.Time
}

// GetScopeList returns the granted scopes.
func (c *oauthConsent) GetScopeList() []string { return parseScopeString(c.Scopes) }

// HasAllScopes reports whether the consent already covers requested.
func (c *oauthConsent) HasAllScopes(requested []string) bool {
	return hasAllScopes(c.GetScopeList(), requested)
}

const oauthConsentColumns = `id::text, user_id::text, client_id::text, scopes, granted_at, revoked_at`

func scanOAuthConsent(row pgx.Row) (*oauthConsent, error) {
	var (
		c         oauthConsent
		grantedAt *time.Time
	)
	if err := row.Scan(&c.ID, &c.UserID, &c.ClientID, &c.Scopes, &grantedAt, &c.RevokedAt); err != nil {
		return nil, err
	}
	if grantedAt != nil {
		c.GrantedAt = grantedAt.UTC()
	}
	c.RevokedAt = utc(c.RevokedAt)
	return &c, nil
}

// findActiveOAuthConsent returns the user's non-revoked consent for a client, or
// (nil, nil) when there is none — upstream treats "no consent" as a normal
// outcome, not an error.
func findActiveOAuthConsent(ctx context.Context, q querier, userID, clientID string) (*oauthConsent, error) {
	c, err := scanOAuthConsent(q.QueryRow(ctx,
		`select `+oauthConsentColumns+` from auth.oauth_consents
		 where user_id = $1::uuid and client_id = $2::uuid and revoked_at is null`, userID, clientID))
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return c, nil
}

// listActiveOAuthConsents returns every live grant of a user, newest first.
func listActiveOAuthConsents(ctx context.Context, q querier, userID string) ([]*oauthConsent, error) {
	rows, err := q.Query(ctx,
		`select `+oauthConsentColumns+` from auth.oauth_consents
		 where user_id = $1::uuid and revoked_at is null order by granted_at desc`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*oauthConsent{}
	for rows.Next() {
		c, err := scanOAuthConsent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// upsertOAuthConsent stores the granted scopes for (user, client). The table
// carries a UNIQUE (user_id, client_id) constraint, so a re-consent updates the
// existing row and un-revokes it — upstream's UpsertOAuthServerConsent.
func upsertOAuthConsent(ctx context.Context, q querier, userID, clientID string, scopes []string, now time.Time) error {
	_, err := q.Exec(ctx, `
		insert into auth.oauth_consents (id, user_id, client_id, scopes, granted_at)
		values ($1::uuid, $2::uuid, $3::uuid, $4, $5)
		on conflict on constraint oauth_consents_user_client_unique do update
		set scopes = excluded.scopes, granted_at = excluded.granted_at, revoked_at = null`,
		uuid.NewString(), userID, clientID, strings.Join(scopes, " "), now)
	return err
}

// revokeOAuthConsent marks a live consent revoked, reporting whether one existed.
func revokeOAuthConsent(ctx context.Context, q querier, userID, clientID string, now time.Time) (bool, error) {
	tag, err := q.Exec(ctx, `
		update auth.oauth_consents set revoked_at = $3
		where user_id = $1::uuid and client_id = $2::uuid and revoked_at is null`, userID, clientID, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ---- OAuth sessions --------------------------------------------------------

// markSessionOAuth stamps the OAuth client and granted scopes on a session, so
// every access token minted for it carries `client_id` and `scope`, and so
// revoking the grant can find the sessions to destroy.
func markSessionOAuth(ctx context.Context, q querier, sessionID, clientID, scopes string) error {
	_, err := q.Exec(ctx,
		`update auth.sessions set oauth_client_id = $2::uuid, scopes = $3 where id = $1::uuid`,
		sessionID, clientID, scopes)
	return err
}

// oauthSessionMeta is the OAuth half of a session row.
type oauthSessionMeta struct {
	ClientID *string
	Scopes   *string
}

func findOAuthSessionMeta(ctx context.Context, q querier, sessionID string) (oauthSessionMeta, error) {
	var m oauthSessionMeta
	err := q.QueryRow(ctx,
		`select oauth_client_id::text, scopes from auth.sessions where id = $1::uuid`, sessionID).
		Scan(&m.ClientID, &m.Scopes)
	return m, err
}

// revokeOAuthSessions destroys every session a user holds with one OAuth client.
// Deleting the session cascades to its refresh tokens, so the client's tokens
// stop working immediately (upstream models.RevokeOAuthSessions).
func revokeOAuthSessions(ctx context.Context, q querier, userID, clientID string) error {
	_, err := q.Exec(ctx,
		`delete from auth.sessions where user_id = $1::uuid and oauth_client_id = $2::uuid`,
		userID, clientID)
	return err
}

// ---- response bodies -------------------------------------------------------

// OAuthClientResponse is the admin/DCR client body (upstream
// oauthserver.OAuthServerClientResponse). Field order and json tags are copied.
type OAuthClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"` // only returned on registration
	ClientType   string `json:"client_type"`

	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`

	RegistrationType string    `json:"registration_type,omitempty"`
	CreatedAt        time.Time `json:"created_at,omitempty"`
	UpdatedAt        time.Time `json:"updated_at,omitempty"`
}

// OAuthClientListResponse is the GET /admin/oauth/clients body.
type OAuthClientListResponse struct {
	Clients []OAuthClientResponse `json:"clients,omitempty"`
}

// oauthClientToResponse renders a client row (upstream oauthServerClientToResponse).
func oauthClientToResponse(c *oauthClient) *OAuthClientResponse {
	return &OAuthClientResponse{
		ClientID:                c.ID,
		ClientType:              c.ClientType,
		RedirectURIs:            c.GetRedirectURIs(),
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		GrantTypes:              c.GetGrantTypes(),
		ResponseTypes:           []string{oauthResponseTypeCode},
		ClientName:              deref(c.ClientName),
		ClientURI:               deref(c.ClientURI),
		LogoURI:                 deref(c.LogoURI),
		RegistrationType:        c.RegistrationType,
		CreatedAt:               c.CreatedAt,
		UpdatedAt:               c.UpdatedAt,
	}
}

// ClientDetailsResponse is the client block of the consent screen payload.
type ClientDetailsResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	URI     string `json:"uri,omitempty"`
	LogoURI string `json:"logo_uri,omitempty"`
}

// UserDetailsResponse is the user block of the consent screen payload.
type UserDetailsResponse struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
}

// AuthorizationDetailsResponse is the GET /oauth/authorizations/{id} body.
type AuthorizationDetailsResponse struct {
	AuthorizationID string                `json:"authorization_id"`
	RedirectURI     string                `json:"redirect_uri,omitempty"`
	Client          ClientDetailsResponse `json:"client,omitempty"`
	User            UserDetailsResponse   `json:"user,omitempty"`
	Scope           string                `json:"scope,omitempty"`
}

// ConsentResponse is what the consent UI receives: the URL it must send the
// browser back to. Upstream returns it from both the consent POST and the
// auto-approve branch of the authorization GET.
type ConsentResponse struct {
	RedirectURL string `json:"redirect_url,omitempty"`
}

// UserOAuthGrantResponse is one entry of GET /user/oauth/grants.
type UserOAuthGrantResponse struct {
	Client    ClientDetailsResponse `json:"client"`
	Scopes    []string              `json:"scopes"`
	GrantedAt time.Time             `json:"granted_at"`
}

// clientDetails renders the client block shared by the consent and grant bodies.
func clientDetails(c *oauthClient) ClientDetailsResponse {
	return ClientDetailsResponse{
		ID:      c.ID,
		Name:    deref(c.ClientName),
		URI:     deref(c.ClientURI),
		LogoURI: deref(c.LogoURI),
	}
}

// writeOAuthError renders an RFC 6749 error body. Upstream answers every
// OAuthError with HTTP 400, whatever the OAuth error code is.
func (a *api) writeOAuthError(w http.ResponseWriter, r *http.Request, e *OAuthError) {
	a.log.WarnContext(r.Context(), "auth: oauth request failed",
		"method", r.Method, "path", r.URL.Path, "error", e.Err, "description", e.Description)
	if err := sendJSON(w, http.StatusBadRequest, e); err != nil {
		a.log.ErrorContext(r.Context(), "auth: failed to write oauth error response", "error", err.Error())
	}
}
