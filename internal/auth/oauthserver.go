package auth

// The OAuth 2.1 / OIDC authorization-server surface: Dilion acting as an
// identity provider for third-party applications.
//
// Mirrors github.com/supabase/auth master, internal/api/oauthserver/* plus the
// routes api.go mounts for it:
//
//	POST   /oauth/clients/register                        dynamic client registration (public, rate limited)
//	POST   /oauth/token                                   authorization_code / refresh_token (client authenticated)
//	GET    /oauth/userinfo                                OIDC UserInfo (end-user Bearer)
//	GET    /oauth/authorize                               start an authorization request
//	GET    /oauth/authorizations/{authorization_id}       consent-screen payload (end-user Bearer)
//	POST   /oauth/authorizations/{authorization_id}/consent   approve / deny (end-user Bearer)
//	GET    /user/oauth/grants                             list the user's live grants
//	DELETE /user/oauth/grants?client_id=…                 revoke one grant
//	GET    /admin/oauth/clients                           list clients            (service_role)
//	POST   /admin/oauth/clients                           manual registration     (service_role)
//	GET    /admin/oauth/clients/{client_id}               read one client         (service_role)
//	PUT    /admin/oauth/clients/{client_id}               update a client         (service_role)
//	DELETE /admin/oauth/clients/{client_id}               soft-delete a client    (service_role)
//	POST   /admin/oauth/clients/{client_id}/regenerate_secret                     (service_role)
//
// Everything is gated by Config.OAuthServer.Enabled: while it is off every route
// answers upstream's 404 feature_disabled.
//
// # The browser flow
//
//	1. the app sends the browser to GET /oauth/authorize?client_id=…&redirect_uri=…
//	   &response_type=code&scope=…&code_challenge=…&code_challenge_method=S256
//	2. Dilion stores a PENDING auth.oauth_authorizations row (3 minutes) and
//	   redirects the browser to SiteURL + OAuthServerAuthorizationPath
//	   ?authorization_id=…  — the hosted consent page, which is a normal Dilion
//	   front-end route and therefore handles "the user is not signed in yet" with
//	   its own login flow.
//	3. that page, holding the end user's access token, reads
//	   GET /oauth/authorizations/{authorization_id} (which claims the pending row
//	   for the signed-in user, and auto-approves when a stored consent already
//	   covers the requested scopes) and POSTs the decision to
//	   .../consent {"action":"approve"|"deny"}
//	4. both return {"redirect_url": …} — the URL the page sends the browser to,
//	   carrying ?code=…&state=… (approve) or ?error=access_denied&… (deny)
//	5. the app redeems the code at POST /oauth/token
//
// # Configuration
//
// Upstream has conf.OAuthServerConfiguration{Enabled, AllowDynamicRegistration,
// AuthorizationPath, AuthorizationTTL, DefaultScope}; Dilion's Config
// (conf.go, shared and owned elsewhere) carries only Enabled today, so the
// remaining knobs are the constants below. They are documented as DEVIATIONS in
// the wave report and become Config fields when conf.go grows them.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---- configuration constants (see the Configuration note above) ------------

const (
	// OAuthServerAuthorizationTTL is how long a pending authorization request
	// stays redeemable — upstream's GOTRUE_OAUTH_SERVER_AUTHORIZATION_TTL.
	//
	// DEVIATION: 3 minutes, not upstream's 10m default. It is the default of
	// auth.oauth_authorizations.expires_at in migration 0116, and a consent
	// screen that takes longer than three minutes is a re-authorization, not a
	// slow click.
	OAuthServerAuthorizationTTL = 3 * time.Minute

	// OAuthServerDefaultScope is the scope assumed when the authorization
	// request omits one (upstream GOTRUE_OAUTH_SERVER_DEFAULT_SCOPE, "email").
	OAuthServerDefaultScope = ScopeEmail

	// OAuthServerAuthorizationPath is the SiteURL-relative path of the hosted
	// consent page /oauth/authorize redirects the browser to
	// (upstream GOTRUE_OAUTH_SERVER_AUTHORIZATION_PATH).
	//
	// DEVIATION: upstream has NO default — an unconfigured deployment redirects
	// the caller back with error=server_error. Dilion defaults to
	// "/oauth/consent" so the flow is usable out of the box.
	OAuthServerAuthorizationPath = "/oauth/consent"

	// OAuthServerAllowDynamicRegistration gates POST /oauth/clients/register
	// (upstream GOTRUE_OAUTH_SERVER_ALLOW_DYNAMIC_REGISTRATION, default false).
	//
	// DEVIATION: Dilion allows DCR whenever the OAuth server is enabled,
	// because Config has no separate knob to turn it on with. The endpoint is
	// rate limited per IP (LimiterOAuthClientRegister). Deployments that must
	// not accept anonymous client registrations should keep the OAuth server
	// off until conf.go grows the flag.
	OAuthServerAllowDynamicRegistration = true

	// LimiterOAuthClientRegister guards POST /oauth/clients/register
	// (upstream GOTRUE_RATE_LIMIT_OAUTH_DYNAMIC_CLIENT_REGISTER).
	LimiterOAuthClientRegister = "oauth_client_register"

	// oauthClientRegisterRate is that limiter's rate: upstream's default of 10
	// registrations per 5 minutes per IP. It is a constant for the same reason
	// as the knobs above — Config.RateLimits has no field for it yet.
	oauthClientRegisterRate = 10

	// maxRedirectURIs is upstream's cap on redirect_uris per client.
	maxRedirectURIs = 10
)

func init() {
	registerFeature("oauthserver", func(a *api, r chi.Router) {
		// The DCR limiter has no Config field yet, so it is registered here
		// rather than in buildLimiters. Register runs single-threaded before
		// the first request, so writing the map is safe.
		if _, ok := a.limiters[LimiterOAuthClientRegister]; !ok {
			a.limiters[LimiterOAuthClientRegister] = newRateLimiter(oauthClientRegisterRate, rateWindow, rateBurst)
		}

		// Admin client management.
		r.Group(func(r chi.Router) {
			r.Use(a.requireOAuthServerEnabled, a.requireAdmin, a.requireAdminPermission(PermAuthSettingsManage))
			r.Get("/admin/oauth/clients", a.handle(a.adminListOAuthClients))
			r.Post("/admin/oauth/clients", a.handle(a.adminRegisterOAuthClient))
			r.Get("/admin/oauth/clients/{client_id}", a.handle(a.adminGetOAuthClient))
			r.Put("/admin/oauth/clients/{client_id}", a.handle(a.adminUpdateOAuthClient))
			r.Delete("/admin/oauth/clients/{client_id}", a.handle(a.adminDeleteOAuthClient))
			r.Post("/admin/oauth/clients/{client_id}/regenerate_secret", a.handle(a.adminRegenerateOAuthClientSecret))
		})

		// Public / client-authenticated endpoints.
		r.Group(func(r chi.Router) {
			r.Use(a.requireOAuthServerEnabled)

			r.With(a.limit(LimiterOAuthClientRegister)).
				Post("/oauth/clients/register", a.handle(a.oauthDynamicRegisterClient))

			r.With(a.requireOAuthClientAuth).Post("/oauth/token", a.handleOAuth(a.oauthToken))

			// RFC 6749 §3.1 requires GET on the authorization endpoint and
			// permits POST; upstream mounts GET only.
			r.Get("/oauth/authorize", a.handle(a.oauthAuthorize))
			r.Post("/oauth/authorize", a.handle(a.oauthAuthorize))

			r.With(a.requireAuthenticationForClients).Get("/oauth/userinfo", a.handle(a.oauthUserInfo))
			r.Group(func(r chi.Router) {
				r.Use(a.requireAuthentication)
				r.Get("/oauth/authorizations/{authorization_id}", a.handle(a.oauthGetAuthorization))
				r.Post("/oauth/authorizations/{authorization_id}/consent", a.handle(a.oauthConsent))
				r.Get("/user/oauth/grants", a.handle(a.userListOAuthGrants))
				r.Delete("/user/oauth/grants", a.handle(a.userRevokeOAuthGrant))
			})
		})
	})
}

// ---- feature gate ----------------------------------------------------------

// requireOAuthServerEnabled answers 404 feature_disabled while
// Config.OAuthServer.Enabled is false (upstream requireOAuthServerEnabled).
func (a *api) requireOAuthServerEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.cfg.OAuthServer.Enabled {
			a.writeError(r, w, notFoundError(ErrorCodeFeatureDisabled, "OAuth server is disabled"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- request context -------------------------------------------------------

type oauthCtxKey int

const ctxKeyOAuthClient oauthCtxKey = iota

func withOAuthClient(ctx context.Context, c *oauthClient) context.Context {
	return context.WithValue(ctx, ctxKeyOAuthClient, c)
}

func oauthClientFrom(ctx context.Context) *oauthClient {
	c, _ := ctx.Value(ctxKeyOAuthClient).(*oauthClient)
	return c
}

// handleOAuth is `handle` for the endpoints that answer RFC 6749 error bodies
// instead of the gotrue envelope: an *OAuthError is rendered as
// {"error":…,"error_description":…} with HTTP 400, everything else falls back to
// the normal gotrue rendering.
func (a *api) handleOAuth(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			var oe *OAuthError
			if errors.As(err, &oe) {
				a.writeOAuthError(w, r, oe)
				return
			}
			a.writeError(r, w, err)
		}
	}
}

// ---- client authentication -------------------------------------------------

// clientCredentials are the credentials presented at POST /oauth/token, plus the
// method they arrived by (upstream oauthserver.ClientCredentials).
type clientCredentials struct {
	ClientID     string
	ClientSecret string
	AuthMethod   string
}

// extractClientCredentials reads client credentials from a token request:
// HTTP Basic first (client_secret_basic), then the JSON or form body
// (client_secret_post when a secret is present, none when it is not).
//
// The body is buffered and restored, so the handler can still decode it.
func extractClientCredentials(r *http.Request) (*clientCredentials, error) {
	creds := &clientCredentials{}

	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
		if err != nil {
			return nil, errors.New("invalid basic auth encoding")
		}
		id, secret, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return nil, errors.New("invalid basic auth format")
		}
		creds.ClientID = id
		creds.ClientSecret = secret
		creds.AuthMethod = TokenEndpointAuthMethodClientSecretBasic
		return creds, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		return nil, errors.New("failed to read request body")
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var jsonData struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		if err := json.Unmarshal(body, &jsonData); err != nil {
			return nil, errors.New("failed to parse JSON body")
		}
		creds.ClientID = jsonData.ClientID
		creds.ClientSecret = jsonData.ClientSecret
	} else {
		if err := r.ParseForm(); err != nil {
			return nil, errors.New("failed to parse form")
		}
		creds.ClientID = r.FormValue("client_id")
		creds.ClientSecret = r.FormValue("client_secret")
		// ParseForm consumed the body; hand the handler a fresh reader.
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}

	if creds.ClientID == "" {
		return nil, errors.New("client_id is required")
	}
	if creds.ClientSecret != "" {
		creds.AuthMethod = TokenEndpointAuthMethodClientSecretPost
	} else {
		creds.AuthMethod = TokenEndpointAuthMethodNone
	}
	return creds, nil
}

// requireOAuthClientAuth authenticates the client of POST /oauth/token and puts
// it on the context.
//
// Failures answer the gotrue envelope with 400 invalid_credentials, exactly as
// upstream does — only the GRANT errors below use the RFC 6749 body.
func (a *api) requireOAuthClientAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		creds, err := extractClientCredentials(r)
		if err != nil {
			a.writeError(r, w, badRequestError(ErrorCodeInvalidCredentials, "Invalid client credentials: %s", err.Error()))
			return
		}
		if _, err := uuid.Parse(creds.ClientID); err != nil {
			a.writeError(r, w, badRequestError(ErrorCodeInvalidCredentials, "Invalid client_id format"))
			return
		}

		pool, perr := a.db(r.Context())
		if perr != nil {
			a.writeError(r, w, perr)
			return
		}
		client, derr := a.oauthClientByID(r.Context(), pool, creds.ClientID)
		if derr != nil {
			if isNoRows(derr) {
				a.writeError(r, w, badRequestError(ErrorCodeInvalidCredentials, "Invalid client credentials"))
				return
			}
			a.writeError(r, w, internalServerError("Error validating client credentials").withInternal(derr))
			return
		}

		if err := validateClientAuthMethod(client, creds.AuthMethod); err != nil {
			a.writeError(r, w, badRequestError(ErrorCodeInvalidCredentials, "%s", err.Error()))
			return
		}
		if err := validateClientAuthentication(client, creds.ClientSecret); err != nil {
			a.writeError(r, w, badRequestError(ErrorCodeInvalidCredentials, "%s", err.Error()))
			return
		}

		next.ServeHTTP(w, r.WithContext(withOAuthClient(r.Context(), client)))
	})
}

// ---- client type / auth method rules (upstream oauthserver/auth.go) --------

// inferClientTypeFromAuthMethod maps an auth method to the client type it
// implies.
func inferClientTypeFromAuthMethod(authMethod string) string {
	if authMethod == TokenEndpointAuthMethodNone {
		return OAuthClientTypePublic
	}
	return OAuthClientTypeConfidential
}

// validAuthMethodsForClientType lists the methods a client type may register.
func validAuthMethodsForClientType(clientType string) []string {
	switch clientType {
	case OAuthClientTypePublic:
		return []string{TokenEndpointAuthMethodNone}
	case OAuthClientTypeConfidential:
		return []string{TokenEndpointAuthMethodClientSecretBasic, TokenEndpointAuthMethodClientSecretPost}
	}
	return []string{}
}

// allValidAuthMethods is upstream's GetAllValidAuthMethods.
func allValidAuthMethods() []string {
	return []string{
		TokenEndpointAuthMethodNone,
		TokenEndpointAuthMethodClientSecretBasic,
		TokenEndpointAuthMethodClientSecretPost,
	}
}

func isValidAuthMethodForClientType(clientType, authMethod string) bool {
	for _, m := range validAuthMethodsForClientType(clientType) {
		if m == authMethod {
			return true
		}
	}
	return false
}

// validateClientTypeConsistency rejects `public` + `client_secret_basic` and
// friends. Either side being empty skips the check (upstream behaviour).
func validateClientTypeConsistency(clientType, authMethod string) error {
	if clientType == "" || authMethod == "" {
		return nil
	}
	if expected := inferClientTypeFromAuthMethod(authMethod); clientType != expected {
		return fmt.Errorf("client_type '%s' is inconsistent with token_endpoint_auth_method '%s' (expected client_type '%s')",
			clientType, authMethod, expected)
	}
	return nil
}

// determineClientType applies upstream's priority: explicit client_type, then
// the type implied by token_endpoint_auth_method, then confidential.
func determineClientType(explicitClientType, authMethod string) string {
	if explicitClientType != "" {
		return explicitClientType
	}
	if authMethod != "" {
		return inferClientTypeFromAuthMethod(authMethod)
	}
	return OAuthClientTypeConfidential
}

// validateClientAuthMethod rejects a credential presented by a method the client
// did not register for — a confidential client registered for
// client_secret_basic may not authenticate with a body parameter.
func validateClientAuthMethod(client *oauthClient, usedMethod string) error {
	if client.code != nil {
		if !client.codeAuthMethodAllowed(usedMethod) {
			return fmt.Errorf("invalid authentication method: '%s' is not allowed for this client", usedMethod)
		}
		return nil
	}
	if usedMethod != client.TokenEndpointAuthMethod {
		return fmt.Errorf("invalid authentication method: client is registered for '%s' but '%s' was used",
			client.TokenEndpointAuthMethod, usedMethod)
	}
	return nil
}

// validateClientAuthentication verifies the presented secret against the client.
// A public client must present NONE; a confidential client must present a valid
// one.
func validateClientAuthentication(client *oauthClient, providedSecret string) error {
	if client.IsPublic() {
		if providedSecret != "" {
			return errors.New("public clients must not provide client_secret")
		}
		return nil
	}
	if providedSecret == "" {
		return errors.New("confidential clients must provide client_secret")
	}
	if client.code != nil {
		if !client.codeSecretValid(providedSecret) {
			return errors.New("invalid client credentials")
		}
		return nil
	}
	if !validateClientSecret(providedSecret, client.ClientSecretHash) {
		return errors.New("invalid client credentials")
	}
	return nil
}

// ---- client secrets --------------------------------------------------------

// generateClientSecret mints a 256-bit client secret. It is shown to the caller
// ONCE, at registration or regeneration, and only its hash is stored.
func generateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashClientSecret is upstream's SHA-256 + base64url(raw) at-rest form.
//
// NOTE (upstream parity, not an endorsement): a client secret is a
// high-entropy machine credential, so upstream hashes it with a plain SHA-256
// rather than a password KDF. Dilion matches that so a secret issued by either
// implementation validates against the other; user PASSWORDS keep using bcrypt
// (password.go).
func hashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validateClientSecret compares a presented secret with the stored hash in
// constant time.
func validateClientSecret(providedSecret, storedHash string) bool {
	calc := sha256.Sum256([]byte(providedSecret))
	stored, err := base64.RawURLEncoding.DecodeString(storedHash)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(calc[:], stored) == 1
}
