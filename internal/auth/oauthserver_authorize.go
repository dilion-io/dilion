package auth

// GET|POST /oauth/authorize — the authorization endpoint of the OAuth 2.1
// server (upstream internal/api/oauthserver/authorize.go,
// OAuthServerAuthorize).
//
// The handler never authenticates the end user itself. It validates the
// request, parks it as a PENDING auth.oauth_authorizations row and redirects
// the browser to the hosted consent page (SiteURL +
// OAuthServerAuthorizationPath) with ?authorization_id=…; that page is a normal
// front-end route, so "the user is not signed in yet" is handled by its own
// login flow. Consent itself is oauthserver_consent.go.
//
// # Where errors go
//
// Until the client and its redirect_uri are known to be valid, errors are
// returned as JSON — a redirect_uri that failed validation must never be used
// as a redirect target (OAuth 2.1 §4.1.2.1). Once both are trusted, every
// further failure is delivered to the client as ?error=…&error_description=…
// on the redirect_uri, which is what an OAuth client library expects.

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// AuthorizeParams are the /oauth/authorize request parameters (upstream
// oauthserver.AuthorizeParams).
type AuthorizeParams struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	ResponseType string `json:"response_type"`
	Scope        string `json:"scope"`
	State        string `json:"state"`

	// Resource is the RFC 8707 resource indicator.
	Resource            string `json:"resource"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	// Nonce is the OIDC nonce, replayed into the id_token.
	Nonce string `json:"nonce"`
}

// oauthAuthorize handles GET|POST /oauth/authorize.
func (a *api) oauthAuthorize(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// Query first (the GET form, and what upstream reads); a POST may carry
	// the same parameters form-encoded (RFC 6749 §3.1 permits POST).
	get := func(name string) string {
		if v := r.URL.Query().Get(name); v != "" {
			return v
		}
		if r.Method == http.MethodPost {
			return r.PostFormValue(name)
		}
		return ""
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return badRequestError(ErrorCodeValidationFailed, "Failed to parse form data")
		}
	}

	params := &AuthorizeParams{
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		ResponseType:        get("response_type"),
		Scope:               get("scope"),
		State:               get("state"),
		Resource:            get("resource"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
		Nonce:               get("nonce"),
	}

	// These two cannot be reported by redirect: without a trusted redirect_uri
	// there is nowhere safe to send the error.
	if params.ClientID == "" {
		return badRequestError(ErrorCodeValidationFailed, "client_id is required")
	}
	if params.RedirectURI == "" {
		return badRequestError(ErrorCodeValidationFailed, "redirect_uri is required")
	}
	if _, err := uuid.Parse(params.ClientID); err != nil {
		return badRequestError(ErrorCodeOAuthClientNotFound, "invalid client_id format")
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	client, cerr := a.oauthClientByID(ctx, pool, params.ClientID)
	if cerr != nil {
		if isNoRows(cerr) {
			return badRequestError(ErrorCodeOAuthClientNotFound, "invalid client_id")
		}
		return internalServerError("error validating client").withInternal(cerr)
	}

	// Exact string match against the registered URIs (OAuth 2.1 §3.1.2.3 — no
	// prefix or wildcard matching, ever).
	if !isRegisteredRedirectURI(client, params.RedirectURI) {
		return badRequestError(ErrorCodeValidationFailed, "invalid redirect_uri")
	}

	// From here the redirect target is trusted, so errors travel on it.
	if err := a.validateRemainingAuthorizeParams(params); err != nil {
		http.Redirect(w, r, buildErrorRedirectURL(params.RedirectURI, oAuth2ErrorInvalidRequest, err.Error(), params.State),
			http.StatusFound)
		return nil
	}

	method := ""
	if params.CodeChallengeMethod != "" {
		// The auth.code_challenge_method enum is lowercase.
		method = strings.ToLower(params.CodeChallengeMethod)
	}
	row := &oauthAuthorization{
		ID:                  uuid.NewString(),
		AuthorizationID:     secureAlphanumeric(32),
		ClientID:            client.ID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		State:               nilIfEmpty(params.State),
		Resource:            nilIfEmpty(params.Resource),
		CodeChallenge:       nilIfEmpty(params.CodeChallenge),
		CodeChallengeMethod: nilIfEmpty(method),
		Nonce:               nilIfEmpty(params.Nonce),
	}

	// A code-defined client needs its inert shadow row before the
	// authorization can reference it (oauthserver_code_clients.go).
	if err := ensureOAuthClientRow(ctx, pool, client, a.now()); err != nil {
		a.log.ErrorContext(ctx, "auth: error preparing code-defined oauth client", "error", err.Error())
		http.Redirect(w, r, buildErrorRedirectURL(params.RedirectURI, oAuth2ErrorServerError, "error creating authorization", params.State),
			http.StatusFound)
		return nil
	}
	stored, ierr := insertOAuthAuthorization(ctx, pool, row, a.now(), OAuthServerAuthorizationTTL)
	if ierr != nil {
		a.log.ErrorContext(ctx, "auth: error creating oauth authorization", "error", ierr.Error())
		http.Redirect(w, r, buildErrorRedirectURL(params.RedirectURI, oAuth2ErrorServerError, "error creating authorization", params.State),
			http.StatusFound)
		return nil
	}

	consentURL := joinURLPath(a.site(ctx).SiteURL, OAuthServerAuthorizationPath) +
		"?authorization_id=" + url.QueryEscape(stored.AuthorizationID)
	http.Redirect(w, r, consentURL, http.StatusFound)
	return nil
}

// validateRemainingAuthorizeParams checks everything that may be reported by
// redirect. It also fills the defaults upstream applies (response_type=code,
// the configured default scope).
func (a *api) validateRemainingAuthorizeParams(params *AuthorizeParams) error {
	if params.ResponseType == "" {
		params.ResponseType = oauthResponseTypeCode
	}
	if params.Scope == "" {
		params.Scope = OAuthServerDefaultScope
	}
	if params.ResponseType != oauthResponseTypeCode {
		return errors.New("only response_type=code is supported")
	}
	if err := validateOAuthScopes(params.Scope); err != nil {
		return err
	}
	if err := validateResourceParam(params.Resource); err != nil {
		return err
	}
	return validateAuthorizePKCEParams(params.CodeChallengeMethod, params.CodeChallenge)
}

// validateOAuthScopes rejects anything outside supportedOAuthScopes.
func validateOAuthScopes(scopeString string) error {
	if scopeString == "" {
		return errors.New("scope parameter is required")
	}
	scopes := parseScopeString(scopeString)
	if len(scopes) == 0 {
		return errors.New("scope parameter cannot be empty")
	}
	for _, scope := range scopes {
		if !isSupportedScope(scope) {
			return fmt.Errorf("unsupported scope: %s", scope)
		}
	}
	return nil
}

// validateAuthorizePKCEParams enforces PKCE.
//
// OAuth 2.1 makes PKCE mandatory for the authorization-code flow — for
// CONFIDENTIAL clients too, not just public ones — and upstream implements
// exactly that: both code_challenge and code_challenge_method must be present.
// `plain` is accepted (upstream accepts it, and the discovery document
// advertises it) but S256 is what every current client sends.
func validateAuthorizePKCEParams(codeChallengeMethod, codeChallenge string) error {
	if codeChallenge == "" || codeChallengeMethod == "" {
		return errors.New("PKCE flow requires both code_challenge and code_challenge_method")
	}
	switch strings.ToLower(codeChallengeMethod) {
	case challengeMethodS256, challengeMethodPlain:
	default:
		return errors.New("code_challenge_method must be 'S256' or 'plain'")
	}
	if len(codeChallenge) < minCodeChallengeLength || len(codeChallenge) > maxCodeChallengeLength {
		return fmt.Errorf("code_challenge must be between %d and %d characters",
			minCodeChallengeLength, maxCodeChallengeLength)
	}
	return nil
}

// validateResourceParam applies RFC 8707 §2: an absolute URI, no fragment, no
// query.
func validateResourceParam(resource string) error {
	if resource == "" {
		return nil
	}
	parsed, err := url.Parse(resource)
	if err != nil {
		return errors.New("resource must be a valid URI")
	}
	if !parsed.IsAbs() {
		return errors.New("resource must be an absolute URI")
	}
	if parsed.Fragment != "" {
		return errors.New("resource must not include a fragment component")
	}
	if parsed.RawQuery != "" {
		return errors.New("resource must not include a query component")
	}
	return nil
}

// isRegisteredRedirectURI is exact-match redirect URI validation.
func isRegisteredRedirectURI(client *oauthClient, redirectURI string) bool {
	if client.code != nil {
		return client.codeRedirectURIAllowed(redirectURI)
	}
	for _, registered := range client.GetRedirectURIs() {
		if registered == redirectURI {
			return true
		}
	}
	return false
}

// buildSuccessRedirectURL is the URL the consent page sends the browser to after
// an approval: the client's redirect_uri with ?code= and the original ?state=.
func buildSuccessRedirectURL(o *oauthAuthorization) string {
	u, err := url.Parse(o.RedirectURI)
	if err != nil {
		return o.RedirectURI
	}
	q := u.Query()
	if o.AuthorizationCode != nil {
		q.Set("code", *o.AuthorizationCode)
	}
	if o.State != nil && *o.State != "" {
		q.Set("state", *o.State)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// buildErrorRedirectURL is the RFC 6749 §4.1.2.1 error redirect.
func buildErrorRedirectURL(redirectURI, errorCode, errorDescription, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", errorDescription)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// joinURLPath joins a base URL and a path without doubling or dropping slashes.
func joinURLPath(baseURL, pathToJoin string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(pathToJoin, "/") {
		pathToJoin = "/" + pathToJoin
	}
	return baseURL + pathToJoin
}
