package auth

// OAuth client registration and management: the admin CRUD surface and RFC 7591
// dynamic client registration.
//
// Mirrors github.com/supabase/auth master, internal/api/oauthserver/handlers.go
// (AdminOAuthServerClientRegister, OAuthServerClientDynamicRegister,
// OAuthServerClient{Get,Update,Delete,List,RegenerateSecret}) and service.go
// (registerOAuthServerClient, updateOAuthServerClient, the validators).
//
// # Secrets
//
// A confidential client's secret is generated here, returned ONCE in the
// registration / regeneration response, and stored only as a hash
// (hashClientSecret). There is no endpoint that can read it back — a lost
// secret is regenerated, never recovered. A public client has no secret at all
// and must use PKCE.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ---- parameters ------------------------------------------------------------

// OAuthClientRegisterParams is the POST /admin/oauth/clients and
// POST /oauth/clients/register body (upstream
// OAuthServerClientRegisterParams).
type OAuthClientRegisterParams struct {
	// RedirectURIs is required: at least one, at most ten.
	RedirectURIs []string `json:"redirect_uris"`

	// ClientType may be given explicitly or inferred from
	// TokenEndpointAuthMethod (see determineClientType).
	ClientType              string `json:"client_type,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	GrantTypes []string `json:"grant_types,omitempty"`
	ClientName string   `json:"client_name,omitempty"`
	ClientURI  string   `json:"client_uri,omitempty"`
	LogoURI    string   `json:"logo_uri,omitempty"`

	// registrationType is set by the handler, never by the caller.
	registrationType string
}

// OAuthClientUpdateParams is the PUT /admin/oauth/clients/{client_id} body.
// Every field is a pointer: only the ones present in the JSON are written.
type OAuthClientUpdateParams struct {
	RedirectURIs            *[]string `json:"redirect_uris,omitempty"`
	GrantTypes              *[]string `json:"grant_types,omitempty"`
	ClientName              *string   `json:"client_name,omitempty"`
	ClientURI               *string   `json:"client_uri,omitempty"`
	LogoURI                 *string   `json:"logo_uri,omitempty"`
	TokenEndpointAuthMethod *string   `json:"token_endpoint_auth_method,omitempty"`
}

func (p *OAuthClientUpdateParams) isEmpty() bool {
	return p.RedirectURIs == nil && p.GrantTypes == nil && p.ClientName == nil &&
		p.ClientURI == nil && p.LogoURI == nil && p.TokenEndpointAuthMethod == nil
}

// ---- validation ------------------------------------------------------------

// validateOAuthRedirectURI reproduces upstream's OAuth 2.1 redirect-URI rules
// (RFC 6749 §3.1.2, RFC 6819 §5.1.1): absolute, no fragment, no
// XSS/token-leaking scheme, and plain http only for loopback.
func validateOAuthRedirectURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("redirect URI cannot be empty")
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URL format")
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("must have scheme and host")
	}
	for _, dangerous := range []string{"javascript", "data", "file", "vbscript", "about", "blob"} {
		if strings.EqualFold(parsed.Scheme, dangerous) {
			return fmt.Errorf("scheme '%s' is not allowed for security reasons", parsed.Scheme)
		}
	}
	if parsed.Scheme == "http" {
		switch parsed.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			return fmt.Errorf("HTTP scheme only allowed for localhost")
		}
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("fragment not allowed in redirect URI")
	}
	return nil
}

func validateRedirectURIList(redirectURIs []string, required bool) error {
	if required && len(redirectURIs) == 0 {
		return badRequestError(ErrorCodeValidationFailed, "redirect_uris is required")
	}
	if len(redirectURIs) == 0 {
		return badRequestError(ErrorCodeValidationFailed, "redirect_uris cannot be empty")
	}
	if len(redirectURIs) > maxRedirectURIs {
		return badRequestError(ErrorCodeValidationFailed, "redirect_uris cannot exceed %d items", maxRedirectURIs)
	}
	for _, uri := range redirectURIs {
		if err := validateOAuthRedirectURI(uri); err != nil {
			return badRequestError(ErrorCodeValidationFailed, "invalid redirect_uri '%s': %v", uri, err)
		}
		// The column is a COMMA-separated list, so a comma inside a URI would
		// silently split it into two registered URIs. Upstream has the same
		// storage and no such check; Dilion rejects it instead of corrupting
		// the redirect allow-list.
		if strings.Contains(uri, ",") {
			return badRequestError(ErrorCodeValidationFailed, "invalid redirect_uri '%s': must not contain a comma", uri)
		}
	}
	return nil
}

func validateGrantTypeList(grantTypes []string) error {
	if len(grantTypes) == 0 {
		return badRequestError(ErrorCodeValidationFailed, "grant_types cannot be empty")
	}
	for _, grantType := range grantTypes {
		if grantType != GrantTypeAuthorizationCode && grantType != GrantTypeRefreshToken {
			return badRequestError(ErrorCodeValidationFailed,
				"grant_types must only contain 'authorization_code' and/or 'refresh_token'")
		}
	}
	return nil
}

func validateClientName(clientName string) error {
	if len(clientName) > 1024 {
		return badRequestError(ErrorCodeValidationFailed, "client_name cannot exceed 1024 characters")
	}
	return nil
}

func validateClientURI(field, clientURI string) error {
	if clientURI == "" {
		return nil
	}
	if len(clientURI) > 2048 {
		return badRequestError(ErrorCodeValidationFailed, "%s cannot exceed 2048 characters", field)
	}
	if _, err := url.ParseRequestURI(clientURI); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "%s must be a valid URL", field)
	}
	return nil
}

func (p *OAuthClientRegisterParams) validate() error {
	if err := validateRedirectURIList(p.RedirectURIs, true); err != nil {
		return err
	}
	if len(p.GrantTypes) > 0 {
		if err := validateGrantTypeList(p.GrantTypes); err != nil {
			return err
		}
	}
	if err := validateClientName(p.ClientName); err != nil {
		return err
	}
	if err := validateClientURI("client_uri", p.ClientURI); err != nil {
		return err
	}
	if err := validateClientURI("logo_uri", p.LogoURI); err != nil {
		return err
	}
	if p.registrationType != OAuthRegistrationDynamic && p.registrationType != OAuthRegistrationManual {
		return badRequestError(ErrorCodeValidationFailed, "registration_type must be 'dynamic' or 'manual'")
	}
	if p.ClientType != "" && p.ClientType != OAuthClientTypePublic && p.ClientType != OAuthClientTypeConfidential {
		return badRequestError(ErrorCodeValidationFailed, "client_type must be '%s' or '%s'",
			OAuthClientTypePublic, OAuthClientTypeConfidential)
	}
	if p.TokenEndpointAuthMethod != "" && !slices.Contains(allValidAuthMethods(), p.TokenEndpointAuthMethod) {
		return badRequestError(ErrorCodeValidationFailed, "token_endpoint_auth_method must be one of: %v", allValidAuthMethods())
	}
	if err := validateClientTypeConsistency(p.ClientType, p.TokenEndpointAuthMethod); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "%s", err.Error())
	}
	return nil
}

func (p *OAuthClientUpdateParams) validate() error {
	if p.RedirectURIs != nil {
		if err := validateRedirectURIList(*p.RedirectURIs, false); err != nil {
			return err
		}
	}
	if p.GrantTypes != nil {
		if err := validateGrantTypeList(*p.GrantTypes); err != nil {
			return err
		}
	}
	if p.ClientName != nil {
		if err := validateClientName(*p.ClientName); err != nil {
			return err
		}
	}
	if p.ClientURI != nil {
		if err := validateClientURI("client_uri", *p.ClientURI); err != nil {
			return err
		}
	}
	if p.LogoURI != nil {
		if err := validateClientURI("logo_uri", *p.LogoURI); err != nil {
			return err
		}
	}
	if p.TokenEndpointAuthMethod != nil && !slices.Contains(allValidAuthMethods(), *p.TokenEndpointAuthMethod) {
		return badRequestError(ErrorCodeValidationFailed,
			"invalid token_endpoint_auth_method: must be one of %v", allValidAuthMethods())
	}
	return nil
}

// ---- registration ----------------------------------------------------------

// registerOAuthClient validates the parameters, mints the client (and, for a
// confidential client, its secret) and stores it. The plaintext secret is
// returned to the caller and then forgotten.
func (a *api) registerOAuthClient(ctx context.Context, params *OAuthClientRegisterParams) (*oauthClient, string, error) {
	if err := params.validate(); err != nil {
		return nil, "", err
	}

	grantTypes := params.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken}
	}

	clientType := determineClientType(params.ClientType, params.TokenEndpointAuthMethod)

	// RFC 7591: an omitted token_endpoint_auth_method defaults to
	// client_secret_basic — but a public client has no secret, so it defaults
	// to `none`.
	authMethod := params.TokenEndpointAuthMethod
	if authMethod == "" {
		if clientType == OAuthClientTypePublic {
			authMethod = TokenEndpointAuthMethodNone
		} else {
			authMethod = TokenEndpointAuthMethodClientSecretBasic
		}
	}

	client := &oauthClient{
		ID:                      uuid.NewString(),
		RegistrationType:        params.registrationType,
		ClientType:              clientType,
		TokenEndpointAuthMethod: authMethod,
		RedirectURIs:            strings.Join(params.RedirectURIs, ","),
		GrantTypes:              strings.Join(grantTypes, ","),
		ClientName:              nilIfEmpty(params.ClientName),
		ClientURI:               nilIfEmpty(params.ClientURI),
		LogoURI:                 nilIfEmpty(params.LogoURI),
	}

	var plaintextSecret string
	if client.IsConfidential() {
		secret, err := generateClientSecret()
		if err != nil {
			return nil, "", internalServerError("Error generating client secret").withInternal(err)
		}
		plaintextSecret = secret
		client.ClientSecretHash = hashClientSecret(secret)
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return nil, "", perr
	}
	stored, err := insertOAuthClient(ctx, pool, client, a.now())
	if err != nil {
		return nil, "", internalServerError("Error creating OAuth client").withInternal(err)
	}
	return stored, plaintextSecret, nil
}

// adminRegisterOAuthClient handles POST /admin/oauth/clients: manual
// registration by an operator.
func (a *api) adminRegisterOAuthClient(w http.ResponseWriter, r *http.Request) error {
	params := &OAuthClientRegisterParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	params.registrationType = OAuthRegistrationManual

	client, secret, err := a.registerOAuthClient(r.Context(), params)
	if err != nil {
		return err
	}
	resp := oauthClientToResponse(client)
	if client.IsConfidential() {
		resp.ClientSecret = secret
	}
	return sendJSON(w, http.StatusCreated, resp)
}

// oauthDynamicRegisterClient handles POST /oauth/clients/register: RFC 7591
// dynamic client registration, unauthenticated and rate limited per IP.
func (a *api) oauthDynamicRegisterClient(w http.ResponseWriter, r *http.Request) error {
	if !OAuthServerAllowDynamicRegistration {
		return forbiddenError(ErrorCodeOAuthDynamicClientRegistrationDisabled,
			"Dynamic client registration is not enabled")
	}

	params := &OAuthClientRegisterParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	params.registrationType = OAuthRegistrationDynamic

	client, secret, err := a.registerOAuthClient(r.Context(), params)
	if err != nil {
		return err
	}
	resp := oauthClientToResponse(client)
	if client.IsConfidential() {
		resp.ClientSecret = secret
	}
	return sendJSON(w, http.StatusCreated, resp)
}

// ---- admin CRUD ------------------------------------------------------------

// loadOAuthClientParam resolves {client_id} (upstream's LoadOAuthServerClient
// middleware).
func (a *api) loadOAuthClientParam(r *http.Request) (*oauthClient, error) {
	clientID := chi.URLParam(r, "client_id")
	if clientID == "" {
		return nil, badRequestError(ErrorCodeValidationFailed, "client_id is required")
	}
	if _, err := uuid.Parse(clientID); err != nil {
		return nil, badRequestError(ErrorCodeValidationFailed, "invalid client_id format")
	}
	pool, perr := a.db(r.Context())
	if perr != nil {
		return nil, perr
	}
	client, err := findOAuthClientByID(r.Context(), pool, clientID)
	if err != nil {
		if isNoRows(err) {
			return nil, notFoundError(ErrorCodeOAuthClientNotFound, "OAuth client not found")
		}
		return nil, internalServerError("Error loading OAuth client").withInternal(err)
	}
	return client, nil
}

// adminListOAuthClients handles GET /admin/oauth/clients.
//
// Upstream carries a TODO for pagination here and returns every client; Dilion
// matches that, since the client list of one project is operator-sized.
func (a *api) adminListOAuthClients(w http.ResponseWriter, r *http.Request) error {
	pool, err := a.db(r.Context())
	if err != nil {
		return err
	}
	clients, lerr := listOAuthClients(r.Context(), pool)
	if lerr != nil {
		return internalServerError("Error listing OAuth clients").withInternal(lerr)
	}
	responses := make([]OAuthClientResponse, len(clients))
	for i, c := range clients {
		responses[i] = *oauthClientToResponse(c)
	}
	return sendJSON(w, http.StatusOK, OAuthClientListResponse{Clients: responses})
}

// adminGetOAuthClient handles GET /admin/oauth/clients/{client_id}.
func (a *api) adminGetOAuthClient(w http.ResponseWriter, r *http.Request) error {
	client, err := a.loadOAuthClientParam(r)
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, oauthClientToResponse(client))
}

// adminUpdateOAuthClient handles PUT /admin/oauth/clients/{client_id}. Only the
// fields present in the body are written; client_type is immutable, so a new
// token_endpoint_auth_method must stay valid for the type the client was
// registered with.
func (a *api) adminUpdateOAuthClient(w http.ResponseWriter, r *http.Request) error {
	client, err := a.loadOAuthClientParam(r)
	if err != nil {
		return err
	}

	params := &OAuthClientUpdateParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	if params.isEmpty() {
		return badRequestError(ErrorCodeValidationFailed, "No fields provided for update")
	}
	if err := params.validate(); err != nil {
		return err
	}

	if params.RedirectURIs != nil {
		client.RedirectURIs = strings.Join(*params.RedirectURIs, ",")
	}
	if params.GrantTypes != nil {
		client.GrantTypes = strings.Join(*params.GrantTypes, ",")
	}
	if params.ClientName != nil {
		client.ClientName = nilIfEmpty(*params.ClientName)
	}
	if params.ClientURI != nil {
		client.ClientURI = nilIfEmpty(*params.ClientURI)
	}
	if params.LogoURI != nil {
		client.LogoURI = nilIfEmpty(*params.LogoURI)
	}
	if params.TokenEndpointAuthMethod != nil {
		if !isValidAuthMethodForClientType(client.ClientType, *params.TokenEndpointAuthMethod) {
			return badRequestError(ErrorCodeValidationFailed,
				"token_endpoint_auth_method '%s' is not valid for client_type '%s'; valid methods: %v",
				*params.TokenEndpointAuthMethod, client.ClientType, validAuthMethodsForClientType(client.ClientType))
		}
		client.TokenEndpointAuthMethod = *params.TokenEndpointAuthMethod
	}

	pool, perr := a.db(r.Context())
	if perr != nil {
		return perr
	}
	updated, uerr := updateOAuthClient(r.Context(), pool, client, a.now())
	if uerr != nil {
		if isNoRows(uerr) {
			return notFoundError(ErrorCodeOAuthClientNotFound, "OAuth client not found")
		}
		return internalServerError("Error updating OAuth client").withInternal(uerr)
	}
	return sendJSON(w, http.StatusOK, oauthClientToResponse(updated))
}

// adminDeleteOAuthClient handles DELETE /admin/oauth/clients/{client_id}: a soft
// delete, so the sessions and authorizations that reference the client keep
// their foreign key. The client stops resolving immediately — every lookup
// filters on deleted_at is null.
//
// DEVIATION (hardening): Dilion also revokes the consents users gave the client
// and destroys the sessions it holds, in the same transaction. Upstream only
// stamps deleted_at, which leaves already-issued refresh tokens working; a
// deleted client must not keep a live grant.
func (a *api) adminDeleteOAuthClient(w http.ResponseWriter, r *http.Request) error {
	client, err := a.loadOAuthClientParam(r)
	if err != nil {
		return err
	}

	now := a.now()
	if err := a.inTx(r.Context(), func(tx pgx.Tx) error {
		if _, derr := tx.Exec(r.Context(),
			`update auth.oauth_consents set revoked_at = $2 where client_id = $1::uuid and revoked_at is null`,
			client.ID, now); derr != nil {
			return internalServerError("Error revoking OAuth consents").withInternal(derr)
		}
		if _, derr := tx.Exec(r.Context(),
			`delete from auth.sessions where oauth_client_id = $1::uuid`, client.ID); derr != nil {
			return internalServerError("Error revoking OAuth sessions").withInternal(derr)
		}
		if derr := softDeleteOAuthClient(r.Context(), tx, client.ID, now); derr != nil {
			return internalServerError("Error deleting OAuth client").withInternal(derr)
		}
		return nil
	}); err != nil {
		return err
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// adminRegenerateOAuthClientSecret handles
// POST /admin/oauth/clients/{client_id}/regenerate_secret. The new secret is
// returned once; the old one stops working immediately.
func (a *api) adminRegenerateOAuthClientSecret(w http.ResponseWriter, r *http.Request) error {
	client, err := a.loadOAuthClientParam(r)
	if err != nil {
		return err
	}
	if !client.IsConfidential() {
		return badRequestError(ErrorCodeValidationFailed, "Cannot regenerate secret for public client")
	}

	secret, gerr := generateClientSecret()
	if gerr != nil {
		return internalServerError("Error regenerating OAuth client secret").withInternal(gerr)
	}
	client.ClientSecretHash = hashClientSecret(secret)

	pool, perr := a.db(r.Context())
	if perr != nil {
		return perr
	}
	updated, uerr := updateOAuthClient(r.Context(), pool, client, a.now())
	if uerr != nil {
		return internalServerError("Error regenerating OAuth client secret").withInternal(uerr)
	}

	resp := oauthClientToResponse(updated)
	resp.ClientSecret = secret
	return sendJSON(w, http.StatusOK, resp)
}

// nilIfEmpty maps "" to a NULL text column.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
