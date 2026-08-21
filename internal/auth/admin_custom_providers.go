package auth

// /admin/custom-providers — the runtime custom OAuth2 / OIDC provider registry.
//
//	GET    /admin/custom-providers          -> {"providers": [customOAuthProvider, ...]}  (?type=oauth2|oidc)
//	POST   /admin/custom-providers          -> customOAuthProvider (201)
//	GET    /admin/custom-providers/{id}      -> customOAuthProvider
//	PUT    /admin/custom-providers/{id}      -> customOAuthProvider
//	DELETE /admin/custom-providers/{id}      -> customOAuthProvider (the deleted one)
//
// Reproduces github.com/supabase/auth internal/api/custom_oauth_admin.go
// (adminCustomOAuthProvider{List,Create,Get,Update,Delete}). {id} is the
// provider's UUID (Dilion addresses the SSO registry by UUID too; upstream
// addresses custom providers by identifier — both keys are unique).
//
// The client_secret is accepted on create/update and NEVER returned
// (customOAuthProvider.ClientSecret is json:"-"); see the secret-handling note
// in custom_providers.go.
//
// DEVIATION: upstream gates these routes on a dedicated feature flag
// (requireCustomOAuthEnabled). Dilion's Config has no such field (conf.go is a
// frozen contract this work does not extend), so the routes are gated on
// requireAdmin alone.

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("admin_custom_providers", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAdmin)
			r.Get("/admin/custom-providers", a.handle(a.adminListCustomProviders))
			r.Post("/admin/custom-providers", a.handle(a.adminCreateCustomProvider))
			r.Get("/admin/custom-providers/{id}", a.handle(a.adminGetCustomProvider))
			r.Put("/admin/custom-providers/{id}", a.handle(a.adminUpdateCustomProvider))
			r.Delete("/admin/custom-providers/{id}", a.handle(a.adminDeleteCustomProvider))
		})
	})
}

// ErrorCodeCustomProviderNotFound is returned for an unknown {id}.
const ErrorCodeCustomProviderNotFound = "custom_oauth_provider_not_found"

// customProviderIdentifierRe mirrors the DB CHECK constraint
// custom_oauth_providers_identifier_format.
var customProviderIdentifierRe = regexp.MustCompile(`^[a-z0-9][a-z0-9:-]{0,48}[a-z0-9]$`)

// reservedAuthorizationParams are the OAuth parameters a custom provider's
// authorization_params must never override (upstream's list).
var reservedAuthorizationParams = map[string]bool{
	"client_id": true, "client_secret": true, "redirect_uri": true,
	"response_type": true, "state": true, "code_challenge": true,
	"code_challenge_method": true, "code_verifier": true, "nonce": true,
}

// protectedAttributeTargets are the user fields attribute_mapping must never
// target (upstream's list).
var protectedAttributeTargets = map[string]bool{
	"id": true, "aud": true, "role": true, "app_metadata": true,
	"created_at": true, "updated_at": true, "confirmed_at": true,
	"email_confirmed_at": true, "phone_confirmed_at": true,
	"email_verified": true, "phone_verified": true, "banned_until": true,
	"is_super_admin": true,
}

// CustomOAuthProviderParams is the POST/PUT body. Pointer fields distinguish an
// absent key (keep the default / existing value) from an explicit zero value.
type CustomOAuthProviderParams struct {
	ProviderType          string         `json:"provider_type"`
	Identifier            string         `json:"identifier"`
	Name                  string         `json:"name"`
	ClientID              string         `json:"client_id"`
	ClientSecret          string         `json:"client_secret"`
	AcceptableClientIDs   []string       `json:"acceptable_client_ids"`
	Scopes                []string       `json:"scopes"`
	PKCEEnabled           *bool          `json:"pkce_enabled"`
	AttributeMapping      map[string]any `json:"attribute_mapping"`
	AuthorizationParams   map[string]any `json:"authorization_params"`
	CustomClaimsAllowlist []string       `json:"custom_claims_allowlist"`
	Enabled               *bool          `json:"enabled"`
	EmailOptional         *bool          `json:"email_optional"`

	// OIDC
	Issuer         string `json:"issuer"`
	DiscoveryURL   string `json:"discovery_url"`
	SkipNonceCheck *bool  `json:"skip_nonce_check"`

	// OAuth2
	AuthorizationURL string `json:"authorization_url"`
	TokenURL         string `json:"token_url"`
	UserinfoURL      string `json:"userinfo_url"`
	JwksURI          string `json:"jwks_uri"`
}

// validate checks the params. forUpdate relaxes client_secret (which may be
// omitted to keep the stored one) and the identifier (immutable after create).
func (p *CustomOAuthProviderParams) validate(forUpdate bool) error {
	switch p.ProviderType {
	case customProviderTypeOAuth2, customProviderTypeOIDC:
	default:
		return badRequestError(ErrorCodeValidationFailed, "provider_type must be 'oauth2' or 'oidc'")
	}
	if !forUpdate {
		if !customProviderIdentifierRe.MatchString(p.Identifier) {
			return badRequestError(ErrorCodeValidationFailed,
				"identifier must match %s", customProviderIdentifierRe.String())
		}
	}
	if l := len(strings.TrimSpace(p.Name)); l < 1 || l > 100 {
		return badRequestError(ErrorCodeValidationFailed, "name must be between 1 and 100 characters")
	}
	if p.ClientID == "" {
		return badRequestError(ErrorCodeValidationFailed, "client_id is required")
	}
	if !forUpdate && p.ClientSecret == "" {
		return badRequestError(ErrorCodeValidationFailed, "client_secret is required")
	}

	switch p.ProviderType {
	case customProviderTypeOIDC:
		if !isHTTPSURL(p.Issuer) {
			return badRequestError(ErrorCodeValidationFailed, "issuer must be an https URL for an oidc provider")
		}
		if p.DiscoveryURL != "" && !isHTTPSURL(p.DiscoveryURL) {
			return badRequestError(ErrorCodeValidationFailed, "discovery_url must be an https URL")
		}
	case customProviderTypeOAuth2:
		for name, v := range map[string]string{
			"authorization_url": p.AuthorizationURL,
			"token_url":         p.TokenURL,
			"userinfo_url":      p.UserinfoURL,
		} {
			if !isHTTPSURL(v) {
				return badRequestError(ErrorCodeValidationFailed, "%s must be an https URL for an oauth2 provider", name)
			}
		}
	}

	for key, v := range p.AuthorizationParams {
		if reservedAuthorizationParams[key] {
			return badRequestError(ErrorCodeValidationFailed, "authorization_params must not override %q", key)
		}
		if _, ok := v.(string); !ok {
			return badRequestError(ErrorCodeValidationFailed, "authorization_params values must be strings")
		}
	}
	for target := range p.AttributeMapping {
		if protectedAttributeTargets[target] {
			return badRequestError(ErrorCodeValidationFailed, "attribute_mapping must not target the protected field %q", target)
		}
	}
	for _, c := range p.CustomClaimsAllowlist {
		if strings.TrimSpace(c) == "" {
			return badRequestError(ErrorCodeValidationFailed, "custom_claims_allowlist entries must be non-empty")
		}
	}
	return nil
}

func isHTTPSURL(v string) bool { return strings.HasPrefix(v, "https://") }

// apply writes the params onto a provider row (a fresh one on create, the
// loaded one on update). On update an empty client_secret preserves the stored
// secret.
func (p *CustomOAuthProviderParams) apply(cp *customOAuthProvider, forUpdate bool) {
	cp.ProviderType = p.ProviderType
	if !forUpdate {
		cp.Identifier = p.Identifier
	}
	cp.Name = strings.TrimSpace(p.Name)
	cp.ClientID = p.ClientID
	if p.ClientSecret != "" {
		cp.ClientSecret = p.ClientSecret
	}
	cp.AcceptableClientIDs = orEmpty(p.AcceptableClientIDs)
	cp.Scopes = orEmpty(p.Scopes)
	cp.CustomClaimsAllowlist = orEmpty(p.CustomClaimsAllowlist)
	cp.AttributeMapping = JSONMap(p.AttributeMapping)
	cp.AuthorizationParams = JSONMap(p.AuthorizationParams)
	cp.PKCEEnabled = boolOr(p.PKCEEnabled, true)
	cp.Enabled = boolOr(p.Enabled, true)
	cp.EmailOptional = boolOr(p.EmailOptional, false)
	cp.SkipNonceCheck = boolOr(p.SkipNonceCheck, false)

	cp.Issuer = nilIfEmpty(p.Issuer)
	cp.DiscoveryURL = nilIfEmpty(p.DiscoveryURL)
	cp.AuthorizationURL = nilIfEmpty(p.AuthorizationURL)
	cp.TokenURL = nilIfEmpty(p.TokenURL)
	cp.UserinfoURL = nilIfEmpty(p.UserinfoURL)
	cp.JwksURI = nilIfEmpty(p.JwksURI)

	// OIDC providers keep no OAuth2-only endpoint columns and vice versa.
	if p.ProviderType == customProviderTypeOIDC {
		cp.AuthorizationURL, cp.TokenURL, cp.UserinfoURL = nil, nil, nil
	} else {
		cp.Issuer, cp.DiscoveryURL = nil, nil
	}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// loadCustomProvider resolves {id} (a UUID) to a stored provider.
func (a *api) loadCustomProvider(r *http.Request) (*customOAuthProvider, error) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		return nil, notFoundError(ErrorCodeCustomProviderNotFound, "Custom OAuth provider not found")
	}
	pool, perr := a.db(ctx)
	if perr != nil {
		return nil, perr
	}
	cp, err := findCustomProviderByID(ctx, pool, id)
	if err != nil {
		if isNoRows(err) {
			return nil, notFoundError(ErrorCodeCustomProviderNotFound, "Custom OAuth provider not found")
		}
		return nil, internalServerError("Database error finding custom OAuth provider").withInternal(err)
	}
	return cp, nil
}

// ---- handlers --------------------------------------------------------------

func (a *api) adminListCustomProviders(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	providerType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	switch providerType {
	case "", customProviderTypeOAuth2, customProviderTypeOIDC:
	default:
		return badRequestError(ErrorCodeValidationFailed, "type must be 'oauth2' or 'oidc'")
	}
	providers, err := listCustomProviders(ctx, pool, providerType)
	if err != nil {
		return internalServerError("Database error loading custom OAuth providers").withInternal(err)
	}
	return sendJSON(w, http.StatusOK, map[string]any{"providers": providers})
}

func (a *api) adminCreateCustomProvider(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	params := &CustomOAuthProviderParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	if err := params.validate(false /* forUpdate */); err != nil {
		return err
	}

	cp := &customOAuthProvider{}
	params.apply(cp, false)

	var stored *customOAuthProvider
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		created, terr := insertCustomProvider(ctx, tx, cp, a.now())
		if terr != nil {
			if isUniqueViolation(terr) {
				return unprocessableEntityError(ErrorCodeConflict,
					"A custom OAuth provider with identifier %q already exists", cp.Identifier).withInternal(terr)
			}
			return internalServerError("Database error creating custom OAuth provider").withInternal(terr)
		}
		stored = created
		return nil
	}); err != nil {
		return err
	}
	return sendJSON(w, http.StatusCreated, stored)
}

func (a *api) adminGetCustomProvider(w http.ResponseWriter, r *http.Request) error {
	cp, err := a.loadCustomProvider(r)
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, cp)
}

func (a *api) adminUpdateCustomProvider(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	params := &CustomOAuthProviderParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	cp, err := a.loadCustomProvider(r)
	if err != nil {
		return err
	}
	// The identifier is immutable; carry over the provider_type default when the
	// body omits it so validation for the existing type still applies.
	if params.ProviderType == "" {
		params.ProviderType = cp.ProviderType
	}
	if err := params.validate(true /* forUpdate */); err != nil {
		return err
	}
	params.apply(cp, true)

	var stored *customOAuthProvider
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		updated, terr := updateCustomProvider(ctx, tx, cp, a.now())
		if terr != nil {
			return internalServerError("Database error updating custom OAuth provider").withInternal(terr)
		}
		stored = updated
		return nil
	}); err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, stored)
}

func (a *api) adminDeleteCustomProvider(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	cp, err := a.loadCustomProvider(r)
	if err != nil {
		return err
	}
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if terr := deleteCustomProvider(ctx, tx, cp.ID); terr != nil {
			return internalServerError("Database error deleting custom OAuth provider").withInternal(terr)
		}
		return nil
	}); err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, cp)
}
