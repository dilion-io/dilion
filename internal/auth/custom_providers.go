package auth

// Runtime-configurable custom OAuth2 / OIDC providers (auth.custom_oauth_providers).
//
// A custom provider is registered through /admin/custom-providers (see
// admin_custom_providers.go) and, once enabled, behaves exactly like a built-in
// one: it is resolved BY IDENTIFIER at GET /authorize and GET|POST /callback,
// plugging into the same externalProvider interface. Upstream reference:
// github.com/supabase/auth internal/api/provider/custom_oauth.go +
// internal/models/custom_oauth_provider.go.
//
// # Secret handling
//
// client_secret is stored in the client_secret column and is NEVER serialized
// (json:"-"), never returned by any endpoint. Upstream encrypts it at rest with
// its DB_ENCRYPTION_KEY; Dilion's auth layer is not wired to a KMS (the same is
// true of the TOTP factor secret and the Twilio auth token, which are also
// stored as-is and never returned), so the secret is stored verbatim and
// protected by the "never returned" contract plus database access control. A
// deployment that needs at-rest encryption should front the column with a
// KMS-backed pool; the wire contract does not change.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	customProviderTypeOAuth2 = "oauth2"
	customProviderTypeOIDC   = "oidc"
)

// customOAuthProvider is one auth.custom_oauth_providers row. The json tags are
// the admin API's wire contract; client_secret is deliberately json:"-".
type customOAuthProvider struct {
	ID                    string    `json:"id"`
	ProviderType          string    `json:"provider_type"`
	Identifier            string    `json:"identifier"`
	Name                  string    `json:"name"`
	ClientID              string    `json:"client_id"`
	ClientSecret          string    `json:"-"`
	AcceptableClientIDs   []string  `json:"acceptable_client_ids"`
	Scopes                []string  `json:"scopes"`
	PKCEEnabled           bool      `json:"pkce_enabled"`
	AttributeMapping      JSONMap   `json:"attribute_mapping"`
	AuthorizationParams   JSONMap   `json:"authorization_params"`
	CustomClaimsAllowlist []string  `json:"custom_claims_allowlist"`
	Enabled               bool      `json:"enabled"`
	EmailOptional         bool      `json:"email_optional"`
	Issuer                *string   `json:"issuer,omitempty"`
	DiscoveryURL          *string   `json:"discovery_url,omitempty"`
	SkipNonceCheck        bool      `json:"skip_nonce_check"`
	AuthorizationURL      *string   `json:"authorization_url,omitempty"`
	TokenURL              *string   `json:"token_url,omitempty"`
	UserinfoURL           *string   `json:"userinfo_url,omitempty"`
	JwksURI               *string   `json:"jwks_uri,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// ---- runtime provider ------------------------------------------------------

// customRuntimeProvider is a resolved custom provider that satisfies
// externalProvider. Endpoints are resolved (from discovery for OIDC, or the
// explicit URLs for OAuth2) when the provider is built.
type customRuntimeProvider struct {
	a *api

	oauth               oauthConfig
	providerType        string
	issuer              string
	userInfoURL         string
	authorizationParams JSONMap
	attributeMapping    JSONMap
	claimsAllowlist     []string
	acceptableClientIDs []string
	emailOptional       bool
}

// redirectURISetter is implemented by providers whose redirect URI is not known
// until request time (custom providers have no per-provider redirect column, so
// it is derived from the incoming request's own host — see externalCallbackURL).
type redirectURISetter interface {
	setRedirectURI(uri string)
}

func (p *customRuntimeProvider) setRedirectURI(uri string) { p.oauth.RedirectURL = uri }

// resolveCustomProvider looks a custom provider up by identifier and, if it is
// enabled, builds its runtime form. It is the fallback path of api.provider for
// a name that is not a built-in factory.
func (a *api) resolveCustomProvider(ctx context.Context, name, scopes string) (externalProvider, error) {
	pool, err := a.db(ctx)
	if err != nil {
		// No database (unit tests): a custom provider can never be resolved.
		return nil, err
	}
	cp, err := findCustomProviderByIdentifier(ctx, pool, name)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("Provider %s could not be found", name)
		}
		return nil, err
	}
	return a.buildCustomProvider(ctx, cp, scopes)
}

// buildCustomProvider resolves endpoints and returns the runtime provider.
func (a *api) buildCustomProvider(ctx context.Context, cp *customOAuthProvider, scopes string) (externalProvider, error) {
	if !cp.Enabled {
		return nil, errors.New("provider is not enabled")
	}
	if cp.ClientID == "" || cp.ClientSecret == "" {
		return nil, errors.New("provider is missing client credentials")
	}

	authURL, tokenURL, userinfoURL, issuer, err := a.customProviderEndpoints(ctx, cp)
	if err != nil {
		return nil, err
	}

	return &customRuntimeProvider{
		a:                   a,
		providerType:        cp.ProviderType,
		issuer:              issuer,
		userInfoURL:         userinfoURL,
		authorizationParams: cp.AuthorizationParams,
		attributeMapping:    cp.AttributeMapping,
		claimsAllowlist:     cp.CustomClaimsAllowlist,
		acceptableClientIDs: cp.AcceptableClientIDs,
		emailOptional:       cp.EmailOptional,
		oauth: oauthConfig{
			ClientID:     cp.ClientID,
			ClientSecret: cp.ClientSecret,
			AuthURL:      authURL,
			TokenURL:     tokenURL,
			Scopes:       scopesWithDefaults(cp.Scopes, scopes),
		},
	}, nil
}

// customProviderEndpoints returns (authURL, tokenURL, userinfoURL, issuer). For
// OIDC it resolves them from the discovery document (a custom discovery_url
// overrides the issuer's well-known location); for OAuth2 it uses the explicit
// URLs.
func (a *api) customProviderEndpoints(ctx context.Context, cp *customOAuthProvider) (string, string, string, string, error) {
	if cp.ProviderType == customProviderTypeOIDC {
		if cp.Issuer == nil || *cp.Issuer == "" {
			return "", "", "", "", errors.New("oidc custom provider is missing its issuer")
		}
		issuer := strings.TrimSuffix(*cp.Issuer, "/")
		doc, err := a.customProviderDiscovery(ctx, issuer, cp.DiscoveryURL)
		if err != nil {
			return "", "", "", "", err
		}
		if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
			return "", "", "", "", fmt.Errorf("oidc: issuer %s publishes no authorization or token endpoint", issuer)
		}
		return doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.UserInfoEndpoint, issuer, nil
	}

	// OAuth2: the endpoints are mandatory (enforced by the DB and the admin
	// validation), so they are all present here.
	get := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return get(cp.AuthorizationURL), get(cp.TokenURL), get(cp.UserinfoURL), "", nil
}

// customProviderDiscovery fetches the OIDC metadata. When discoveryURL is set it
// is fetched verbatim; otherwise the cached issuer/.well-known path is used.
func (a *api) customProviderDiscovery(ctx context.Context, issuer string, discoveryURL *string) (*oidcDiscovery, error) {
	if discoveryURL != nil && *discoveryURL != "" {
		doc := &oidcDiscovery{}
		if err := getJSON(ctx, a.httpClient(), *discoveryURL, "", doc); err != nil {
			return nil, fmt.Errorf("oidc: discovery for %s: %w", issuer, err)
		}
		return doc, nil
	}
	return oidcCache.discover(ctx, a.httpClient(), issuer)
}

func (p *customRuntimeProvider) authCodeURL(state string, extra url.Values) string {
	if len(p.authorizationParams) > 0 {
		if extra == nil {
			extra = url.Values{}
		} else {
			extra = cloneValues(extra)
		}
		for k, v := range p.authorizationParams {
			if s, ok := v.(string); ok {
				extra.Set(k, s)
			}
		}
	}
	return p.oauth.authCodeURL(state, extra)
}

func (p *customRuntimeProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

func (p *customRuntimeProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	// OIDC with an id_token: verify it and read the claims from the token.
	if p.providerType == customProviderTypeOIDC && tok.IDToken != "" {
		idt, err := p.a.verifyIDToken(ctx, p.issuer, tok.IDToken, idTokenOptions{
			AccessToken:          tok.AccessToken,
			SkipAccessTokenCheck: tok.AccessToken == "",
		})
		if err != nil {
			return nil, err
		}
		if !p.audienceAccepted(idt.Audience) {
			return nil, fmt.Errorf("custom provider: id token audience %v is not accepted", idt.Audience)
		}
		return p.claimsToUserData(idt.Claims), nil
	}

	// OAuth2, or OIDC without an id_token: read the userinfo endpoint.
	if p.userInfoURL == "" {
		return nil, errors.New("custom provider: no id_token and no userinfo endpoint")
	}
	var claims map[string]any
	if err := getJSON(ctx, hc, p.userInfoURL, tok.AccessToken, &claims); err != nil {
		return nil, err
	}
	return p.claimsToUserData(claims), nil
}

// audienceAccepted checks the id_token audience against the configured client id
// and any additionally acceptable client ids.
func (p *customRuntimeProvider) audienceAccepted(aud []string) bool {
	for _, id := range append([]string{p.oauth.ClientID}, p.acceptableClientIDs...) {
		if id != "" && containsString(aud, id) {
			return true
		}
	}
	return false
}

// claimsToUserData maps a claims object onto the shared claim model, honouring
// attribute_mapping (a target field name is filled from the named source claim,
// or a literal value) and custom_claims_allowlist (only the listed keys are
// copied verbatim into custom_claims).
func (p *customRuntimeProvider) claimsToUserData(raw map[string]any) *userProvidedData {
	pick := func(target, defaultSource string) string {
		if src, ok := p.attributeMapping[target]; ok {
			switch v := src.(type) {
			case string:
				if val := claimString(raw, v); val != "" {
					return val
				}
				return v // literal string mapping
			default:
				return fmt.Sprintf("%v", v)
			}
		}
		return claimString(raw, defaultSource)
	}

	sub := pick("sub", "sub")
	if sub == "" {
		sub = pick("subject", "sub")
	}
	email := pick("email", "email")
	verified := claimBool(raw, "email_verified")
	if src, ok := p.attributeMapping["email_verified"].(string); ok {
		verified = claimBool(raw, src)
	}
	name := pick("name", "name")
	picture := pick("picture", "picture")

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:            p.issuer,
			Subject:           sub,
			Name:              name,
			Picture:           picture,
			PreferredUsername: pick("preferred_username", "preferred_username"),
			Email:             email,
			EmailVerified:     verified,

			// To be deprecated upstream, still emitted.
			AvatarURL:  picture,
			FullName:   name,
			ProviderID: sub,
		},
	}

	if len(p.claimsAllowlist) > 0 {
		custom := map[string]any{}
		for _, key := range p.claimsAllowlist {
			if v, ok := raw[key]; ok {
				custom[key] = v
			}
		}
		if len(custom) > 0 {
			data.Metadata.CustomClaims = custom
		}
	}

	if email != "" {
		data.Emails = append(data.Emails, providerEmail{Email: email, Verified: verified, Primary: true})
	}
	return data
}

// externalCallbackURL derives the absolute /callback URL from the current
// request, so a custom provider (which has no configured redirect URI) uses the
// same host the request arrived on. The redirect_uri sent at /authorize and at
// the token exchange are identical because both resolve to the same last path
// segment ("callback") under the request's mount.
func (a *api) externalCallbackURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}
	path := r.URL.Path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[:i+1] + "callback"
	}
	return scheme + "://" + r.Host + path
}

// ---- storage ---------------------------------------------------------------

const customProviderColumns = `id::text, provider_type, identifier, name, client_id,
	coalesce(client_secret, ''), acceptable_client_ids, scopes, pkce_enabled,
	attribute_mapping, authorization_params, custom_claims_allowlist, enabled,
	email_optional, issuer, discovery_url, skip_nonce_check,
	authorization_url, token_url, userinfo_url, jwks_uri, created_at, updated_at`

func scanCustomProvider(row rowScanner) (*customOAuthProvider, error) {
	var (
		cp                   customOAuthProvider
		attributeMapping     []byte
		authorizationParams  []byte
		createdAt, updatedAt time.Time
	)
	if err := row.Scan(
		&cp.ID, &cp.ProviderType, &cp.Identifier, &cp.Name, &cp.ClientID,
		&cp.ClientSecret, &cp.AcceptableClientIDs, &cp.Scopes, &cp.PKCEEnabled,
		&attributeMapping, &authorizationParams, &cp.CustomClaimsAllowlist, &cp.Enabled,
		&cp.EmailOptional, &cp.Issuer, &cp.DiscoveryURL, &cp.SkipNonceCheck,
		&cp.AuthorizationURL, &cp.TokenURL, &cp.UserinfoURL, &cp.JwksURI,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	cp.AttributeMapping = jsonbToMap(attributeMapping)
	cp.AuthorizationParams = jsonbToMap(authorizationParams)
	if cp.AcceptableClientIDs == nil {
		cp.AcceptableClientIDs = []string{}
	}
	if cp.Scopes == nil {
		cp.Scopes = []string{}
	}
	if cp.CustomClaimsAllowlist == nil {
		cp.CustomClaimsAllowlist = []string{}
	}
	cp.CreatedAt = createdAt.UTC()
	cp.UpdatedAt = updatedAt.UTC()
	return &cp, nil
}

// rowScanner is the subset of pgx.Row scanCustomProvider needs.
type rowScanner interface {
	Scan(dest ...any) error
}

func jsonbToMap(b []byte) JSONMap {
	m := JSONMap{}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// mapToJSONB marshals a claim map for a ::jsonb bind parameter. A nil map is
// stored as an empty object so the column's NOT NULL default is respected.
func mapToJSONB(m JSONMap) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func findCustomProviderByID(ctx context.Context, q querier, id string) (*customOAuthProvider, error) {
	return scanCustomProvider(q.QueryRow(ctx,
		`select `+customProviderColumns+` from auth.custom_oauth_providers where id = $1::uuid`, id))
}

func findCustomProviderByIdentifier(ctx context.Context, q querier, identifier string) (*customOAuthProvider, error) {
	return scanCustomProvider(q.QueryRow(ctx,
		`select `+customProviderColumns+` from auth.custom_oauth_providers where identifier = $1`, identifier))
}

func listCustomProviders(ctx context.Context, q querier, providerType string) ([]*customOAuthProvider, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if providerType != "" {
		rows, err = q.Query(ctx, `select `+customProviderColumns+
			` from auth.custom_oauth_providers where provider_type = $1 order by created_at`, providerType)
	} else {
		rows, err = q.Query(ctx, `select `+customProviderColumns+
			` from auth.custom_oauth_providers order by created_at`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*customOAuthProvider{}
	for rows.Next() {
		cp, serr := scanCustomProvider(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, cp)
	}
	return out, rows.Err()
}

func insertCustomProvider(ctx context.Context, q querier, cp *customOAuthProvider, now time.Time) (*customOAuthProvider, error) {
	if cp.ID == "" {
		cp.ID = uuid.NewString()
	}
	return scanCustomProvider(q.QueryRow(ctx, `
		insert into auth.custom_oauth_providers (
			id, provider_type, identifier, name, client_id, client_secret,
			acceptable_client_ids, scopes, pkce_enabled, attribute_mapping,
			authorization_params, custom_claims_allowlist, enabled, email_optional,
			issuer, discovery_url, skip_nonce_check,
			authorization_url, token_url, userinfo_url, jwks_uri,
			created_at, updated_at
		) values (
			$1::uuid, $2, $3, $4, $5, $6,
			$7::text[], $8::text[], $9, $10::jsonb,
			$11::jsonb, $12::text[], $13, $14,
			$15, $16, $17,
			$18, $19, $20, $21,
			$22, $22
		)
		returning `+customProviderColumns,
		cp.ID, cp.ProviderType, cp.Identifier, cp.Name, cp.ClientID, cp.ClientSecret,
		cp.AcceptableClientIDs, cp.Scopes, cp.PKCEEnabled, mapToJSONB(cp.AttributeMapping),
		mapToJSONB(cp.AuthorizationParams), cp.CustomClaimsAllowlist, cp.Enabled, cp.EmailOptional,
		cp.Issuer, cp.DiscoveryURL, cp.SkipNonceCheck,
		cp.AuthorizationURL, cp.TokenURL, cp.UserinfoURL, cp.JwksURI,
		now))
}

func updateCustomProvider(ctx context.Context, q querier, cp *customOAuthProvider, now time.Time) (*customOAuthProvider, error) {
	return scanCustomProvider(q.QueryRow(ctx, `
		update auth.custom_oauth_providers set
			provider_type = $2, name = $3, client_id = $4, client_secret = $5,
			acceptable_client_ids = $6::text[], scopes = $7::text[], pkce_enabled = $8,
			attribute_mapping = $9::jsonb, authorization_params = $10::jsonb,
			custom_claims_allowlist = $11::text[], enabled = $12, email_optional = $13,
			issuer = $14, discovery_url = $15, skip_nonce_check = $16,
			authorization_url = $17, token_url = $18, userinfo_url = $19, jwks_uri = $20,
			updated_at = $21
		where id = $1::uuid
		returning `+customProviderColumns,
		cp.ID, cp.ProviderType, cp.Name, cp.ClientID, cp.ClientSecret,
		cp.AcceptableClientIDs, cp.Scopes, cp.PKCEEnabled,
		mapToJSONB(cp.AttributeMapping), mapToJSONB(cp.AuthorizationParams),
		cp.CustomClaimsAllowlist, cp.Enabled, cp.EmailOptional,
		cp.Issuer, cp.DiscoveryURL, cp.SkipNonceCheck,
		cp.AuthorizationURL, cp.TokenURL, cp.UserinfoURL, cp.JwksURI,
		now))
}

func deleteCustomProvider(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `delete from auth.custom_oauth_providers where id = $1::uuid`, id)
	return err
}
