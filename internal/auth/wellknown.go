package auth

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func init() {
	registerFeature("wellknown", func(a *api, r chi.Router) {
		// Unauthenticated on purpose: discovery is what a relying party reads
		// BEFORE it holds any credential.
		r.Get("/.well-known/openid-configuration", a.handle(a.wellKnownOpenID))

		// RFC 8414 OAuth 2.0 Authorization Server Metadata. OIDC Discovery is an
		// extension of RFC 8414, so ONE document satisfies both specs and
		// upstream serves the same handler on both paths — but this one only
		// exists while the OAuth server is enabled (upstream gates it with
		// requireOAuthServerEnabled).
		r.With(a.requireOAuthServerEnabled).
			Get("/.well-known/oauth-authorization-server", a.handle(a.wellKnownOpenID))
	})
}

// OpenIDConfigurationResponse is the OIDC Discovery / RFC 8414 metadata
// document. Field names, json tags and field order are copied from upstream
// api.OpenIDConfigurationResponse — OIDC Discovery extends RFC 8414, so one
// structure serves both /.well-known/openid-configuration and (once Dilion
// grows an OAuth server) /.well-known/oauth-authorization-server.
type OpenIDConfigurationResponse struct {
	// Core Discovery Fields (Required by both OIDC and OAuth 2.0)
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURL               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"` // OIDC-specific
	RegistrationEndpoint  string `json:"registration_endpoint,omitempty"`

	// Supported Parameters
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`               // OIDC-specific
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"` // OIDC-specific
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`       // OIDC-specific
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"` // OAuth 2.1/PKCE
}

// supportedOAuthScopes mirrors upstream models.SupportedOAuthScopes.
var supportedOAuthScopes = []string{"openid", "profile", "email", "phone", "offline_access"}

// oidcClaimsSupported mirrors upstream's claims_supported list verbatim.
var oidcClaimsSupported = []string{
	"sub",
	"aud",
	"iss",
	"exp",
	"iat",
	"auth_time",
	"nonce",
	"email",
	"email_verified",
	"phone_number",
	"phone_number_verified",
	"name",
	"picture",
	"preferred_username",
	"updated_at",
}

// wellKnownOpenID serves GET /.well-known/openid-configuration (upstream
// api.WellKnownOpenID).
//
// Two deliberate deviations from upstream:
//
//   - id_token_signing_alg_values_supported reports what this deployment can
//     actually verify — ["ES256"] with a key set, ["HS256"] on the symmetric-only
//     developer path, both while a rotation is in flight — instead of upstream's
//     hard-coded ["RS256","HS256","ES256"] (upstream carries a TODO to do the
//     same).
//   - The issuer falls back to SiteURL + /auth/v1 when JWT_ISSUER is unset,
//     because Dilion has no API_EXTERNAL_URL. Note that access tokens only carry
//     an `iss` claim when JWT_ISSUER is configured (upstream's
//     GOTRUE_JWT_ISSUER semantics, see JWTConfig.Issuer): a deployment whose
//     relying parties validate `iss` must set it explicitly.
//
// The authorization / token / userinfo endpoints are advertised
// unconditionally, relative to the issuer, exactly as upstream advertises them:
// the document is the upstream contract, not a capability probe, so a
// deployment with the OAuth server disabled still publishes the paths (they
// answer 404 feature_disabled). They are the real routes of oauthserver.go.
// registration_endpoint is the one exception — upstream emits it only when
// dynamic client registration can actually be used, and so does this.
func (a *api) wellKnownOpenID(w http.ResponseWriter, r *http.Request) error {
	ts, _ := a.tokensFor(r.Context()) // nil on an unconfigured mount: defaults below
	issuer := issuerURL(a.cfg, ts)

	resp := OpenIDConfigurationResponse{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oauth/authorize",
		TokenEndpoint:         issuer + "/oauth/token",
		JWKSURL:               issuer + "/.well-known/jwks.json",
		UserInfoEndpoint:      issuer + "/oauth/userinfo",

		ScopesSupported:                   supportedOAuthScopes,
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  signingAlgsSupported(ts),
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
		ClaimsSupported:                   oidcClaimsSupported,
	}

	// The registration endpoint is advertised only when a client could actually
	// register there, which is upstream's condition too.
	if a.cfg.OAuthServer.Enabled && OAuthServerAllowDynamicRegistration {
		resp.RegistrationEndpoint = issuer + "/oauth/clients/register"
	}

	w.Header().Set("Cache-Control", "public, max-age=600")
	return sendJSON(w, http.StatusOK, resp)
}

// signingAlgsSupported reports the algorithms a relying party may encounter:
// ES256 whenever a public key set is published, HS256 whenever the legacy secret
// is still accepted. Never empty — a discovery document without a signing
// algorithm is not usable, so an unconfigured mount advertises ES256.
func signingAlgsSupported(ts *TokenService) []string {
	var algs []string
	if ts != nil {
		algs = ts.validMethods()
	}
	if len(algs) == 0 {
		algs = []string{AlgES256}
	}
	return algs
}
