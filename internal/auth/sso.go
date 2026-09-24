package auth

// POST /sso — the entry point of every SAML 2.0 single sign-on.
//
// Reproduces github.com/supabase/auth/internal/api/sso.go (SingleSignOn) and
// the /sso route group of internal/api/api.go.
//
// # Shape of an SSO flow
//
//	POST /sso  {provider_id | domain, redirect_to, skip_http_redirect,
//	            code_challenge, code_challenge_method}
//	  -> auth.flow_state row (authentication_method = provider_type = "sso/saml")
//	  -> auth.saml_relay_states row (request_id = the AuthnRequest's ID,
//	     flow_state_id -> the flow state, redirect_to = the client's target)
//	  -> 303 to the IdP's SSO endpoint with SAMLRequest + RelayState=<row id>,
//	     or {"url": "..."} when skip_http_redirect is true
//	POST /sso/saml/acs  SAMLResponse=<assertion>&RelayState=<row id>
//	  -> implicit flow: 302 to <redirect_to>#access_token=…
//	  -> PKCE flow:     302 to <redirect_to>?code=<auth_code>
//
// # Why the RelayState is a database row
//
// The RelayState is the only value that survives the round trip through the
// IdP, and it is a bare UUID: everything else about the flow (which provider,
// where the client wanted to land, which AuthnRequest the assertion must answer,
// which PKCE challenge is in play) stays server-side in auth.saml_relay_states
// and auth.flow_state. An assertion is therefore only accepted if it is an
// InResponseTo of a request this server minted, within
// DefaultSAMLRelayStateValidityPeriod, and the row dies on first use.

import (
	"context"
	"net/http"
	"time"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("sso", func(a *api, r chi.Router) {
		r.Route("/sso", func(r chi.Router) {
			r.Use(a.requireSAMLEnabled)
			r.With(a.limit(LimiterSSO)).Post("/", a.handle(a.singleSignOn))

			r.Get("/saml/metadata", a.handle(a.samlMetadata))
			// The ACS is a browser POST from the IdP, so it carries no bearer
			// token and cannot be rate-limited per user. Upstream limits it per
			// IP with its own SAML_ASSERTION limiter; Dilion folds it into the
			// SSO limiter, which Config already exposes (GOTRUE_RATE_LIMIT_SSO).
			r.With(a.limit(LimiterSSO)).Post("/saml/acs", a.handle(a.samlACS))
		})
	})
}

// requireSAMLEnabled is upstream's middleware of the same name: with SAML off
// the whole /sso surface answers 404, not 403 — an unconfigured deployment must
// not advertise that the routes exist.
func (a *api) requireSAMLEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.cfg.SAML.Enabled {
			a.writeError(r, w, notFoundError(ErrorCodeSAMLProviderDisabled, "SAML 2.0 is disabled"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SingleSignOnParams is the POST /sso body (upstream api.SingleSignOnParams).
type SingleSignOnParams struct {
	ProviderID          string `json:"provider_id"`
	Domain              string `json:"domain"`
	RedirectTo          string `json:"redirect_to"`
	SkipHTTPRedirect    *bool  `json:"skip_http_redirect"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// SingleSignOnResponse is the skip_http_redirect body
// (upstream api.SingleSignOnResponse).
type SingleSignOnResponse struct {
	URL string `json:"url"`
}

// validate is upstream's SingleSignOnParams.validate: exactly one of
// provider_id / domain. The bool reports which one was given.
func (p *SingleSignOnParams) validate() (bool, error) {
	hasProviderID := p.ProviderID != "" && p.ProviderID != uuid.Nil.String()
	hasDomain := p.Domain != ""

	switch {
	case hasProviderID && hasDomain:
		return hasProviderID, badRequestError(ErrorCodeValidationFailed, "Only one of provider_id or domain supported")
	case !hasProviderID && !hasDomain:
		return hasProviderID, badRequestError(ErrorCodeValidationFailed, "A provider_id or domain needs to be provided")
	}
	return hasProviderID, nil
}

// singleSignOn is upstream's API.SingleSignOn.
func (a *api) singleSignOn(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	if err := a.verifyCaptcha(r); err != nil {
		return err
	}

	params := &SingleSignOnParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	hasProviderID, err := params.validate()
	if err != nil {
		return err
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}

	var ssoProvider *SSOProvider
	if hasProviderID {
		// A malformed UUID cannot name a row; upstream's uuid.UUID parameter
		// would have failed to decode, producing the same "no such provider".
		if _, uerr := uuid.Parse(params.ProviderID); uerr != nil {
			return notFoundError(ErrorCodeSSOProviderNotFound, "No such SSO provider")
		}
		ssoProvider, err = findSSOProviderByID(ctx, pool, params.ProviderID)
		if err != nil {
			if isNoRows(err) {
				return notFoundError(ErrorCodeSSOProviderNotFound, "No such SSO provider")
			}
			return internalServerError("Unable to find SSO provider by ID").withInternal(err)
		}
	} else {
		ssoProvider, err = findSSOProviderByDomain(ctx, pool, params.Domain)
		if err != nil {
			if isNoRows(err) {
				return notFoundError(ErrorCodeSSOProviderNotFound, "No SSO provider assigned for this domain")
			}
			return internalServerError("Unable to find SSO provider by domain").withInternal(err)
		}
	}

	if !ssoProvider.IsEnabled() {
		return notFoundError(ErrorCodeSSOProviderDisabled, "SSO Provider is currently disabled")
	}

	if err := validatePKCEParams(params.CodeChallengeMethod, params.CodeChallenge); err != nil {
		return err
	}

	entityDescriptor, err := parseSAMLMetadata([]byte(ssoProvider.SAMLProvider.MetadataXML))
	if err != nil {
		return internalServerError("Error parsing SAML Metadata for SAML provider").withInternal(err)
	}

	sp, err := a.newSAMLServiceProvider(ctx, entityDescriptor, false /* idpInitiated */)
	if err != nil {
		return err
	}

	authnRequest, err := sp.MakeAuthenticationRequest(
		sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return internalServerError("Error creating SAML Authentication Request").withInternal(err)
	}
	// Some IdPs reject the `persistent` NameID format and need another one.
	if ssoProvider.SAMLProvider.NameIDFormat != nil {
		authnRequest.NameIDPolicy.Format = ssoProvider.SAMLProvider.NameIDFormat
	}

	// The redirect target is validated HERE, against the allow-list, and stored
	// on the relay state; the ACS re-validates before using it. A SAML flow must
	// never become an open redirect.
	redirectTo := a.site(ctx).RedirectURLOrSiteURL(params.RedirectTo, r.Referer())

	relayState := &samlRelayState{
		SSOProviderID: ssoProvider.ID,
		RequestID:     authnRequest.ID,
		RedirectTo:    redirectTo,
	}

	now := a.now()
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		// Upstream always creates a flow state, PKCE or not: it is what carries
		// the auth code of a PKCE exchange and, for the implicit flow, the
		// record that the flow existed.
		fs, ferr := createSSOFlowState(ctx, tx, params.CodeChallengeMethod, params.CodeChallenge, redirectTo, now)
		if ferr != nil {
			if he, ok := ferr.(*HTTPError); ok {
				return he
			}
			return internalServerError("Error creating flow state").withInternal(ferr)
		}
		relayState.FlowStateID = &fs.ID

		if rerr := insertSAMLRelayState(ctx, tx, relayState, now); rerr != nil {
			return internalServerError("Error creating SAML relay state from sign up").withInternal(rerr)
		}
		return nil
	}); err != nil {
		return err
	}

	ssoRedirectURL, err := authnRequest.Redirect(relayState.ID, sp)
	if err != nil {
		return internalServerError("Error creating SAML authentication request redirect URL").withInternal(err)
	}

	skipHTTPRedirect := false
	if params.SkipHTTPRedirect != nil {
		skipHTTPRedirect = *params.SkipHTTPRedirect
	}
	if skipHTTPRedirect {
		return sendJSON(w, http.StatusOK, SingleSignOnResponse{URL: ssoRedirectURL.String()})
	}

	http.Redirect(w, r, ssoRedirectURL.String(), http.StatusSeeOther)
	return nil
}

// createSSOFlowState inserts the auth.flow_state row of an SSO flow.
//
// It is external.go's createOAuthFlowState with authentication_method and
// provider_type set to "sso/saml" (upstream models.SSOSAML.String(), used for
// BOTH fields in api/sso.go's FlowStateParams). The row is read back through
// external.go's oauthFlowState helpers — same table, same columns.
func createSSOFlowState(ctx context.Context, q querier, codeChallengeMethod, codeChallenge, referrer string, now time.Time) (*oauthFlowState, error) {
	var method *string
	var challenge *string
	if codeChallenge != "" {
		m, err := parseCodeChallengeMethod(codeChallengeMethod)
		if err != nil {
			return nil, badRequestError(ErrorCodeValidationFailed, "%v", err)
		}
		method = &m
		challenge = &codeChallenge
	}
	return scanOAuthFlowState(q.QueryRow(ctx, `
		insert into auth.flow_state (
			id, auth_code, code_challenge_method, code_challenge,
			provider_type, authentication_method, referrer,
			created_at, updated_at
		) values (
			$1::uuid, $2, $3::auth.code_challenge_method, $4,
			$5, $5, nullif($6, ''),
			$7, $7
		)
		returning `+oauthFlowStateColumns,
		uuid.NewString(), uuid.NewString(), method, challenge,
		authMethodSSOSAML, referrer, now))
}
