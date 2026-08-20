package auth

// GET /authorize — the entry point of every external (social) login.
//
// Reproduces github.com/supabase/auth/internal/api/external.go
// (ExternalProviderRedirect / GetExternalProviderRedirectURL) and the parts of
// external_oauth.go and models/flow_state.go the OAuth flow needs.
//
// # Shape of an OAuth flow
//
//	GET /authorize?provider=github&redirect_to=…[&scopes=…][&code_challenge=…&code_challenge_method=s256]
//	  -> auth.flow_state row (authentication_method = "oauth", provider_type,
//	     referrer = the validated redirect_to, code_challenge for a PKCE flow)
//	  -> 302 to the provider, state = the flow state's UUID
//	GET|POST /callback?code=…&state=<flow state id>
//	  -> code exchanged for provider tokens, profile fetched, account resolved
//	  -> implicit flow: 302 to <referrer>#access_token=…&provider_token=…
//	  -> PKCE flow:     302 to <referrer>?code=<auth_code>, redeemed by
//	                    POST /token?grant_type=pkce
//
// # The `state` parameter
//
// state IS the flow state's id: a v4 UUID (122 bits from crypto/rand) that only
// exists as a row in auth.flow_state. This is upstream master's design and it
// replaced the signed-JWT state older gotrue releases used — the row is the
// tamper-proofing, because a state that is not a UUID, that names no row, that
// has expired, or whose row was already consumed is rejected outright, and none
// of the flow's context (provider, referrer, linking target, code challenge)
// ever leaves the server. See loadExternalState in external_callback.go.

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("external", func(a *api, r chi.Router) {
		r.Get("/authorize", a.handle(a.externalProviderRedirect))
		// Apple uses response_mode=form_post, so the callback must accept both.
		r.Get("/callback", a.handle(a.externalProviderCallback))
		r.Post("/callback", a.handle(a.externalProviderCallback))
	})
}

// ---- error codes (upstream apierrors/errorcode.go) -------------------------

const (
	// ErrorCodeBadOAuthState is a `state` that is not a UUID, names no flow
	// state, or names one that has expired.
	ErrorCodeBadOAuthState = "bad_oauth_state"
	// ErrorCodeBadOAuthCallback is a callback without `state` or without `code`.
	ErrorCodeBadOAuthCallback = "bad_oauth_callback"
	// ErrorCodeOAuthProviderNotSupported is a provider Dilion has no
	// implementation for.
	ErrorCodeOAuthProviderNotSupported = "oauth_provider_not_supported"
	// ErrorCodeProviderDisabled is a provider that exists but is switched off.
	ErrorCodeProviderDisabled = "provider_disabled"
	// ErrorCodeProviderEmailNeedsVerification is a sign-in whose provider email
	// is unverified while the project requires confirmed addresses.
	ErrorCodeProviderEmailNeedsVerification = "provider_email_needs_verification"
	// ErrorCodeFlowStateAlreadyUsed is a callback for a flow that already
	// produced an auth code.
	ErrorCodeFlowStateAlreadyUsed = "flow_state_already_used"
	// ErrorCodeIdentityAlreadyExists is a manual link of an identity that is
	// already attached to a user.
	ErrorCodeIdentityAlreadyExists = "identity_already_exists"
	// ErrorCodeIdentityNotFound is DELETE /user/identities/{id} for an identity
	// that is not the caller's.
	ErrorCodeIdentityNotFound = "identity_not_found"
	// ErrorCodeSingleIdentityNotDeletable is an attempt to unlink the last
	// identity of a user.
	ErrorCodeSingleIdentityNotDeletable = "single_identity_not_deletable"
	// ErrorCodeEmailConflictIdentityNotDeletable is an unlink that would promote
	// an email another account already owns.
	ErrorCodeEmailConflictIdentityNotDeletable = "email_conflict_identity_not_deletable"
	// ErrorCodeManualLinkingDisabled is /user/identities/authorize while
	// GOTRUE_SECURITY_MANUAL_LINKING_ENABLED is false.
	ErrorCodeManualLinkingDisabled = "manual_linking_disabled"
	// ErrorCodeUnexpectedAudience is a token whose `aud` is not the request's.
	ErrorCodeUnexpectedAudience = "unexpected_audience"
)

// authMethodOAuth is flow_state.authentication_method for an external login
// (upstream models.OAuth.String()).
const authMethodOAuth = "oauth"

// amrOAuth is the `amr` method recorded on a session issued by an external
// provider (upstream models.OAuth).
const amrOAuth = "oauth"

// ---- flow state ------------------------------------------------------------

// oauthFlowState is one auth.flow_state row as the OAuth flow uses it. It is a
// superset of pkce.go's flowState (which models the email flows and leaves the
// OAuth columns at their defaults) — the columns are the same row.
type oauthFlowState struct {
	ID                   string
	UserID               *string
	AuthCode             *string
	AuthenticationMethod string
	CodeChallenge        *string
	CodeChallengeMethod  *string
	ProviderType         string
	ProviderAccessToken  string
	ProviderRefreshToken string
	Referrer             string
	InviteToken          string
	LinkingTargetID      *string
	CreatedAt            time.Time
	AuthCodeIssuedAt     *time.Time
}

// IsPKCE reports whether the client asked for the PKCE flow.
func (f *oauthFlowState) IsPKCE() bool { return f.CodeChallenge != nil && *f.CodeChallenge != "" }

// IsExpired is upstream's FlowState.IsExpired for an OAuth flow: the clock runs
// from creation (only magic-link flows measure from the auth code's issuance).
func (f *oauthFlowState) IsExpired(now time.Time, expiry time.Duration) bool {
	return now.After(f.CreatedAt.Add(expiry))
}

const oauthFlowStateColumns = `id::text, user_id::text, auth_code, authentication_method,
	code_challenge, code_challenge_method::text, provider_type,
	coalesce(provider_access_token, ''), coalesce(provider_refresh_token, ''),
	coalesce(referrer, ''), coalesce(invite_token, ''), linking_target_id::text,
	created_at, auth_code_issued_at`

func scanOAuthFlowState(row pgx.Row) (*oauthFlowState, error) {
	var (
		f         oauthFlowState
		createdAt *time.Time
	)
	if err := row.Scan(&f.ID, &f.UserID, &f.AuthCode, &f.AuthenticationMethod,
		&f.CodeChallenge, &f.CodeChallengeMethod, &f.ProviderType,
		&f.ProviderAccessToken, &f.ProviderRefreshToken,
		&f.Referrer, &f.InviteToken, &f.LinkingTargetID,
		&createdAt, &f.AuthCodeIssuedAt); err != nil {
		return nil, err
	}
	if createdAt != nil {
		f.CreatedAt = createdAt.UTC()
	}
	f.AuthCodeIssuedAt = utc(f.AuthCodeIssuedAt)
	return &f, nil
}

// newOAuthFlowStateParams is the row GET /authorize creates.
type newOAuthFlowStateParams struct {
	ProviderType        string
	CodeChallenge       string
	CodeChallengeMethod string
	Referrer            string
	LinkingTargetID     string
	Now                 time.Time
}

// createOAuthFlowState inserts the flow state of an external login.
//
// Unlike pkce.go's createFlowState it tolerates an ABSENT code challenge: an
// implicit OAuth flow needs a row too (it carries the provider, the referrer and
// the linking target), and upstream master creates one for every flow.
// auth_code is minted up front and only handed out for a PKCE flow.
func createOAuthFlowState(ctx context.Context, q querier, p newOAuthFlowStateParams) (*oauthFlowState, error) {
	var method *string
	if p.CodeChallenge != "" {
		m, err := parseCodeChallengeMethod(p.CodeChallengeMethod)
		if err != nil {
			return nil, badRequestError(ErrorCodeValidationFailed, "%v", err)
		}
		method = &m
	}
	var challenge *string
	if p.CodeChallenge != "" {
		challenge = &p.CodeChallenge
	}
	var linkingTarget *string
	if p.LinkingTargetID != "" {
		linkingTarget = &p.LinkingTargetID
	}
	authCode := uuid.NewString()

	return scanOAuthFlowState(q.QueryRow(ctx, `
		insert into auth.flow_state (
			id, auth_code, code_challenge_method, code_challenge,
			provider_type, authentication_method, referrer, linking_target_id,
			created_at, updated_at
		) values (
			$1::uuid, $2, $3::auth.code_challenge_method, $4,
			$5, $6, nullif($7, ''), $8::uuid,
			$9, $9
		)
		returning `+oauthFlowStateColumns,
		uuid.NewString(), authCode, method, challenge,
		p.ProviderType, authMethodOAuth, p.Referrer, linkingTarget, p.Now))
}

func findOAuthFlowStateByID(ctx context.Context, q querier, id string) (*oauthFlowState, error) {
	return scanOAuthFlowState(q.QueryRow(ctx,
		`select `+oauthFlowStateColumns+` from auth.flow_state where id = $1::uuid`, id))
}

// findOAuthFlowStateByIDForUpdate locks the row so two concurrent callbacks for
// the same state cannot both claim it.
func findOAuthFlowStateByIDForUpdate(ctx context.Context, q querier, id string) (*oauthFlowState, error) {
	return scanOAuthFlowState(q.QueryRow(ctx,
		`select `+oauthFlowStateColumns+` from auth.flow_state where id = $1::uuid for update`, id))
}

// claimOAuthFlowState finishes a PKCE flow: it records the user the callback
// resolved together with the provider's tokens, which POST /token?grant_type=pkce
// later reads.
func claimOAuthFlowState(ctx context.Context, q querier, id, userID, providerToken, providerRefreshToken string, now time.Time) error {
	_, err := q.Exec(ctx, `
		update auth.flow_state set
			user_id = $2::uuid,
			provider_access_token = nullif($3, ''),
			provider_refresh_token = nullif($4, ''),
			auth_code_issued_at = $5,
			updated_at = $5
		where id = $1::uuid`, id, userID, providerToken, providerRefreshToken, now)
	return err
}

// ---- GET /authorize --------------------------------------------------------

// externalProviderRedirect is upstream's ExternalProviderRedirect.
func (a *api) externalProviderRedirect(w http.ResponseWriter, r *http.Request) error {
	return a.startExternalProviderFlow(w, r, nil)
}

// startExternalProviderFlow builds the provider's authorization URL and answers
// with it. `linkingTarget` is non-nil for manual identity linking
// (/user/identities/authorize), which is upstream's LinkIdentity path.
func (a *api) startExternalProviderFlow(w http.ResponseWriter, r *http.Request, linkingTarget *User) error {
	ctx := r.Context()
	query := r.URL.Query()

	providerType := strings.ToLower(strings.TrimSpace(query.Get("provider")))
	scopes := query.Get("scopes")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	p, _, err := a.provider(ctx, providerType, scopes)
	if err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Unsupported provider: %+v", err).withInternal(err)
	}
	if err := validatePKCEParams(codeChallengeMethod, codeChallenge); err != nil {
		return err
	}

	// Upstream forwards every unrecognised query parameter to the provider
	// (prompt, access_type, login_hint, …).
	extra := url.Values{}
	for key, vals := range query {
		switch key {
		case "provider", "scopes", "code_challenge", "code_challenge_method",
			"redirect_to", "skip_http_redirect":
			continue
		}
		if len(vals) > 0 {
			extra.Set(key, vals[0])
		}
	}

	redirectURL := a.cfg.RedirectURLOrSiteURL(query.Get("redirect_to"), r.Referer())

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	params := newOAuthFlowStateParams{
		ProviderType:        providerType,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Referrer:            redirectURL,
		Now:                 a.now(),
	}
	if linkingTarget != nil {
		params.LinkingTargetID = linkingTarget.ID
	}
	fs, ferr := createOAuthFlowState(ctx, pool, params)
	if ferr != nil {
		if he, ok := ferr.(*HTTPError); ok {
			return he
		}
		return internalServerError("Error creating flow state").withInternal(ferr)
	}

	authURL := p.authCodeURL(fs.ID, extra)
	if authURL == "" {
		return internalServerError("Error building the provider authorization URL")
	}

	a.log.InfoContext(ctx, "auth: redirecting to external provider",
		slog.String("provider", providerType), slog.String("flow_state", fs.ID))

	// skip_http_redirect answers with the URL instead of a 302 — upstream does
	// this on the identity-linking route; Dilion accepts it on /authorize too,
	// which is what a native client needs to open its own browser tab.
	if query.Get("skip_http_redirect") == "true" || wantsJSON(r) {
		return sendJSON(w, http.StatusOK, map[string]any{"url": authURL})
	}
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

// wantsJSON reports whether the caller asked for a JSON body rather than a
// browser redirect.
func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return accept != "" && strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

// ---- redirect helpers ------------------------------------------------------

// externalRedirectURL is upstream's getExternalRedirectURL: the referrer the
// flow was started with, otherwise SiteURL. The value stored on the flow state
// was already validated against the allow-list at /authorize time; it is
// re-validated here so a row written by an older/looser build cannot redirect
// off the allow-list.
func (a *api) externalRedirectURL(fs *oauthFlowState) string {
	if fs != nil && fs.Referrer != "" && a.cfg.IsRedirectAllowed(fs.Referrer) {
		return fs.Referrer
	}
	return a.cfg.SiteURL
}

// redirectWithError is upstream's redirectErrors: a failed OAuth flow bounces
// back to the client with the error in the query string AND (deprecated
// upstream, still emitted) in the fragment.
func (a *api) redirectExternalError(w http.ResponseWriter, r *http.Request, rurl string, err error, status int) {
	u, perr := url.Parse(rurl)
	if perr != nil {
		// The redirect target is unusable: answer in the error envelope.
		a.writeError(r, w, err)
		return
	}

	q := u.Query()
	oauthErr, description, code := oauthErrorQuery(err)
	q.Set("error", oauthErr)
	q.Set("error_description", description)
	if code != "" {
		q.Set("error_code", code)
	}
	u.RawQuery = q.Encode()

	hq := url.Values{}
	hq.Set("error", oauthErr)
	hq.Set("error_description", description)
	if code != "" {
		hq.Set("error_code", code)
	}
	hq.Set("sb", "")
	u.Fragment = hq.Encode()

	a.logRedirectError(r, err)
	http.Redirect(w, r, u.String(), status)
}

func (a *api) logRedirectError(r *http.Request, err error) {
	he, ok := err.(*HTTPError)
	if ok && he.HTTPStatus < http.StatusInternalServerError {
		a.log.InfoContext(r.Context(), "auth: external provider flow failed",
			slog.String("error", he.Error()))
		return
	}
	a.log.ErrorContext(r.Context(), "auth: external provider flow failed",
		slog.String("error", err.Error()))
}

// oauthErrorQuery is upstream's getErrorQueryString: the mapping from an
// internal error to the OAuth 2.0 error triple a client sees.
func oauthErrorQuery(err error) (oauthErr, description, code string) {
	// An error the PROVIDER reported is handed through as it arrived.
	if pe, ok := err.(*providerOAuthError); ok {
		return pe.Err, pe.Description, ""
	}
	he, ok := err.(*HTTPError)
	if !ok {
		return "server_error", err.Error(), ""
	}
	switch he.ErrorCode {
	case ErrorCodeSignupDisabled, ErrorCodeUserBanned, ErrorCodeProviderEmailNeedsVerification:
		oauthErr = "access_denied"
	default:
		oauthErr = "server_error"
		if mapped, found := oauthErrorForStatus[he.HTTPStatus]; found {
			oauthErr = mapped
		}
	}
	return oauthErr, he.Message, he.ErrorCode
}
