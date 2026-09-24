package auth

// POST /token?grant_type=id_token — sign in with an ID token the CLIENT already
// obtained (Sign in with Apple on iOS, Google One Tap, the Kakao SDK, …).
//
// Reproduces github.com/supabase/auth/internal/api/token_oidc.go: the token is
// verified against the issuer's published keys, its audience must be one of the
// configured client ids, the nonce must match, and the account is then resolved
// through exactly the same logic as the /callback flow.
//
// Errors use upstream's OAuth error body — {"error": …, "error_description": …} —
// rather than the gotrue HTTPError envelope, because that is what upstream's
// NewOAuthError produces for this grant and what clients parse.

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/ports"
)

func init() {
	// Upstream guards every grant with the refresh limit.
	registerGrant("id_token", LimiterToken, (*api).idTokenGrant)
}

// IDTokenGrantParams is the POST /token?grant_type=id_token body
// (upstream api.IdTokenGrantParams).
type IDTokenGrantParams struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	Nonce        string `json:"nonce"`
	Provider     string `json:"provider"`
	ClientID     string `json:"client_id"`
	Issuer       string `json:"issuer"`
	LinkIdentity bool   `json:"link_identity"`
}

// oauthErrorBody is upstream's OAuthError wire format.
type oauthErrorBody struct {
	Err         string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// sendOAuthError writes upstream's OAuth error body. Upstream answers every
// OAuthError with 400.
func sendOAuthError(w http.ResponseWriter, err, description string, args ...any) error {
	return sendJSON(w, http.StatusBadRequest, oauthErrorBody{
		Err:         err,
		Description: fmt.Sprintf(description, args...),
	})
}

// idTokenProviderResolution is what getIDTokenProvider works out from the
// request: which provider, which issuer to trust, and which audiences count.
type idTokenProviderResolution struct {
	ProviderType        string
	Issuer              string
	AcceptableIssuers   []string
	AcceptableClientIDs []string
	SkipNonceCheck      bool
}

// idTokenGrant is upstream's IdTokenGrant.
func (a *api) idTokenGrant(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params := &IDTokenGrantParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	if params.IDToken == "" {
		return sendOAuthError(w, "invalid request", "id_token required")
	}
	if params.Provider == "" && (params.ClientID == "" || params.Issuer == "") {
		return sendOAuthError(w, "invalid request", "provider or client_id and issuer required")
	}

	// link_identity turns the grant into a manual link onto the caller's account.
	var linkTarget *User
	if params.LinkIdentity {
		if r.Header.Get("Authorization") == "" {
			return sendOAuthError(w, "invalid request",
				"Linking requires a valid user access token in Authorization")
		}
		u, err := a.userFromBearer(r)
		if err != nil {
			return err
		}
		linkTarget = u
	}

	res, herr := a.resolveIDTokenProvider(params)
	if herr != nil {
		return herr
	}

	idt, err := a.verifyIDToken(ctx, res.Issuer, params.IDToken, idTokenOptions{
		AcceptableIssuers:    res.AcceptableIssuers,
		AccessToken:          params.AccessToken,
		SkipAccessTokenCheck: params.AccessToken == "",
	})
	if err != nil {
		a.log.WarnContext(ctx, "auth: id_token verification failed",
			"provider", res.ProviderType, "error", err.Error())
		return sendOAuthError(w, "invalid request", "Bad ID token")
	}
	if idt.Subject == "" {
		return sendOAuthError(w, "invalid request", "Missing sub claim in id_token")
	}

	// Audience: the token must be addressed to one of OUR client ids, otherwise
	// a token minted for a completely different app would sign its bearer in.
	correctAudience := false
	for _, clientID := range res.AcceptableClientIDs {
		if clientID != "" && containsString(idt.Audience, clientID) {
			correctAudience = true
			break
		}
	}
	if !correctAudience {
		return sendOAuthError(w, "invalid request", "Unacceptable audience in id_token: %v", idt.Audience)
	}

	if !res.SkipNonceCheck {
		tokenHasNonce := idt.Nonce != ""
		paramsHasNonce := params.Nonce != ""
		switch {
		case tokenHasNonce != paramsHasNonce:
			return sendOAuthError(w, "invalid request",
				"Passed nonce and nonce in id_token should either both exist or not.")
		case tokenHasNonce && paramsHasNonce:
			// The token carries the HASH of the nonce the client generated.
			if fmt.Sprintf("%x", sha256.Sum256([]byte(params.Nonce))) != idt.Nonce {
				return sendOAuthError(w, "invalid nonce", "Nonces mismatch")
			}
		}
	}

	data := parseIDTokenClaims(res.ProviderType, idt)
	data.applyPrimaryEmail()

	var (
		user    *User
		session *AccessTokenResponse
		created bool
	)
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		var terr error
		if linkTarget != nil {
			user, terr = a.linkIdentityToUser(ctx, tx, r, linkTarget.ID, data, res.ProviderType, false)
		} else {
			user, created, terr = a.createAccountFromExternalIdentity(ctx, tx, r, data, res.ProviderType, false)
		}
		if terr != nil {
			return terr
		}
		session, terr = a.grantSession(ctx, tx, user, r, amrOAuth)
		return terr
	}); err != nil {
		return err
	}

	if created {
		a.observeHook(ctx, ports.AfterSignup, map[string]any{
			"user_id":  user.ID,
			"email":    user.Email,
			"provider": res.ProviderType,
		})
	}

	return sendJSON(w, http.StatusOK, session)
}

// userFromBearer authenticates the Authorization header the way
// requireAuthentication does, for the handlers that need it INSIDE the handler
// rather than as middleware (upstream calls a.requireAuthentication here).
func (a *api) userFromBearer(r *http.Request) (*User, error) {
	token, err := extractBearerToken(r)
	if err != nil {
		return nil, err
	}
	claims, verr := a.verifyToken(r.Context(), token)
	if verr != nil {
		return nil, verr
	}
	pool, perr := a.db(r.Context())
	if perr != nil {
		return nil, perr
	}
	u, s, lerr := a.loadTokenUser(r.Context(), pool, claims)
	if lerr != nil {
		return nil, lerr
	}
	if s != nil && s.OAuthClientID != nil {
		return nil, forbiddenError(ErrorCodeOAuthClientToken, "An OAuth application's token cannot be used here")
	}
	return u, nil
}

// resolveIDTokenProvider is upstream's IdTokenGrantParams.getProvider, for the
// providers wave III ships.
//
// DILION DEVIATION: upstream still honours GOTRUE_EXTERNAL_ALLOWED_ID_TOKEN_ISSUERS
// (an arbitrary issuer + client_id, which upstream itself logs as deprecated
// "for security reasons"). Dilion has no such setting: an unknown issuer is
// rejected outright.
func (a *api) resolveIDTokenProvider(p *IDTokenGrantParams) (*idTokenProviderResolution, error) {
	name := strings.ToLower(strings.TrimSpace(p.Provider))
	res := &idTokenProviderResolution{}

	switch {
	case name == "apple" || isAppleIssuer(p.Issuer):
		detected, err := unverifiedIDTokenIssuer(p.IDToken)
		if err != nil {
			return nil, badRequestError(ErrorCodeValidationFailed,
				"Unable to detect issuer in ID token for Apple provider").withInternal(err)
		}
		if !isAppleIssuer(detected) {
			return nil, badRequestError(ErrorCodeValidationFailed,
				"Detected ID token issuer is not an Apple ID token issuer")
		}
		if p.Issuer != "" && p.Issuer != detected {
			return nil, badRequestError(ErrorCodeValidationFailed,
				"Provided issuer does not match ID token issuer")
		}
		res.ProviderType = "apple"
		// Apple signs with either host but publishes its keys under the
		// canonical issuer.
		res.Issuer = endpointsFor("apple", providerEndpoints{Issuer: DefaultAppleIssuer}).Issuer
		res.AcceptableIssuers = []string{DefaultAppleIssuer, OtherAppleIssuer}

	case name == "google" || p.Issuer == IssuerGoogle:
		res.ProviderType = "google"
		res.Issuer = endpointsFor("google", providerEndpoints{Issuer: IssuerGoogle}).Issuer

	case name == "kakao" || p.Issuer == IssuerKakao:
		res.ProviderType = "kakao"
		res.Issuer = endpointsFor("kakao", providerEndpoints{Issuer: IssuerKakao}).Issuer

	default:
		return nil, badRequestError(ErrorCodeValidationFailed,
			"Custom OIDC provider %q not allowed", p.Provider)
	}

	cfg := a.cfg.External[res.ProviderType]
	if !cfg.Enabled {
		return nil, badRequestError(ErrorCodeProviderDisabled,
			"Provider (issuer %q) is not enabled", res.Issuer)
	}
	res.AcceptableClientIDs = append(res.AcceptableClientIDs, cfg.ClientID...)
	res.SkipNonceCheck = cfg.SkipNonceCheck
	if len(res.AcceptableIssuers) == 0 {
		res.AcceptableIssuers = []string{res.Issuer}
	}
	return res, nil
}

// parseIDTokenClaims dispatches on the provider, exactly as upstream's
// provider.ParseIDToken dispatches on the issuer.
func parseIDTokenClaims(providerType string, t *idToken) *userProvidedData {
	switch providerType {
	case "google":
		return parseGoogleIDToken(t)
	case "apple":
		return parseAppleIDToken(t)
	case "kakao":
		return parseKakaoIDToken(t)
	}
	return parseGenericIDToken(t)
}

// parseGenericIDToken is upstream's provider.parseGenericIDToken: the standard
// OIDC claims, verbatim.
func parseGenericIDToken(t *idToken) *userProvidedData {
	c := t.Claims
	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:            t.Issuer,
			Subject:           t.Subject,
			Audience:          t.Audience,
			IssuedAt:          t.IssuedAt,
			Expires:           t.Expires,
			Name:              claimString(c, "name"),
			FamilyName:        claimString(c, "family_name"),
			GivenName:         claimString(c, "given_name"),
			MiddleName:        claimString(c, "middle_name"),
			NickName:          claimString(c, "nickname"),
			PreferredUsername: claimString(c, "preferred_username"),
			Profile:           claimString(c, "profile"),
			Picture:           claimString(c, "picture"),
			Website:           claimString(c, "website"),
			Gender:            claimString(c, "gender"),
			Birthdate:         claimString(c, "birthdate"),
			ZoneInfo:          claimString(c, "zoneinfo"),
			Locale:            claimString(c, "locale"),
			Email:             claimString(c, "email"),
			EmailVerified:     claimBool(c, "email_verified"),
			Phone:             claimString(c, "phone"),
			PhoneVerified:     claimBool(c, "phone_verified"),
		},
	}
	if data.Metadata.Email != "" {
		data.Emails = append(data.Emails, providerEmail{
			Email:    data.Metadata.Email,
			Verified: data.Metadata.EmailVerified,
			Primary:  true,
		})
	}
	return data
}
