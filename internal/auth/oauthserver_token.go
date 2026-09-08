package auth

// POST /oauth/token — the token endpoint of the OAuth 2.1 server.
//
// This is NOT /token. The gotrue-compatible /token endpoint speaks the Supabase
// session envelope (a full user object, `expires_at`, …) and answers errors in
// the gotrue {code,error_code,msg} form; THIS endpoint speaks RFC 6749 to a
// third-party OAuth client: a bare token response and {"error",
// "error_description"} bodies with HTTP 400. Upstream keeps the two apart the
// same way (internal/api/oauthserver/handlers.go OAuthToken).
//
// Supported grants:
//
//	authorization_code  redeem the code minted by the consent flow (+ PKCE)
//	refresh_token       rotate an OAuth session's refresh token
//
// The client is authenticated by requireOAuthClientAuth (oauthserver.go) before
// this handler runs, so its errors are the gotrue-style 400 invalid_credentials
// — matching upstream, where client authentication is middleware and only the
// GRANT is RFC 6749.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-project/dilion/ports"
)

// OAuthTokenParams is the POST /oauth/token body, accepted as JSON or as
// application/x-www-form-urlencoded (upstream OAuthTokenParams).
type OAuthTokenParams struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RefreshToken string `json:"refresh_token"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CodeVerifier string `json:"code_verifier"`
	Resource     string `json:"resource"`
}

// OAuthTokenResponse is the RFC 6749 §5.1 success body. Note what is NOT here:
// the user object and `expires_at` of the gotrue session envelope. An OAuth
// client learns about the user from the id_token or /oauth/userinfo.
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
}

// oauthToken handles POST /oauth/token.
func (a *api) oauthToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params, err := parseOAuthTokenParams(r)
	if err != nil {
		return err
	}
	if params.GrantType == "" {
		return oauthError(oAuth2ErrorInvalidRequest, "grant_type is required")
	}

	client := oauthClientFrom(ctx)
	if client == nil {
		return oauthError(oAuth2ErrorInvalidClient, "Client authentication required")
	}
	if !client.IsGrantTypeAllowed(params.GrantType) {
		return oauthError(oAuth2ErrorUnsupportedGrantType, "Client is not allowed to use grant type: %s", params.GrantType)
	}

	switch params.GrantType {
	case GrantTypeAuthorizationCode:
		return a.oauthAuthorizationCodeGrant(w, r, client, params)
	case GrantTypeRefreshToken:
		return a.oauthRefreshTokenGrant(w, r, client, params)
	default:
		return oauthError(oAuth2ErrorUnsupportedGrantType, "Unsupported grant type: %s", params.GrantType)
	}
}

// parseOAuthTokenParams reads the request body as JSON or as a form.
func parseOAuthTokenParams(r *http.Request) (*OAuthTokenParams, error) {
	params := &OAuthTokenParams{}

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(params); err != nil {
			return nil, oauthError(oAuth2ErrorInvalidRequest, "Invalid JSON body")
		}
		return params, nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, oauthError(oAuth2ErrorInvalidRequest, "Failed to parse form data")
	}
	params.GrantType = r.FormValue("grant_type")
	params.Code = r.FormValue("code")
	params.RefreshToken = r.FormValue("refresh_token")
	params.RedirectURI = r.FormValue("redirect_uri")
	params.ClientID = r.FormValue("client_id")
	params.ClientSecret = r.FormValue("client_secret")
	params.CodeVerifier = r.FormValue("code_verifier")
	params.Resource = r.FormValue("resource")
	return params, nil
}

// ---- authorization_code ----------------------------------------------------

// oauthAuthorizationCodeGrant redeems an authorization code.
//
// Every failure mode is reported as `invalid_grant`, deliberately without
// distinguishing "no such code" from "expired", "wrong client" or "already
// used": the endpoint must not become an oracle for codes it has issued.
//
// The code is SINGLE USE. The authorization row is re-read FOR UPDATE inside the
// issuing transaction and destroyed as the tokens are minted, so two concurrent
// redemptions cannot both produce a session.
func (a *api) oauthAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client *oauthClient, params *OAuthTokenParams) error {
	ctx := r.Context()

	if params.Code == "" {
		return oauthError(oAuth2ErrorInvalidRequest, "code is required for authorization_code grant")
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}

	authorization, err := findOAuthAuthorizationByCode(ctx, pool, params.Code)
	if err != nil {
		if isNoRows(err) {
			return oauthError(oAuth2ErrorInvalidGrant, "Invalid authorization code")
		}
		return internalServerError("Error finding authorization code").withInternal(err)
	}
	if authorization.IsExpired(a.now()) {
		return oauthError(oAuth2ErrorInvalidGrant, "Authorization code has expired")
	}
	if authorization.ClientID != client.ID {
		return oauthError(oAuth2ErrorInvalidGrant, "Authorization code was not issued for this client")
	}
	if params.Resource != "" && params.Resource != deref(authorization.Resource) {
		return oauthError(oAuth2ErrorInvalidGrant, "Authorization code resource does not match the resource parameter")
	}
	if params.RedirectURI != "" && params.RedirectURI != authorization.RedirectURI {
		return oauthError(oAuth2ErrorInvalidGrant, "Invalid redirect_uri")
	}
	if err := authorization.VerifyPKCE(params.CodeVerifier); err != nil {
		return oauthError(oAuth2ErrorInvalidGrant, "PKCE verification failed: %s", err.Error())
	}
	if authorization.UserID == nil {
		return oauthError(oAuth2ErrorInvalidGrant, "Authorization code has no associated user")
	}

	var (
		resp      OAuthTokenResponse
		grantUser *User
	)
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		// Re-read under the row lock: the loser of a concurrent redemption
		// finds the row gone and is told the code is invalid.
		locked, lerr := findOAuthAuthorizationForUpdate(ctx, tx, authorization.AuthorizationID)
		if lerr != nil {
			if isNoRows(lerr) {
				return oauthError(oAuth2ErrorInvalidGrant, "Invalid authorization code")
			}
			return internalServerError("Error locking authorization code").withInternal(lerr)
		}
		if locked.Status != OAuthAuthorizationApproved || deref(locked.AuthorizationCode) != params.Code {
			return oauthError(oAuth2ErrorInvalidGrant, "Invalid authorization code")
		}

		user, uerr := a.loadUserWithIdentities(ctx, tx, *authorization.UserID)
		if uerr != nil {
			if isNoRows(uerr) {
				return oauthError(oAuth2ErrorInvalidGrant, "User not found for authorization code")
			}
			return internalServerError("Error finding user").withInternal(uerr)
		}
		if user.DeletedAt != nil {
			return oauthError(oAuth2ErrorInvalidGrant, "User not found for authorization code")
		}
		if user.IsBanned(a.now()) {
			return oauthError(oAuth2ErrorAccessDenied, "User is banned")
		}
		grantUser = user

		sessionID, refresh, serr := a.grantOAuthSession(ctx, tx, user, r, client.ID, locked.Scope)
		if serr != nil {
			return serr
		}
		accessToken, expiresAt, terr := a.issueOAuthAccessToken(ctx, tx, user, sessionID, client.ID, locked.Scope)
		if terr != nil {
			return terr
		}

		// Single use: the code dies with the tokens it produced.
		if derr := deleteOAuthAuthorization(ctx, tx, locked.ID); derr != nil {
			return internalServerError("Error consuming authorization code").withInternal(derr)
		}

		resp = OAuthTokenResponse{
			AccessToken:  accessToken,
			TokenType:    "bearer",
			ExpiresIn:    int(time.Until(expiresAt).Round(time.Second).Seconds()),
			RefreshToken: refresh,
		}
		return nil
	}); err != nil {
		return err
	}

	// OIDC: an `openid` scope earns an ID token, signed ES256 like the access
	// token but audienced at the CLIENT, not at `authenticated`.
	if hasScope(authorization.GetScopeList(), ScopeOpenID) {
		idToken, err := a.signIDToken(idTokenParams{
			User:     grantUser,
			ClientID: client.ID,
			Nonce:    deref(authorization.Nonce),
			Scopes:   authorization.GetScopeList(),
		})
		if err != nil {
			return internalServerError("Error generating ID token").withInternal(err)
		}
		resp.IDToken = idToken
	}

	return sendJSON(w, http.StatusOK, resp)
}

// grantOAuthSession creates the session an OAuth client's tokens hang off:
// a normal auth.sessions row that additionally carries oauth_client_id and the
// granted scopes, so every access token minted for it reports `client_id` and
// `scope`, and revoking the grant can find it.
func (a *api) grantOAuthSession(ctx context.Context, tx querier, u *User, r *http.Request, clientID, scope string) (string, string, error) {
	now := a.now()
	sessionID := uuid.NewString()

	if err := insertSession(ctx, tx, sessionID, u.ID, r.UserAgent(), clientIPInet(r), now); err != nil {
		return "", "", internalServerError("Error creating session").withInternal(err)
	}
	if err := markSessionOAuth(ctx, tx, sessionID, clientID, scope); err != nil {
		return "", "", internalServerError("Error creating session").withInternal(err)
	}
	if err := addAMRClaimToSession(ctx, tx, sessionID, oauthAMRMethod, now); err != nil {
		return "", "", internalServerError("Error recording authentication method").withInternal(err)
	}

	refresh, err := newRefreshToken()
	if err != nil {
		return "", "", internalServerError("Error generating refresh token").withInternal(err)
	}
	if err := insertRefreshToken(ctx, tx, refresh, u.ID, "", sessionID, now); err != nil {
		return "", "", internalServerError("Error creating refresh token").withInternal(err)
	}
	if _, err := updateUserFields(ctx, tx, u.ID, now, map[string]any{"last_sign_in_at": now}); err != nil {
		return "", "", internalServerError("Error updating user").withInternal(err)
	}
	u.LastSignInAt = &now
	u.UpdatedAt = now

	return sessionID, refresh, nil
}

// issueOAuthAccessToken signs the access token of an OAuth session. It is
// api.issueAccessToken plus the two OAuth claims upstream adds
// (v0hooks.AccessTokenClaims.ClientID / .Scope): `client_id` names the client
// the token was issued to, `scope` the scopes it may exercise — /oauth/userinfo
// and any resource server read them.
func (a *api) issueOAuthAccessToken(ctx context.Context, q querier, u *User, sessionID, clientID, scope string) (string, time.Time, error) {
	now := a.now()
	expiresAt := now.Add(a.tokens.TTL())

	claims, cerr := findAMRClaims(ctx, q, sessionID)
	if cerr != nil {
		return "", time.Time{}, internalServerError("Database error loading AMR claims").withInternal(cerr)
	}
	aal, amr := computeAAL(claims)

	extra := map[string]any{
		"phone":         u.Phone,
		"app_metadata":  map[string]any(u.AppMetaData),
		"user_metadata": map[string]any(u.UserMetaData),
		"is_anonymous":  u.IsAnonymous,
		"session_id":    sessionID,
		"aal":           aal,
		"amr":           amr,
		"client_id":     clientID,
		"scope":         scope,
	}

	extra, err := a.runHook(ctx, ports.TokenClaims, extra)
	if err != nil {
		return "", time.Time{}, internalServerError("Error running token claims hook").withInternal(err)
	}

	role := userTokenRole(u.Role)
	aud := u.Aud
	if aud == "" {
		aud = AudienceAuthenticated
	}

	token, err := a.tokens.Sign(ctx, ports.Claims{
		Subject:   u.ID,
		Role:      role,
		Email:     u.Email,
		Audience:  aud,
		ExpiresAt: expiresAt,
		Extra:     extra,
	})
	if err != nil {
		return "", time.Time{}, internalServerError("Error generating access token").withInternal(err)
	}
	return token, expiresAt, nil
}

// ---- refresh_token ---------------------------------------------------------

// oauthRefreshTokenGrant rotates the refresh token of an OAuth session.
//
// It is the /token refresh grant (grant.go) with two OAuth rules added, both
// from upstream tokens.Service.RefreshTokenGrant:
//
//   - the session's oauth_client_id MUST equal the authenticated client, so one
//     client can never refresh another's session;
//   - a session with NO oauth_client_id (an ordinary password/OTP sign-in) is
//     not refreshable here at all.
//
// The reuse policy is the same as /token's: inside
// Security.RefreshTokenReuseInterval a replayed token returns the session's
// current token, beyond it the whole family is revoked and the session
// destroyed.
func (a *api) oauthRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client *oauthClient, params *OAuthTokenParams) error {
	ctx := r.Context()

	if params.RefreshToken == "" {
		return oauthError(oAuth2ErrorInvalidRequest, "refresh_token is required for refresh_token grant")
	}

	var resp OAuthTokenResponse
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		rt, err := findRefreshTokenForUpdate(ctx, tx, params.RefreshToken)
		if err != nil {
			if isNoRows(err) {
				return oauthError(oAuth2ErrorInvalidGrant, "Invalid Refresh Token: Refresh Token Not Found")
			}
			return internalServerError("Error loading refresh token").withInternal(err)
		}

		now := a.now()

		var sess *session
		if rt.SessionID != nil {
			sess, err = findSessionByID(ctx, tx, *rt.SessionID)
			if err != nil {
				if !isNoRows(err) {
					return internalServerError("Error loading session").withInternal(err)
				}
				sess = nil
			}
		}
		if rt.SessionID == nil || sess == nil {
			return oauthError(oAuth2ErrorInvalidGrant, "Invalid Refresh Token: No Valid Session Found")
		}

		meta, merr := findOAuthSessionMeta(ctx, tx, sess.ID)
		if merr != nil {
			return internalServerError("Error loading session").withInternal(merr)
		}
		if meta.ClientID == nil || *meta.ClientID == "" {
			return oauthError(oAuth2ErrorInvalidClient, "Client authentication not allowed for non-OAuth session")
		}
		if *meta.ClientID != client.ID {
			return oauthError(oAuth2ErrorInvalidClient, "Client does not match the session's OAuth client")
		}
		scope := deref(meta.Scopes)

		if rt.Revoked {
			token, rerr := a.oauthReuseRefreshToken(ctx, tx, r, rt, sess, client.ID, scope, now)
			if rerr != nil {
				return rerr
			}
			resp = *token
			return nil
		}

		if serr := a.checkSessionValidity(ctx, tx, sess, rt, now); serr != nil {
			return serr
		}
		user, uerr := a.loadRefreshUser(ctx, tx, sess.UserID, now)
		if uerr != nil {
			return uerr
		}

		if err := revokeRefreshToken(ctx, tx, rt.ID, now); err != nil {
			return internalServerError("Error revoking refresh token").withInternal(err)
		}
		next, err := newRefreshToken()
		if err != nil {
			return internalServerError("Error generating refresh token").withInternal(err)
		}
		if err := insertRefreshToken(ctx, tx, next, rt.UserID, rt.Token, sess.ID, now); err != nil {
			return internalServerError("Error creating refresh token").withInternal(err)
		}
		if err := touchSession(ctx, tx, sess.ID, now); err != nil {
			return internalServerError("Error updating session").withInternal(err)
		}

		accessToken, expiresAt, terr := a.issueOAuthAccessToken(ctx, tx, user, sess.ID, client.ID, scope)
		if terr != nil {
			return terr
		}
		resp = OAuthTokenResponse{
			AccessToken:  accessToken,
			TokenType:    "bearer",
			ExpiresIn:    int(time.Until(expiresAt).Round(time.Second).Seconds()),
			RefreshToken: next,
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, resp)
}

// oauthReuseRefreshToken is the OAuth mirror of handleRefreshTokenReuse: inside
// the reuse interval the session's ACTIVE token is handed back (a client that
// lost the response of its last refresh), beyond it the family is revoked, the
// session destroyed, and the punishment committed with commitAndFail.
func (a *api) oauthReuseRefreshToken(ctx context.Context, tx querier, r *http.Request,
	rt *refreshToken, sess *session, clientID, scope string, now time.Time) (*OAuthTokenResponse, error) {

	window := a.cfg.Security.ReuseIntervalDuration()
	if window > 0 && now.Before(rt.UpdatedAt.Add(window)) {
		active, err := findActiveRefreshTokenForSession(ctx, tx, sess.ID)
		if err != nil && !isNoRows(err) {
			return nil, internalServerError("Error loading refresh token").withInternal(err)
		}
		if active != nil {
			if serr := a.checkSessionValidity(ctx, tx, sess, rt, now); serr != nil {
				return nil, serr
			}
			user, uerr := a.loadRefreshUser(ctx, tx, sess.UserID, now)
			if uerr != nil {
				return nil, uerr
			}
			accessToken, expiresAt, terr := a.issueOAuthAccessToken(ctx, tx, user, sess.ID, clientID, scope)
			if terr != nil {
				return nil, terr
			}
			a.log.InfoContext(ctx, "auth: oauth refresh token reused inside the reuse interval, returning the active token",
				"user_id", rt.UserID, "refresh_token_id", rt.ID, "client_ip", clientIP(r))
			return &OAuthTokenResponse{
				AccessToken:  accessToken,
				TokenType:    "bearer",
				ExpiresIn:    int(time.Until(expiresAt).Round(time.Second).Seconds()),
				RefreshToken: active.Token,
			}, nil
		}
	}

	if a.cfg.Security.RefreshTokenRotationEnabled {
		if rerr := revokeTokenFamily(ctx, tx, rt, now); rerr != nil {
			return nil, internalServerError("Error revoking token family").withInternal(rerr)
		}
	}
	if derr := deleteSession(ctx, tx, sess.ID); derr != nil {
		return nil, internalServerError("Error destroying session after detected refresh token reuse").withInternal(derr)
	}
	a.log.WarnContext(ctx, "auth: oauth refresh token reuse detected, session family revoked",
		"user_id", rt.UserID, "refresh_token_id", rt.ID, "client_ip", clientIP(r))
	return nil, commitAndFail(oauthError(oAuth2ErrorInvalidGrant, "Invalid Refresh Token: Already Used"))
}

// ---- OIDC ID token ---------------------------------------------------------

// idTokenParams are the inputs of signIDToken (upstream
// tokens.GenerateIDTokenParams).
type idTokenParams struct {
	User     *User
	ClientID string
	Nonce    string
	AuthTime *time.Time
	Scopes   []string
}

// IDTokenClaims are the OIDC ID Token claims (upstream tokens.IDTokenClaims).
// `email_verified` and `phone_number_verified` are NOT omitempty: OIDC requires
// them whenever their scope was granted, including when they are false.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce               string `json:"nonce,omitempty"`
	AuthTime            int64  `json:"auth_time"`
	Email               string `json:"email,omitempty"`
	EmailVerified       bool   `json:"email_verified"`
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified"`
	Name                string `json:"name,omitempty"`
	Picture             string `json:"picture,omitempty"`
	UpdatedAt           int64  `json:"updated_at,omitempty"`
	PreferredUsername   string `json:"preferred_username,omitempty"`
	ClientID            string `json:"client_id,omitempty"`
}

// errIDTokenRequiresES256 is returned when `openid` was granted but the
// deployment can only sign HS256 (see signIDToken).
var errIDTokenRequiresES256 = errors.New("auth: HS256 is not supported for ID token signing; configure an ES256 key set (JWT_KEYS)")

// idTokenTTL is the OIDC-conventional one hour, independent of JWT_EXP
// (upstream hard-codes the same).
const idTokenTTL = time.Hour

// signIDToken mints the OIDC ID token, ES256 with the same key and `kid` as the
// access token.
//
// HS256 is REFUSED, as upstream refuses it: an ID token is verified by the
// relying party, and handing a shared secret to every relying party would let
// any of them mint tokens for all the others. A deployment on the symmetric-only
// developer path therefore cannot serve `openid`.
//
// Claims follow the granted scopes: `sub`/`aud`/`iss`/`iat`/`exp`/`auth_time`
// always, email* with the email scope, phone_number* with the phone scope, and
// name/picture/preferred_username/updated_at with the profile scope.
func (a *api) signIDToken(p idTokenParams) (string, error) {
	if a.tokens == nil || a.tokens.sign == nil {
		return "", errIDTokenRequiresES256
	}

	now := a.now()
	authTime := now
	switch {
	case p.AuthTime != nil:
		authTime = *p.AuthTime
	case p.User.LastSignInAt != nil:
		authTime = *p.User.LastSignInAt
	}

	claims := &IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   p.User.ID,
			Audience:  jwt.ClaimStrings{p.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(idTokenTTL)),
			// DEVIATION: upstream emits config.JWT.Issuer, which may be empty.
			// `iss` is REQUIRED by OIDC Core §2, so Dilion always emits the
			// discovery document's issuer (JWT_ISSUER, else SiteURL+/auth/v1).
			Issuer: issuerURL(a.cfg),
		},
		AuthTime: authTime.Unix(),
		ClientID: p.ClientID,
		Nonce:    p.Nonce,
	}

	if hasScope(p.Scopes, ScopeEmail) {
		claims.Email = p.User.Email
		claims.EmailVerified = p.User.EmailConfirmedAt != nil
	}
	if hasScope(p.Scopes, ScopePhone) {
		claims.PhoneNumber = p.User.Phone
		claims.PhoneNumberVerified = p.User.PhoneConfirmedAt != nil
	}
	if hasScope(p.Scopes, ScopeProfile) {
		if name := metaString(p.User.UserMetaData, "name"); name != "" {
			claims.Name = name
		} else if p.User.Email != "" {
			claims.Name = p.User.Email
		}
		if picture := metaString(p.User.UserMetaData, "picture"); picture != "" {
			claims.Picture = picture
		} else if avatar := metaString(p.User.UserMetaData, "avatar_url"); avatar != "" {
			claims.Picture = avatar
		}
		if username := metaString(p.User.UserMetaData, "preferred_username"); username != "" {
			claims.PreferredUsername = username
		} else if username := metaString(p.User.UserMetaData, "username"); username != "" {
			claims.PreferredUsername = username
		}
		if p.User.UpdatedAt.Unix() > 0 {
			claims.UpdatedAt = p.User.UpdatedAt.Unix()
		}
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = a.tokens.sign.kid
	return tok.SignedString(a.tokens.sign.priv)
}

// metaString reads a string out of a user's metadata map.
func metaString(m JSONMap, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}
