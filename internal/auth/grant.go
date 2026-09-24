package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- grant registry --------------------------------------------------------

// grantHandler serves one POST /token grant type.
type grantHandler func(a *api, w http.ResponseWriter, r *http.Request) error

// grantHandlers is the POST /token dispatch table, keyed by grant_type. A new
// grant (pkce, id_token, web3, ...) is added by calling registerGrant from its
// own file's init() — nothing in this file or auth.go needs to change.
var grantHandlers = map[string]grantHandler{}

// grantLimiters maps a grant type to the rate limiter that guards it.
var grantLimiters = map[string]string{}

// registerGrant adds a grant type to POST /token.
//
//	name:    the grant_type value on the wire, e.g. "pkce"
//	limiter: the rate-limiter name from middleware.go that guards it
//	         ("" means LimiterToken, upstream's default for /token)
//	fn:      the handler
//
// Registering the same grant twice is a programming error and panics.
func registerGrant(name, limiter string, fn grantHandler) {
	if name == "" || fn == nil {
		panic("auth: registerGrant requires a grant type and a handler")
	}
	if _, dup := grantHandlers[name]; dup {
		panic("auth: duplicate grant registration: " + name)
	}
	if limiter == "" {
		limiter = LimiterToken
	}
	grantHandlers[name] = fn
	grantLimiters[name] = limiter
}

func init() {
	// Upstream shares the refresh limit across all grants; Dilion guards the
	// password grant with the (stricter) OTP limit — it is a credential-guessing
	// surface, a refresh is not.
	registerGrant("password", LimiterTokenPassword, (*api).passwordGrant)
	registerGrant("refresh_token", LimiterToken, (*api).refreshTokenGrant)
}

// PasswordGrantParams is the POST /token?grant_type=password body.
type PasswordGrantParams struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

// RefreshTokenGrantParams is the POST /token?grant_type=refresh_token body.
type RefreshTokenGrantParams struct {
	RefreshToken string `json:"refresh_token"`
}

// token implements POST /token: it resolves grant_type, applies that grant's
// rate limit and dispatches through grantHandlers.
func (a *api) token(w http.ResponseWriter, r *http.Request) error {
	grantType := grantTypeOf(r)

	fn, ok := grantHandlers[grantType]
	if !ok {
		// Upstream reports every unknown, unset or disabled grant this way.
		return badRequestError(ErrorCodeInvalidCredentials, "unsupported_grant_type")
	}
	if err := a.limitCheck(grantLimiters[grantType], r); err != nil {
		return err
	}
	return fn(a, w, r)
}

// grantTypeOf reads grant_type from the query string first (upstream documents
// it as a query parameter and Dilion keeps that precedence) and otherwise from
// a form-encoded body, which is what r.FormValue gives OAuth2 clients.
//
// The body is buffered and restored around the form parse, so a JSON body is
// still readable by decodeBody afterwards.
func grantTypeOf(r *http.Request) string {
	if gt := r.URL.Query().Get("grant_type"); gt != "" {
		return gt
	}
	if r.Body == nil {
		return r.FormValue("grant_type")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	gt := r.FormValue("grant_type")
	// FormValue may have consumed the body (form content types); hand the
	// handler a fresh reader over the same bytes.
	r.Body = io.NopCloser(bytes.NewReader(body))
	return gt
}

// ---- password grant --------------------------------------------------------

// passwordGrant is upstream's ResourceOwnerPasswordGrant.
//
// It accepts EITHER an email or a phone number, never both. The phone branch is
// gated on GOTRUE_EXTERNAL_PHONE_ENABLED and refuses an unconfirmed number with
// upstream's 400 phone_not_confirmed. Both branches record the same AMR method,
// "password", because both are exactly that.
func (a *api) passwordGrant(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// Captcha gates the password grant only; pkce/refresh_token/id_token are
	// exempt upstream (isIgnoreCaptchaRoute).
	if err := a.verifyCaptcha(r); err != nil {
		return err
	}

	params := &PasswordGrantParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	params.Email = strings.ToLower(strings.TrimSpace(params.Email))

	if params.Email != "" && params.Phone != "" {
		return badRequestError(ErrorCodeValidationFailed,
			"Only an email address or phone number should be provided on login.")
	}
	if params.Email == "" && params.Phone == "" {
		return badRequestError(ErrorCodeValidationFailed,
			"missing email or phone")
	}

	aud := requestAud(r)

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}

	// Guessing spread over many addresses is caught per account (attempts.go).
	var user *User
	account := aud + ":" + params.Email
	if params.Phone != "" {
		account = aud + ":" + formatPhoneNumber(params.Phone)
	}
	if terr := a.throttled(ctx, attemptPassword, account, func() error {
		var err error
		if params.Phone != "" {
			if !a.phoneProviderEnabled() {
				return unprocessableEntityError(ErrorCodePhoneProviderDisabled, "Phone logins are disabled")
			}
			// Upstream NORMALIZES but does not validate here (formatPhoneNumber, not
			// validatePhone): a malformed number simply finds no user and gets the
			// same invalid_credentials answer as a wrong password, so the login
			// endpoint never reveals which numbers are well-formed, let alone
			// registered.
			params.Phone = formatPhoneNumber(params.Phone)
			user, err = findUserByPhone(ctx, pool, params.Phone, aud)
		} else {
			user, err = findUserByEmail(ctx, pool, params.Email, aud)
		}
		if err != nil && !isNoRows(err) {
			return internalServerError("Database error querying schema").withInternal(err)
		}
		if user == nil || user.DeletedAt != nil {
			// Identical body to a wrong password: no user-enumeration oracle.
			return badRequestError(ErrorCodeInvalidCredentials, "%s", InvalidLoginMessage)
		}
		if user.IsBanned(a.now()) {
			return forbiddenError(ErrorCodeUserBanned, "User is banned")
		}
		if user.EncryptedPassword == nil || ComparePassword(*user.EncryptedPassword, params.Password) != nil {
			return badRequestError(ErrorCodeInvalidCredentials, "%s", InvalidLoginMessage)
		}
		return nil
	}); terr != nil {
		return terr
	}
	// The credential is good, but the strength policy may have been tightened
	// (or the password may have entered the HIBP corpus) since it was set.
	// Upstream ACCEPTS the login and hands the client an advisory instead of
	// rejecting — a policy change must never lock existing users out — so the
	// result is stashed here and attached to the response below.
	//
	// Non-weak failures (over the 72-byte bcrypt limit, or an HIBP lookup that
	// failed with fail-closed on) are swallowed with a WARN, exactly as
	// upstream does: the sign-in path is not where a password is judged.
	var weakPassword *WeakPasswordError
	if herr := a.checkPasswordStrength(ctx, params.Password); herr != nil {
		if wpe, ok := herr.internal.(*WeakPasswordError); ok {
			weakPassword = wpe
		} else {
			a.log.WarnContext(ctx, "auth: password strength check on sign-in failed",
				"error", herr)
		}
	}
	// An unconfirmed identifier cannot sign in. The check runs AFTER the
	// password comparison, upstream's order: it may only be reached by someone
	// who already holds the credentials, so it is not an enumeration oracle.
	// Only reachable when the matching Autoconfirm is off.
	if params.Phone != "" {
		if user.PhoneConfirmedAt == nil {
			return badRequestError(ErrorCodePhoneNotConfirmed, "Phone not confirmed")
		}
	} else if user.EmailConfirmedAt == nil {
		return badRequestError(ErrorCodeEmailNotConfirmed, "Email not confirmed")
	}

	var session *AccessTokenResponse
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		ids, ierr := findIdentitiesByUserID(ctx, tx, user.ID)
		if ierr != nil {
			return internalServerError("Error loading identities").withInternal(ierr)
		}
		user.Identities = ids

		var gerr error
		session, gerr = a.grantSession(ctx, tx, user, r, "password")
		return gerr
	}); err != nil {
		return err
	}
	session.WeakPassword = weakPassword

	return sendJSON(w, http.StatusOK, session)
}

// ---- refresh_token grant ---------------------------------------------------

// refreshTokenGrant rotates a refresh token.
//
// Semantics (gotrue-compatible):
//   - unknown token                -> 400 refresh_token_not_found
//   - already-revoked token        -> reuse: tolerated inside
//     Security.RefreshTokenReuseInterval (the session's CURRENT token is
//     returned, upstream's answer for a client that lost the response of its
//     last refresh); beyond the window the whole session token family is
//     revoked, the session destroyed, and 400 refresh_token_already_used
//     returned
//   - missing/expired session      -> 400 session_not_found / session_expired
//   - session past Sessions.Timebox
//     or Sessions.InactivityTimeout -> session destroyed, 400 session_expired
//   - Sessions.SinglePerUser on and a
//     newer login has refreshed since -> 400 session_expired (see
//     checkSinglePerUser); nothing is destroyed
//   - success                      -> old token revoked, child token issued with
//     parent = old token, same session_id, sessions.refreshed_at bumped
func (a *api) refreshTokenGrant(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params := &RefreshTokenGrantParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	if len(params.RefreshToken) < refreshTokenLength {
		return badRequestError(ErrorCodeValidationFailed, "Refresh token is not valid")
	}

	var resp *AccessTokenResponse

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		rt, err := findRefreshTokenForUpdate(ctx, tx, params.RefreshToken)
		if err != nil {
			if isNoRows(err) {
				return badRequestError(ErrorCodeRefreshTokenNotFound,
					"Invalid Refresh Token: Refresh Token Not Found")
			}
			return internalServerError("Error loading refresh token").withInternal(err)
		}

		now := a.now()

		// The session the token belongs to, when it still exists.
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

		// An OAuth application's refresh token is redeemed at /oauth/token,
		// with its client's credentials, and keeps its client_id and scope.
		// Here it would come back as the user's own first-party token.
		// Upstream refuses it the same way (tokens.Service.RefreshTokenGrant).
		if sess != nil && sess.OAuthClientID != nil {
			return errOAuthSessionRefresh
		}

		// SESSIONS_SINGLE_PER_USER, checked in upstream's position: before the
		// revoked-token branch, so a reuse-interval replay is judged by the
		// same rule as a normal refresh.
		if serr := a.checkSinglePerUser(ctx, tx, sess, rt, now); serr != nil {
			return serr
		}

		if rt.Revoked {
			tolerated, rerr := a.handleRefreshTokenReuse(ctx, tx, r, rt, sess, now)
			if rerr != nil {
				return rerr
			}
			resp = tolerated
			return nil
		}

		if rt.SessionID == nil || sess == nil {
			return badRequestError(ErrorCodeSessionNotFound, "Invalid Refresh Token: No Valid Session Found")
		}
		if serr := a.checkSessionValidity(ctx, tx, sess, rt, now); serr != nil {
			return serr
		}

		user, err := a.loadRefreshUser(ctx, tx, sess.UserID, now)
		if err != nil {
			return err
		}

		// Rotate: revoke the presented token, issue its child.
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
		// sessions.refreshed_at drives the inactivity timeout.
		if err := touchSession(ctx, tx, sess.ID, now); err != nil {
			return internalServerError("Error updating session").withInternal(err)
		}

		// A refresh does NOT add an AMR claim (upstream never records
		// `token_refresh` on the session): the session keeps the methods it
		// was built from, so its AAL — aal2 after an MFA verification —
		// survives rotation unchanged, and drops back to aal1 by itself once
		// the factor behind the claim is unenrolled.
		// No new authentication happened, so the method reported to the token
		// hooks is derived from the session's existing AMR claims.
		resp, err = a.buildSessionResponse(ctx, tx, user, sess.ID, next, "")
		return err
	}); err != nil {
		if errors.Is(err, errOAuthSessionRefresh) {
			return sendOAuthError(w, oAuth2ErrorInvalidClient, "Client authentication required for OAuth session")
		}
		return err
	}

	return sendJSON(w, http.StatusOK, resp)
}

// errOAuthSessionRefresh aborts a /token refresh of an OAuth application's
// session; refreshTokenGrant answers it in upstream's OAuth error shape.
var errOAuthSessionRefresh = errors.New("auth: refresh token belongs to an OAuth application")

// handleRefreshTokenReuse implements the reuse decision for an already-revoked
// refresh token.
//
// Inside Security.RefreshTokenReuseInterval seconds of the token's revocation
// the reuse is treated as a client that never received the response of its last
// refresh: the session's currently active token is returned again, no new token
// is minted and nothing is revoked (upstream tokens.Service.RefreshTokenGrant).
//
// Beyond the window it is treated as abuse: the whole token family is revoked,
// the session destroyed, and the error is returned with commitAndFail so the
// punishment survives the failed request.
func (a *api) handleRefreshTokenReuse(ctx context.Context, tx querier, r *http.Request,
	rt *refreshToken, sess *session, now time.Time) (*AccessTokenResponse, error) {

	window := a.cfg.Security.ReuseIntervalDuration()

	if sess != nil && window > 0 && now.Before(rt.UpdatedAt.Add(window)) {
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
			a.log.InfoContext(ctx, "auth: refresh token reused inside the reuse interval, returning the active token",
				slog.String("user_id", rt.UserID), slog.Int64("refresh_token_id", rt.ID),
				slog.String("client_ip", clientIP(r)))
			return a.buildSessionResponse(ctx, tx, user, sess.ID, active.Token, "")
		}
	}

	// Outside the window (or nothing left to hand back): abuse.
	if a.cfg.Security.RefreshTokenRotationEnabled {
		if rerr := revokeTokenFamily(ctx, tx, rt, now); rerr != nil {
			return nil, internalServerError("Error revoking token family").withInternal(rerr)
		}
	}
	if rt.SessionID != nil {
		if derr := deleteSession(ctx, tx, *rt.SessionID); derr != nil {
			return nil, internalServerError("Error destroying session after detected refresh token reuse").withInternal(derr)
		}
	}
	a.log.WarnContext(ctx, "auth: refresh token reuse detected, session family revoked",
		slog.String("user_id", rt.UserID), slog.Int64("refresh_token_id", rt.ID),
		slog.String("client_ip", clientIP(r)))
	// commitAndFail: the revocation must survive the error response.
	return nil, commitAndFail(
		badRequestError(ErrorCodeRefreshTokenAlreadyUsed, "Invalid Refresh Token: Already Used"))
}

// checkSinglePerUser enforces GOTRUE_SESSIONS_SINGLE_PER_USER, reproducing
// upstream tokens.Service.RefreshTokenGrant (internal/tokens/service.go, the
// `if config.Sessions.SinglePerUser` block).
//
// # What upstream actually does, and what it does not
//
// The name suggests session creation is restricted. It is not: NOTHING in
// upstream reads Sessions.SinglePerUser except this one refresh-time check —
// `grep -rn SinglePerUser` over supabase/auth master hits
// internal/conf/configuration.go (the field), internal/tokens/service.go:316
// (this check) and a test. Signing in a second time is always allowed and
// always mints a second session; no session is deleted and no refresh token is
// revoked, then or here.
//
// What the flag does is make the OLDER session unusable, LAZILY: when a session
// is refreshed, every other still-valid session of the same user is examined,
// and if any of them has been refreshed more recently than this one, this
// refresh is rejected with 400 session_expired "(Revoked by Newer Login)". The
// newest login wins; the loser finds out the next time it tries to refresh, and
// its row stays in the table until the session cleaner or a logout removes it.
// Note the asymmetry that follows from that: the check is on
// LastRefreshedAt, so a session that is merely OLDER is fine — it only loses
// once the newer session has actually refreshed at least once.
//
// # Deviations, both forced by config surface
//
//   - Upstream partitions the comparison by session TAG
//     (Session.DetermineTag over GOTRUE_SESSIONS_TAGS). Dilion has no
//     Sessions.Tags knob, which is exactly upstream's `len(tags) == 0` case:
//     DetermineTag returns "" for every session, so every session is comparable
//     with every other. Identical behaviour for any deployment that does not
//     set GOTRUE_SESSIONS_TAGS.
//   - Upstream's "is the other session still valid" test is
//     Session.CheckValidity, which also covers GOTRUE_SESSIONS_ALLOW_LOW_AAL.
//     Dilion has no such knob either, so validity here is not_after + Timebox +
//     InactivityTimeout — upstream's CheckValidity with AllowLowAAL unset.
//
// A no-op when the flag is off (the default), which is why it is safe to run
// on every refresh.
func (a *api) checkSinglePerUser(ctx context.Context, q querier, sess *session, rt *refreshToken, now time.Time) error {
	if !a.cfg.Sessions.SinglePerUser || sess == nil {
		return nil
	}

	others, err := findAllSessionsForUser(ctx, q, sess.UserID)
	if err != nil {
		return internalServerError("Error loading sessions").withInternal(err)
	}

	// The presented token's updated_at counts as activity on THIS session, but
	// says nothing about any other session — upstream passes nil there.
	mine := sess.lastRefreshedAt(rt)

	for _, other := range others {
		if other.ID == sess.ID {
			continue
		}
		if !a.sessionStillValid(other, now) {
			// Not active, so it cannot out-rank this one.
			continue
		}
		if other.lastRefreshedAt(nil).After(mine) {
			return badRequestError(ErrorCodeSessionExpired,
				"Invalid Refresh Token: Session Expired (Revoked by Newer Login)")
		}
	}
	return nil
}

// sessionStillValid is upstream models.Session.CheckValidity reduced to a
// boolean, over the validity knobs Dilion configures (see checkSinglePerUser).
// Unlike checkSessionValidity it never destroys anything: it is asked about
// OTHER people's sessions, which this request has no business reaping.
func (a *api) sessionStillValid(s *session, now time.Time) bool {
	if s.NotAfter != nil && now.After(*s.NotAfter) {
		return false
	}
	if tb := a.cfg.Sessions.Timebox; tb > 0 && now.After(s.CreatedAt.Add(tb)) {
		return false
	}
	if it := a.cfg.Sessions.InactivityTimeout; it > 0 && now.After(s.lastRefreshedAt(nil).Add(it)) {
		return false
	}
	return true
}

// checkSessionValidity enforces the session policy on a refresh, mirroring
// upstream models.Session.CheckValidity: sessions.not_after,
// Sessions.Timebox (measured from created_at) and Sessions.InactivityTimeout
// (measured from the later of sessions.refreshed_at and the presented token's
// updated_at). A session that fails any of them is destroyed, and the error is
// returned through commitAndFail so the destruction is committed.
func (a *api) checkSessionValidity(ctx context.Context, tx querier, sess *session, rt *refreshToken, now time.Time) error {
	expire := func(msg string) error {
		if derr := deleteSession(ctx, tx, sess.ID); derr != nil {
			return internalServerError("Error destroying expired session").withInternal(derr)
		}
		return commitAndFail(badRequestError(ErrorCodeSessionExpired, "%s", msg))
	}

	if sess.NotAfter != nil && !now.Before(*sess.NotAfter) {
		return expire("Invalid Refresh Token: Session Expired")
	}
	if tb := a.cfg.Sessions.Timebox; tb > 0 && now.After(sess.CreatedAt.Add(tb)) {
		return expire("Invalid Refresh Token: Session Expired")
	}
	if it := a.cfg.Sessions.InactivityTimeout; it > 0 && now.After(sess.lastRefreshedAt(rt).Add(it)) {
		return expire("Invalid Refresh Token: Session Expired (Inactivity)")
	}
	return nil
}

// loadRefreshUser loads the user behind a session and applies the checks every
// refresh shares.
func (a *api) loadRefreshUser(ctx context.Context, tx querier, userID string, now time.Time) (*User, error) {
	user, err := a.loadUserWithIdentities(ctx, tx, userID)
	if err != nil {
		if isNoRows(err) {
			return nil, badRequestError(ErrorCodeUserNotFound, "Invalid Refresh Token: User Not Found")
		}
		return nil, internalServerError("Database error querying schema").withInternal(err)
	}
	if user.DeletedAt != nil {
		return nil, badRequestError(ErrorCodeUserNotFound, "Invalid Refresh Token: User Not Found")
	}
	if user.IsBanned(now) {
		return nil, forbiddenError(ErrorCodeUserBanned, "User is banned")
	}
	return user, nil
}
