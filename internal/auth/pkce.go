package auth

// PKCE (RFC 7636) for the email flows and the `pkce` grant.
//
// Reproduces github.com/supabase/auth/internal/api/pkce.go,
// internal/models/flow_state.go, internal/security/pkce.go and the PKCE branch
// of internal/api/token.go.
//
// # Shape of a PKCE flow
//
//	POST /signup|/otp|/magiclink|/recover|/resend   {..., code_challenge, code_challenge_method}
//	  -> auth.flow_state row (auth_code = a fresh uuid, user_id set)
//	  -> the mailed token hash is prefixed "pkce_"
//	GET  /verify?token=pkce_<hash>&type=<t>&redirect_to=<r>
//	  -> 303 to <r>?code=<auth_code>            (implicit flow puts tokens in the #fragment instead)
//	POST /token?grant_type=pkce  {auth_code, code_verifier}
//	  -> S256(code_verifier) == code_challenge, single use, then a full session
//
// The flow state is the ONLY place the challenge lives, and it is destroyed as
// the session is issued — an auth code is single-use even under concurrency
// because the consume runs inside the issuing transaction with the row locked.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func init() {
	// Upstream guards every grant with the refresh limit; Dilion uses
	// LimiterToken here for the same reason: a PKCE exchange is a one-shot
	// redemption of a code the server itself minted, not a guessing surface.
	registerGrant("pkce", LimiterToken, (*api).pkceGrant)
}

// Code challenge bounds, from RFC 7636 §4.2 (upstream api/pkce.go).
const (
	minCodeChallengeLength = 43
	maxCodeChallengeLength = 128

	// invalidPKCEParamsMessage is upstream's InvalidPKCEParamsErrorMessage.
	invalidPKCEParamsMessage = "PKCE flow requires code_challenge_method and code_challenge"
)

// codeChallengePattern is RFC 7636's unreserved set (upstream's regexp).
var codeChallengePattern = regexp.MustCompile(`^[a-zA-Z._~0-9-]+$`)

// Code challenge methods, matching the auth.code_challenge_method enum.
const (
	challengeMethodS256  = "s256"
	challengeMethodPlain = "plain"
)

// Authentication methods stored on flow_state.authentication_method. The strings
// are upstream's models.AuthenticationMethod.String().
const (
	authMethodEmailSignup = "email/signup"
	authMethodMagicLink   = "magiclink"
	authMethodRecovery    = "recovery"
	authMethodEmailChange = "email_change"
	authMethodOTP         = "otp"
	authMethodInvite      = "invite"
)

// ---- parameter validation --------------------------------------------------

// validatePKCEParams is upstream's validatePKCEParams: the pair is all-or-nothing
// and the challenge must satisfy RFC 7636 §4.2.
func validatePKCEParams(codeChallengeMethod, codeChallenge string) error {
	switch {
	case (codeChallenge == "") != (codeChallengeMethod == ""):
		return badRequestError(ErrorCodeValidationFailed, "%s", invalidPKCEParamsMessage)
	case codeChallenge != "":
		if err := validateCodeChallenge(codeChallenge); err != nil {
			return err
		}
		if _, err := parseCodeChallengeMethod(codeChallengeMethod); err != nil {
			return badRequestError(ErrorCodeValidationFailed, "%v", err)
		}
	}
	return nil
}

func validateCodeChallenge(codeChallenge string) error {
	switch n := len(codeChallenge); {
	case n < minCodeChallengeLength, n > maxCodeChallengeLength:
		return badRequestError(ErrorCodeValidationFailed,
			"code challenge has to be between %v and %v characters", minCodeChallengeLength, maxCodeChallengeLength)
	case !codeChallengePattern.MatchString(codeChallenge):
		return badRequestError(ErrorCodeValidationFailed,
			"code challenge can only contain alphanumeric characters, hyphens, periods, underscores and tildes")
	}
	return nil
}

// parseCodeChallengeMethod normalizes s256 / plain (upstream
// models.ParseCodeChallengeMethod).
func parseCodeChallengeMethod(method string) (string, error) {
	switch strings.ToLower(method) {
	case challengeMethodS256:
		return challengeMethodS256, nil
	case challengeMethodPlain:
		return challengeMethodPlain, nil
	}
	return "", fmt.Errorf("unsupported code_challenge method %q", method)
}

// isPKCERequest reports whether a request carries a code challenge, i.e. whether
// the flow is PKCE rather than implicit (upstream getFlowFromChallenge).
func isPKCERequest(codeChallenge string) bool { return codeChallenge != "" }

// ---- challenge verification ------------------------------------------------

// PKCE verification error messages (upstream internal/security/pkce.go).
const (
	pkceInvalidCodeChallengeError = "code challenge does not match previously saved code verifier"
	pkceInvalidCodeMethodError    = "code challenge method not supported"
)

// verifyPKCEChallenge is upstream's security.VerifyPKCEChallenge. Both branches
// compare in constant time: a timing oracle on the challenge would let an
// attacker who intercepted an auth code reconstruct the verifier byte by byte.
func verifyPKCEChallenge(codeChallenge, codeChallengeMethod, codeVerifier string) error {
	switch strings.ToLower(codeChallengeMethod) {
	case challengeMethodS256:
		sum := sha256.Sum256([]byte(codeVerifier))
		encoded := base64.RawURLEncoding.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(codeChallenge), []byte(encoded)) != 1 {
			return errors.New(pkceInvalidCodeChallengeError)
		}
	case challengeMethodPlain:
		if subtle.ConstantTimeCompare([]byte(codeChallenge), []byte(codeVerifier)) != 1 {
			return errors.New(pkceInvalidCodeChallengeError)
		}
	default:
		return errors.New(pkceInvalidCodeMethodError)
	}
	return nil
}

// ---- storage ---------------------------------------------------------------

// flowState is one auth.flow_state row (the PKCE subset Dilion uses; the OAuth
// and SSO columns are left at their defaults by this package).
type flowState struct {
	ID                   string
	UserID               *string
	AuthCode             *string
	AuthenticationMethod string
	CodeChallenge        *string
	CodeChallengeMethod  *string
	ProviderType         string
	ProviderAccessToken  string
	ProviderRefreshToken string
	CreatedAt            time.Time
	AuthCodeIssuedAt     *time.Time
}

// IsPKCE reports whether the row carries a code challenge.
func (f *flowState) IsPKCE() bool { return f.CodeChallenge != nil && *f.CodeChallenge != "" }

// IsExpired is upstream's FlowState.IsExpired: a magic-link flow expires from
// the moment its auth code was ISSUED (the user may sit on the email for a
// while), everything else from the moment the flow was created.
func (f *flowState) IsExpired(now time.Time, expiry time.Duration) bool {
	if f.AuthCodeIssuedAt != nil && f.AuthenticationMethod == authMethodMagicLink {
		return now.After(f.AuthCodeIssuedAt.Add(expiry))
	}
	return now.After(f.CreatedAt.Add(expiry))
}

const flowStateColumns = `id::text, user_id::text, auth_code, authentication_method,
	code_challenge, code_challenge_method::text, provider_type,
	coalesce(provider_access_token, ''), coalesce(provider_refresh_token, ''),
	created_at, auth_code_issued_at`

func scanFlowState(row pgx.Row) (*flowState, error) {
	var (
		f         flowState
		createdAt *time.Time
	)
	if err := row.Scan(&f.ID, &f.UserID, &f.AuthCode, &f.AuthenticationMethod,
		&f.CodeChallenge, &f.CodeChallengeMethod, &f.ProviderType,
		&f.ProviderAccessToken, &f.ProviderRefreshToken, &createdAt, &f.AuthCodeIssuedAt); err != nil {
		return nil, err
	}
	if createdAt != nil {
		f.CreatedAt = createdAt.UTC()
	}
	f.AuthCodeIssuedAt = utc(f.AuthCodeIssuedAt)
	return &f, nil
}

// createFlowState inserts a PKCE flow state and returns it. providerType is the
// value reported back to the client on the session (upstream stores the OAuth
// provider here; for the email flows it is the authentication method itself).
func createFlowState(ctx context.Context, q querier, providerType, authMethod, codeChallengeMethod, codeChallenge, userID string, now time.Time) (*flowState, error) {
	method, err := parseCodeChallengeMethod(codeChallengeMethod)
	if err != nil {
		return nil, badRequestError(ErrorCodeValidationFailed, "%v", err)
	}
	authCode := uuid.NewString()
	var uid *string
	if userID != "" {
		uid = &userID
	}
	return scanFlowState(q.QueryRow(ctx, `
		insert into auth.flow_state (
			id, user_id, auth_code, code_challenge_method, code_challenge,
			provider_type, authentication_method, created_at, updated_at
		) values (
			$1::uuid, $2::uuid, $3, $4::auth.code_challenge_method, $5,
			$6, $7, $8, $8
		)
		returning `+flowStateColumns,
		uuid.NewString(), uid, authCode, method, codeChallenge, providerType, authMethod, now))
}

func findFlowStateByAuthCode(ctx context.Context, q querier, authCode string) (*flowState, error) {
	return scanFlowState(q.QueryRow(ctx,
		`select `+flowStateColumns+` from auth.flow_state where auth_code = $1 for update`, authCode))
}

// findFlowStateForUser returns the NEWEST flow state of a user for one
// authentication method — upstream's FindFlowStateByUserID, which takes the
// Last() row.
func findFlowStateForUser(ctx context.Context, q querier, userID, authMethod string) (*flowState, error) {
	return scanFlowState(q.QueryRow(ctx, `
		select `+flowStateColumns+` from auth.flow_state
		where user_id = $1::uuid and authentication_method = $2
		order by created_at desc, id desc
		limit 1`, userID, authMethod))
}

func recordAuthCodeIssuedAt(ctx context.Context, q querier, id string, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.flow_state set auth_code_issued_at = $2, updated_at = $2 where id = $1::uuid`, id, now)
	return err
}

func deleteFlowState(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `delete from auth.flow_state where id = $1::uuid`, id)
	return err
}

// ---- issuing an auth code --------------------------------------------------

// issueAuthCode is upstream's issueAuthCode: at /verify time the flow state
// created by the ORIGINATING request (signup, otp, recover, ...) is looked up by
// (user, authentication_method) and its auth code handed to the redirect.
func (a *api) issueAuthCode(ctx context.Context, tx querier, userID, authMethod string) (string, error) {
	fs, err := findFlowStateForUser(ctx, tx, userID, authMethod)
	if err != nil {
		if isNoRows(err) {
			return "", unprocessableEntityError(ErrorCodeFlowStateNotFound, "No valid flow state found for user.")
		}
		return "", internalServerError("Error finding flow state").withInternal(err)
	}
	if !fs.IsPKCE() {
		return "", unprocessableEntityError(ErrorCodeFlowStateNotFound,
			"Flow state does not have an auth code (not a PKCE flow).")
	}
	if err := recordAuthCodeIssuedAt(ctx, tx, fs.ID, a.now()); err != nil {
		return "", internalServerError("Error updating flow state").withInternal(err)
	}
	return *fs.AuthCode, nil
}

// authMethodForVerifyType maps a /verify `type` to the authentication method the
// originating request stored on its flow state. Upstream does the same through
// models.ParseAuthenticationMethod, whose "any *signup* means email/signup" rule
// is reproduced here.
func authMethodForVerifyType(verifyType string) (string, error) {
	if strings.HasSuffix(verifyType, "signup") {
		return authMethodEmailSignup, nil
	}
	switch verifyType {
	case mailMagicLink:
		return authMethodMagicLink, nil
	case mailRecovery:
		return authMethodRecovery, nil
	case mailEmailChange:
		return authMethodEmailChange, nil
	case mailEmailOTP:
		return authMethodOTP, nil
	case mailInvite:
		return authMethodInvite, nil
	}
	return "", badRequestError(ErrorCodeValidationFailed, "unsupported authentication method %q", verifyType)
}

// ---- grant_type=pkce -------------------------------------------------------

// PKCEGrantParams is the POST /token?grant_type=pkce body.
type PKCEGrantParams struct {
	AuthCode     string `json:"auth_code"`
	CodeVerifier string `json:"code_verifier"`
}

// pkceGrant exchanges an auth code + verifier for a session. Upstream's
// api.PKCE, with upstream's error codes and statuses:
//
//	missing parameters  -> 400 validation_failed
//	unknown auth code   -> 404 flow_state_not_found
//	past FlowStateExpiry-> 422 flow_state_expired
//	wrong verifier      -> 400 bad_code_verifier
//
// Everything after the lookup runs in one transaction with the flow-state row
// locked (FOR UPDATE), so two concurrent redemptions of the same code cannot
// both issue a session: the loser finds the row gone and gets
// flow_state_not_found.
func (a *api) pkceGrant(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params := &PKCEGrantParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	if params.AuthCode == "" || params.CodeVerifier == "" {
		return badRequestError(ErrorCodeValidationFailed,
			"invalid request: both auth code and code verifier should be non-empty")
	}

	var session *AccessTokenResponse
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		fs, err := findFlowStateByAuthCode(ctx, tx, params.AuthCode)
		if err != nil {
			if isNoRows(err) {
				return notFoundError(ErrorCodeFlowStateNotFound, "invalid flow state, no valid flow state found")
			}
			return internalServerError("Error finding flow state").withInternal(err)
		}
		if fs.UserID == nil {
			return notFoundError(ErrorCodeFlowStateNotFound, "invalid flow state, no valid flow state found")
		}
		if fs.IsExpired(a.now(), a.cfg.FlowStateExpiry) {
			return unprocessableEntityError(ErrorCodeFlowStateExpired, "invalid flow state, flow state has expired")
		}
		if !fs.IsPKCE() {
			return notFoundError(ErrorCodeFlowStateNotFound, "invalid flow state, no valid flow state found")
		}
		if err := verifyPKCEChallenge(*fs.CodeChallenge, *fs.CodeChallengeMethod, params.CodeVerifier); err != nil {
			return badRequestError(ErrorCodeBadCodeVerifier, "%s", err.Error())
		}

		user, err := a.loadUserWithIdentities(ctx, tx, *fs.UserID)
		if err != nil {
			if isNoRows(err) {
				return notFoundError(ErrorCodeUserNotFound, "User from flow state does not exist")
			}
			return internalServerError("Database error finding user").withInternal(err)
		}
		if user.DeletedAt != nil {
			return notFoundError(ErrorCodeUserNotFound, "User from flow state does not exist")
		}
		if user.IsBanned(a.now()) {
			return forbiddenError(ErrorCodeUserBanned, "User is banned")
		}

		// Single use: the code dies with the session it produced.
		if err := deleteFlowState(ctx, tx, fs.ID); err != nil {
			return internalServerError("Error consuming flow state").withInternal(err)
		}

		session, err = a.grantSession(ctx, tx, user, r, amrForAuthMethod(fs.AuthenticationMethod))
		if err == nil {
			// External-OAuth flows park the provider tokens on the flow state;
			// the PKCE exchange is the only place they can reach the client
			// (upstream parity).
			session.ProviderToken = fs.ProviderAccessToken
			session.ProviderRefreshToken = fs.ProviderRefreshToken
		}
		return err
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, session)
}

// amrForAuthMethod maps a flow state's authentication method to the `amr` method
// recorded on the access token. Everything the email lifecycle produces is an
// OTP-class sign-in upstream (models.OTP), except an explicit password signup.
func amrForAuthMethod(authMethod string) string {
	switch authMethod {
	case authMethodEmailSignup:
		return "otp"
	case authMethodMagicLink:
		return "magiclink"
	case authMethodRecovery:
		return "recovery"
	case authMethodInvite:
		return "invite"
	case authMethodEmailChange:
		return "email_change"
	case authMethodSSOSAML:
		return AMRMethodSSOSAML
	}
	return "otp"
}
