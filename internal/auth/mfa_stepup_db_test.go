package auth

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// enableMFA gives userID a verified TOTP factor, as a completed enrolment
// would.
func (e *testEnv) enableMFA(t *testing.T, userID string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `
		insert into auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at)
		values ($1::uuid, $2::uuid, $3, 'totp', 'verified', now(), now())`,
		uuid.NewString(), userID, "stepup-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("enable MFA: %v", err)
	}
}

// stepUp records a TOTP verification on the session behind token, which is
// what a successful challenge does: the session is aal2 from then on.
func (e *testEnv) stepUp(t *testing.T, token string) {
	t.Helper()
	claims, err := e.tokens.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	sessionID, _ := claims.Extra["session_id"].(string)
	if _, err := e.pool.Exec(context.Background(), `
		insert into auth.mfa_amr_claims (id, session_id, created_at, updated_at, authentication_method)
		values ($1::uuid, $2::uuid, now(), now(), 'totp')`, uuid.NewString(), sessionID); err != nil {
		t.Fatalf("step up: %v", err)
	}
}

// Upstream: with MFA on, a password alone cannot change the email, phone or
// password. Other profile changes still work at aal1.
func TestMFAUserNeedsAAL2ToChangeCredentials(t *testing.T) {
	env := newTestEnv(t)
	user := env.signup(t, "stepup@example.com", "correct-horse-battery")
	env.enableMFA(t, user.User.ID)

	for name, body := range map[string]map[string]any{
		"password": {"password": "another-horse-battery"},
		"email":    {"email": "stolen@example.com"},
	} {
		rec := env.do(t, http.MethodPut, "/user", body, user.Token)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), ErrorCodeInsufficientAAL) {
			t.Errorf("%s change at aal1 = %d %s, want 401 %s", name, rec.Code, rec.Body.String(), ErrorCodeInsufficientAAL)
		}
	}
	if rec := env.do(t, http.MethodPut, "/user", map[string]any{"data": map[string]any{"nickname": "s"}}, user.Token); rec.Code != http.StatusOK {
		t.Errorf("metadata change at aal1 = %d %s, want 200", rec.Code, rec.Body.String())
	}

	env.stepUp(t, user.Token)
	if rec := env.do(t, http.MethodPut, "/user", map[string]any{"password": "another-horse-battery"}, user.Token); rec.Code != http.StatusOK {
		t.Errorf("password change at aal2 = %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// Authorizing an application hands it the account, so an MFA user needs an
// aal2 session to open or approve the request — including the paths that
// approve without asking.
func TestMFAUserNeedsAAL2ToAuthorizeApp(t *testing.T) {
	env := newOAuthEnv(t, nil)
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
	user := env.signup(t, "consent-mfa@example.com", "hunter22")
	env.enableMFA(t, user.User.ID)

	id := env.authorize(t, client.ClientID, "openid", "s1", nil)
	rec := env.do(t, http.MethodGet, "/oauth/authorizations/"+id, nil, user.Token)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), ErrorCodeInsufficientAAL) {
		t.Fatalf("opening the request at aal1 = %d %s, want 403 %s", rec.Code, rec.Body.String(), ErrorCodeInsufficientAAL)
	}
	rec = env.do(t, http.MethodPost, "/oauth/authorizations/"+id+"/consent", map[string]any{"action": "approve"}, user.Token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("approving at aal1 = %d %s, want 403", rec.Code, rec.Body.String())
	}

	env.stepUp(t, user.Token)
	env.claimAndApprove(t, id, user.Token, "s1")
}
