package auth

import (
	"net/http"
	"testing"
	"time"
)

// An account erased before erasure released its identities still has the
// provider's subject on its identity row. Signing up again with that provider
// account must start a fresh account, not reopen the erased one and write the
// provider's profile back onto it.
func TestOAuthSignUpAfterErasureStartsAFreshAccount(t *testing.T) {
	env := newExternalEnv(t, nil)
	env.signInWithGoogle(t)
	erased := env.userByEmail(t, "gina@example.com")

	// What the erasure pipeline used to leave behind: the account emptied and
	// marked deleted, the identity emptied but still naming the subject.
	for _, q := range []string{
		`update auth.users set email = null, raw_user_meta_data = '{}'::jsonb, deleted_at = now() where id = $1::uuid`,
		`update auth.identities set identity_data = '{}'::jsonb where user_id = $1::uuid`,
	} {
		if _, err := env.pool.Exec(t.Context(), q, erased.ID); err != nil {
			t.Fatalf("erase: %v", err)
		}
	}

	back := env.signInWithGoogle(t)
	if fragmentValues(t, back).Get("access_token") == "" {
		t.Fatalf("sign-up after erasure issued no session: %s", back)
	}
	fresh := env.userByEmail(t, "gina@example.com")
	if fresh.ID == erased.ID {
		t.Fatal("signing up again reopened the erased account")
	}

	var meta string
	if err := env.pool.QueryRow(t.Context(),
		`select raw_user_meta_data::text from auth.users where id = $1::uuid`, erased.ID).Scan(&meta); err != nil {
		t.Fatalf("erased user: %v", err)
	}
	if meta != "{}" {
		t.Errorf("provider profile was written back onto the erased account: %s", meta)
	}
	for _, id := range env.identityRows(t, erased.ID) {
		if id.ProviderID == env.google.sub || len(id.IdentityData) != 0 {
			t.Errorf("erased account's identity still names the provider account: %+v", id)
		}
	}
}

// A soft-deleted account keeps its passkeys, and a passkey must not sign in to
// it. The refusal is the generic one, so the endpoint does not reveal which
// accounts were deleted.
func TestPasskeySignInRefusesDeletedUser(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-deleted@dilion.test", "correct-horse-battery")
	va := newVirtualAuthenticator(testRPID, testRPOrgin)
	env.registerPasskey(t, session.Token, va)

	if rec := env.do(t, http.MethodDelete, "/admin/users/"+session.User.ID,
		map[string]any{"should_soft_delete": true}, env.serviceRoleToken(t)); rec.Code != http.StatusOK {
		t.Fatalf("soft delete = %d %s", rec.Code, rec.Body.String())
	}
	assertAuthError(t, env.signInWithPasskey(t, va, 1), http.StatusBadRequest, ErrorCodeWebAuthnVerificationFailed)
}

// Whatever credential a deleted account still holds, no session is issued for
// it: grantSession is where every sign-in ends.
func TestGrantSessionRefusesDeletedUser(t *testing.T) {
	env := newTestEnv(t)
	session := env.signup(t, "grant-deleted@dilion.test", "correct-horse-battery")
	a := newAPI(Deps{Pool: env.pool, Tokens: env.tokens, Config: testConfig()})

	u, err := findUserByID(t.Context(), env.pool, session.User.ID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	now := a.now()
	u.DeletedAt = &now
	req, _ := http.NewRequest(http.MethodPost, "/token", nil)
	if _, err := a.grantSession(t.Context(), env.pool, u, req, "password"); err == nil {
		t.Fatal("grantSession issued a session for a deleted user")
	}
}

// A banned account gets no session either, whatever credential it signs in
// with.
func TestGrantSessionRefusesBannedUser(t *testing.T) {
	env := newTestEnv(t)
	session := env.signup(t, "grant-banned@dilion.test", "correct-horse-battery")
	a := newAPI(Deps{Pool: env.pool, Tokens: env.tokens, Config: testConfig()})
	u, err := findUserByID(t.Context(), env.pool, session.User.ID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	until := a.now().Add(time.Hour)
	u.BannedUntil = &until
	req, _ := http.NewRequest(http.MethodPost, "/token", nil)
	if _, err := a.grantSession(t.Context(), env.pool, u, req, "password"); err == nil {
		t.Fatal("grantSession issued a session for a banned user")
	}
}
