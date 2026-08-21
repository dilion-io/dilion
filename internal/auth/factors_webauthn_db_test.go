package auth

// Database-backed tests for the WebAuthn MFA factor, driven by the in-test
// software authenticator (passkey_authenticator_test.go). They cover the full
// enrol (options -> finish registration) -> challenge -> verify -> aal2 loop,
// a wrong-origin rejection, and the enroll gate. The RP is derived from the
// default SiteURL (http://localhost:5173), so the virtual authenticator uses
// rpID "localhost" and origin "http://localhost:5173".

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

const (
	testWebAuthnRPID   = "localhost"
	testWebAuthnOrigin = "http://localhost:5173"
)

func webAuthnConfig() *Config {
	cfg := DefaultConfig()
	cfg.MFA.WebAuthn.EnrollEnabled = true
	cfg.MFA.WebAuthn.VerifyEnabled = true
	return cfg
}

func (e *mfaEnv) enrollWebAuthn(t *testing.T, token, name string) EnrollFactorResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "webauthn", "friendly_name": name}, token)
	return decodeInto[EnrollFactorResponse](t, rec, http.StatusOK)
}

func (e *mfaEnv) challengeWebAuthn(t *testing.T, token, factorID string) ChallengeFactorResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/factors/"+factorID+"/challenge", map[string]any{}, token)
	return decodeInto[ChallengeFactorResponse](t, rec, http.StatusOK)
}

// creationOptionsOf re-marshals the generic credential_options into the typed
// registration options the virtual authenticator consumes.
func creationOptionsOf(t *testing.T, ch ChallengeFactorResponse) *protocol.PublicKeyCredentialCreationOptions {
	t.Helper()
	if ch.WebAuthn == nil || ch.WebAuthn.Type != webAuthnFactorTypeCreate {
		t.Fatalf("challenge webauthn = %+v, want a create ceremony", ch.WebAuthn)
	}
	raw, err := json.Marshal(ch.WebAuthn.CredentialOptions)
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	var opts protocol.PublicKeyCredentialCreationOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatalf("unmarshal creation options: %v", err)
	}
	return &opts
}

func requestOptionsOf(t *testing.T, ch ChallengeFactorResponse) *protocol.PublicKeyCredentialRequestOptions {
	t.Helper()
	if ch.WebAuthn == nil || ch.WebAuthn.Type != webAuthnFactorTypeRequest {
		t.Fatalf("challenge webauthn = %+v, want a request ceremony", ch.WebAuthn)
	}
	raw, err := json.Marshal(ch.WebAuthn.CredentialOptions)
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	var opts protocol.PublicKeyCredentialRequestOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatalf("unmarshal request options: %v", err)
	}
	return &opts
}

func webAuthnVerifyBody(challengeID, ceremonyType string, credential json.RawMessage) map[string]any {
	return map[string]any{
		"challenge_id": challengeID,
		"webauthn": map[string]any{
			"type":       ceremonyType,
			"credential": credential,
		},
	}
}

// TestMFAWebAuthnEnrollChallengeVerifyProducesAAL2 exercises the whole loop:
// enrol (create ceremony), then a second challenge+verify (request ceremony)
// against the now-verified factor.
func TestMFAWebAuthnEnrollChallengeVerifyProducesAAL2(t *testing.T) {
	env := newMFAEnv(t, webAuthnConfig())
	session := env.signupUser(t, "mfa-webauthn@dilion.test")

	factor := env.enrollWebAuthn(t, session.Token, "Security key")
	if factor.Type != FactorTypeWebAuthn {
		t.Fatalf("enroll type = %q, want webauthn", factor.Type)
	}

	va := newVirtualAuthenticator(testWebAuthnRPID, testWebAuthnOrigin)

	// ---- registration ceremony (unverified factor) ----------------------
	ch := env.challengeWebAuthn(t, session.Token, factor.ID)
	credential := va.createCredential(t, creationOptionsOf(t, ch))

	env.clock.advance(2 * time.Second)
	rec := env.do(t, http.MethodPost, "/factors/"+factor.ID+"/verify",
		webAuthnVerifyBody(ch.ID, webAuthnFactorTypeCreate, credential), session.Token)
	upgraded := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	if got := env.aal(t, upgraded.Token); got != AAL2 {
		t.Fatalf("post-enrol aal = %q, want aal2", got)
	}
	if got := env.amrMethods(t, upgraded.Token); !equalMethods(got, []string{AMRMethodMFAWebAuthn, AMRMethodPassword}) {
		t.Fatalf("post-enrol amr = %v, want [mfa/webauthn password]", got)
	}
	if upgraded.RefreshToken == session.RefreshToken {
		t.Fatal("verify must issue a NEW refresh token")
	}

	// The credential blob is now on the factor row, not in webauthn_credentials.
	var hasCred bool
	if err := env.pool.QueryRow(t.Context(),
		`select web_authn_credential is not null from auth.mfa_factors where id = $1::uuid`, factor.ID).Scan(&hasCred); err != nil {
		t.Fatalf("read factor credential: %v", err)
	}
	if !hasCred {
		t.Fatal("verified webauthn factor must carry a stored credential")
	}

	// ---- login ceremony (verified factor) -------------------------------
	env.clock.advance(2 * time.Second)
	ch2 := env.challengeWebAuthn(t, session.Token, factor.ID)
	assertion := va.getAssertion(t, requestOptionsOf(t, ch2), 1)

	env.clock.advance(2 * time.Second)
	rec = env.do(t, http.MethodPost, "/factors/"+factor.ID+"/verify",
		webAuthnVerifyBody(ch2.ID, webAuthnFactorTypeRequest, assertion), session.Token)
	loggedIn := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if got := env.aal(t, loggedIn.Token); got != AAL2 {
		t.Fatalf("post-login aal = %q, want aal2", got)
	}
	if got := env.amrMethods(t, loggedIn.Token); !equalMethods(got, []string{AMRMethodMFAWebAuthn, AMRMethodPassword}) {
		t.Fatalf("post-login amr = %v, want [mfa/webauthn password]", got)
	}
}

// TestMFAWebAuthnWrongOriginRejected: an authenticator whose origin is not in
// RPOrigins is refused with the protocol verification-failed code.
func TestMFAWebAuthnWrongOriginRejected(t *testing.T) {
	env := newMFAEnv(t, webAuthnConfig())
	session := env.signupUser(t, "mfa-webauthn-origin@dilion.test")
	factor := env.enrollWebAuthn(t, session.Token, "Security key")

	evil := newVirtualAuthenticator(testWebAuthnRPID, "https://evil.example.com")
	ch := env.challengeWebAuthn(t, session.Token, factor.ID)
	credential := evil.createCredential(t, creationOptionsOf(t, ch))

	rec := env.do(t, http.MethodPost, "/factors/"+factor.ID+"/verify",
		webAuthnVerifyBody(ch.ID, webAuthnFactorTypeCreate, credential), session.Token)
	if b := decodeInto[errorBody](t, rec, http.StatusBadRequest); b.ErrorCode != ErrorCodeWebAuthnVerificationFailed {
		t.Fatalf("error_code = %q, want %q", b.ErrorCode, ErrorCodeWebAuthnVerificationFailed)
	}
}

// TestMFAWebAuthnEnrollDisabled: a default deployment leaves webauthn MFA off.
func TestMFAWebAuthnEnrollDisabled(t *testing.T) {
	env := newMFAEnv(t, nil) // DefaultConfig: webauthn MFA off
	session := env.signupUser(t, "mfa-webauthn-off@dilion.test")
	rec := env.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "webauthn", "friendly_name": "Key"}, session.Token)
	if b := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); b.ErrorCode != ErrorCodeMFAWebAuthnEnrollDisabled {
		t.Fatalf("error_code = %q, want %q", b.ErrorCode, ErrorCodeMFAWebAuthnEnrollDisabled)
	}
}

// TestAdminListsMixedFactorTypes: the admin factor list renders totp, phone and
// webauthn factors together with their type and status.
func TestAdminListsMixedFactorTypes(t *testing.T) {
	sender := &recordingSender{}
	cfg := webAuthnConfig()
	cfg.MFA.Phone.EnrollEnabled = true
	cfg.MFA.Phone.VerifyEnabled = true
	cfg.SMS.Sender = sender
	env := newMFAEnv(t, cfg)
	admin := env.serviceRoleToken(t)

	session := env.signupUser(t, "mfa-admin-mixed@dilion.test")
	userID := env.claims(t, session.Token).Subject

	env.enroll(t, session.Token, "TOTP")
	env.enrollPhone(t, session.Token, "+15550109999", "Phone")
	env.enrollWebAuthn(t, session.Token, "Key")

	list := decodeInto[[]Factor](t, env.do(t, http.MethodGet, "/admin/users/"+userID+"/factors", nil, admin), http.StatusOK)
	if len(list) != 3 {
		t.Fatalf("factor list length = %d, want 3", len(list))
	}
	seen := map[string]string{}
	for _, f := range list {
		seen[f.FactorType] = f.Status
	}
	for _, want := range []string{FactorTypeTOTP, FactorTypePhone, FactorTypeWebAuthn} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("admin list is missing factor type %q; got %v", want, seen)
		}
	}
}
