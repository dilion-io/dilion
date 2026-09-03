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
	"net/http/httptest"
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

// ---- web_authn_aaguid / last_webauthn_challenge_data -----------------------

// appleAAGUID is a real, published authenticator model id (Apple Passwords),
// used here only because it is a well-formed non-zero AAGUID.
const appleAAGUIDString = "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"

// factorJSON re-reads one factor through the admin factor list as RAW JSON, so
// the assertions below are about the wire body and not about a Go struct that
// might round-trip a key it never emitted.
func (e *mfaEnv) factorJSON(t *testing.T, admin, userID, factorID string) map[string]any {
	t.Helper()
	list := decodeInto[[]map[string]any](t,
		e.do(t, http.MethodGet, "/admin/users/"+userID+"/factors", nil, admin), http.StatusOK)
	for _, f := range list {
		if f["id"] == factorID {
			return f
		}
	}
	t.Fatalf("factor %s not in admin list %v", factorID, list)
	return nil
}

// TestMFAWebAuthnFactorSerializesAAGUIDAndChallengeData covers items C1 and C2
// together, because upstream writes both columns from the same place
// (internal/api/mfa.go verifyWebAuthnFactor -> models.Factor
// .SaveWebAuthnCredential + .UpdateLastWebAuthnChallenge) and exposes both the
// same way (plain json tags on models.Factor, so every factor read carries
// them).
func TestMFAWebAuthnFactorSerializesAAGUIDAndChallengeData(t *testing.T) {
	env := newMFAEnv(t, webAuthnConfig())
	admin := env.serviceRoleToken(t)
	session := env.signupUser(t, "mfa-webauthn-aaguid@dilion.test")
	userID := env.claims(t, session.Token).Subject

	factor := env.enrollWebAuthn(t, session.Token, "Security key")

	// An unverified factor has completed no ceremony: both keys must be absent,
	// which is what upstream's `omitempty` on two nil pointers produces.
	before := env.factorJSON(t, admin, userID, factor.ID)
	if _, ok := before["web_authn_aaguid"]; ok {
		t.Errorf("web_authn_aaguid must be absent before any ceremony; got %v", before)
	}
	if _, ok := before["last_webauthn_challenge_data"]; ok {
		t.Errorf("last_webauthn_challenge_data must be absent before any ceremony; got %v", before)
	}

	va := newVirtualAuthenticator(testWebAuthnRPID, testWebAuthnOrigin).
		withAAGUID(t, appleAAGUIDString)

	// ---- registration ceremony ------------------------------------------
	ch := env.challengeWebAuthn(t, session.Token, factor.ID)
	credential := va.createCredential(t, creationOptionsOf(t, ch))
	env.clock.advance(2 * time.Second)
	rec := env.do(t, http.MethodPost, "/factors/"+factor.ID+"/verify",
		webAuthnVerifyBody(ch.ID, webAuthnFactorTypeCreate, credential), session.Token)
	upgraded := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	after := env.factorJSON(t, admin, userID, factor.ID)
	if got := after["web_authn_aaguid"]; got != appleAAGUIDString {
		t.Errorf("web_authn_aaguid = %v, want %q", got, appleAAGUIDString)
	}
	assertLastChallengeData(t, after, webAuthnFactorTypeCreate, ch.ID)

	// The verify response's own `user.factors` is built from the same read, so
	// it carries the fields too — upstream's verify likewise answers with a
	// session whose user was re-loaded after the two writes.
	assertSessionUserFactor(t, rec, factor.ID, appleAAGUIDString, webAuthnFactorTypeCreate)
	if upgraded.User == nil {
		t.Fatal("verify response must carry a user")
	}

	// ---- assertion ceremony ---------------------------------------------
	// Upstream calls UpdateLastWebAuthnChallenge on EVERY verify, not only the
	// one that promotes the factor, so a login ceremony must overwrite it.
	env.clock.advance(2 * time.Second)
	ch2 := env.challengeWebAuthn(t, session.Token, factor.ID)
	assertion := va.getAssertion(t, requestOptionsOf(t, ch2), 1)
	env.clock.advance(2 * time.Second)
	rec = env.do(t, http.MethodPost, "/factors/"+factor.ID+"/verify",
		webAuthnVerifyBody(ch2.ID, webAuthnFactorTypeRequest, assertion), session.Token)
	loggedIn := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	relogin := env.factorJSON(t, admin, userID, factor.ID)
	if got := relogin["web_authn_aaguid"]; got != appleAAGUIDString {
		t.Errorf("web_authn_aaguid changed across a login ceremony: %v", got)
	}
	assertLastChallengeData(t, relogin, webAuthnFactorTypeRequest, ch2.ID)

	// GET /user serves the same factor objects (user.go loadFactors).
	userRec := env.do(t, http.MethodGet, "/user", nil, loggedIn.Token)
	if userRec.Code != http.StatusOK {
		t.Fatalf("GET /user status = %d: %s", userRec.Code, userRec.Body.String())
	}
	var got struct {
		Factors []map[string]any `json:"factors"`
	}
	if err := json.Unmarshal(userRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal /user: %v", err)
	}
	if len(got.Factors) != 1 {
		t.Fatalf("GET /user factors = %d, want 1", len(got.Factors))
	}
	if v := got.Factors[0]["web_authn_aaguid"]; v != appleAAGUIDString {
		t.Errorf("GET /user factor web_authn_aaguid = %v, want %q", v, appleAAGUIDString)
	}
	assertLastChallengeData(t, got.Factors[0], webAuthnFactorTypeRequest, ch2.ID)
}

// assertLastChallengeData pins the stored document to upstream's
// models.LastWebAuthnChallengeData shape: {challenge, type, credential_response},
// with `challenge` carrying models.Challenge's json tags (challenge_id, not id).
// wantChallengeID "" skips the challenge-id comparison.
func assertLastChallengeData(t *testing.T, factor map[string]any, wantType, wantChallengeID string) {
	t.Helper()
	raw, ok := factor["last_webauthn_challenge_data"].(map[string]any)
	if !ok {
		t.Fatalf("last_webauthn_challenge_data missing or not an object: %v", factor["last_webauthn_challenge_data"])
	}
	if got := raw["type"]; got != wantType {
		t.Errorf("last_webauthn_challenge_data.type = %v, want %q", got, wantType)
	}
	challenge, ok := raw["challenge"].(map[string]any)
	if !ok {
		t.Fatalf("last_webauthn_challenge_data.challenge is not an object: %v", raw["challenge"])
	}
	if wantChallengeID != "" && challenge["challenge_id"] != wantChallengeID {
		t.Errorf("challenge.challenge_id = %v, want %q", challenge["challenge_id"], wantChallengeID)
	}
	// Upstream snapshots the challenge BEFORE consuming it, so verified_at is
	// never in the document (`omitempty` over a nil pointer).
	if _, ok := challenge["verified_at"]; ok {
		t.Errorf("challenge.verified_at must be absent (upstream snapshots the unconsumed challenge): %v", challenge)
	}
	if _, ok := challenge["ip_address"]; !ok {
		t.Errorf("challenge.ip_address missing: %v", challenge)
	}
	// The stored response is the PARSED authenticator response — go-webauthn's
	// ParsedCredentialCreationData / ParsedCredentialAssertionData — exactly as
	// upstream stores it (internal/models/factor.go marshals the same library
	// types). Those types carry NO json tags, so they marshal under their Go
	// field names: "ID" and "Type" from the embedded ParsedCredential, "Raw"
	// for the client's original body, "Response" for the decoded ceremony data.
	// Asserting the capitalised keys is what pins us to upstream's encoding;
	// lowercase "id" would mean we had invented our own.
	cr, ok := raw["credential_response"].(map[string]any)
	if !ok {
		t.Fatalf("credential_response is not an object: %v", raw["credential_response"])
	}
	if id, _ := cr["ID"].(string); id == "" {
		t.Errorf("credential_response.ID (go-webauthn ParsedCredential.ID) is missing: %v", cr)
	}
	if got := cr["Type"]; got != "public-key" {
		t.Errorf("credential_response.Type = %v, want public-key", got)
	}
	if _, ok := cr["Response"].(map[string]any); !ok {
		t.Errorf("credential_response.Response (the decoded ceremony data) is missing: %v", cr)
	}
	if _, ok := cr["Raw"].(map[string]any); !ok {
		t.Errorf("credential_response.Raw (the client's original body) is missing: %v", cr)
	}
}

// assertSessionUserFactor checks the factor embedded in a session envelope's
// `user.factors`.
func assertSessionUserFactor(t *testing.T, rec *httptest.ResponseRecorder, factorID, wantAAGUID, wantType string) {
	t.Helper()
	var body struct {
		User struct {
			Factors []map[string]any `json:"factors"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal session envelope: %v", err)
	}
	for _, f := range body.User.Factors {
		if f["id"] != factorID {
			continue
		}
		if f["web_authn_aaguid"] != wantAAGUID {
			t.Errorf("session user.factors web_authn_aaguid = %v, want %q", f["web_authn_aaguid"], wantAAGUID)
		}
		assertLastChallengeData(t, f, wantType, "")
		return
	}
	t.Fatalf("factor %s not in session envelope user.factors: %s", factorID, rec.Body.String())
}

// TestMFAFactorsWithoutWebAuthnOmitTheWebAuthnFields: a TOTP factor, and a
// webauthn factor whose authenticator declined to identify its model (the
// all-zero AAGUID, stored as NULL), leave both keys out entirely — upstream's
// `omitempty` over nil pointers.
func TestMFAFactorsWithoutWebAuthnOmitTheWebAuthnFields(t *testing.T) {
	env := newMFAEnv(t, webAuthnConfig())
	admin := env.serviceRoleToken(t)
	session := env.signupUser(t, "mfa-no-aaguid@dilion.test")
	userID := env.claims(t, session.Token).Subject

	totpFactor := env.enroll(t, session.Token, "TOTP")
	totpJSON := env.factorJSON(t, admin, userID, totpFactor.ID)
	for _, key := range []string{"web_authn_aaguid", "last_webauthn_challenge_data"} {
		if _, ok := totpJSON[key]; ok {
			t.Errorf("a totp factor must not carry %q; got %v", key, totpJSON)
		}
	}

	// A webauthn factor verified by an authenticator with the all-zero AAGUID:
	// the credential and the challenge record are stored, the AAGUID is not.
	factor := env.enrollWebAuthn(t, session.Token, "Anonymous key")
	va := newVirtualAuthenticator(testWebAuthnRPID, testWebAuthnOrigin) // no AAGUID
	ch := env.challengeWebAuthn(t, session.Token, factor.ID)
	credential := va.createCredential(t, creationOptionsOf(t, ch))
	env.clock.advance(2 * time.Second)
	if rec := env.do(t, http.MethodPost, "/factors/"+factor.ID+"/verify",
		webAuthnVerifyBody(ch.ID, webAuthnFactorTypeCreate, credential), session.Token); rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d: %s", rec.Code, rec.Body.String())
	}

	anon := env.factorJSON(t, admin, userID, factor.ID)
	if _, ok := anon["web_authn_aaguid"]; ok {
		t.Errorf("an all-zero AAGUID must be stored as NULL and omitted; got %v", anon["web_authn_aaguid"])
	}
	assertLastChallengeData(t, anon, webAuthnFactorTypeCreate, ch.ID)
}
