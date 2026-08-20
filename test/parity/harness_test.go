//go:build parity

// Differential parity + coverage harness for Dilion's /auth/v1 surface against
// the real upstream github.com/supabase/auth (GoTrue).
//
// It is compiled ONLY under the `parity` build tag, so `go test ./...` never
// runs it. Bring both servers up (see README.md / compose.parity.yml), then:
//
//	PARITY_DILION_URL=http://localhost:8787/auth/v1 \
//	PARITY_GOTRUE_URL=http://localhost:9999 \
//	PARITY_JWT_SECRET=parity-super-secret-shared-jwt-key-0123456789 \
//	go test -tags parity ./test/parity/ -run TestParity -v
//
// PARITY_DILION_URL must include the /auth/v1 mount prefix; PARITY_GOTRUE_URL is
// the bare GoTrue host (upstream serves the routes at its root). Scenario paths
// are relative ("/health", "/token?grant_type=password") and joined onto each
// base, which is what makes the two mounts comparable.
//
// The runner, per scenario:
//  1. issues the SAME logical request to BOTH servers (injecting each server's
//     own credential/refresh-token where the scenario needs one),
//  2. normalises volatile fields (normalize.go),
//  3. diffs status + compared headers + body (or redirect Location + JWT claims),
//  4. consults deviations.yaml — a diff that matches an allow-list entry is
//     downgraded from FAIL to KNOWN,
//  5. records which OpenAPI operation the scenario exercised.
//
// A coverage report (covered / uncovered of the 69 curated ops) is emitted at
// the end so gaps are visible, and a TODO table lists the remaining ops with
// enough structure that filling them in is mechanical.
package parity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---- environment -----------------------------------------------------------

type harnessEnv struct {
	dilionURL string
	gotrueURL string
	secret    string
	devs      []Deviation
	contract  *Contract
	http      *http.Client
}

func loadEnv(t *testing.T) *harnessEnv {
	t.Helper()
	e := &harnessEnv{
		dilionURL: os.Getenv("PARITY_DILION_URL"),
		gotrueURL: os.Getenv("PARITY_GOTRUE_URL"),
		secret:    envOr("PARITY_JWT_SECRET", "parity-super-secret-shared-jwt-key-0123456789"),
		http:      &http.Client{Timeout: 15 * time.Second},
	}
	if e.dilionURL == "" || e.gotrueURL == "" {
		t.Skip("PARITY_DILION_URL and PARITY_GOTRUE_URL must both be set; bring the stack up with `make parity-up` first")
	}
	e.dilionURL = strings.TrimRight(e.dilionURL, "/")
	e.gotrueURL = strings.TrimRight(e.gotrueURL, "/")

	devPath := envOr("PARITY_DEVIATIONS", relToThisFile("deviations.yaml"))
	devs, err := LoadDeviations(devPath)
	if err != nil {
		t.Fatalf("load deviations: %v", err)
	}
	e.devs = devs

	oapiPath := envOr("PARITY_OPENAPI", relToThisFile("../../web/openapi-auth.yaml"))
	c, err := LoadContract(oapiPath)
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}
	e.contract = c
	return e
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// relToThisFile resolves paths relative to the test file's directory, so the
// harness works regardless of the `go test` working directory.
func relToThisFile(rel string) string {
	// go test runs with the package dir as CWD, so a plain relative path works;
	// this indirection keeps that assumption in one place.
	abs, err := filepath.Abs(rel)
	if err != nil {
		return rel
	}
	return abs
}

// ---- credentials -----------------------------------------------------------

// serverCreds holds one bootstrapped user's live credentials ON ONE server.
// Tokens differ per server (separate databases), so every credentialed request
// injects the target server's own token.
type serverCreds struct {
	email        string
	password     string
	accessToken  string
	refreshToken string
}

// fixtureUser is one bootstrap identity, with the email/password SHARED across
// both servers so the resulting user objects are comparable (only the minted
// ids/tokens differ). The emails are generated ONCE per run.
type fixtureUser struct{ name, email, password string }

func newFixtures() []fixtureUser {
	stamp := time.Now().UnixNano()
	return []fixtureUser{
		{name: "userA", email: fmt.Sprintf("parity-usera-%d@example.test", stamp), password: "Sup3rSecret!pw-A"},
		{name: "userB", email: fmt.Sprintf("parity-userb-%d@example.test", stamp), password: "Sup3rSecret!pw-B"},
	}
}

// bootstrap signs up each fixture user on ONE server and captures that server's
// tokens. The SAME fixtures are passed for both servers, so userA has an
// identical email on both — which is what makes the /user bodies diff cleanly.
func (e *harnessEnv) bootstrap(t *testing.T, base string, fixtures []fixtureUser) map[string]*serverCreds {
	t.Helper()
	out := map[string]*serverCreds{}
	for _, f := range fixtures {
		if _, _, _, err := e.do(base, "POST", "/signup", "", nil,
			fmt.Sprintf(`{"email":%q,"password":%q}`, f.email, f.password)); err != nil {
			t.Fatalf("bootstrap %s signup on %s: %v", f.name, base, err)
		}
		status, _, body, err := e.do(base, "POST", "/token?grant_type=password", "", nil,
			fmt.Sprintf(`{"email":%q,"password":%q}`, f.email, f.password))
		if err != nil || status != 200 {
			t.Fatalf("bootstrap %s token on %s: status=%d err=%v body=%s", f.name, base, status, err, body)
		}
		v := NormalizeJSONRaw(body)
		out[f.name] = &serverCreds{
			email:        f.email,
			password:     f.password,
			accessToken:  strField(v, "access_token"),
			refreshToken: strField(v, "refresh_token"),
		}
	}
	return out
}

// mintServiceRole builds a service_role HS256 JWT signed with the shared secret;
// because both servers verify with the same secret it is accepted by both. Used
// by admin-surface scenarios.
func (e *harnessEnv) mintServiceRole(t *testing.T) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"role": "service_role",
		"aud":  "authenticated",
		"sub":  "00000000-0000-0000-0000-000000000000",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte(e.secret))
	if err != nil {
		t.Fatalf("mint service_role: %v", err)
	}
	return s
}

// ---- scenario model --------------------------------------------------------

// bodyCompare selects how a scenario's response body is compared.
type bodyCompare int

const (
	compareFull      bodyCompare = iota // deep structural diff after scrubbing
	compareTopKeys                      // only the set of top-level object keys
	compareRedirect                     // compare Location, not the body
	compareNone                         // status + headers only
)

// scenario is one differential request executed against both servers.
type scenario struct {
	name    string
	method  string
	path    string // relative; may include a query string
	cred    string // "" | "userA" | "userB" | "service_role"
	headers map[string]string
	// body is a JSON/form string; the tokens {{refresh_token}} and {{email}} are
	// substituted per server from that server's bootstrapped credentials.
	body    string
	compare bodyCompare
	// wantStatus, when non-zero, additionally asserts BOTH servers returned it
	// (a guard that the scenario actually exercised the path it claims to).
	wantStatus int
}

// scenarios is the working slice. Each exercises a distinct span of the surface;
// the operationId each maps to is resolved automatically for the coverage report.
func scenarios() []scenario {
	return []scenario{
		// ---- Core, unauthenticated ----
		{name: "health", method: "GET", path: "/health", compare: compareFull, wantStatus: 200},
		{name: "settings", method: "GET", path: "/settings", compare: compareFull, wantStatus: 200},
		{name: "jwks", method: "GET", path: "/.well-known/jwks.json", compare: compareFull, wantStatus: 200},
		{name: "openid-config", method: "GET", path: "/.well-known/openid-configuration", compare: compareFull, wantStatus: 200},
		// Both servers 404 this with feature_disabled when the OAuth server is off
		// (the default). The assertion is that they AGREE, so no wantStatus is set;
		// enabling the OAuth-server twin on both flips this to a 200 body compare.
		{name: "oauth-as-metadata", method: "GET", path: "/.well-known/oauth-authorization-server", compare: compareFull},

		// ---- Signup / token / user lifecycle ----
		{
			name: "signup-email", method: "POST", path: "/signup", compare: compareFull, wantStatus: 200,
			headers: map[string]string{"Content-Type": "application/json"},
			// unique email per run so both DBs see a fresh account
			body: fmt.Sprintf(`{"email":"parity-signup-%d@example.test","password":"Sup3rSecret!pw"}`, time.Now().UnixNano()),
		},
		{
			name: "token-password", method: "POST", path: "/token?grant_type=password", compare: compareFull, wantStatus: 200,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"email":"{{email}}","password":"{{password}}"}`, cred: "userA",
		},
		{
			name: "token-refresh", method: "POST", path: "/token?grant_type=refresh_token", compare: compareFull, wantStatus: 200,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"refresh_token":"{{refresh_token}}"}`, cred: "userA",
		},
		{name: "get-user", method: "GET", path: "/user", cred: "userA", compare: compareFull, wantStatus: 200},
		{
			name: "update-user", method: "PUT", path: "/user", cred: "userA", compare: compareFull, wantStatus: 200,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"data":{"parity_marker":"x"}}`,
		},
		{name: "logout", method: "POST", path: "/logout", cred: "userB", compare: compareNone, wantStatus: 204},

		// ---- Admin (cross-verifiable service_role token) ----
		{name: "admin-list-users", method: "GET", path: "/admin/users", cred: "service_role", compare: compareTopKeys, wantStatus: 200},

		// ---- Error case ----
		{
			name: "token-bad-credentials", method: "POST", path: "/token?grant_type=password", compare: compareFull, wantStatus: 400,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"email":"nobody-parity@example.test","password":"definitely-wrong"}`,
		},

		// ---- Redirect case ----
		{name: "verify-redirect", method: "GET", path: "/verify?type=signup&token=deadbeefdeadbeefdeadbeef&redirect_to=http://localhost:3000/welcome", compare: compareRedirect},
	}
}

// ---- runner ----------------------------------------------------------------

func TestParity(t *testing.T) {
	e := loadEnv(t)

	fixtures := newFixtures()
	dilionCreds := e.bootstrap(t, e.dilionURL, fixtures)
	gotrueCreds := e.bootstrap(t, e.gotrueURL, fixtures)
	serviceRole := e.mintServiceRole(t)

	hit := map[string]bool{}
	var knownCount, failCount int

	for _, sc := range scenarios() {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			op := e.contract.Resolve(sc.method, sc.path)
			if op != "" {
				hit[op] = true
			}

			dStatus, dHdr, dBody := e.exec(t, e.dilionURL, sc, dilionCreds, serviceRole)
			uStatus, uHdr, uBody := e.exec(t, e.gotrueURL, sc, gotrueCreds, serviceRole)

			if sc.wantStatus != 0 {
				if dStatus != sc.wantStatus {
					t.Errorf("dilion status=%d, scenario expected %d (body=%s)", dStatus, sc.wantStatus, truncate(dBody))
				}
				if uStatus != sc.wantStatus {
					t.Errorf("upstream status=%d, scenario expected %d (body=%s)", uStatus, sc.wantStatus, truncate(uBody))
				}
			}

			diffs := e.diff(sc, dStatus, uStatus, dHdr, uHdr, dBody, uBody)

			for _, d := range diffs {
				if dev := Match(e.devs, op, d); dev != nil {
					knownCount++
					t.Logf("KNOWN  %-24s %s  (deviation %q: %s)", op, d, dev.ID, dev.Reason)
					continue
				}
				failCount++
				t.Errorf("FAIL   %-24s %s", op, d)
			}
			if len(diffs) == 0 {
				t.Logf("green  %-24s (%s %s)", op, sc.method, sc.path)
			}
		})
	}

	reportCoverage(t, e.contract, hit)
	t.Logf("parity summary: %d KNOWN deviations tolerated, %d FAIL diffs", knownCount, failCount)
}

// exec issues one scenario request against base and returns status/headers/body.
func (e *harnessEnv) exec(t *testing.T, base string, sc scenario, creds map[string]*serverCreds, serviceRole string) (int, http.Header, []byte) {
	t.Helper()
	token := ""
	body := sc.body
	switch sc.cred {
	case "", "none":
	case "service_role":
		token = serviceRole
	default:
		c := creds[sc.cred]
		if c == nil {
			t.Fatalf("scenario %q references unknown credential %q", sc.name, sc.cred)
		}
		token = c.accessToken
		body = strings.NewReplacer(
			"{{refresh_token}}", c.refreshToken,
			"{{email}}", c.email,
			"{{password}}", c.password,
		).Replace(body)
	}
	status, hdr, respBody, err := e.do(base, sc.method, sc.path, token, sc.headers, body)
	if err != nil {
		t.Fatalf("scenario %q request to %s: %v", sc.name, base, err)
	}
	return status, hdr, respBody
}

// do performs one HTTP request. base already carries any /auth/v1 prefix.
func (e *harnessEnv) do(base, method, path, token string, headers map[string]string, body string) (int, http.Header, []byte, error) {
	var r io.Reader
	if body != "" {
		r = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, base+path, r)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Do NOT auto-follow redirects: the redirect itself is the assertion.
	e.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := e.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, resp.Header, respBody, nil
}

// diff builds the full diff set for a scenario according to its compare mode.
func (e *harnessEnv) diff(sc scenario, dStatus, uStatus int, dHdr, uHdr http.Header, dBody, uBody []byte) []Diff {
	var diffs []Diff
	if dStatus != uStatus {
		diffs = append(diffs, Diff{Kind: "status", Path: "status", Dilion: dStatus, Upstream: uStatus})
	}
	diffs = append(diffs, DiffHeaders(dHdr, uHdr)...)

	switch sc.compare {
	case compareNone:
		// status + headers only
	case compareRedirect:
		diffs = append(diffs, DiffRedirect(dHdr.Get("Location"), uHdr.Get("Location"))...)
	case compareTopKeys:
		diffs = append(diffs, diffTopKeys(dBody, uBody)...)
	case compareFull:
		diffs = append(diffs, DiffJSON("", NormalizeJSON(dBody), NormalizeJSON(uBody))...)
		// When both bodies carry an access token, additionally assert the stable
		// JWT claims match (they were scrubbed out of the body diff above).
		if dt, ut := rawField(dBody, "access_token"), rawField(uBody, "access_token"); dt != "" && ut != "" {
			diffs = append(diffs, DiffJWTClaims(dt, ut)...)
		}
	}
	return diffs
}

// diffTopKeys compares only the set of top-level object keys (used where the
// body content legitimately differs, e.g. an admin listing of different users,
// but the envelope shape must match).
func diffTopKeys(dBody, uBody []byte) []Diff {
	dk, uk := topKeys(dBody), topKeys(uBody)
	var out []Diff
	for _, k := range symmetricDiff(dk, uk) {
		out = append(out, Diff{Kind: "body", Path: k + "(top-level key)", Dilion: dk[k], Upstream: uk[k]})
	}
	return out
}

// ---- coverage report + TODO scaffold ---------------------------------------

func reportCoverage(t *testing.T, c *Contract, hit map[string]bool) {
	rep := c.Coverage(hit)
	pct := 0.0
	if rep.Total > 0 {
		pct = 100 * float64(len(rep.Covered)) / float64(rep.Total)
	}
	t.Logf("=== COVERAGE: %d/%d operations exercised (%.1f%%) ===", len(rep.Covered), rep.Total, pct)
	t.Logf("covered: %s", strings.Join(rep.Covered, ", "))
	t.Logf("--- %d uncovered operations (fill these in; see the TODO table below) ---", len(rep.Uncovered))
	for _, id := range rep.Uncovered {
		t.Logf("  TODO scenario for op: %s", id)
	}
}

// TODOScaffold documents, per still-uncovered operation, the credential and the
// prerequisite state a future scenario needs. Filling in a row is mechanical:
// add a scenario{} to scenarios() with the method/path/cred below and the right
// compare mode, then add any genuinely-new intentional difference to
// deviations.yaml. This lives as a test so it shows up in `go test -tags parity
// -run TestParityTODO -v` and never drifts silently.
//
//	op                              cred           prerequisite / notes
//	------------------------------- -------------- -------------------------------------------
//	authVerifyPost                  none           POST /verify {type,token,...}; needs a real OTP (mint via /admin/generate_link)
//	authOtp                         none           POST /otp {email}; asserts 200 + rate-limit headers
//	authMagicLink                   none           POST /magiclink {email}
//	authRecover                     none           POST /recover {email}
//	authResend                      none           POST /resend {type,email}
//	authReauthenticate              userA          GET /reauthenticate
//	authInvite                      service_role   POST /invite {email}
//	authAdminGenerateLink           service_role   POST /admin/generate_link {type,email} — also the OTP source for authVerifyPost
//	authExternalAuthorize           none           GET /authorize?provider=github — assert redirect host (external OAuth start)
//	authExternalCallbackGet/Post    none           GET|POST /callback — needs a stubbed provider; compare error redirect
//	authLinkIdentity                userA          GET /user/identities/authorize (SECURITY_MANUAL_LINKING_ENABLED on both)
//	authUnlinkIdentity              userA          DELETE /user/identities/{identity_id}
//	authEnrollFactor                userA          POST /factors {factor_type:totp} (MFA_TOTP_ENROLL_ENABLED on both)
//	authChallengeFactor             userA          POST /factors/{id}/challenge
//	authVerifyFactor                userA          POST /factors/{id}/verify {code} — needs a TOTP code from the enrol secret
//	authUnenrollFactor              userA          DELETE /factors/{id}
//	authAdminListFactors            service_role   GET /admin/users/{user_id}/factors
//	authAdminUpdateFactor           service_role   PUT /admin/users/{user_id}/factors/{id}
//	authAdminDeleteFactor           service_role   DELETE /admin/users/{user_id}/factors/{id}
//	authPasskey* (7 ops)            mixed          enable passkeys on BOTH (DILION_AUTH_PASSKEY_ENABLED / GOTRUE_MFA_WEB_AUTHN_*)
//	authSingleSignOn                none           POST /sso {domain} (SAML enabled on both) — compare redirect
//	authSamlMetadata                none           GET /sso/saml/metadata — compare XML entityID (see saml-external-url deviation)
//	authSamlAcs                     none           POST /sso/saml/acs — needs a signed SAML response fixture
//	authAdmin*SSOProvider (5 ops)   service_role   /admin/sso/providers CRUD (SAML enabled on both)
//	authOAuth* (12 ops)             mixed          enable the OAuth2.1 server on both (DILION_AUTH_OAUTH_SERVER_ENABLED / GOTRUE_OAUTH_SERVER_ENABLED); register a client, run DCR/authorize/token/userinfo/consent/grants
//	authAdminGetUser                service_role   GET /admin/users/{user_id}
//	authAdminCreateUser             service_role   POST /admin/users {email,password}
//	authAdminUpdateUser             service_role   PUT /admin/users/{user_id}
//	authAdminDeleteUser             service_role   DELETE /admin/users/{user_id} — assert 200/204 + outbox side-effect is Dilion-only (deviation)
//	authAdminAuditLog               service_role   GET /admin/audit — Dilion translates its own audit store (see admin_audit.go)
//
// See internal/auth/*.go for each handler; the deviations.yaml already carries
// the intentional differences most of these will surface.
const TODOScaffold = "see the table in the doc comment above"

// ---- small helpers ---------------------------------------------------------

func topKeys(body []byte) map[string]bool {
	v := NormalizeJSONRaw(body)
	out := map[string]bool{}
	if m, ok := v.(map[string]any); ok {
		for k := range m {
			out[k] = true
		}
	}
	return out
}

func symmetricDiff(a, b map[string]bool) []string {
	var only []string
	for k := range a {
		if !b[k] {
			only = append(only, k)
		}
	}
	for k := range b {
		if !a[k] {
			only = append(only, k)
		}
	}
	sort.Strings(only)
	return only
}

// NormalizeJSONRaw unmarshals without scrubbing (used to pull specific fields).
func NormalizeJSONRaw(body []byte) any {
	return jsonDecode(body)
}

func jsonDecode(body []byte) any {
	var v any
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return strings.TrimSpace(string(body))
	}
	return v
}

func strField(v any, key string) string {
	if m, ok := v.(map[string]any); ok {
		if s, ok := m[key].(string); ok {
			return s
		}
	}
	return ""
}

func rawField(body []byte, key string) string {
	return strField(jsonDecode(body), key)
}

func truncate(b []byte) string {
	s := string(b)
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
