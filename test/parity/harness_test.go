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
		// userC/userD are dedicated to the stateful MFA flows so enrolling factors
		// on them never perturbs the userA/userB single-request scenarios.
		{name: "userC", email: fmt.Sprintf("parity-userc-%d@example.test", stamp), password: "Sup3rSecret!pw-C"},
		{name: "userD", email: fmt.Sprintf("parity-userd-%d@example.test", stamp), password: "Sup3rSecret!pw-D"},
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
	compareFull     bodyCompare = iota // deep structural diff after scrubbing
	compareTopKeys                     // only the set of top-level object keys
	compareRedirect                    // compare Location, not the body
	compareNone                        // status + headers only
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
	// profile gates a scenario on the feature-flag twin: "" runs always, "off"
	// only when the flagged surfaces are DISABLED (the default stack), "on" only
	// when PARITY_FLAGS=1 brings the flagged twin up on both servers.
	profile string
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
		// Admin SSO provider listing is NOT gated on the SAML feature flag, so an
		// empty catalogue ({"items":[]}) is comparable on the default stack.
		{name: "admin-list-sso-providers", method: "GET", path: "/admin/sso/providers", cred: "service_role", compare: compareFull, wantStatus: 200},
		// Admin audit log: both expose it and return a 200 JSON array, but the rows
		// are each instance's OWN audit history (different actors/actions/counts),
		// so only status + content-type are comparable; Dilion additionally
		// decorates payload.traits (dilion_action/dilion_event_id) — see deviation.
		{name: "admin-audit-log", method: "GET", path: "/admin/audit", cred: "service_role", compare: compareNone, wantStatus: 200},

		// ---- Error case ----
		{
			name: "token-bad-credentials", method: "POST", path: "/token?grant_type=password", compare: compareFull, wantStatus: 400,
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"email":"nobody-parity@example.test","password":"definitely-wrong"}`,
		},

		// ---- Redirect case ----
		{name: "verify-redirect", method: "GET", path: "/verify?type=signup&token=deadbeefdeadbeefdeadbeef&redirect_to=http://localhost:3000/welcome", compare: compareRedirect},

		// ---- Request-side email/SMS OTP flows (enumeration-safe 200 {} shapes) ----
		// These accept-and-acknowledge without a real inbox; the OTP-CONSUMING half
		// is driven through admin generate_link in flows() (otp-recovery/magiclink).
		{
			name: "otp-email", method: "POST", path: "/otp", compare: compareFull, wantStatus: 200,
			headers: jsonHdr(), body: fmt.Sprintf(`{"email":"parity-otp-%d@example.test"}`, time.Now().UnixNano()),
		},
		{
			name: "magiclink-request", method: "POST", path: "/magiclink", compare: compareFull, wantStatus: 200,
			headers: jsonHdr(), body: fmt.Sprintf(`{"email":"parity-ml-%d@example.test"}`, time.Now().UnixNano()),
		},
		{
			name: "recover-request", method: "POST", path: "/recover", compare: compareFull, wantStatus: 200,
			headers: jsonHdr(), body: fmt.Sprintf(`{"email":"parity-rec-%d@example.test"}`, time.Now().UnixNano()),
		},
		{
			name: "resend-signup", method: "POST", path: "/resend", compare: compareFull, wantStatus: 200,
			headers: jsonHdr(), body: fmt.Sprintf(`{"type":"signup","email":"parity-res-%d@example.test"}`, time.Now().UnixNano()),
		},

		// ---- Reauthenticate (authenticated user, mails a nonce → 200 {}) ----
		{name: "reauthenticate", method: "GET", path: "/reauthenticate", cred: "userA", compare: compareFull, wantStatus: 200},

		// ---- Invite (service_role; returns the invited user object) ----
		{
			name: "invite", method: "POST", path: "/invite", cred: "service_role", compare: compareFull, wantStatus: 200,
			headers: jsonHdr(), body: fmt.Sprintf(`{"email":"parity-invite-%d@example.test","data":{"team":"parity"}}`, time.Now().UnixNano()),
		},

		// ---- External OAuth start: an unconfigured provider must be REFUSED
		// identically (no client id/secret on either) — 400 validation_failed. ----
		{name: "external-authorize-github", method: "GET", path: "/authorize?provider=github", compare: compareFull, wantStatus: 400},

		// ---- SAML/SSO on the DEFAULT (flags-off) stack: both must report the
		// feature disabled identically. The flags-on twin exercises the live paths. ----
		{name: "sso-disabled", method: "POST", path: "/sso", headers: jsonHdr(), body: `{"domain":"parity.example.com"}`, compare: compareFull, wantStatus: 404, profile: "off"},
		// SAML stays disabled in BOTH the default and the flagged twin (the flags
		// overlay does not supply SAML key material), so the disabled-metadata shape
		// is comparable under either profile — hence profile "" (always run).
		{name: "saml-metadata-disabled", method: "GET", path: "/sso/saml/metadata", compare: compareFull, wantStatus: 404},

		// ============================================================================
		// FLAGGED surfaces (PARITY_FLAGS=1 brings the twin up on BOTH servers).
		// ============================================================================

		// ---- OAuth 2.1 authorization server ----
		// Dynamic Client Registration (public): a fresh client each run.
		{
			name: "oauth-dcr", method: "POST", path: "/oauth/clients/register", compare: compareFull, wantStatus: 201, profile: "on",
			headers: jsonHdr(), body: `{"redirect_uris":["http://localhost:3000/callback"],"client_name":"parity-dcr","grant_types":["authorization_code","refresh_token"]}`,
		},
		// authorize with a bogus/unregistered client_id → JSON 400 on both.
		{name: "oauth-authorize-get-badclient", method: "GET", path: "/oauth/authorize?client_id=00000000-0000-0000-0000-000000000000&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=abc&code_challenge_method=S256", compare: compareFull, wantStatus: 400, profile: "on"},
		// token with no client credentials → RFC 6749 / gotrue error on both.
		{name: "oauth-token-noclient", method: "POST", path: "/oauth/token", headers: jsonHdr(), body: `{"grant_type":"authorization_code","code":"nope"}`, compare: compareFull, profile: "on"},

		// ---- Passkeys / WebAuthn (options endpoints; a full ceremony needs a
		// software authenticator — see README) ----
		{name: "passkey-list", method: "GET", path: "/passkeys", cred: "userA", compare: compareFull, wantStatus: 200, profile: "on"},
		{name: "passkey-registration-options", method: "POST", path: "/passkeys/registration/options", cred: "userA", headers: jsonHdr(), body: `{}`, compare: compareFull, wantStatus: 200, profile: "on"},
		{name: "passkey-authentication-options", method: "POST", path: "/passkeys/authentication/options", headers: jsonHdr(), body: `{}`, compare: compareFull, wantStatus: 200, profile: "on"},

		// OAuth userinfo with a normal user access token → 200 {sub:...} on both.
		{name: "oauth-userinfo", method: "GET", path: "/oauth/userinfo", cred: "userA", compare: compareFull, wantStatus: 200, profile: "on"},

		// ---- SSO on the flags-on stack: an unknown domain is refused identically. ----
		{name: "sso-unknown-domain", method: "POST", path: "/sso", headers: jsonHdr(), body: `{"domain":"no-such-provider.example.com"}`, compare: compareFull, profile: "on"},

		// ---- Manual identity linking (SECURITY_MANUAL_LINKING_ENABLED on both) ----
		// Link start for an unconfigured external provider is refused identically.
		{name: "link-identity-github", method: "GET", path: "/user/identities/authorize?provider=github", cred: "userA", compare: compareFull, wantStatus: 400, profile: "on"},
		// Unlinking the sole (email) identity is refused identically — a bogus id
		// still trips the "must keep ≥1 identity" guard on both before any lookup.
		{name: "unlink-identity-guard", method: "DELETE", path: "/user/identities/00000000-0000-0000-0000-000000000001", cred: "userA", compare: compareFull, wantStatus: 422, profile: "on"},
	}
}

// ---- runner ----------------------------------------------------------------

func TestParity(t *testing.T) {
	e := loadEnv(t)

	flagsOn := os.Getenv("PARITY_FLAGS") == "1"
	t.Logf("parity profile: PARITY_FLAGS=%q (flagged surfaces %s)", os.Getenv("PARITY_FLAGS"),
		map[bool]string{true: "ENABLED on both", false: "disabled (default stack)"}[flagsOn])

	fixtures := newFixtures()
	dilionCreds := e.bootstrap(t, e.dilionURL, fixtures)
	gotrueCreds := e.bootstrap(t, e.gotrueURL, fixtures)
	serviceRole := e.mintServiceRole(t)

	hit := map[string]bool{}
	var knownCount, failCount int

	for _, sc := range scenarios() {
		sc := sc
		if !profileMatches(sc.profile, flagsOn) {
			continue
		}
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

	// ---- multi-step flows (admin lifecycle, MFA/TOTP, OTP-consuming email) ----
	for _, f := range flows() {
		if !profileMatches(f.profile, flagsOn) {
			continue
		}
		k, fl := e.runFlow(t, f, dilionCreds, gotrueCreds, serviceRole, hit)
		knownCount += k
		failCount += fl
	}

	reportCoverage(t, e.contract, hit)
	t.Logf("parity summary: %d KNOWN deviations tolerated, %d FAIL diffs", knownCount, failCount)
}

// profileMatches reports whether a scenario/flow tagged with the given profile
// ("" any, "off" flags-disabled only, "on" flags-enabled only) runs under the
// current flag state.
func profileMatches(profile string, flagsOn bool) bool {
	switch profile {
	case "", "any":
		return true
	case "off":
		return !flagsOn
	case "on":
		return flagsOn
	}
	return true
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

// TODOScaffold documents the operations STILL uncovered after this expansion and
// the concrete blocker each hits in a no-inbox / no-external-IdP / no-SMS /
// no-software-authenticator environment. The covered ops (default profile: 36;
// PARITY_FLAGS=1 flagged profile: 51 — the flagged run is the superset) are
// exercised by scenarios() and flows(); reportCoverage prints the live
// covered/uncovered split each run. The 18 below each need a capability this
// harness deliberately does not fake:
//
//	authPasskeyRegistrationVerify / authPasskeyAuthenticationVerify /
//	authPasskeyUpdate / authPasskeyDelete / authAdminPasskeyList /
//	authAdminPasskeyDelete  - the /passkeys OPTIONS endpoints are covered, but the
//	  verify/update/delete + admin passkey surface need a real (or ported test)
//	  software WebAuthn authenticator to sign the ceremony / enrol a credential.
//	authOAuthAuthorizePost  - upstream v2.196.0 has no POST /oauth/authorize route
//	  (returns 405); Dilion implements it, so there is nothing to differentially
//	  test (a Dilion-only capability, not a parity gap).
//	authOAuthGetAuthorization / authOAuthConsent / authListOAuthGrants /
//	authRevokeOAuthGrant  - need a live authorize->consent flow: a browser session
//	  cookie / logged-in principal to reach the consent screen and record a grant,
//	  then read/revoke it (the authorize step 302s to the consent UI).
//	authExternalCallbackGet / authExternalCallbackPost  - need a stubbed external
//	  OAuth provider returning a signed state+code to /callback.
//	authAdminCreateSSOProvider / authAdminGetSSOProvider /
//	authAdminUpdateSSOProvider / authAdminDeleteSSOProvider  - need VALID SAML IdP
//	  metadata; a malformed doc diverges (Dilion 400 vs upstream 500), so these
//	  need a real metadata fixture (e.g. the crewjam test IdP). List IS covered.
//	authSamlAcs  - needs a signed SAML assertion posted to the ACS URL.
//
// See internal/auth/*.go for each handler; deviations.yaml carries the intentional
// differences the covered ops surface.
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
