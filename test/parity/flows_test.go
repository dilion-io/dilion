//go:build parity

// Multi-step differential flows for the parity harness.
//
// A `scenario` (harness_test.go) is a single stateless request compared across
// both servers. Many operations, though, are only reachable through a SEQUENCE
// of requests that thread server-minted state (a factor id, a TOTP secret, an
// admin-generated OTP, a fresh user id) into the next call — and that state is
// necessarily DIFFERENT on each server because they run separate databases.
//
// A `flow` runs its steps against ONE server at a time, capturing per-server
// values into a substitution map, so the SAME logical sequence executes on both.
// Each step is still diffed across the two servers exactly like a scenario
// (status + headers + body/redirect/jwt), and each step maps to an operationId
// for coverage. This is what unlocks the admin user lifecycle, the full MFA/TOTP
// enrol→challenge→verify chain, the admin factor surface, and the
// generate_link→verify OTP-consuming email flows — none of which have a real
// inbox, external IdP, or SMS in this environment.
package parity

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// step is one request within a flow. Path and body may contain {{tokens}} that
// are substituted from the flow's base credential and from values captured by
// earlier steps ON THE SAME SERVER.
type step struct {
	name   string
	method string
	path   string // relative; may contain {{captured}} placeholders and a query
	// token selects the bearer credential: "" = flow's base cred access token,
	// "service_role", "none", "userA".. = that fixture's access token, or
	// "cap:VAR" = a token captured by an earlier step.
	token   string
	headers map[string]string
	body    string // may contain {{captured}} placeholders and {{totp:VAR}}
	compare bodyCompare
	// wantStatus, when non-zero, asserts BOTH servers returned it.
	wantStatus int
	// capture pulls values out of THIS server's response body into the flow's
	// per-server var map: varName -> dot-path ("id", "totp.secret",
	// "access_token"). Captured values feed later steps' {{varName}}.
	capture map[string]string
	// skipCompare marks a step as pure setup (its cross-server diff is ignored);
	// it still runs and still captures.
	skipCompare bool
}

// flow is a sequence of steps sharing a per-server capture map.
type flow struct {
	name string
	// cred is the base credential for steps whose token is "": a bootstrapped
	// fixture name ("userC") or "service_role".
	cred string
	// freshEmail, when true, seeds {{flow_email}} with an address unique to this
	// flow+run, IDENTICAL on both servers (so admin-created users are comparable).
	freshEmail bool
	// profile gates the flow on the feature-flag twin, like scenario.profile.
	profile string
	steps   []step
}

// flows is the multi-step slice. Ops each step maps to are resolved for coverage.
func flows() []flow {
	return []flow{
		// ---- Admin user lifecycle (service_role): create → get → update → delete.
		{
			name: "admin-user-lifecycle", cred: "service_role", freshEmail: true,
			steps: []step{
				{
					name: "create", method: "POST", path: "/admin/users",
					headers: jsonHdr(), compare: compareFull, wantStatus: 200,
					body:    `{"email":"{{flow_email}}","password":"Sup3rSecret!pw","email_confirm":true,"user_metadata":{"parity":"x"}}`,
					capture: map[string]string{"uid": "id"},
				},
				{name: "get", method: "GET", path: "/admin/users/{{uid}}", compare: compareFull, wantStatus: 200},
				{
					name: "update", method: "PUT", path: "/admin/users/{{uid}}",
					headers: jsonHdr(), compare: compareFull, wantStatus: 200,
					body: `{"user_metadata":{"parity":"y"},"app_metadata":{"tier":"gold"}}`,
				},
				{
					name: "delete", method: "DELETE", path: "/admin/users/{{uid}}",
					headers: jsonHdr(), compare: compareFull, wantStatus: 200, body: `{}`,
				},
			},
		},

		// ---- MFA / TOTP end-to-end + the admin factor surface, on a dedicated
		// user so it never perturbs the userA/userB single scenarios.
		//   GET /user (uid) → enroll → challenge → verify(TOTP → aal2)
		//   → admin list/update/delete factor.
		{
			name: "mfa-totp", cred: "userC",
			steps: []step{
				{name: "whoami", method: "GET", path: "/user", compare: compareFull, wantStatus: 200,
					capture: map[string]string{"uid": "id"}},
				{
					name: "enroll", method: "POST", path: "/factors", headers: jsonHdr(),
					compare: compareFull, wantStatus: 200,
					body:    `{"factor_type":"totp","friendly_name":"parity-totp"}`,
					capture: map[string]string{"fid": "id", "secret": "totp.secret"},
				},
				{
					name: "challenge", method: "POST", path: "/factors/{{fid}}/challenge",
					headers: jsonHdr(), compare: compareFull, wantStatus: 200, body: `{}`,
					capture: map[string]string{"cid": "id"},
				},
				{
					name: "verify", method: "POST", path: "/factors/{{fid}}/verify",
					headers: jsonHdr(), compare: compareFull, wantStatus: 200,
					body:    `{"challenge_id":"{{cid}}","code":"{{totp:secret}}"}`,
					capture: map[string]string{"aal2": "access_token"},
				},
				{
					name: "admin-list-factors", method: "GET",
					path: "/admin/users/{{uid}}/factors", token: "service_role",
					compare: compareFull, wantStatus: 200,
				},
				{
					name: "admin-update-factor", method: "PUT",
					path: "/admin/users/{{uid}}/factors/{{fid}}", token: "service_role",
					headers: jsonHdr(), compare: compareFull, wantStatus: 200,
					body: `{"friendly_name":"parity-renamed"}`,
				},
				{
					name: "admin-delete-factor", method: "DELETE",
					path: "/admin/users/{{uid}}/factors/{{fid}}", token: "service_role",
					compare: compareFull, wantStatus: 200,
				},
			},
		},

		// ---- User-facing unenroll of an (unverified) factor: enroll → unenroll.
		{
			name: "mfa-unenroll", cred: "userD",
			steps: []step{
				{
					name: "enroll", method: "POST", path: "/factors", headers: jsonHdr(),
					compare: compareFull, wantStatus: 200,
					body:    `{"factor_type":"totp","friendly_name":"parity-doomed"}`,
					capture: map[string]string{"fid": "id"},
				},
				{
					name: "unenroll", method: "DELETE", path: "/factors/{{fid}}",
					compare: compareFull, wantStatus: 200,
				},
			},
		},

		// ---- OTP-consuming email flow via admin generate_link (recovery): the key
		// that redeems a real OTP without an inbox. admin-create a confirmed user →
		// generate_link recovery (capture hashed_token) → POST /verify → session.
		{
			name: "otp-recovery", cred: "service_role", freshEmail: true,
			steps: []step{
				{
					name: "seed-user", method: "POST", path: "/admin/users", headers: jsonHdr(),
					compare: compareFull, wantStatus: 200, skipCompare: false,
					body: `{"email":"{{flow_email}}","password":"Sup3rSecret!pw","email_confirm":true}`,
				},
				{
					name: "generate-link", method: "POST", path: "/admin/generate_link", headers: jsonHdr(),
					compare: compareFull, wantStatus: 200,
					body:    `{"type":"recovery","email":"{{flow_email}}"}`,
					capture: map[string]string{"hashed": "hashed_token"},
				},
				{
					name: "verify", method: "POST", path: "/verify", headers: jsonHdr(),
					token: "none", compare: compareFull, wantStatus: 200,
					body: `{"type":"recovery","token_hash":"{{hashed}}"}`,
				},
			},
		},

		// ---- OAuth 2.1 admin client lifecycle (PARITY_FLAGS=1): register → get →
		// list → update → regenerate secret → delete. All status codes and the
		// client object shape are byte-identical to upstream.
		{
			name: "oauth-admin-clients", cred: "service_role", profile: "on",
			steps: []step{
				{
					name: "register", method: "POST", path: "/admin/oauth/clients", headers: jsonHdr(),
					compare: compareFull, wantStatus: 201,
					body:    `{"redirect_uris":["http://localhost:3000/cb"],"client_name":"parity-admin-client","grant_types":["authorization_code","refresh_token"]}`,
					capture: map[string]string{"cid": "client_id"},
				},
				{name: "get", method: "GET", path: "/admin/oauth/clients/{{cid}}", compare: compareFull, wantStatus: 200},
				{name: "list", method: "GET", path: "/admin/oauth/clients", compare: compareTopKeys, wantStatus: 200},
				{
					name: "update", method: "PUT", path: "/admin/oauth/clients/{{cid}}", headers: jsonHdr(),
					compare: compareFull, wantStatus: 200, body: `{"client_name":"parity-renamed-client"}`,
				},
				{
					name: "regenerate-secret", method: "POST", path: "/admin/oauth/clients/{{cid}}/regenerate_secret",
					compare: compareFull, wantStatus: 200,
				},
				{name: "delete", method: "DELETE", path: "/admin/oauth/clients/{{cid}}", compare: compareNone, wantStatus: 204},
			},
		},

		// ---- OTP-consuming email flow (magiclink) via generate_link.
		{
			name: "otp-magiclink", cred: "service_role", freshEmail: true,
			steps: []step{
				{
					name: "seed-user", method: "POST", path: "/admin/users", headers: jsonHdr(),
					compare: compareFull, wantStatus: 200,
					body: `{"email":"{{flow_email}}","password":"Sup3rSecret!pw","email_confirm":true}`,
				},
				{
					name: "generate-link", method: "POST", path: "/admin/generate_link", headers: jsonHdr(),
					compare: compareFull, wantStatus: 200,
					body:    `{"type":"magiclink","email":"{{flow_email}}"}`,
					capture: map[string]string{"hashed": "hashed_token"},
				},
				{
					name: "verify", method: "POST", path: "/verify", headers: jsonHdr(),
					token: "none", compare: compareFull, wantStatus: 200,
					body: `{"type":"magiclink","token_hash":"{{hashed}}"}`,
				},
			},
		},
	}
}

// json is the ubiquitous JSON content-type header set.
func jsonHdr() map[string]string { return map[string]string{"Content-Type": "application/json"} }

// runFlow executes flow f against both servers, threading each server's own
// captured state, and diffs every non-setup step. It returns the ops it touched
// plus the KNOWN/FAIL tallies (added to the caller's totals).
func (e *harnessEnv) runFlow(t *testing.T, f flow, dilionCreds, gotrueCreds map[string]*serverCreds, serviceRole string, hit map[string]bool, operationResults map[string]OperationResult) (known, fail int) {
	t.Helper()
	// {{flow_email}} is identical on both servers so admin-created users compare.
	flowEmail := fmt.Sprintf("parity-%s-%d@example.test", f.name, time.Now().UnixNano())

	dVars := map[string]string{}
	uVars := map[string]string{}
	if f.freshEmail {
		dVars["flow_email"] = flowEmail
		uVars["flow_email"] = flowEmail
	}

	for _, st := range f.steps {
		st := st
		t.Run(f.name+"/"+st.name, func(t *testing.T) {
			// Resolve the op from the (substituted) Dilion path for coverage.
			dPath := subst(st.path, dVars)
			op := e.contract.Resolve(st.method, dPath)
			if op != "" {
				hit[op] = true
				result := operationResults[op]
				result.Exercised = true
				operationResults[op] = result
			}
			completed, compared, positive := false, false, false
			finish := trackOperation(operationResults, op)
			defer func() { finish(completed, compared, positive, t.Failed()) }()

			dStatus, dHdr, dBody := e.execStep(t, e.dilionURL, f, st, dilionCreds, serviceRole, dVars)
			uStatus, uHdr, uBody := e.execStep(t, e.gotrueURL, f, st, gotrueCreds, serviceRole, uVars)
			if dStatus == http.StatusNotImplemented && op != "" {
				result := operationResults[op]
				result.Unimplemented = true
				operationResults[op] = result
			}

			if st.wantStatus != 0 {
				if dStatus != st.wantStatus {
					t.Errorf("dilion status=%d, step expected %d (body=%s)", dStatus, st.wantStatus, truncate(dBody))
				}
				if uStatus != st.wantStatus {
					t.Errorf("upstream status=%d, step expected %d (body=%s)", uStatus, st.wantStatus, truncate(uBody))
				}
			}
			if st.skipCompare {
				completed = true
				return
			}

			diffs := e.diffStep(st, dStatus, uStatus, dHdr, uHdr, dBody, uBody)
			compared = true
			positive = dStatus >= 200 && dStatus < 300 && uStatus >= 200 && uStatus < 300
			for _, d := range diffs {
				if dev := Match(e.devs, op, d); dev != nil {
					known++
					result := operationResults[op]
					result.Known++
					operationResults[op] = result
					t.Logf("KNOWN  %-28s %s  (deviation %q: %s)", op, d, dev.ID, dev.Reason)
					continue
				}
				fail++
				result := operationResults[op]
				result.Fail++
				operationResults[op] = result
				t.Errorf("FAIL   %-28s %s", op, d)
			}
			completed = true
			if len(diffs) == 0 {
				t.Logf("green  %-28s (%s %s)", op, st.method, st.path)
			}
		})
	}
	return known, fail
}

// execStep issues one flow step against base, substituting captured vars into the
// path/body, selecting the bearer token, and applying this step's captures to the
// server-local var map.
func (e *harnessEnv) execStep(t *testing.T, base string, f flow, st step, creds map[string]*serverCreds, serviceRole string, vars map[string]string) (int, http.Header, []byte) {
	t.Helper()

	// Base credential fields available to substitution.
	if c := creds[f.cred]; c != nil {
		vars["email"] = c.email
		vars["password"] = c.password
		vars["access_token"] = c.accessToken
		vars["refresh_token"] = c.refreshToken
	}

	path := subst(st.path, vars)
	body := subst(st.body, vars)

	// Select the bearer token for this step.
	tokenSel := st.token
	if tokenSel == "" {
		tokenSel = f.cred
	}
	token := ""
	switch {
	case tokenSel == "none":
		token = ""
	case tokenSel == "service_role":
		token = serviceRole
	case strings.HasPrefix(tokenSel, "cap:"):
		token = vars[strings.TrimPrefix(tokenSel, "cap:")]
	default:
		if c := creds[tokenSel]; c != nil {
			token = c.accessToken
		}
	}

	status, hdr, respBody, err := e.do(base, st.method, path, token, st.headers, body)
	if err != nil {
		t.Fatalf("flow %q step %q request to %s: %v", f.name, st.name, base, err)
	}
	for varName, jsonPath := range st.capture {
		vars[varName] = getPath(respBody, jsonPath)
	}
	return status, hdr, respBody
}

// diffStep mirrors harnessEnv.diff but for a flow step's compare mode.
func (e *harnessEnv) diffStep(st step, dStatus, uStatus int, dHdr, uHdr http.Header, dBody, uBody []byte) []Diff {
	var diffs []Diff
	if dStatus != uStatus {
		diffs = append(diffs, Diff{Kind: "status", Path: "status", Dilion: dStatus, Upstream: uStatus})
	}
	diffs = append(diffs, DiffHeaders(dHdr, uHdr)...)
	switch st.compare {
	case compareNone:
	case compareRedirect:
		diffs = append(diffs, DiffRedirect(dHdr.Get("Location"), uHdr.Get("Location"))...)
	case compareTopKeys:
		diffs = append(diffs, diffTopKeys(dBody, uBody)...)
	case compareFull:
		diffs = append(diffs, DiffJSON("", NormalizeJSON(dBody), NormalizeJSON(uBody))...)
		if dt, ut := rawField(dBody, "access_token"), rawField(uBody, "access_token"); dt != "" && ut != "" {
			diffs = append(diffs, DiffJWTClaims(dt, ut)...)
		}
	}
	return diffs
}

// subst replaces {{name}} and {{totp:name}} placeholders in s from vars. A
// {{totp:secret}} placeholder computes the current RFC-6238 TOTP code from the
// base32 secret stored in vars["secret"].
func subst(s string, vars map[string]string) string {
	if s == "" || !strings.Contains(s, "{{") {
		return s
	}
	for {
		open := strings.Index(s, "{{")
		if open < 0 {
			break
		}
		close := strings.Index(s[open:], "}}")
		if close < 0 {
			break
		}
		close += open
		name := s[open+2 : close]
		var val string
		if strings.HasPrefix(name, "totp:") {
			secret := vars[strings.TrimPrefix(name, "totp:")]
			val = computeTOTP(secret)
		} else {
			val = vars[name]
		}
		s = s[:open] + val + s[close+2:]
	}
	return s
}

// computeTOTP returns the current 6-digit TOTP code for a base32 secret, matching
// what an authenticator app would submit (SHA1, 30s period — GoTrue's defaults).
func computeTOTP(secret string) string {
	if secret == "" {
		return ""
	}
	code, err := totp.GenerateCode(strings.ToUpper(secret), time.Now())
	if err != nil {
		return ""
	}
	return code
}

// getPath extracts a dotted field path ("totp.secret") from a JSON body as a
// string; returns "" when absent.
func getPath(body []byte, path string) string {
	v := jsonDecode(body)
	for _, seg := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[seg]
	}
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
