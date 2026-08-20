//go:build parity

// Package parity holds the Dilion <-> upstream-GoTrue differential test harness.
//
// This file provides the value-normalisation and structural-diff primitives the
// harness (harness_test.go) uses to decide whether two responses are equivalent:
//
//   - volatile-field scrubbing (ids, timestamps, tokens, nonces, csrf, ...),
//   - JWT claim comparison that ignores per-instance/per-request claims
//     (iat/exp/session_id/sub/...) while comparing the stable ones
//     (role/aud/iss/amr/aal),
//   - HTTP header normalisation,
//   - a redirect-Location comparison that is robust to the /auth/v1 path prefix,
//   - a structural JSON diff that yields path-qualified Diff entries the
//     deviation allow-list can be matched against.
//
// Nothing here talks to a server; it is pure data massaging so it is trivially
// unit-testable and reusable across every scenario.
package parity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// scrubbed is the placeholder every volatile value is replaced with, so two
// responses that differ ONLY in volatile fields compare equal after scrubbing.
const scrubbed = "<scrubbed>"

// volatileKeys are JSON object keys whose VALUES legitimately differ between two
// independent server+database instances or between two requests, and so must be
// blanked before diffing. Matching is case-insensitive on the exact key name.
var volatileKeys = map[string]bool{
	// identifiers minted per-instance
	"id": true, "sub": true, "user_id": true, "session_id": true,
	"identity_id": true, "factor_id": true, "provider_id": true,
	"authorization_id": true, "client_id": true, "flow_state_id": true,
	// tokens / secrets / one-time material
	"access_token": true, "refresh_token": true, "provider_token": true,
	"provider_refresh_token": true, "token": true, "token_hash": true,
	"hashed_token": true, "confirmation_token": true, "recovery_token": true,
	"email_change_token": true, "email_change_token_new": true,
	"email_change_token_current": true, "reauthentication_token": true,
	"code": true, "code_challenge": true, "client_secret": true,
	"csrf_token": true, "nonce": true, "secret": true, "qr_code": true,
	"uri": true, "challenge": true, "public_key": true, "credential_id": true,
	// timestamps
	"created_at": true, "updated_at": true, "last_sign_in_at": true,
	"confirmed_at": true, "email_confirmed_at": true, "phone_confirmed_at": true,
	"invited_at": true, "banned_until": true, "deleted_at": true,
	"confirmation_sent_at": true, "recovery_sent_at": true,
	"email_change_sent_at": true, "phone_change_sent_at": true,
	"reauthentication_sent_at": true, "not_after": true, "refreshed_at": true,
	"expires_in": true, "expires_at": true, "iat": true, "exp": true, "nbf": true,
	"timestamp": true, // amr-claim method timestamp
	// diagnostics gotrue attaches to some error bodies
	"error_id": true, "request_id": true,
}

// Scrub returns a deep copy of v with every volatile-keyed value replaced by the
// placeholder. Maps and slices are walked recursively; scalars are returned
// unchanged. The input is not mutated.
func Scrub(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if volatileKeys[strings.ToLower(k)] {
				out[k] = scrubbed
				continue
			}
			out[k] = Scrub(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = Scrub(val)
		}
		return out
	default:
		return v
	}
}

// NormalizeJSON unmarshals body and scrubs it. A body that is not JSON is
// returned as its trimmed string form so text/redirect bodies still diff.
func NormalizeJSON(body []byte) any {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return trimmed
	}
	return Scrub(v)
}

// ---- structural diff -------------------------------------------------------

// Diff is one structural difference between the Dilion and upstream responses.
// Kind classifies it so the deviation allow-list can be matched by aspect, and
// Path is the JSON pointer-ish location ("user.app_metadata.provider") the
// allow-list matches its `field` against.
type Diff struct {
	Kind     string // status | header | body | redirect | jwt-claim
	Path     string
	Dilion   any
	Upstream any
}

func (d Diff) String() string {
	return fmt.Sprintf("[%s] %s: dilion=%v upstream=%v", d.Kind, d.Path, d.Dilion, d.Upstream)
}

// DiffJSON structurally compares two already-scrubbed JSON values and appends a
// body Diff for every mismatch. keyPresenceOneSided lets a field that exists on
// one side but is null/absent on the other be reported (so dilion-only fields
// surface and can be allow-listed rather than silently ignored).
func DiffJSON(path string, dilion, upstream any) []Diff {
	var out []Diff
	switch dv := dilion.(type) {
	case map[string]any:
		uv, ok := upstream.(map[string]any)
		if !ok {
			return []Diff{{Kind: "body", Path: path, Dilion: typeName(dilion), Upstream: typeName(upstream)}}
		}
		keys := unionKeys(dv, uv)
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			d, dok := dv[k]
			u, uok := uv[k]
			switch {
			case dok && !uok:
				out = append(out, Diff{Kind: "body", Path: child, Dilion: compact(d), Upstream: "<absent>"})
			case !dok && uok:
				out = append(out, Diff{Kind: "body", Path: child, Dilion: "<absent>", Upstream: compact(u)})
			default:
				out = append(out, DiffJSON(child, d, u)...)
			}
		}
	case []any:
		uv, ok := upstream.([]any)
		if !ok {
			return []Diff{{Kind: "body", Path: path, Dilion: typeName(dilion), Upstream: typeName(upstream)}}
		}
		if len(dv) != len(uv) {
			out = append(out, Diff{Kind: "body", Path: path + ".length", Dilion: len(dv), Upstream: len(uv)})
			return out
		}
		for i := range dv {
			out = append(out, DiffJSON(fmt.Sprintf("%s[%d]", path, i), dv[i], uv[i])...)
		}
	default:
		if !scalarEqual(dilion, upstream) {
			out = append(out, Diff{Kind: "body", Path: path, Dilion: dilion, Upstream: upstream})
		}
	}
	return out
}

func scalarEqual(a, b any) bool {
	// JSON numbers decode as float64; compare via canonical JSON to avoid
	// int/float and formatting mismatches.
	return compact(a) == compact(b)
}

func compact(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func typeName(v any) string {
	switch v.(type) {
	case map[string]any:
		return "<object>"
	case []any:
		return "<array>"
	case nil:
		return "<null>"
	default:
		return fmt.Sprintf("<%T>", v)
	}
}

func unionKeys(a, b map[string]any) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- headers ---------------------------------------------------------------

// comparedHeaders is the small set of response headers whose exact value is part
// of the compatibility contract. Everything else is ignored, including:
//   - Date, Content-Length, transport headers, the per-request X-Request-Id;
//   - X-Total-Count and Link — these encode the row COUNT / page URLs of the
//     instance's own database, which legitimately differ between two independent
//     servers+databases, so they are volatile in a differential harness (the
//     Link path-prefix difference is separately catalogued as a deviation).
var comparedHeaders = []string{
	"Content-Type",
	"Cache-Control",
	"Www-Authenticate",
}

// NormalizeHeaders returns the compared subset, canonicalised and lower-cased,
// so header comparison is order- and case-insensitive.
func NormalizeHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, name := range comparedHeaders {
		if v := h.Get(name); v != "" {
			out[strings.ToLower(name)] = strings.ToLower(strings.TrimSpace(v))
		}
	}
	return out
}

// DiffHeaders reports header mismatches in the compared set.
func DiffHeaders(dilion, upstream http.Header) []Diff {
	dn, un := NormalizeHeaders(dilion), NormalizeHeaders(upstream)
	var out []Diff
	seen := map[string]bool{}
	for k := range dn {
		seen[k] = true
	}
	for k := range un {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if dn[k] != un[k] {
			out = append(out, Diff{Kind: "header", Path: k, Dilion: dn[k], Upstream: un[k]})
		}
	}
	return out
}

// ---- redirect Location -----------------------------------------------------

// authPrefix is the mount prefix Dilion adds and upstream does not; a redirect
// path that differs ONLY by this prefix is treated as equivalent (deviation
// mailer-verify-path-prefix / saml-external-url / oidc-issuer-fallback).
const authPrefix = "/auth/v1"

// volatileQueryParams are result params of a redirect whose values differ per
// request but whose PRESENCE is meaningful; presence is compared, value scrubbed.
var volatileQueryParams = map[string]bool{
	"access_token": true, "refresh_token": true, "code": true,
	"token": true, "token_hash": true, "expires_in": true,
	"expires_at": true, "message": true, "error_description": true,
}

// DiffRedirect compares two redirect targets structurally: the host, the path
// (modulo the /auth/v1 prefix), and the SET of query/fragment param KEYS present
// on each side (error/error_code keys compared by value; volatile result params
// compared by presence only).
func DiffRedirect(dilionLoc, upstreamLoc string) []Diff {
	if dilionLoc == "" && upstreamLoc == "" {
		return nil
	}
	du, derr := url.Parse(dilionLoc)
	uu, uerr := url.Parse(upstreamLoc)
	if derr != nil || uerr != nil {
		if dilionLoc != upstreamLoc {
			return []Diff{{Kind: "redirect", Path: "Location", Dilion: dilionLoc, Upstream: upstreamLoc}}
		}
		return nil
	}
	var out []Diff
	if !strings.EqualFold(du.Host, uu.Host) {
		out = append(out, Diff{Kind: "redirect", Path: "Location.host", Dilion: du.Host, Upstream: uu.Host})
	}
	if trimPrefix(du.Path) != trimPrefix(uu.Path) {
		out = append(out, Diff{Kind: "redirect", Path: "Location.path", Dilion: du.Path, Upstream: uu.Path})
	}
	// Both query and fragment can carry the result (see openapi "Redirects").
	out = append(out, diffParams("Location.query", du.RawQuery, uu.RawQuery)...)
	out = append(out, diffParams("Location.fragment", du.Fragment, uu.Fragment)...)
	return out
}

func trimPrefix(p string) string {
	return strings.TrimPrefix(p, authPrefix)
}

func diffParams(path, dilionRaw, upstreamRaw string) []Diff {
	dq, _ := url.ParseQuery(dilionRaw)
	uq, _ := url.ParseQuery(upstreamRaw)
	var out []Diff
	seen := map[string]bool{}
	for k := range dq {
		seen[k] = true
	}
	for k := range uq {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, dok := dq[k]
		_, uok := uq[k]
		if dok != uok {
			out = append(out, Diff{Kind: "redirect", Path: path + "." + k + "(presence)", Dilion: dok, Upstream: uok})
			continue
		}
		if volatileQueryParams[k] {
			continue // value is volatile; presence already matched
		}
		if dq.Get(k) != uq.Get(k) {
			out = append(out, Diff{Kind: "redirect", Path: path + "." + k, Dilion: dq.Get(k), Upstream: uq.Get(k)})
		}
	}
	return out
}

// ---- JWT claims ------------------------------------------------------------

// stableClaims are the access-token claims that MUST match between the two
// servers when they run identical config and the same shared HS256 secret.
var stableClaims = []string{"role", "aud", "iss", "amr", "aal"}

// ignoredClaims are per-request or per-instance claims that legitimately differ.
var ignoredClaims = map[string]bool{
	"iat": true, "exp": true, "nbf": true, "session_id": true,
	"sub": true, "email": true, "phone": true, "jti": true,
}

// DecodeJWTClaims decodes (WITHOUT verifying — verification is a separate
// assertion) the claim set of a compact JWS. The harness uses the shared secret
// to verify signatures elsewhere; here we only need the payload to compare the
// stable claims.
func DecodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWS (%d segments)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	return claims, nil
}

// DiffJWTClaims compares the stable claims of two access tokens, reporting a
// jwt-claim Diff per stable claim that differs. Volatile claims are ignored.
func DiffJWTClaims(dilionTok, upstreamTok string) []Diff {
	dc, derr := DecodeJWTClaims(dilionTok)
	uc, uerr := DecodeJWTClaims(upstreamTok)
	if derr != nil || uerr != nil {
		return []Diff{{Kind: "jwt-claim", Path: "decode", Dilion: errStr(derr), Upstream: errStr(uerr)}}
	}
	var out []Diff
	for _, c := range stableClaims {
		dv, dok := dc[c]
		uv, uok := uc[c]
		if !dok && !uok {
			continue
		}
		// Scrub volatile sub-fields (e.g. the amr method `timestamp`) so only the
		// stable structure of the claim is compared.
		if compact(Scrub(dv)) != compact(Scrub(uv)) {
			out = append(out, Diff{Kind: "jwt-claim", Path: c, Dilion: dv, Upstream: uv})
		}
	}
	return out
}

func errStr(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}
