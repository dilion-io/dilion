package auth

// Upstream API conformance oracle.
//
// internal/auth/upstreamspec holds Go types generated from the openapi.yaml
// that github.com/supabase/auth publishes for itself. This file is the ONLY
// consumer: it reflects over those types and asserts that every JSON property
// upstream DOCUMENTS is a property Dilion also serves, with a compatible JSON
// shape.
//
// # What this proves, and what it does not
//
// It proves the one direction that matters for compatibility: a client written
// against upstream's published spec finds every field it was promised. It
// deliberately does NOT require the converse — Dilion is allowed to be a strict
// superset, because upstream's spec lags upstream's own implementation (see
// upstreamspec/doc.go). Those extras are not waved through, though: each one
// must be named in knownExtensions, so a NEW unexplained field on a wire struct
// still trips review.
//
// Three allow-lists, three different meanings — keep them straight:
//
//	knownSpecGaps    a property the SPEC declares that Dilion does not mirror
//	                 as a struct field. Each entry must justify itself against
//	                 upstream's Go source: either upstream never emits it
//	                 either (a spec bug), or we emit it by another mechanism.
//	knownExtensions  a property DILION serves that the spec does not declare.
//	                 Each entry says where it comes from.
//	skipField()      struct fields that are not wire fields at all.
//
// Adding a pair is one line in conformancePairs.

import (
	"encoding"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dilion-project/dilion/internal/auth/upstreamspec"
)

// ---- pair table -------------------------------------------------------------

// conformancePair is one upstream schema and the Dilion type(s) that answer for
// it. `ours` is a list because upstream sometimes documents ONE schema for what
// is really two disjoint response bodies: ErrorSchema is both the gotrue
// {code,error_code,msg} envelope and the RFC 6749 {error,error_description}
// body. A spec property is satisfied when ANY member carries it.
type conformancePair struct {
	name string
	spec any
	ours []any
}

var conformancePairs = []conformancePair{
	{"User", upstreamspec.UserSchema{}, []any{User{}}},
	{"Identity", upstreamspec.IdentitySchema{}, []any{Identity{}}},
	{"AccessTokenResponse", upstreamspec.AccessTokenResponseSchema{}, []any{AccessTokenResponse{}}},
	{"Error", upstreamspec.ErrorSchema{}, []any{HTTPError{}, OAuthError{}}},
	{"MFAFactor", upstreamspec.MFAFactorSchema{}, []any{Factor{}}},
	{"SSOProvider", upstreamspec.SSOProviderSchema{}, []any{SSOProvider{}}},
	{"SAMLAttributeMapping", upstreamspec.SAMLAttributeMappingSchema{}, []any{SAMLAttributeMapping{}}},
	{"OAuthClient", upstreamspec.OAuthClientSchema{}, []any{OAuthClientResponse{}}},
	{"CustomOAuthProvider", upstreamspec.CustomOAuthProviderSchema{}, []any{customOAuthProvider{}}},
}

// ---- allow-list 1: spec properties we do not mirror -------------------------

// knownSpecGaps is keyed "<pair>.<json property>". Every entry is a claim about
// UPSTREAM'S GO SOURCE, not about our convenience: the property is either one
// upstream itself never puts on the wire (an openapi.yaml bug), or one we do
// put on the wire through something other than a struct field.
//
// A property that upstream genuinely returns and we genuinely do not MUST NOT
// be listed here — add the field instead.
var knownSpecGaps = map[string]string{
	"Error.weak_password": "not a struct field: HTTPError.MarshalJSON (password.go) synthesizes it from the " +
		"*WeakPasswordError cause, mirroring upstream's handleResponseErrorWeakPassword, which likewise builds " +
		"an anonymous wrapper struct rather than a field on HTTPError. Asserted directly by " +
		"TestHTTPErrorMarshalsWeakPassword below.",

	"MFAFactor.webauthn_credential": "spec bug: upstream models.Factor tags WebAuthnCredential `json:\"-\"`, so no " +
		"upstream response has ever contained this property. Mirroring it would leak credential material.",

	"SSOProvider.sso_domains": "spec bug: upstream models.SSOProvider serializes the domain list as `domains` " +
		"(`json:\"domains\"`), not `sso_domains`. SSOProvider.SSODomains carries it under the name upstream " +
		"actually emits; see knownExtensions[\"SSOProvider.domains\"].",

	"OAuthClient.scope": "spec bug: upstream's oauthserver.OAuthServerClientResponse has no scope field and its " +
		"handlers never set one, so no upstream response carries this property.",
}

// ---- allow-list 2: our properties the spec does not declare -----------------

// knownExtensions is keyed the same way. Everything here is a field Dilion
// serves that upstream's openapi.yaml omits. Each entry must say why it exists;
// most are properties upstream's Go code returns while its spec has not caught
// up, which is precisely the reason the generated types are an oracle and not
// the runtime types.
var knownExtensions = map[string]string{
	"User.invited_at": "upstream models.User has `InvitedAt *time.Time json:\"invited_at,omitempty\"` and returns " +
		"it from the invite flow; UserSchema simply omits it.",

	"AccessTokenResponse.provider_token": "upstream tokens.AccessTokenResponse has " +
		"`ProviderAccessToken string json:\"provider_token,omitempty\"`; the spec omits it.",
	"AccessTokenResponse.provider_refresh_token": "upstream tokens.AccessTokenResponse has " +
		"`ProviderRefreshToken string json:\"provider_refresh_token,omitempty\"`; the spec omits it.",
	"AccessTokenResponse.id_token": "upstream tokens.AccessTokenResponse has " +
		"`IDToken string json:\"id_token,omitempty\"` (internal/tokens/service.go:121); the spec omits it. " +
		"Upstream's only assignment to it is internal/api/oauthserver/handlers.go:461 (authorization_code " +
		"grant, openid scope), and that handler re-projects into a map rather than serializing the struct, so " +
		"no upstream SESSION body ever carries the key. Dilion matches: the field exists and is never set on " +
		"this envelope — see TestAccessTokenResponseIDTokenNeverSetOnSessionGrants.",

	"MFAFactor.web_authn_aaguid": "upstream models.Factor has " +
		"`WebAuthnAAGUID *uuid.UUID json:\"web_authn_aaguid,omitempty\"` (internal/models/factor.go:175), " +
		"written by SaveWebAuthnCredential; the spec omits it (see upstreamspec/doc.go).",
	"MFAFactor.last_webauthn_challenge_data": "upstream models.Factor has " +
		"`LastWebAuthnChallengeData *LastWebAuthnChallengeData json:\"last_webauthn_challenge_data,omitempty\"` " +
		"(internal/models/factor.go:176), written by UpdateLastWebAuthnChallenge on every webauthn verify " +
		"(internal/api/mfa.go:949) and carried by every factor read, since the field has no `json:\"-\"`; " +
		"the spec omits it (see upstreamspec/doc.go).",

	"SSOProvider.domains": "the real name of the spec's `sso_domains` — see knownSpecGaps[\"SSOProvider.sso_domains\"].",
	"SSOProvider.resource_id": "upstream models.SSOProvider has `ResourceID *string json:\"resource_id,omitempty\"`; " +
		"the spec omits it.",
	"SSOProvider.disabled": "upstream models.SSOProvider has `Disabled *bool json:\"disabled\"`; the spec omits it.",
	"SSOProvider.created_at": "upstream models.SSOProvider has `CreatedAt time.Time json:\"created_at\"`; the spec " +
		"declares created_at on most schemas but not this one.",
	"SSOProvider.updated_at": "upstream models.SSOProvider has `UpdatedAt time.Time json:\"updated_at\"`; same omission.",
}

// ---- allow-list 3: fields that are not wire fields --------------------------

// skipField reports whether a Go struct field is outside the comparison
// entirely, because it is not part of any JSON body: `json:"-"` fields (DB-only
// columns, secrets, internal error causes) and unexported fields.
//
// Nothing else is skipped. In particular an embedded or anonymous struct field
// is flattened, so its properties count as the outer type's.
func skipField(f reflect.StructField) bool {
	if f.PkgPath != "" { // unexported
		return true
	}
	return jsonName(f) == ""
}

// ---- the test ---------------------------------------------------------------

func TestUpstreamSpecConformance(t *testing.T) {
	seenGaps := map[string]bool{}
	seenExtensions := map[string]bool{}

	for _, pair := range conformancePairs {
		t.Run(pair.name, func(t *testing.T) {
			specFields := jsonFields(reflect.TypeOf(pair.spec))

			// Union of our types' fields; remember which type contributed each
			// so the failure message can point at it.
			ourFields := map[string]reflect.Type{}
			ourOwner := map[string]string{}
			for _, o := range pair.ours {
				ot := reflect.TypeOf(o)
				for name, ft := range jsonFields(ot) {
					if _, dup := ourFields[name]; dup {
						continue
					}
					ourFields[name] = ft
					ourOwner[name] = ot.Name()
				}
			}

			ourNames := make([]string, 0, len(pair.ours))
			for _, o := range pair.ours {
				ourNames = append(ourNames, reflect.TypeOf(o).Name())
			}
			ourLabel := strings.Join(ourNames, " + ")

			// Direction 1 (hard failure): every documented property exists here.
			for _, name := range sortedKeys(specFields) {
				key := pair.name + "." + name
				ourType, ok := ourFields[name]
				if !ok {
					if reason, excused := knownSpecGaps[key]; excused {
						seenGaps[key] = true
						t.Logf("SPEC GAP  %-52s not a field on %s\n            reason: %s",
							key, ourLabel, reason)
						continue
					}
					t.Errorf("MISSING FROM OURS: %T declares %q (%s), but no field of %s carries it.\n"+
						"  Fix by adding the field (check github.com/supabase/auth for the exact Go type and json tag),\n"+
						"  or, if upstream's implementation never actually emits it, record it in knownSpecGaps[%q].",
						pair.spec, name, describe(specFields[name]), ourLabel, key)
					continue
				}
				if want, got := jsonKindOf(specFields[name]), jsonKindOf(ourType); !kindsCompatible(want, got) {
					t.Errorf("INCOMPATIBLE KIND: %s.%s is %s upstream (%s) but %s here (%s on %s).",
						pair.name, name, want, describe(specFields[name]),
						got, describe(ourType), ourOwner[name])
				}
			}

			// Direction 2 (allow-listed): extras are fine, but must be declared.
			for _, name := range sortedKeys(ourFields) {
				if _, ok := specFields[name]; ok {
					continue
				}
				key := pair.name + "." + name
				if reason, known := knownExtensions[key]; known {
					seenExtensions[key] = true
					t.Logf("EXTENSION %-52s on %s (%s)\n            reason: %s",
						key, ourOwner[name], describe(ourFields[name]), reason)
					continue
				}
				t.Errorf("UNDECLARED EXTENSION: %s.%s carries %q (%s), which %T does not declare.\n"+
					"  Every field we serve beyond upstream's spec is a compatibility decision. Confirm against\n"+
					"  github.com/supabase/auth that upstream really returns it, then record it in knownExtensions[%q].",
					ourOwner[name], name, name, describe(ourFields[name]), pair.spec, key)
			}
		})
	}

	// A stale allow-list is itself a drift signal: if upstream's spec grows the
	// property, or we drop the field, the entry stops applying and must go.
	for key := range knownSpecGaps {
		if !seenGaps[key] {
			t.Errorf("STALE knownSpecGaps[%q]: no longer applies (the spec property is now satisfied, "+
				"or the pair/property no longer exists). Delete the entry.", key)
		}
	}
	for key := range knownExtensions {
		if !seenExtensions[key] {
			t.Errorf("STALE knownExtensions[%q]: no longer applies (upstream now declares the property, "+
				"or we no longer serve it). Delete the entry.", key)
		}
	}
}

// TestHTTPErrorMarshalsWeakPassword backs knownSpecGaps["Error.weak_password"]
// with an actual observation instead of a promise: the property is absent from
// the HTTPError struct but present in the body it marshals.
func TestHTTPErrorMarshalsWeakPassword(t *testing.T) {
	body, err := json.Marshal(weakPasswordError("too short", []string{"length"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		ErrorCode    string `json:"error_code"`
		WeakPassword *struct {
			Reasons []string `json:"reasons"`
		} `json:"weak_password"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	if got.ErrorCode != ErrorCodeWeakPassword {
		t.Errorf("error_code = %q, want %q (body: %s)", got.ErrorCode, ErrorCodeWeakPassword, body)
	}
	if got.WeakPassword == nil || len(got.WeakPassword.Reasons) != 1 || got.WeakPassword.Reasons[0] != "length" {
		t.Errorf("weak_password not rendered as upstream does; body: %s", body)
	}
}

// TestAccessTokenResponseWeakPasswordShape pins the advisory to upstream's
// WeakPasswordError encoding — {"message":…,"reasons":[…]} — and confirms a
// strong password leaves the key out (the documented deviation from upstream's
// literal `"weak_password": null`).
func TestAccessTokenResponseWeakPasswordShape(t *testing.T) {
	strong, err := json.Marshal(AccessTokenResponse{Token: "t"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(strong), "weak_password") {
		t.Errorf("weak_password must be omitted when unset; got %s", strong)
	}

	weak, err := json.Marshal(AccessTokenResponse{
		Token:        "t",
		WeakPassword: &WeakPasswordError{Message: "Password should be at least 8 characters.", Reasons: []string{"length"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		WeakPassword *struct {
			Message string   `json:"message"`
			Reasons []string `json:"reasons"`
		} `json:"weak_password"`
	}
	if err := json.Unmarshal(weak, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", weak, err)
	}
	if got.WeakPassword == nil {
		t.Fatalf("weak_password missing from %s", weak)
	}
	if got.WeakPassword.Message == "" || len(got.WeakPassword.Reasons) != 1 {
		t.Errorf("weak_password = %+v, want upstream's {message, reasons}; body %s", *got.WeakPassword, weak)
	}
}

// TestUpstreamSpecIsNotImportedByRuntimeCode enforces the invariant that
// upstreamspec/doc.go states in prose: the generated types are an oracle, not a
// wire contract, and no non-test file may depend on them. Reviewers forget
// prose; this does not.
func TestUpstreamSpecIsNotImportedByRuntimeCode(t *testing.T) {
	const importPath = "github.com/dilion-project/dilion/internal/auth/upstreamspec"

	// The test binary runs with cwd = internal/auth.
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", "upstreamspec":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), importPath) {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("%s references %s. That package is a conformance oracle built from a spec "+
				"that lags upstream's implementation — see upstreamspec/doc.go. Change the "+
				"hand-written struct in internal/auth instead and let this file's conformance "+
				"test confirm it.", rel, importPath)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// ---- reflection helpers -----------------------------------------------------

// jsonFields returns the JSON property name -> Go type map of a struct,
// flattening embedded structs the way encoding/json does and dropping
// unexported and `json:"-"` fields.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	t = derefType(t)
	out := map[string]reflect.Type{}
	if t.Kind() != reflect.Struct {
		return out
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Tag.Get("json") == "" && derefType(f.Type).Kind() == reflect.Struct {
			for name, ft := range jsonFields(f.Type) {
				if _, ok := out[name]; !ok {
					out[name] = ft
				}
			}
			continue
		}
		if skipField(f) {
			continue
		}
		out[jsonName(f)] = f.Type
	}
	return out
}

// jsonName is the wire name of a field: the json tag's name, else the Go name.
// It returns "" for `json:"-"`.
func jsonName(f reflect.StructField) string {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	switch name {
	case "-":
		return ""
	case "":
		return f.Name
	}
	return name
}

// jsonKind is the JSON value shape a Go type serializes to. Comparing these,
// rather than reflect.Kind, is what lets a spec-side openapi_types.UUID
// ([16]byte) match our string, and time.Time match either.
type jsonKind string

const (
	jkString jsonKind = "string"
	jkNumber jsonKind = "number"
	jkBool   jsonKind = "boolean"
	jkArray  jsonKind = "array"
	jkObject jsonKind = "object"
	jkAny    jsonKind = "any"
)

var textMarshaler = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()

func jsonKindOf(t reflect.Type) jsonKind {
	t = derefType(t)

	// time.Time and anything else that marshals through text (google/uuid's
	// UUID, which oapi-codegen emits for `format: uuid`, is a [16]byte array
	// that encodes as a string) is a JSON string on the wire.
	if t == reflect.TypeOf(time.Time{}) {
		return jkString
	}
	if t.Implements(textMarshaler) || reflect.PointerTo(t).Implements(textMarshaler) {
		return jkString
	}

	switch t.Kind() {
	case reflect.String:
		return jkString
	case reflect.Bool:
		return jkBool
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return jkNumber
	case reflect.Slice, reflect.Array:
		return jkArray
	case reflect.Map, reflect.Struct:
		return jkObject
	default:
		// interface{} (our User.Factors is []any, JSONMap values are any) and
		// anything exotic: no constraint to assert.
		return jkAny
	}
}

// kindsCompatible ignores pointer-ness (already stripped) and treats an
// untyped side as satisfying anything.
func kindsCompatible(want, got jsonKind) bool {
	return want == got || want == jkAny || got == jkAny
}

func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// describe renders a Go type for a failure message, without the package noise.
func describe(t reflect.Type) string {
	s := t.String()
	if len(s) > 60 {
		s = fmt.Sprintf("%s… (%s)", s[:57], jsonKindOf(t))
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestAccessTokenResponseIDTokenShape backs knownExtensions
// ["AccessTokenResponse.id_token"]: the field exists, is tagged exactly as
// upstream tags it, and — because upstream's `omitempty` is what keeps the key
// out of every session body — disappears when unset.
func TestAccessTokenResponseIDTokenShape(t *testing.T) {
	omitted, err := json.Marshal(AccessTokenResponse{Token: "t"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(omitted), "id_token") {
		t.Errorf("id_token must be omitted when unset; got %s", omitted)
	}

	set, err := json.Marshal(AccessTokenResponse{Token: "t", IDToken: "eyJ.a.b"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(set, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", set, err)
	}
	if got["id_token"] != "eyJ.a.b" {
		t.Errorf("id_token key = %v, want the token string (body %s)", got["id_token"], set)
	}
}
