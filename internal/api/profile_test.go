package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dilion-project/dilion/httpapi"
	"github.com/dilion-project/dilion/internal/audit"
	"github.com/dilion-project/dilion/internal/iam"
	"github.com/dilion-project/dilion/internal/privacy"
	"github.com/dilion-project/dilion/ports"
)

func maskedProfile() *privacy.Profile {
	at := time.Date(2026, 8, 12, 3, 4, 5, 0, time.UTC)
	return &privacy.Profile{
		UserID: testUserID,
		Fields: map[string]privacy.ProfileField{
			"email": {Value: "j**@example.com", Hint: privacy.HintEmail},
			"name":  {Value: "홍**", Hint: privacy.HintName},
		},
		View:      privacy.ViewMasked,
		UpdatedAt: &at,
	}
}

func fullProfile() *privacy.Profile {
	p := maskedProfile()
	p.Fields = map[string]privacy.ProfileField{
		"email": {Value: "joseph@example.com", Hint: privacy.HintEmail},
		"name":  {Value: "홍길동", Hint: privacy.HintName},
	}
	p.View = privacy.ViewFull
	return p
}

func decodeProfile(t *testing.T, body []byte) Profile {
	t.Helper()
	var p Profile
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode profile: %v (body=%s)", err, body)
	}
	return p
}

// permDeps authenticates as a regular user access token whose RBAC roles grant
// exactly the listed permissions.
func permDeps(sink *recordingSink, perms ...string) Deps {
	allow := map[string]bool{}
	for _, p := range perms {
		allow[p] = true
	}
	return Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: testUserID, Role: "authenticated"}},
		Authz:    fakeAuthorizer{allow: allow},
		Audit:    sink,
	}
}

// ---- GET /privacy/v1/users/{userId}/profile ----

func TestGetUserProfileReturnsMaskedAndAudits(t *testing.T) {
	sink := &recordingSink{}
	var gotFull bool
	svc := &fakePrivacy{
		getProfile: func(_ context.Context, project, user string, full bool) (*privacy.Profile, error) {
			gotFull = full
			if project != iam.DefaultProjectID || user != testUserID {
				t.Errorf("GetProfile(%q,%q)", project, user)
			}
			return maskedProfile(), nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Get("/privacy/v1/users/"+testUserID+"/profile", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	if gotFull {
		t.Error("GetProfile called with full=true: the plain GET must stay masked")
	}

	body := decodeProfile(t, resp.Body.Bytes())
	if body.View != "MASKED" {
		t.Errorf("view = %q, want MASKED", body.View)
	}
	if got := body.Fields["email"]; got.Value != "j**@example.com" || got.Hint != "EMAIL" {
		t.Errorf("email field = %+v", got)
	}
	if body.UpdatedAt == nil {
		t.Error("updated_at should be present")
	}

	ev, ok := sink.find(audit.ActionPIIMaskedRead)
	if !ok {
		t.Fatalf("missing PII_MASKED_READ, got %v", sink.actions())
	}
	if ev.AccessLevel != audit.AccessMasked {
		t.Errorf("access_level = %q, want masked", ev.AccessLevel)
	}
	if len(ev.SubjectIDs) != 1 || ev.SubjectIDs[0] != testUserID {
		t.Errorf("subject manifest = %v, want [%s]", ev.SubjectIDs, testUserID)
	}
	if ev.Reason != "" {
		t.Errorf("reason = %q, want empty for a masked read", ev.Reason)
	}
}

// TestProfileEndpointsGuardedByPermission pins the permission each profile
// operation demands. The three authorities are deliberately distinct: reading a
// masked profile, unmasking it, and writing it are separate grants (§2.11).
func TestProfileEndpointsGuardedByPermission(t *testing.T) {
	tapi := newAPI(t, &fakePrivacy{}, Deps{})
	want := map[string]string{
		"getUserProfile":    iam.PermUsersRead,
		"revealUserProfile": iam.PermPIIReveal,
		"updateUserProfile": iam.PermPIIWrite,
	}
	got := map[string]string{}
	for _, item := range tapi.OpenAPI().Paths {
		for _, op := range operationsOf(item) {
			if op == nil {
				continue
			}
			got[op.OperationID] = op.Description
		}
	}
	for id, perm := range want {
		desc, ok := got[id]
		if !ok {
			t.Errorf("operation %s not registered", id)
			continue
		}
		if !strings.Contains(desc, "Requires permission `"+perm+"`") {
			t.Errorf("operation %s does not document permission %s: %q", id, perm, desc)
		}
	}
}

// A user access token holding pii.read gets the unmasked projection, exactly
// like a service_role caller would (§2.11 사용자 토큰 + RBAC).
func TestGetUserProfileAcceptsUserTokenWithPermission(t *testing.T) {
	sink := &recordingSink{}
	svc := &fakePrivacy{
		getProfile: func(_ context.Context, _, _ string, _ bool) (*privacy.Profile, error) {
			return maskedProfile(), nil
		},
	}
	tapi := newAPI(t, svc, permDeps(sink, iam.PermUsersRead, iam.PermPIIRead))

	resp := tapi.Get("/privacy/v1/users/"+testUserID+"/profile", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	ev, ok := sink.find(audit.ActionPIIMaskedRead)
	if !ok {
		t.Fatalf("missing PII_MASKED_READ, got %v", sink.actions())
	}
	if ev.ActorType != iam.ActorTypeUser || ev.ActorID != testUserID {
		t.Errorf("audit actor = %q/%q, want user/%s", ev.ActorType, ev.ActorID, testUserID)
	}
	if _, srv := sink.find(audit.ActionServiceRoleUse); srv {
		t.Errorf("a user actor must not emit SERVICE_ROLE_USED: %v", sink.actions())
	}
}

func TestProfileEndpointsRejectCompatibilityPlaneJWT(t *testing.T) {
	// An anon JWT carries no management-plane authority at all, even when the
	// installed Authorizer would grant the permission.
	for _, tc := range []struct {
		name, method, path string
		body               map[string]any
	}{
		{"get", http.MethodGet, "/privacy/v1/users/" + testUserID + "/profile", nil},
		{"reveal", http.MethodPost, "/privacy/v1/users/" + testUserID + "/profile/reveal",
			map[string]any{"reason": "why"}},
		{"update", http.MethodPatch, "/privacy/v1/users/" + testUserID + "/profile",
			map[string]any{"remove": []string{"email"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &recordingSink{}
			d := permDeps(sink, iam.PermUsersRead, iam.PermPIIRead, iam.PermPIIReveal, iam.PermPIIWrite)
			d.Verifier = fakeVerifier{claims: &ports.Claims{Subject: "anon-1", Role: "anon"}}
			tapi := newAPI(t, &fakePrivacy{}, d)

			args := []any{bearer}
			if tc.body != nil {
				args = append(args, tc.body)
			}
			resp := tapi.Do(tc.method, tc.path, args...)
			if resp.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body=%s)", resp.Code, resp.Body.String())
			}
			if p := decodeProblem(t, resp.Body.Bytes()); p.Code != httpapi.CodePermissionDenied {
				t.Errorf("code = %q, want permission_denied", p.Code)
			}
			if _, ok := sink.find(audit.ActionPermissionDenied); !ok {
				t.Errorf("missing PERMISSION_DENIED, got %v", sink.actions())
			}
		})
	}
}

func TestGetUserProfileNotFound(t *testing.T) {
	svc := &fakePrivacy{
		getProfile: func(context.Context, string, string, bool) (*privacy.Profile, error) {
			// Profile absent, or unreadable after erasure (crypto-shred).
			return nil, privacy.ErrNotFound
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(&recordingSink{}))

	resp := tapi.Get("/privacy/v1/users/"+testUserID+"/profile", bearer)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body=%s)", resp.Code, resp.Body.String())
	}
	if p := decodeProblem(t, resp.Body.Bytes()); p.Code != httpapi.CodeNotFound {
		t.Errorf("code = %q, want not_found", p.Code)
	}
}

// ---- POST /privacy/v1/users/{userId}/profile/reveal ----

func TestRevealUserProfileReturnsFullAndRecordsReason(t *testing.T) {
	sink := &recordingSink{}
	var gotFull bool
	svc := &fakePrivacy{
		getProfile: func(_ context.Context, _, _ string, full bool) (*privacy.Profile, error) {
			gotFull = full
			return fullProfile(), nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Post("/privacy/v1/users/"+testUserID+"/profile/reveal", bearer,
		map[string]any{"reason": "CS ticket #4417 identity verification"})
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	if !gotFull {
		t.Error("GetProfile called with full=false: reveal must request the originals")
	}

	body := decodeProfile(t, resp.Body.Bytes())
	if body.View != "FULL" {
		t.Errorf("view = %q, want FULL", body.View)
	}
	if body.Fields["email"].Value != "joseph@example.com" {
		t.Errorf("email = %q, want the original value", body.Fields["email"].Value)
	}

	ev, ok := sink.find(audit.ActionPIIFullRead)
	if !ok {
		t.Fatalf("missing PII_FULL_READ, got %v", sink.actions())
	}
	if ev.AccessLevel != audit.AccessFull {
		t.Errorf("access_level = %q, want full", ev.AccessLevel)
	}
	if ev.Reason != "CS ticket #4417 identity verification" {
		t.Errorf("reason = %q, not recorded on the event", ev.Reason)
	}
	if len(ev.SubjectIDs) != 1 || ev.SubjectIDs[0] != testUserID {
		t.Errorf("subject manifest = %v", ev.SubjectIDs)
	}
}

func TestRevealUserProfileRequiresReason(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing", map[string]any{}},
		{"empty", map[string]any{"reason": ""}},
		{"too long", map[string]any{"reason": strings.Repeat("x", 501)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &recordingSink{}
			svc := &fakePrivacy{
				getProfile: func(context.Context, string, string, bool) (*privacy.Profile, error) {
					t.Error("engine must not be called without a valid reason")
					return fullProfile(), nil
				},
			}
			tapi := newAPI(t, svc, serviceRoleDeps(sink))

			resp := tapi.Post("/privacy/v1/users/"+testUserID+"/profile/reveal", bearer, tc.body)
			if resp.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422 (body=%s)", resp.Code, resp.Body.String())
			}
			p := decodeProblem(t, resp.Body.Bytes())
			if p.Code != httpapi.CodeValidationFailed {
				t.Errorf("code = %q, want validation_failed", p.Code)
			}
			if len(p.Errors) == 0 {
				t.Error("expected errors[] detail list")
			}
			if _, ok := sink.find(audit.ActionPIIFullRead); ok {
				t.Error("PII_FULL_READ recorded for a rejected reveal")
			}
		})
	}
}

// ---- PATCH /privacy/v1/users/{userId}/profile ----

func TestUpdateUserProfilePassesSetAndRemove(t *testing.T) {
	sink := &recordingSink{}
	var (
		gotSet    map[string]privacy.ProfileField
		gotRemove []string
	)
	svc := &fakePrivacy{
		updateProfile: func(_ context.Context, _, _ string, set map[string]privacy.ProfileField, remove []string) (*privacy.Profile, error) {
			gotSet, gotRemove = set, remove
			return maskedProfile(), nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Patch("/privacy/v1/users/"+testUserID+"/profile", bearer, map[string]any{
		"set":    map[string]any{"phone": map[string]any{"value": "010-1234-5678", "hint": "PHONE"}},
		"remove": []string{"address"},
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	if got := gotSet["phone"]; got.Value != "010-1234-5678" || got.Hint != privacy.HintPhone {
		t.Errorf("set = %+v", gotSet)
	}
	if len(gotRemove) != 1 || gotRemove[0] != "address" {
		t.Errorf("remove = %v", gotRemove)
	}
	// A write never reveals: the response is the masked projection.
	if body := decodeProfile(t, resp.Body.Bytes()); body.View != "MASKED" {
		t.Errorf("view = %q, want MASKED", body.View)
	}

	ev, ok := sink.find(audit.ActionPIIUpdate)
	if !ok {
		t.Fatalf("missing PII_UPDATE, got %v", sink.actions())
	}
	if len(ev.SubjectIDs) != 1 || ev.SubjectIDs[0] != testUserID {
		t.Errorf("subject manifest = %v", ev.SubjectIDs)
	}
}

func TestUpdateUserProfileRequiresSetOrRemove(t *testing.T) {
	sink := &recordingSink{}
	svc := &fakePrivacy{
		updateProfile: func(context.Context, string, string, map[string]privacy.ProfileField, []string) (*privacy.Profile, error) {
			t.Error("engine must not be called for an empty patch")
			return maskedProfile(), nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Patch("/privacy/v1/users/"+testUserID+"/profile", bearer, map[string]any{})
	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (body=%s)", resp.Code, resp.Body.String())
	}
	p := decodeProblem(t, resp.Body.Bytes())
	if p.Code != httpapi.CodeValidationFailed {
		t.Errorf("code = %q, want validation_failed", p.Code)
	}
	if len(p.Errors) == 0 {
		t.Error("expected errors[] detail list")
	}
	if _, ok := sink.find(audit.ActionPIIUpdate); ok {
		t.Error("PII_UPDATE recorded for a rejected patch")
	}
}

func TestProfileErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
		wantKind string
	}{
		{"invalid input", privacy.ErrInvalidInput, http.StatusUnprocessableEntity, httpapi.CodeValidationFailed},
		{"conflict", privacy.ErrConflict, http.StatusConflict, httpapi.CodeConflict},
		{"not found", privacy.ErrNotFound, http.StatusNotFound, httpapi.CodeNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakePrivacy{
				updateProfile: func(context.Context, string, string, map[string]privacy.ProfileField, []string) (*privacy.Profile, error) {
					return nil, tc.err
				},
			}
			tapi := newAPI(t, svc, serviceRoleDeps(&recordingSink{}))
			resp := tapi.Patch("/privacy/v1/users/"+testUserID+"/profile", bearer, map[string]any{
				"set": map[string]any{"email": map[string]any{"value": "a@b.c", "hint": "EMAIL"}},
			})
			if resp.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", resp.Code, tc.wantCode, resp.Body.String())
			}
			if p := decodeProblem(t, resp.Body.Bytes()); p.Code != tc.wantKind {
				t.Errorf("code = %q, want %q", p.Code, tc.wantKind)
			}
		})
	}
}

func TestUnknownFieldHintIsRejected(t *testing.T) {
	svc := &fakePrivacy{
		updateProfile: func(context.Context, string, string, map[string]privacy.ProfileField, []string) (*privacy.Profile, error) {
			t.Error("engine must not be called with an unknown hint")
			return maskedProfile(), nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(&recordingSink{}))
	resp := tapi.Patch("/privacy/v1/users/"+testUserID+"/profile", bearer, map[string]any{
		"set": map[string]any{"email": map[string]any{"value": "a@b.c", "hint": "SSN"}},
	})
	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (body=%s)", resp.Code, resp.Body.String())
	}
}
