package api

// Tests for the self-service surface (/privacy/v1/me/*, use-cases.md P2), the
// cross-user consent surface (P1), user search (P4) and the consents.write
// permission split. Same fakes/harness as api_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/privacy"
	"github.com/dilion-io/dilion/ports"
)

// endUserDeps authenticates every request as a plain end-user token with NO
// RBAC role at all — exactly the caller the self-service surface exists for.
func endUserDeps(sink *recordingSink) Deps {
	return Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: testUserID, Role: "authenticated"}},
		Authz:    fakeAuthorizer{}, // deny-by-default everywhere else
		Audit:    sink,
	}
}

func TestMeSurfaceScopesEverythingToTheTokenSubject(t *testing.T) {
	sink := &recordingSink{}
	var createdFor string
	var listedFor *string
	var consentFor, consentSource string
	svc := &fakePrivacy{
		createRequest: func(_ context.Context, in privacy.CreateRequestInput) (*privacy.Request, error) {
			createdFor = in.UserID
			r := sampleRequest()
			r.UserID = in.UserID
			return r, nil
		},
		listRequests: func(_ context.Context, _ string, f privacy.RequestFilter, _ httpapi.ListParams) (httpapi.Page[privacy.Request], error) {
			listedFor = f.UserID
			return httpapi.Page[privacy.Request]{Items: []privacy.Request{}}, nil
		},
		updateConsent: func(_ context.Context, _, u string, ch privacy.ConsentChange) (*privacy.ConsentState, error) {
			consentFor, consentSource = u, ch.Source
			return &privacy.ConsentState{Purpose: ch.Purpose, Granted: ch.Granted,
				PolicyVersion: ch.PolicyVersion, UpdatedAt: time.Now()}, nil
		},
		getConsents: func(context.Context, string, string) ([]privacy.ConsentState, error) {
			return []privacy.ConsentState{}, nil
		},
	}
	tapi := newAPI(t, svc, endUserDeps(sink))

	resp := tapi.Post("/privacy/v1/me/requests", bearer, map[string]any{"type": "DELETION"})
	if resp.Code != http.StatusAccepted {
		t.Fatalf("create status = %d (body=%s)", resp.Code, resp.Body.String())
	}
	if createdFor != testUserID {
		t.Errorf("request created for %q, want the token subject %q", createdFor, testUserID)
	}

	if resp := tapi.Get("/privacy/v1/me/requests", bearer); resp.Code != http.StatusOK {
		t.Fatalf("list status = %d (body=%s)", resp.Code, resp.Body.String())
	}
	if listedFor == nil || *listedFor != testUserID {
		t.Errorf("list filter user = %v, want the token subject", listedFor)
	}

	resp = tapi.Patch("/privacy/v1/me/consents", bearer, map[string]any{
		"purpose": "marketing", "granted": false, "policy_version": "v1.4"})
	if resp.Code != http.StatusOK {
		t.Fatalf("consent status = %d (body=%s)", resp.Code, resp.Body.String())
	}
	if consentFor != testUserID || consentSource != "ui" {
		t.Errorf("consent recorded for %q via %q, want %s via ui", consentFor, consentSource, testUserID)
	}

	// Every self-service action lands in the audit log with the subject.
	for _, action := range []string{audit.ActionPrivacyRequestCreated,
		audit.ActionPrivacyRequestListRead, audit.ActionConsentChanged} {
		ev, ok := sink.find(action)
		if !ok {
			t.Fatalf("missing audit event %s: %v", action, sink.actions())
		}
		if ev.ActorType != iam.ActorTypeUser || ev.ActorID != testUserID {
			t.Errorf("%s actor = %q/%q, want user/%s", action, ev.ActorType, ev.ActorID, testUserID)
		}
	}
}

func TestMeCancelHidesOtherSubjectsRequests(t *testing.T) {
	sink := &recordingSink{}
	other := sampleRequest()
	other.UserID = "99999999-9999-4999-8999-999999999999"
	canceled := false
	svc := &fakePrivacy{
		getRequest: func(context.Context, string, string) (*privacy.Request, error) {
			return other, nil
		},
		cancelRequest: func(context.Context, string, string) (*privacy.Request, error) {
			canceled = true
			return other, nil
		},
	}
	tapi := newAPI(t, svc, endUserDeps(sink))

	resp := tapi.Post("/privacy/v1/me/requests/"+testReqID+"/cancel", bearer)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (존재 노출 방지)", resp.Code)
	}
	if canceled {
		t.Fatal("another subject's request must never be canceled")
	}

	// The subject's own request cancels normally.
	own := sampleRequest()
	svc.getRequest = func(context.Context, string, string) (*privacy.Request, error) { return own, nil }
	svc.cancelRequest = func(context.Context, string, string) (*privacy.Request, error) { return own, nil }
	if resp := tapi.Post("/privacy/v1/me/requests/"+testReqID+"/cancel", bearer); resp.Code != http.StatusOK {
		t.Fatalf("own cancel status = %d (body=%s)", resp.Code, resp.Body.String())
	}
}

func TestMeSurfaceRejectsNonUserCredentials(t *testing.T) {
	cases := []struct {
		name string
		deps Deps
		auth string
		want int
	}{
		{"service_role", serviceRoleDeps(&recordingSink{}), bearer, http.StatusForbidden},
		{"anon", Deps{
			Verifier: fakeVerifier{claims: &ports.Claims{Subject: "anon-1", Role: "anon"}},
			Audit:    &recordingSink{},
		}, bearer, http.StatusForbidden},
		{"api_key", serviceRoleDeps(&recordingSink{}),
			"Authorization: Bearer dk_notarealkey", http.StatusForbidden},
		{"missing", serviceRoleDeps(&recordingSink{}), "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tapi := newAPI(t, &fakePrivacy{}, tc.deps)
			var resp = tapi.Get("/privacy/v1/me/requests")
			if tc.auth != "" {
				resp = tapi.Get("/privacy/v1/me/requests", tc.auth)
			}
			if resp.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", resp.Code, tc.want, resp.Body.String())
			}
		})
	}
}

// consents.write is the consent-recording authority; DSR powers no longer
// imply it and vice versa (migration 0304).
func TestUpdateUserConsentRequiresConsentsWrite(t *testing.T) {
	svc := &fakePrivacy{
		updateConsent: func(_ context.Context, _, _ string, ch privacy.ConsentChange) (*privacy.ConsentState, error) {
			return &privacy.ConsentState{Purpose: ch.Purpose, Granted: ch.Granted,
				PolicyVersion: ch.PolicyVersion, UpdatedAt: time.Now()}, nil
		},
	}
	body := map[string]any{"purpose": "marketing", "granted": true, "policy_version": "v1", "source": "API"}

	dsrOnly := Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: testUserID, Role: "authenticated"}},
		Authz:    fakeAuthorizer{allow: map[string]bool{iam.PermPrivacyRequestsManage: true}},
		Audit:    &recordingSink{},
	}
	tapi := newAPI(t, svc, dsrOnly)
	if resp := tapi.Patch("/privacy/v1/users/"+testUserID+"/consents", bearer, body); resp.Code != http.StatusForbidden {
		t.Fatalf("DSR-only actor status = %d, want 403", resp.Code)
	}

	writer := Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: testUserID, Role: "authenticated"}},
		Authz:    fakeAuthorizer{allow: map[string]bool{iam.PermConsentsWrite: true}},
		Audit:    &recordingSink{},
	}
	tapi = newAPI(t, svc, writer)
	if resp := tapi.Patch("/privacy/v1/users/"+testUserID+"/consents", bearer, body); resp.Code != http.StatusOK {
		t.Fatalf("consents.write actor status = %d (body=%s)", resp.Code, resp.Body.String())
	}
}

func TestSearchUsersEndpoint(t *testing.T) {
	sink := &recordingSink{}
	var gotQuery privacy.UserSearchQuery
	svc := &fakePrivacy{
		searchUsers: func(_ context.Context, _ string, q privacy.UserSearchQuery, _ httpapi.ListParams) (httpapi.Page[privacy.UserMatch], error) {
			gotQuery = q
			return httpapi.Page[privacy.UserMatch]{Items: []privacy.UserMatch{
				{UserID: testUserID, Source: privacy.MatchAuthEmail},
			}}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Get("/privacy/v1/users?email=joseph%40example.com", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", resp.Code, resp.Body.String())
	}
	if gotQuery.Email != "joseph@example.com" {
		t.Errorf("engine query = %+v", gotQuery)
	}
	var page UserMatchPage
	if err := json.Unmarshal(resp.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].UserID != testUserID ||
		page.Items[0].Source != "AUTH_EMAIL" || page.Items[0].FieldKey != nil {
		t.Errorf("page = %+v", page)
	}

	ev, ok := sink.find(audit.ActionUserSearch)
	if !ok {
		t.Fatalf("missing USER_SEARCH audit event: %v", sink.actions())
	}
	if len(ev.SubjectIDs) != 1 || ev.SubjectIDs[0] != testUserID {
		t.Errorf("subject manifest = %v", ev.SubjectIDs)
	}
	// §5.1: the searched value must never appear in the recorded resource.
	if ev.Resource != "users:search" {
		t.Errorf("resource = %q, must not carry the search value", ev.Resource)
	}

	// Engine-side validation (two criteria, none, ...) maps to 422.
	svc.searchUsers = func(context.Context, string, privacy.UserSearchQuery, httpapi.ListParams) (httpapi.Page[privacy.UserMatch], error) {
		return httpapi.Page[privacy.UserMatch]{}, privacy.ErrInvalidInput
	}
	if resp := tapi.Get("/privacy/v1/users", bearer); resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("validation status = %d, want 422", resp.Code)
	}
}

func TestListConsentStatesEndpoint(t *testing.T) {
	sink := &recordingSink{}
	var gotFilter privacy.ConsentSegmentFilter
	svc := &fakePrivacy{
		listConsentStates: func(_ context.Context, _ string, f privacy.ConsentSegmentFilter, _ httpapi.ListParams) (httpapi.Page[privacy.SubjectConsent], error) {
			gotFilter = f
			return httpapi.Page[privacy.SubjectConsent]{Items: []privacy.SubjectConsent{{
				UserID: testUserID,
				ConsentState: privacy.ConsentState{Purpose: "marketing", Granted: true,
					PolicyVersion: "v1.4", UpdatedAt: time.Now()},
			}}}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Get("/privacy/v1/consents?purpose=marketing&granted=true", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", resp.Code, resp.Body.String())
	}
	if gotFilter.Purpose != "marketing" || gotFilter.Granted == nil || !*gotFilter.Granted {
		t.Errorf("filter = %+v", gotFilter)
	}
	ev, ok := sink.find(audit.ActionConsentSegmentRead)
	if !ok {
		t.Fatalf("missing CONSENT_SEGMENT_READ: %v", sink.actions())
	}
	if len(ev.SubjectIDs) != 1 || ev.SubjectIDs[0] != testUserID {
		t.Errorf("subject manifest = %v", ev.SubjectIDs)
	}
}

func TestExportConsentAudienceEndpoint(t *testing.T) {
	sink := &recordingSink{}
	svc := &fakePrivacy{
		exportAudience: func(_ context.Context, _, purpose string, _ httpapi.ListParams) (httpapi.Page[privacy.AudienceMember], error) {
			if purpose != "marketing" {
				t.Errorf("purpose = %q", purpose)
			}
			return httpapi.Page[privacy.AudienceMember]{Items: []privacy.AudienceMember{
				{UserID: testUserID, Email: "joseph@example.com", Phone: "+821012345678"},
			}}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	// reason is mandatory.
	resp := tapi.Post("/privacy/v1/consents/export", bearer, map[string]any{"purpose": "marketing"})
	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing reason status = %d, want 422", resp.Code)
	}

	resp = tapi.Post("/privacy/v1/consents/export", bearer, map[string]any{
		"purpose": "marketing", "reason": "2026-09 뉴스레터 캠페인"})
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", resp.Code, resp.Body.String())
	}
	var page AudiencePage
	if err := json.Unmarshal(resp.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %+v", page.Items)
	}
	// Default fields = [email]: phone stays null (data minimization).
	if page.Items[0].Email == nil || *page.Items[0].Email != "joseph@example.com" {
		t.Errorf("email = %v", page.Items[0].Email)
	}
	if page.Items[0].Phone != nil {
		t.Errorf("phone = %v, want null when not requested", *page.Items[0].Phone)
	}

	ev, ok := sink.find(audit.ActionConsentAudienceExport)
	if !ok {
		t.Fatalf("missing CONSENT_AUDIENCE_EXPORT: %v", sink.actions())
	}
	if ev.AccessLevel != audit.AccessFull || ev.Reason == "" {
		t.Errorf("export event = level %q reason %q, want full + recorded reason", ev.AccessLevel, ev.Reason)
	}
	if len(ev.SubjectIDs) != 1 || ev.SubjectIDs[0] != testUserID {
		t.Errorf("subject manifest = %v", ev.SubjectIDs)
	}
}
