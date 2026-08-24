package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/privacy"
	"github.com/dilion-io/dilion/ports"
)

// ---- fakes ----

// fakePrivacy is a privacy.Service whose behaviour each test overrides via the
// function fields it cares about.
type fakePrivacy struct {
	createRequest     func(context.Context, privacy.CreateRequestInput) (*privacy.Request, error)
	getRequest        func(context.Context, string, string) (*privacy.Request, error)
	listRequests      func(context.Context, string, privacy.RequestFilter, httpapi.ListParams) (httpapi.Page[privacy.Request], error)
	cancelRequest     func(context.Context, string, string) (*privacy.Request, error)
	getConsents       func(context.Context, string, string) ([]privacy.ConsentState, error)
	updateConsent     func(context.Context, string, string, privacy.ConsentChange) (*privacy.ConsentState, error)
	listConsentStates func(context.Context, string, privacy.ConsentSegmentFilter, httpapi.ListParams) (httpapi.Page[privacy.SubjectConsent], error)
	exportAudience    func(context.Context, string, string, httpapi.ListParams) (httpapi.Page[privacy.AudienceMember], error)
	searchUsers       func(context.Context, string, privacy.UserSearchQuery, httpapi.ListParams) (httpapi.Page[privacy.UserMatch], error)
	getProfile        func(context.Context, string, string, bool) (*privacy.Profile, error)
	updateProfile     func(context.Context, string, string, map[string]privacy.ProfileField, []string) (*privacy.Profile, error)
	getDest           func(context.Context, string, string) (*privacy.Destination, error)
	listDests         func(context.Context, string, httpapi.ListParams) (httpapi.Page[privacy.Destination], error)
	deleteDest        func(context.Context, string, string) error
	createHold        func(context.Context, privacy.CreateHoldInput) (*privacy.LegalHold, error)
}

func (f *fakePrivacy) CreateRequest(ctx context.Context, in privacy.CreateRequestInput) (*privacy.Request, error) {
	return f.createRequest(ctx, in)
}

func (f *fakePrivacy) GetRequest(ctx context.Context, p, id string) (*privacy.Request, error) {
	return f.getRequest(ctx, p, id)
}

func (f *fakePrivacy) ListRequests(ctx context.Context, p string, fl privacy.RequestFilter, lp httpapi.ListParams) (httpapi.Page[privacy.Request], error) {
	return f.listRequests(ctx, p, fl, lp)
}

func (f *fakePrivacy) ListConsentStates(ctx context.Context, p string, fl privacy.ConsentSegmentFilter, lp httpapi.ListParams) (httpapi.Page[privacy.SubjectConsent], error) {
	if f.listConsentStates == nil {
		return httpapi.Page[privacy.SubjectConsent]{Items: []privacy.SubjectConsent{}}, nil
	}
	return f.listConsentStates(ctx, p, fl, lp)
}

func (f *fakePrivacy) ExportConsentAudience(ctx context.Context, p, purpose string, lp httpapi.ListParams) (httpapi.Page[privacy.AudienceMember], error) {
	if f.exportAudience == nil {
		return httpapi.Page[privacy.AudienceMember]{Items: []privacy.AudienceMember{}}, nil
	}
	return f.exportAudience(ctx, p, purpose, lp)
}

func (f *fakePrivacy) SearchUsers(ctx context.Context, p string, q privacy.UserSearchQuery, lp httpapi.ListParams) (httpapi.Page[privacy.UserMatch], error) {
	if f.searchUsers == nil {
		return httpapi.Page[privacy.UserMatch]{Items: []privacy.UserMatch{}}, nil
	}
	return f.searchUsers(ctx, p, q, lp)
}

func (f *fakePrivacy) CancelRequest(ctx context.Context, p, id string) (*privacy.Request, error) {
	return f.cancelRequest(ctx, p, id)
}

func (f *fakePrivacy) GetConsents(ctx context.Context, p, u string) ([]privacy.ConsentState, error) {
	return f.getConsents(ctx, p, u)
}

func (f *fakePrivacy) UpdateConsent(ctx context.Context, p, u string, ch privacy.ConsentChange) (*privacy.ConsentState, error) {
	return f.updateConsent(ctx, p, u, ch)
}

func (f *fakePrivacy) GetProfile(ctx context.Context, p, u string, full bool) (*privacy.Profile, error) {
	if f.getProfile == nil {
		return nil, privacy.ErrNotFound
	}
	return f.getProfile(ctx, p, u, full)
}

func (f *fakePrivacy) UpdateProfile(ctx context.Context, p, u string, set map[string]privacy.ProfileField, remove []string) (*privacy.Profile, error) {
	if f.updateProfile == nil {
		return nil, privacy.ErrNotFound
	}
	return f.updateProfile(ctx, p, u, set, remove)
}

func (f *fakePrivacy) CreateDestination(context.Context, privacy.CreateDestinationInput) (*privacy.Destination, error) {
	return nil, privacy.ErrNotFound
}

func (f *fakePrivacy) GetDestination(ctx context.Context, p, id string) (*privacy.Destination, error) {
	if f.getDest == nil {
		return nil, privacy.ErrNotFound
	}
	return f.getDest(ctx, p, id)
}

func (f *fakePrivacy) ListDestinations(ctx context.Context, p string, lp httpapi.ListParams) (httpapi.Page[privacy.Destination], error) {
	if f.listDests == nil {
		return httpapi.Page[privacy.Destination]{Items: []privacy.Destination{}}, nil
	}
	return f.listDests(ctx, p, lp)
}

func (f *fakePrivacy) UpdateDestination(context.Context, string, string, *bool, map[string]any) (*privacy.Destination, error) {
	return nil, privacy.ErrNotFound
}

func (f *fakePrivacy) DeleteDestination(ctx context.Context, p, id string) error {
	if f.deleteDest == nil {
		return nil
	}
	return f.deleteDest(ctx, p, id)
}

func (f *fakePrivacy) CreateHold(ctx context.Context, in privacy.CreateHoldInput) (*privacy.LegalHold, error) {
	return f.createHold(ctx, in)
}

func (f *fakePrivacy) ReleaseHold(context.Context, string, string, string) (*privacy.LegalHold, error) {
	return nil, privacy.ErrNotFound
}

func (f *fakePrivacy) ListHolds(context.Context, string, privacy.HoldFilter, httpapi.ListParams) (httpapi.Page[privacy.LegalHold], error) {
	return httpapi.Page[privacy.LegalHold]{Items: []privacy.LegalHold{}}, nil
}

var _ privacy.Service = (*fakePrivacy)(nil)

type fakeVerifier struct {
	claims *ports.Claims
	err    error
}

func (f fakeVerifier) Verify(context.Context, string) (*ports.Claims, error) {
	return f.claims, f.err
}

type fakeAuthorizer struct {
	allow map[string]bool
	err   error
}

func (f fakeAuthorizer) Can(_ context.Context, _ ports.Actor, permission, _ string) (bool, error) {
	return f.allow[permission], f.err
}

type recordingSink struct {
	mu     sync.Mutex
	events []ports.AuditEvent
}

func (r *recordingSink) Append(_ context.Context, e ports.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordingSink) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, e.Action)
	}
	return out
}

func (r *recordingSink) find(action string) (ports.AuditEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if e.Action == action {
			return e, true
		}
	}
	return ports.AuditEvent{}, false
}

// ---- helpers ----

const (
	testUserID = "6a1f2b3c-4d5e-4f70-8192-a3b4c5d6e7f8"
	testReqID  = "pr_0123456789abcdef0123456789abcdef"
)

// serviceRoleDeps authenticates every request as a service_role JWT.
func serviceRoleDeps(sink *recordingSink) Deps {
	return Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: "svc-1", Role: "service_role"}},
		Authz:    fakeAuthorizer{},
		Audit:    sink,
	}
}

func newAPI(t *testing.T, svc privacy.Service, d Deps) humatest.TestAPI {
	t.Helper()
	_, tapi := humatest.New(t, NewConfig())
	RegisterPrivacyAPI(tapi, StaticService(svc), d)
	RegisterIAMAPI(tapi, d)
	return tapi
}

func decodeProblem(t *testing.T, body []byte) Problem {
	t.Helper()
	var p Problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode problem: %v (body=%s)", err, body)
	}
	return p
}

func sampleRequest() *privacy.Request {
	return &privacy.Request{
		ID:          testReqID,
		UserID:      testUserID,
		Type:        privacy.RequestDeletion,
		Status:      privacy.StatusRequested,
		PolicyID:    "kr",
		ScheduledAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		RequestedAt: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC),
	}
}

const bearer = "Authorization: Bearer test-jwt"

// ---- authentication / authorization ----

func TestMissingCredentialsReturns401Problem(t *testing.T) {
	sink := &recordingSink{}
	tapi := newAPI(t, &fakePrivacy{}, serviceRoleDeps(sink))

	resp := tapi.Get("/privacy/v1/requests")
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.Code)
	}
	if ct := resp.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
		t.Errorf("content-type = %q, want application/problem+json", ct)
	}
	p := decodeProblem(t, resp.Body.Bytes())
	if p.Code != httpapi.CodeUnauthenticated {
		t.Errorf("code = %q, want %q", p.Code, httpapi.CodeUnauthenticated)
	}
	if p.Status != http.StatusUnauthorized {
		t.Errorf("problem.status = %d, want 401", p.Status)
	}
	if resp.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

// A user access token (role=authenticated) is a first-class management-plane
// credential as long as RBAC grants it the operation's permission (§2.11).
func TestAuthenticatedUserWithGrantedPermissionIsAllowed(t *testing.T) {
	sink := &recordingSink{}
	svc := &fakePrivacy{
		listRequests: func(context.Context, string, privacy.RequestFilter, httpapi.ListParams) (httpapi.Page[privacy.Request], error) {
			return httpapi.Page[privacy.Request]{Items: []privacy.Request{}}, nil
		},
	}
	d := Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: testUserID, Role: "authenticated"}},
		Authz:    fakeAuthorizer{allow: map[string]bool{iam.PermPrivacyRequestsManage: true}},
		Audit:    sink,
	}
	tapi := newAPI(t, svc, d)

	resp := tapi.Get("/privacy/v1/requests", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	// A user actor is never a service_role use.
	if _, ok := sink.find(audit.ActionServiceRoleUse); ok {
		t.Errorf("unexpected SERVICE_ROLE_USED for a user actor: %v", sink.actions())
	}
	ev, ok := sink.find(audit.ActionPrivacyRequestListRead)
	if !ok {
		t.Fatalf("expected a read audit event, got %v", sink.actions())
	}
	if ev.ActorType != iam.ActorTypeUser || ev.ActorID != testUserID {
		t.Errorf("audit actor = %q/%q, want user/%s", ev.ActorType, ev.ActorID, testUserID)
	}
}

// Deny-by-default: an authenticated user without any role assignment is denied.
func TestAuthenticatedUserWithoutRoleIsDeniedWithAudit(t *testing.T) {
	sink := &recordingSink{}
	d := Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: testUserID, Role: "authenticated"}},
		Authz:    fakeAuthorizer{},
		Audit:    sink,
	}
	tapi := newAPI(t, &fakePrivacy{}, d)

	resp := tapi.Get("/privacy/v1/requests", bearer)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
	p := decodeProblem(t, resp.Body.Bytes())
	if p.Code != httpapi.CodePermissionDenied {
		t.Errorf("code = %q, want permission_denied", p.Code)
	}
	ev, ok := sink.find(audit.ActionPermissionDenied)
	if !ok {
		t.Fatalf("expected PERMISSION_DENIED audit event, got %v", sink.actions())
	}
	if ev.ActorType != iam.ActorTypeUser {
		t.Errorf("audit actor_type = %q, want user", ev.ActorType)
	}
}

// Any other compatibility-plane role (anon) is rejected before RBAC runs.
func TestAnonJWTIsRejectedWithAudit(t *testing.T) {
	sink := &recordingSink{}
	d := Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: "anon-1", Role: "anon"}},
		// Even an all-allowing Authorizer must not rescue an anon token.
		Authz: fakeAuthorizer{allow: map[string]bool{iam.PermPrivacyRequestsManage: true}},
		Audit: sink,
	}
	tapi := newAPI(t, &fakePrivacy{}, d)

	resp := tapi.Get("/privacy/v1/requests", bearer)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
	p := decodeProblem(t, resp.Body.Bytes())
	if p.Code != httpapi.CodePermissionDenied {
		t.Errorf("code = %q, want permission_denied", p.Code)
	}
	ev, ok := sink.find(audit.ActionPermissionDenied)
	if !ok {
		t.Fatalf("expected PERMISSION_DENIED audit event, got %v", sink.actions())
	}
	if ev.ActorType != "anon" {
		t.Errorf("audit actor_type = %q, want anon", ev.ActorType)
	}
}

func TestPermissionDeniedEmitsAudit(t *testing.T) {
	sink := &recordingSink{}
	// A compatibility-plane JWT never reaches the management plane, so the
	// denial is recorded with the route that was attempted.
	d := Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: "admin-1", Role: "authenticated"}},
		Authz:    fakeAuthorizer{},
		Audit:    sink,
	}
	tapi := newAPI(t, &fakePrivacy{}, d)

	resp := tapi.Get("/iam/v1/roles", bearer)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
	ev, ok := sink.find(audit.ActionPermissionDenied)
	if !ok {
		t.Fatalf("expected PERMISSION_DENIED audit event, got %v", sink.actions())
	}
	if !strings.Contains(ev.Resource, "/iam/v1/roles") {
		t.Errorf("audit resource = %q, want it to name the route", ev.Resource)
	}
}

func TestServiceRoleUseIsAuditedOncePerRequest(t *testing.T) {
	sink := &recordingSink{}
	svc := &fakePrivacy{
		listRequests: func(context.Context, string, privacy.RequestFilter, httpapi.ListParams) (httpapi.Page[privacy.Request], error) {
			return httpapi.Page[privacy.Request]{Items: []privacy.Request{}}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	if resp := tapi.Get("/privacy/v1/requests", bearer); resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	n := 0
	for _, a := range sink.actions() {
		if a == audit.ActionServiceRoleUse {
			n++
		}
	}
	if n != 1 {
		t.Errorf("SERVICE_ROLE_USED emitted %d times, want 1 (%v)", n, sink.actions())
	}
}

// ---- privacy requests ----

func TestCreatePrivacyRequestAcceptsAndPassesIdempotencyKey(t *testing.T) {
	sink := &recordingSink{}
	var got privacy.CreateRequestInput
	svc := &fakePrivacy{
		createRequest: func(_ context.Context, in privacy.CreateRequestInput) (*privacy.Request, error) {
			got = in
			return sampleRequest(), nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Post("/privacy/v1/requests", bearer, "Idempotency-Key: abc-123",
		map[string]any{"user_id": testUserID, "type": "DELETION", "immediate": true})

	if resp.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", resp.Code, resp.Body.String())
	}
	if loc := resp.Header().Get("Location"); loc != "/privacy/v1/requests/"+testReqID {
		t.Errorf("Location = %q", loc)
	}
	if got.IdempotencyKey != "abc-123" {
		t.Errorf("idempotency key = %q, want abc-123", got.IdempotencyKey)
	}
	if !got.Immediate {
		t.Error("immediate flag not passed through")
	}
	if got.ProjectID != iam.DefaultProjectID {
		t.Errorf("project = %q, want default", got.ProjectID)
	}
	ev, ok := sink.find(audit.ActionPrivacyRequestCreated)
	if !ok {
		t.Fatalf("missing PRIVACY_REQUEST_CREATED audit event, got %v", sink.actions())
	}
	if len(ev.SubjectIDs) != 1 || ev.SubjectIDs[0] != testUserID {
		t.Errorf("subject manifest = %v, want [%s]", ev.SubjectIDs, testUserID)
	}

	var body PrivacyRequest
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Type != "DELETION" || body.Status != "REQUESTED" {
		t.Errorf("body = %+v", body)
	}
	if body.CompletedAt != nil {
		t.Errorf("completed_at = %v, want null", body.CompletedAt)
	}
}

func TestCreatePrivacyRequestValidationFailure(t *testing.T) {
	tapi := newAPI(t, &fakePrivacy{}, serviceRoleDeps(&recordingSink{}))

	resp := tapi.Post("/privacy/v1/requests", bearer,
		map[string]any{"user_id": "not-a-uuid", "type": "NOPE"})

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
}

func TestListPrivacyRequestsPaginationEnvelope(t *testing.T) {
	sink := &recordingSink{}
	cursor := "Y3Vyc29y"
	var gotParams httpapi.ListParams
	svc := &fakePrivacy{
		listRequests: func(_ context.Context, _ string, f privacy.RequestFilter, lp httpapi.ListParams) (httpapi.Page[privacy.Request], error) {
			gotParams = lp
			if f.Status == nil || *f.Status != privacy.StatusProcessing {
				t.Errorf("status filter = %v, want PROCESSING", f.Status)
			}
			return httpapi.Page[privacy.Request]{
				Items:      []privacy.Request{*sampleRequest()},
				NextCursor: &cursor,
			}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Get("/privacy/v1/requests?limit=5&cursor=abc&sort=-requested_at&status=PROCESSING", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", resp.Code, resp.Body.String())
	}
	if gotParams.Limit != 5 || gotParams.Cursor != "abc" || gotParams.Sort != "-requested_at" {
		t.Errorf("list params = %+v", gotParams)
	}

	var page PrivacyRequestPage
	if err := json.Unmarshal(resp.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(page.Items))
	}
	if page.NextCursor == nil || *page.NextCursor != cursor {
		t.Errorf("next_cursor = %v, want %q", page.NextCursor, cursor)
	}

	// The list read itself is auditable, with the subject manifest (§5.3).
	ev, ok := sink.find(audit.ActionPrivacyRequestListRead)
	if !ok {
		t.Fatalf("missing PRIVACY_REQUEST_LIST_READ, got %v", sink.actions())
	}
	if ev.ResultCount != 1 || len(ev.SubjectIDs) != 1 {
		t.Errorf("audit = %+v", ev)
	}
	if ev.AccessLevel != audit.AccessMasked {
		t.Errorf("access level = %q, want masked", ev.AccessLevel)
	}
}

func TestListPrivacyRequestsEmptyEnvelopeHasNullCursor(t *testing.T) {
	svc := &fakePrivacy{
		listRequests: func(context.Context, string, privacy.RequestFilter, httpapi.ListParams) (httpapi.Page[privacy.Request], error) {
			return httpapi.Page[privacy.Request]{}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(&recordingSink{}))

	resp := tapi.Get("/privacy/v1/requests", bearer)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(resp.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(raw["items"]) != "[]" {
		t.Errorf("items = %s, want []", raw["items"])
	}
	if string(raw["next_cursor"]) != "null" {
		t.Errorf("next_cursor = %s, want null", raw["next_cursor"])
	}
}

func TestCancelPrivacyRequest(t *testing.T) {
	sink := &recordingSink{}
	svc := &fakePrivacy{
		cancelRequest: func(_ context.Context, _, id string) (*privacy.Request, error) {
			r := sampleRequest()
			r.Status = privacy.StatusCanceled
			return r, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Post("/privacy/v1/requests/"+testReqID+"/cancel", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", resp.Code, resp.Body.String())
	}
	if _, ok := sink.find(audit.ActionPrivacyRequestCanceled); !ok {
		t.Errorf("missing PRIVACY_REQUEST_CANCELED, got %v", sink.actions())
	}
}

func TestPrivacyErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
		wantKind string
	}{
		{"not found", privacy.ErrNotFound, http.StatusNotFound, httpapi.CodeNotFound},
		{"conflict", privacy.ErrConflict, http.StatusConflict, httpapi.CodeConflict},
		{"idempotency", privacy.ErrIdempotencyReplay, http.StatusConflict, httpapi.CodeIdempotencyConflict},
		{"legal hold", privacy.ErrLegalHold, http.StatusConflict, httpapi.CodeLegalHoldActive},
		{"policy", privacy.ErrPolicyViolation, http.StatusBadRequest, httpapi.CodePolicyViolation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakePrivacy{
				createRequest: func(context.Context, privacy.CreateRequestInput) (*privacy.Request, error) {
					return nil, tc.err
				},
			}
			tapi := newAPI(t, svc, serviceRoleDeps(&recordingSink{}))
			resp := tapi.Post("/privacy/v1/requests", bearer,
				map[string]any{"user_id": testUserID, "type": "DELETION"})
			if resp.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", resp.Code, tc.wantCode, resp.Body.String())
			}
			p := decodeProblem(t, resp.Body.Bytes())
			if p.Code != tc.wantKind {
				t.Errorf("code = %q, want %q", p.Code, tc.wantKind)
			}
			if !strings.HasPrefix(p.Type, errorTypeBase) {
				t.Errorf("type = %q, want %s prefix", p.Type, errorTypeBase)
			}
		})
	}
}

// ---- consents ----

func TestUpdateUserConsentLowercasesSourceAndAudits(t *testing.T) {
	sink := &recordingSink{}
	var got privacy.ConsentChange
	svc := &fakePrivacy{
		updateConsent: func(_ context.Context, _, _ string, ch privacy.ConsentChange) (*privacy.ConsentState, error) {
			got = ch
			return &privacy.ConsentState{
				Purpose: ch.Purpose, Granted: ch.Granted,
				PolicyVersion: ch.PolicyVersion, UpdatedAt: time.Now().UTC(),
			}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Patch("/privacy/v1/users/"+testUserID+"/consents", bearer, map[string]any{
		"purpose": "marketing", "granted": true, "policy_version": "v1.4", "source": "UI",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", resp.Code, resp.Body.String())
	}
	if got.Source != "ui" {
		t.Errorf("source = %q, want lowercase ui", got.Source)
	}
	ev, ok := sink.find(audit.ActionConsentChanged)
	if !ok {
		t.Fatalf("missing CONSENT_CHANGED, got %v", sink.actions())
	}
	if len(ev.SubjectIDs) != 1 || ev.SubjectIDs[0] != testUserID {
		t.Errorf("subjects = %v", ev.SubjectIDs)
	}
}

func TestGetConsentsRequiresUsersRead(t *testing.T) {
	sink := &recordingSink{}
	// The user token holds an unrelated permission, never users.read.
	d := Deps{
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: "u", Role: "authenticated"}},
		Authz:    fakeAuthorizer{allow: map[string]bool{iam.PermAuditRead: true}},
		Audit:    sink,
	}
	tapi := newAPI(t, &fakePrivacy{}, d)
	resp := tapi.Get("/privacy/v1/users/"+testUserID+"/consents", bearer)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
	if p := decodeProblem(t, resp.Body.Bytes()); !strings.Contains(p.Detail, iam.PermUsersRead) {
		t.Errorf("detail = %q, want it to name %s", p.Detail, iam.PermUsersRead)
	}
}

// ---- destinations / holds ----

func TestDeleteDestinationReturns204(t *testing.T) {
	sink := &recordingSink{}
	called := false
	svc := &fakePrivacy{deleteDest: func(context.Context, string, string) error {
		called = true
		return nil
	}}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	id := "dst_0123456789abcdef0123456789abcdef"
	resp := tapi.Delete("/privacy/v1/destinations/"+id, bearer)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body=%s)", resp.Code, resp.Body.String())
	}
	if !called {
		t.Error("service not called")
	}
	if _, ok := sink.find(audit.ActionDestinationChanged); !ok {
		t.Errorf("missing DESTINATION_CHANGED, got %v", sink.actions())
	}
}

// Destination reads are auditable (DESTINATION_READ, §5.2) but are not
// subject-scoped, so they carry no subject manifest (§5.3).
func TestListDestinationsIsAudited(t *testing.T) {
	sink := &recordingSink{}
	svc := &fakePrivacy{
		listDests: func(context.Context, string, httpapi.ListParams) (httpapi.Page[privacy.Destination], error) {
			return httpapi.Page[privacy.Destination]{Items: []privacy.Destination{
				{ID: "dst_0123456789abcdef0123456789abcdef", Type: privacy.DestinationWebhook, Name: "crm"},
			}}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Get("/privacy/v1/destinations", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	ev, ok := sink.find(audit.ActionDestinationRead)
	if !ok {
		t.Fatalf("missing DESTINATION_READ, got %v", sink.actions())
	}
	if ev.Resource != "destinations" || ev.ResultCount != 1 {
		t.Errorf("audit = %+v", ev)
	}
	if ev.AccessLevel != audit.AccessMasked {
		t.Errorf("access level = %q, want masked", ev.AccessLevel)
	}
	if len(ev.SubjectIDs) != 0 {
		t.Errorf("subject manifest = %v, want empty (destinations are not subject-scoped)", ev.SubjectIDs)
	}
}

func TestGetDestinationIsAudited(t *testing.T) {
	sink := &recordingSink{}
	id := "dst_0123456789abcdef0123456789abcdef"
	svc := &fakePrivacy{
		getDest: func(context.Context, string, string) (*privacy.Destination, error) {
			return &privacy.Destination{ID: id, Type: privacy.DestinationWebhook, Name: "crm", Enabled: true}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Get("/privacy/v1/destinations/"+id, bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	ev, ok := sink.find(audit.ActionDestinationRead)
	if !ok {
		t.Fatalf("missing DESTINATION_READ, got %v", sink.actions())
	}
	if ev.Resource != "destination:"+id || ev.ResultCount != 1 {
		t.Errorf("audit = %+v", ev)
	}
	if len(ev.SubjectIDs) != 0 {
		t.Errorf("subject manifest = %v, want empty", ev.SubjectIDs)
	}
}

func TestMalformedResourceIDIsRejected(t *testing.T) {
	tapi := newAPI(t, &fakePrivacy{}, serviceRoleDeps(&recordingSink{}))
	resp := tapi.Get("/privacy/v1/requests/not-an-id", bearer)
	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (body=%s)", resp.Code, resp.Body.String())
	}
	if p := decodeProblem(t, resp.Body.Bytes()); p.Code != httpapi.CodeValidationFailed {
		t.Errorf("code = %q", p.Code)
	}
}

func TestCreateLegalHoldReturns201WithLocation(t *testing.T) {
	sink := &recordingSink{}
	holdID := "hold_0123456789abcdef0123456789abcdef"
	svc := &fakePrivacy{
		createHold: func(_ context.Context, in privacy.CreateHoldInput) (*privacy.LegalHold, error) {
			if in.CreatedBy == "" {
				t.Error("created_by not propagated from the authenticated actor")
			}
			return &privacy.LegalHold{
				ID: holdID, UserID: in.UserID, Reason: in.Reason,
				Basis: in.Basis, CreatedAt: time.Now().UTC(),
			}, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Post("/privacy/v1/holds", bearer, map[string]any{
		"user_id": testUserID, "reason": "litigation", "basis": "court order",
	})
	if resp.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", resp.Code, resp.Body.String())
	}
	if loc := resp.Header().Get("Location"); loc != "/privacy/v1/holds/"+holdID {
		t.Errorf("Location = %q", loc)
	}
	if _, ok := sink.find(audit.ActionHoldCreated); !ok {
		t.Errorf("missing HOLD_CREATED, got %v", sink.actions())
	}
}

// ---- IAM surface ----

func TestIAMRoutesAreRegisteredAndGuarded(t *testing.T) {
	tapi := newAPI(t, &fakePrivacy{}, Deps{})

	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/iam/v1/roles"},
		{http.MethodPost, "/iam/v1/roles"},
		{http.MethodGet, "/iam/v1/permissions"},
		{http.MethodGet, "/iam/v1/api-keys"},
		{http.MethodPost, "/iam/v1/api-keys"},
	} {
		resp := tapi.Do(route.method, route.path, bearer)
		// No verifier configured: the credential cannot be validated at all.
		if resp.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401", route.method, route.path, resp.Code)
		}
	}
}

func TestIAMHandlersReportMissingPool(t *testing.T) {
	sink := &recordingSink{}
	tapi := newAPI(t, &fakePrivacy{}, serviceRoleDeps(sink))

	resp := tapi.Get("/iam/v1/roles", bearer)
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body=%s)", resp.Code, resp.Body.String())
	}
	p := decodeProblem(t, resp.Body.Bytes())
	if p.Code != httpapi.CodeInternal {
		t.Errorf("code = %q, want internal", p.Code)
	}
	if strings.Contains(strings.ToLower(p.Detail), "pool") {
		t.Errorf("detail leaks internals: %q", p.Detail)
	}
}

// ---- OpenAPI document ----

func TestOpenAPIDocumentShape(t *testing.T) {
	_, tapi := humatest.New(t, NewConfig())
	RegisterPrivacyAPI(tapi, StaticService(&fakePrivacy{}), Deps{})
	RegisterIAMAPI(tapi, Deps{})

	doc := tapi.OpenAPI()
	if doc.Info.Title != APITitle || doc.Info.Version != APIVersion {
		t.Errorf("info = %+v", doc.Info)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].URL != DefaultURL {
		t.Errorf("servers = %+v", doc.Servers)
	}

	wantOps := map[string]string{
		"createPrivacyRequest":  "/privacy/v1/requests",
		"listPrivacyRequests":   "/privacy/v1/requests",
		"getPrivacyRequest":     "/privacy/v1/requests/{requestId}",
		"cancelPrivacyRequest":  "/privacy/v1/requests/{requestId}/cancel",
		"listUserConsents":      "/privacy/v1/users/{userId}/consents",
		"updateUserConsent":     "/privacy/v1/users/{userId}/consents",
		"createDestination":     "/privacy/v1/destinations",
		"deleteDestination":     "/privacy/v1/destinations/{destinationId}",
		"createLegalHold":       "/privacy/v1/holds",
		"releaseLegalHold":      "/privacy/v1/holds/{holdId}/release",
		"listRoles":             "/iam/v1/roles",
		"createRoleAssignment":  "/iam/v1/roles/{roleId}/assignments",
		"revokeRoleAssignment":  "/iam/v1/assignments/{assignmentId}",
		"createPermission":      "/iam/v1/permissions",
		"listPermissionHolders": "/iam/v1/permissions/{permissionName}/holders",
		"createApiKey":          "/iam/v1/api-keys",
		"revokeApiKey":          "/iam/v1/api-keys/{keyId}",
	}
	found := map[string]string{}
	for path, item := range doc.Paths {
		for _, op := range operationsOf(item) {
			if op == nil {
				continue
			}
			found[op.OperationID] = path
		}
	}
	for id, path := range wantOps {
		got, ok := found[id]
		if !ok {
			t.Errorf("operation %s not registered", id)
			continue
		}
		if got != path {
			t.Errorf("operation %s at %s, want %s", id, got, path)
		}
	}

	// Every operation must declare the bearer security scheme and problem
	// responses.
	for path, item := range doc.Paths {
		for _, op := range operationsOf(item) {
			if op == nil {
				continue
			}
			if len(op.Security) == 0 {
				t.Errorf("%s %s: no security requirement", op.Method, path)
			}
			if _, ok := op.Responses["401"]; !ok {
				t.Errorf("%s %s: no 401 response documented", op.Method, path)
			}
		}
	}

	if _, ok := doc.Components.Schemas.Map()["PrivacyRequestPage"]; !ok {
		t.Error("PrivacyRequestPage schema missing")
	}
	if _, ok := doc.Components.Schemas.Map()["CreatePrivacyRequestBody"]; !ok {
		t.Error("CreatePrivacyRequestBody schema missing")
	}
	if _, ok := doc.Components.SecuritySchemes[securitySchemeName]; !ok {
		t.Error("bearerAuth security scheme missing")
	}
}

// ---- unit helpers ----

func TestBearerToken(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER  abc ", "abc", true},
		{"Basic abc", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := bearerToken(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("bearerToken(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestClientIP(t *testing.T) {
	if got := clientIP("10.0.0.1:5555", ""); got != "10.0.0.1" {
		t.Errorf("clientIP = %q", got)
	}
	if got := clientIP("10.0.0.1:5555", "203.0.113.7, 10.0.0.1"); got != "203.0.113.7" {
		t.Errorf("clientIP(xff) = %q", got)
	}
}

func TestDefaultCodeMapping(t *testing.T) {
	cases := map[int]string{
		http.StatusUnauthorized:        httpapi.CodeUnauthenticated,
		http.StatusForbidden:           httpapi.CodePermissionDenied,
		http.StatusNotFound:            httpapi.CodeNotFound,
		http.StatusConflict:            httpapi.CodeConflict,
		http.StatusUnprocessableEntity: httpapi.CodeValidationFailed,
		http.StatusTooManyRequests:     httpapi.CodeRateLimited,
		http.StatusInternalServerError: httpapi.CodeInternal,
	}
	for status, want := range cases {
		if got := defaultCode(status); got != want {
			t.Errorf("defaultCode(%d) = %q, want %q", status, got, want)
		}
	}
}

func operationsOf(item *huma.PathItem) []*huma.Operation {
	return []*huma.Operation{
		item.Get, item.Post, item.Put, item.Patch, item.Delete,
		item.Head, item.Options, item.Trace,
	}
}

func TestScopesAllow(t *testing.T) {
	key := ports.Actor{ID: "key_1", Type: iam.ActorTypeAPIKey}
	admin := ports.Actor{ID: "admin_1", Type: iam.ActorTypeAdmin}

	if !scopesAllow(key, []string{iam.PermUsersRead, iam.PermPIIRead}, iam.PermPIIRead) {
		t.Error("in-scope permission should be allowed")
	}
	if scopesAllow(key, []string{iam.PermUsersRead}, iam.PermPIIReveal) {
		t.Error("out-of-scope permission must be denied for API keys")
	}
	if scopesAllow(key, nil, iam.PermUsersRead) {
		t.Error("a key with no scopes must be denied")
	}
	if !scopesAllow(admin, nil, iam.PermUsersRead) {
		t.Error("non-key actors are decided by the Authorizer, not scopes")
	}
}
