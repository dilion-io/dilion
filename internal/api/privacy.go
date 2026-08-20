package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/privacy"
)

// ServiceProvider resolves the compliance service for a request. In a
// multi-instance deployment it returns the engine of the instance selected on
// the context (instances.Registry.PrivacyService); single-instance deployments
// use StaticService. A nil provider (spec generation) yields a 500 at call
// time and never at registration time.
type ServiceProvider func(context.Context) (privacy.Service, error)

// StaticService is the single-instance ServiceProvider over one fixed engine.
func StaticService(svc privacy.Service) ServiceProvider {
	return func(context.Context) (privacy.Service, error) { return svc, nil }
}

// registrar holds everything the handlers need. Constructing it never touches
// the database, so spec generation works with a zero-value Deps.
type registrar struct {
	api    huma.API
	d      Deps
	keys   *iam.Service
	events *audit.Reader
	svcs   ServiceProvider
}

// newRegistrar wires the read-side services. Constructing them performs no I/O,
// so a zero Deps (nil pool) is enough to describe every route.
func newRegistrar(api huma.API, d Deps, svcs ServiceProvider) *registrar {
	pools := d.pools()
	return &registrar{
		api:    api,
		d:      d,
		keys:   iam.NewFor(iam.PoolFunc(pools)),
		events: audit.NewReaderFor(audit.PoolFunc(pools)),
		svcs:   svcs,
	}
}

// privacy resolves the compliance service for this request's instance.
func (r *registrar) privacy(ctx context.Context) (privacy.Service, error) {
	if r.svcs == nil {
		return nil, NewProblem(http.StatusInternalServerError, httpapi.CodeInternal,
			"privacy engine is not configured")
	}
	svc, err := r.svcs(ctx)
	if err != nil {
		return nil, mapPrivacyError(ctx, err)
	}
	if svc == nil {
		return nil, NewProblem(http.StatusInternalServerError, httpapi.CodeInternal,
			"privacy engine is not configured")
	}
	return svc, nil
}

// ---- DTOs (schema names follow docs/api-conventions.md) ----

// PrivacyRequest is a data subject request (DSR).
type PrivacyRequest struct {
	ID          string     `json:"id" example:"pr_1f0c0b6a7d5e4a2b9c8d7e6f5a4b3c2d" doc:"Request identifier."`
	UserID      string     `json:"user_id" format:"uuid" doc:"Canonical user id of the data subject."`
	Type        string     `json:"type" enum:"DELETION,EXPORT,CONSENT_WITHDRAWAL" doc:"Request type."`
	Status      string     `json:"status" enum:"REQUESTED,PROCESSING,DONE,MANUAL_REVIEW,CANCELED" doc:"Lifecycle status."`
	PolicyID    string     `json:"policy_id" doc:"Compliance policy snapshot applied to this request."`
	ScheduledAt time.Time  `json:"scheduled_at" doc:"When the erasure pipeline is due to run (grace deadline)."`
	RequestedAt time.Time  `json:"requested_at" doc:"When the request was accepted."`
	CompletedAt *time.Time `json:"completed_at" nullable:"true" doc:"When processing finished, or null."`
}

// CreatePrivacyRequestBody is the POST /privacy/v1/requests payload.
type CreatePrivacyRequestBody struct {
	UserID    string `json:"user_id" format:"uuid" doc:"Canonical user id of the data subject."`
	Type      string `json:"type" enum:"DELETION,EXPORT,CONSENT_WITHDRAWAL" doc:"Request type."`
	Immediate *bool  `json:"immediate,omitempty" doc:"Skip the grace period and schedule erasure immediately."`
}

// PrivacyRequestPage is the cursor-paginated list envelope.
type PrivacyRequestPage struct {
	Items      []PrivacyRequest `json:"items" nullable:"false"`
	NextCursor *string          `json:"next_cursor" nullable:"true" doc:"Opaque cursor for the next page, or null."`
}

// ConsentState is the current projection of the consent ledger for one purpose.
type ConsentState struct {
	Purpose       string     `json:"purpose" doc:"Consent purpose key."`
	Granted       bool       `json:"granted" doc:"Whether consent is currently granted."`
	PolicyVersion string     `json:"policy_version" doc:"Policy version the consent was recorded against."`
	UpdatedAt     time.Time  `json:"updated_at"`
	ReconfirmDue  *time.Time `json:"reconfirm_due" nullable:"true" doc:"When re-confirmation notice is due, or null."`
}

// ConsentStatePage is the consent list envelope. Consents are not paginated
// today; next_cursor is always null.
type ConsentStatePage struct {
	Items      []ConsentState `json:"items" nullable:"false"`
	NextCursor *string        `json:"next_cursor" nullable:"true" doc:"Always null: consent state is returned in full."`
}

// UpdateConsentBody appends one entry to the consent ledger.
type UpdateConsentBody struct {
	Purpose       string `json:"purpose" minLength:"1" doc:"Consent purpose key."`
	Granted       bool   `json:"granted" doc:"true = grant, false = withdraw."`
	PolicyVersion string `json:"policy_version" minLength:"1" doc:"Policy version presented to the subject."`
	Source        string `json:"source" enum:"UI,API,IMPORT" default:"API" doc:"Where the change originated."`
}

// Destination is a downstream system that receives erasure instructions.
type Destination struct {
	ID      string         `json:"id" example:"dst_1f0c0b6a7d5e4a2b9c8d7e6f5a4b3c2d"`
	Type    string         `json:"type" enum:"WEBHOOK,CONNECTOR"`
	Name    string         `json:"name"`
	Config  map[string]any `json:"config" doc:"Type specific configuration. Secrets are never returned."`
	Enabled bool           `json:"enabled"`
}

type CreateDestinationBody struct {
	Type   string         `json:"type" enum:"WEBHOOK,CONNECTOR"`
	Name   string         `json:"name" minLength:"1"`
	Config map[string]any `json:"config" doc:"Webhook: {url, identity_field}."`
	Secret *string        `json:"secret,omitempty" doc:"Webhook HMAC secret. Write-only, never returned."`
}

type UpdateDestinationBody struct {
	Enabled *bool          `json:"enabled,omitempty"`
	Config  map[string]any `json:"config,omitempty"`
}

type DestinationPage struct {
	Items      []Destination `json:"items" nullable:"false"`
	NextCursor *string       `json:"next_cursor" nullable:"true"`
}

// LegalHold blocks erasure for a subject (or one domain of a subject).
type LegalHold struct {
	ID         string     `json:"id" example:"hold_1f0c0b6a7d5e4a2b9c8d7e6f5a4b3c2d"`
	UserID     string     `json:"user_id" format:"uuid"`
	Domain     *string    `json:"domain" nullable:"true" doc:"Data domain held, or null for the whole subject."`
	Reason     string     `json:"reason"`
	Basis      string     `json:"basis" doc:"Legal basis for the hold."`
	CreatedAt  time.Time  `json:"created_at"`
	ReleasedAt *time.Time `json:"released_at" nullable:"true"`
}

type CreateLegalHoldBody struct {
	UserID string  `json:"user_id" format:"uuid"`
	Domain *string `json:"domain,omitempty" doc:"Data domain to hold. Omit to hold the whole subject."`
	Reason string  `json:"reason" minLength:"1"`
	Basis  string  `json:"basis" minLength:"1"`
}

type LegalHoldPage struct {
	Items      []LegalHold `json:"items" nullable:"false"`
	NextCursor *string     `json:"next_cursor" nullable:"true"`
}

// ---- conversions ----

func toPrivacyRequest(in privacy.Request) PrivacyRequest {
	return PrivacyRequest{
		ID:          in.ID,
		UserID:      in.UserID,
		Type:        string(in.Type),
		Status:      string(in.Status),
		PolicyID:    in.PolicyID,
		ScheduledAt: in.ScheduledAt,
		RequestedAt: in.RequestedAt,
		CompletedAt: in.CompletedAt,
	}
}

func toConsentState(in privacy.ConsentState) ConsentState {
	return ConsentState{
		Purpose:       in.Purpose,
		Granted:       in.Granted,
		PolicyVersion: in.PolicyVersion,
		UpdatedAt:     in.UpdatedAt,
		ReconfirmDue:  in.ReconfirmDue,
	}
}

func toDestination(in privacy.Destination) Destination {
	return Destination{
		ID:      in.ID,
		Type:    string(in.Type),
		Name:    in.Name,
		Config:  in.Config,
		Enabled: in.Enabled,
	}
}

func toLegalHold(in privacy.LegalHold) LegalHold {
	return LegalHold{
		ID:         in.ID,
		UserID:     in.UserID,
		Domain:     in.Domain,
		Reason:     in.Reason,
		Basis:      in.Basis,
		CreatedAt:  in.CreatedAt,
		ReleasedAt: in.ReleasedAt,
	}
}

func mapItems[T any, U any](in []T, f func(T) U) []U {
	out := make([]U, 0, len(in))
	for _, v := range in {
		out = append(out, f(v))
	}
	return out
}

func subjectsOf[T any](items []T, id func(T) string) []string {
	out := make([]string, 0, len(items))
	for _, v := range items {
		out = append(out, id(v))
	}
	return out
}

// ---- inputs / outputs ----

type createPrivacyRequestInput struct {
	IdempotencyKey string `header:"Idempotency-Key" required:"false" doc:"Retry-safe key: replaying the same key returns the original response."`
	Body           CreatePrivacyRequestBody
}

type privacyRequestOutput struct {
	Location string `header:"Location"`
	Body     PrivacyRequest
}

type privacyRequestBodyOutput struct {
	Body PrivacyRequest
}

type listPrivacyRequestsInput struct {
	Limit  int    `query:"limit" default:"20" minimum:"1" maximum:"100" doc:"Page size."`
	Cursor string `query:"cursor" doc:"Opaque cursor from a previous response."`
	Sort   string `query:"sort" enum:"requested_at,-requested_at,scheduled_at,-scheduled_at" doc:"Sort field; prefix with - for descending."`
	Status string `query:"status" enum:"REQUESTED,PROCESSING,DONE,MANUAL_REVIEW,CANCELED" doc:"Filter by status."`
}

type privacyRequestPageOutput struct {
	Body PrivacyRequestPage
}

type getPrivacyRequestInput struct {
	RequestID string `path:"requestId" pattern:"^pr_[0-9a-f]{32}$"`
}

type userConsentsInput struct {
	UserID string `path:"userId" format:"uuid"`
}

type updateUserConsentInput struct {
	UserID string `path:"userId" format:"uuid"`
	Body   UpdateConsentBody
}

type consentStatePageOutput struct {
	Body ConsentStatePage
}

type consentStateOutput struct {
	Body ConsentState
}

type createDestinationInput struct {
	Body CreateDestinationBody
}

type destinationOutput struct {
	Location string `header:"Location"`
	Body     Destination
}

type destinationBodyOutput struct {
	Body Destination
}

type listDestinationsInput struct {
	Limit  int    `query:"limit" default:"20" minimum:"1" maximum:"100"`
	Cursor string `query:"cursor"`
}

type destinationPageOutput struct {
	Body DestinationPage
}

type destinationIDInput struct {
	DestinationID string `path:"destinationId" pattern:"^dst_[0-9a-f]{32}$"`
}

type updateDestinationInput struct {
	DestinationID string `path:"destinationId" pattern:"^dst_[0-9a-f]{32}$"`
	Body          UpdateDestinationBody
}

type createLegalHoldInput struct {
	Body CreateLegalHoldBody
}

type legalHoldOutput struct {
	Location string `header:"Location"`
	Body     LegalHold
}

type legalHoldBodyOutput struct {
	Body LegalHold
}

type listLegalHoldsInput struct {
	Limit  int    `query:"limit" default:"20" minimum:"1" maximum:"100"`
	Cursor string `query:"cursor"`
	UserID string `query:"user_id" format:"uuid" doc:"Filter by data subject."`
}

type legalHoldPageOutput struct {
	Body LegalHoldPage
}

type releaseLegalHoldInput struct {
	HoldID string `path:"holdId" pattern:"^hold_[0-9a-f]{32}$"`
}

// ---- registration ----

// RegisterPrivacyAPI mounts /privacy/v1 on the given huma API. svcs resolves
// the compliance service per request (see ServiceProvider), which is what makes
// one mounted API serve several instances. Registration performs no I/O and
// never dereferences Deps or svcs, so it is safe to call with a zero Deps and a
// nil provider to generate the OpenAPI document.
func RegisterPrivacyAPI(api huma.API, svcs ServiceProvider, d Deps) {
	installErrorModel()
	r := newRegistrar(api, d, svcs)
	r.registerRequests()
	r.registerConsents()
	r.registerProfiles()
	r.registerDestinations()
	r.registerHolds()
}

func (r *registrar) op(id, method, path, summary, perm string, tag string, status int) huma.Operation {
	return huma.Operation{
		OperationID:   id,
		Method:        method,
		Path:          path,
		Summary:       summary,
		Description:   "Requires permission `" + perm + "`.",
		Tags:          []string{tag},
		DefaultStatus: status,
		Errors:        errorStatuses,
		Security:      []map[string][]string{{securitySchemeName: {}}},
		Middlewares:   r.guardFor(perm),
	}
}

func (r *registrar) registerRequests() {
	const perm = iam.PermPrivacyRequestsManage

	huma.Register(r.api, r.op("createPrivacyRequest", http.MethodPost, "/privacy/v1/requests",
		"Create a privacy request", perm, "privacy", http.StatusAccepted),
		func(ctx context.Context, in *createPrivacyRequestInput) (*privacyRequestOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			out, err := svc.CreateRequest(ctx, privacy.CreateRequestInput{
				UserID:         in.Body.UserID,
				Type:           privacy.RequestType(in.Body.Type),
				Immediate:      in.Body.Immediate != nil && *in.Body.Immediate,
				IdempotencyKey: in.IdempotencyKey,
				RequestedBy:    requestInfoFrom(ctx).Actor.ID,
			})
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionPrivacyRequestCreated,
				Resource:    "privacy_request:" + out.ID,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
				SubjectIDs:  []string{out.UserID},
			})
			return &privacyRequestOutput{
				Location: "/privacy/v1/requests/" + out.ID,
				Body:     toPrivacyRequest(*out),
			}, nil
		})

	huma.Register(r.api, r.op("listPrivacyRequests", http.MethodGet, "/privacy/v1/requests",
		"List privacy requests", perm, "privacy", http.StatusOK),
		func(ctx context.Context, in *listPrivacyRequestsInput) (*privacyRequestPageOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			var status *privacy.RequestStatus
			if in.Status != "" {
				s := privacy.RequestStatus(in.Status)
				status = &s
			}
			page, err := svc.ListRequests(ctx, status, listParams(in.Limit, in.Cursor, in.Sort))
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			items := mapItems(page.Items, toPrivacyRequest)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionPrivacyRequestListRead,
				Resource:    "privacy_requests",
				AccessLevel: audit.AccessMasked,
				ResultCount: len(items),
				SubjectIDs:  subjectsOf(items, func(p PrivacyRequest) string { return p.UserID }),
			})
			return &privacyRequestPageOutput{Body: PrivacyRequestPage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})

	huma.Register(r.api, r.op("getPrivacyRequest", http.MethodGet, "/privacy/v1/requests/{requestId}",
		"Get a privacy request", perm, "privacy", http.StatusOK),
		func(ctx context.Context, in *getPrivacyRequestInput) (*privacyRequestBodyOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			out, err := svc.GetRequest(ctx, in.RequestID)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionPrivacyRequestDetailRead,
				Resource:    "privacy_request:" + out.ID,
				AccessLevel: audit.AccessMasked,
				ResultCount: 1,
				SubjectIDs:  []string{out.UserID},
			})
			return &privacyRequestBodyOutput{Body: toPrivacyRequest(*out)}, nil
		})

	huma.Register(r.api, r.op("cancelPrivacyRequest", http.MethodPost, "/privacy/v1/requests/{requestId}/cancel",
		"Cancel a privacy request", perm, "privacy", http.StatusOK),
		func(ctx context.Context, in *getPrivacyRequestInput) (*privacyRequestBodyOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			out, err := svc.CancelRequest(ctx, in.RequestID)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionPrivacyRequestCanceled,
				Resource:    "privacy_request:" + out.ID,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
				SubjectIDs:  []string{out.UserID},
			})
			return &privacyRequestBodyOutput{Body: toPrivacyRequest(*out)}, nil
		})
}

func (r *registrar) registerConsents() {
	huma.Register(r.api, r.op("listUserConsents", http.MethodGet, "/privacy/v1/users/{userId}/consents",
		"List a user's consent state", iam.PermUsersRead, "privacy", http.StatusOK),
		func(ctx context.Context, in *userConsentsInput) (*consentStatePageOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			states, err := svc.GetConsents(ctx, in.UserID)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			items := mapItems(states, toConsentState)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionConsentRead,
				Resource:    "consents",
				AccessLevel: audit.AccessMasked,
				ResultCount: len(items),
				SubjectIDs:  []string{in.UserID},
			})
			return &consentStatePageOutput{Body: ConsentStatePage{Items: items}}, nil
		})

	huma.Register(r.api, r.op("updateUserConsent", http.MethodPatch, "/privacy/v1/users/{userId}/consents",
		"Record a consent change", iam.PermPrivacyRequestsManage, "privacy", http.StatusOK),
		func(ctx context.Context, in *updateUserConsentInput) (*consentStateOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			source := in.Body.Source
			if source == "" {
				source = "API"
			}
			out, err := svc.UpdateConsent(ctx, in.UserID, privacy.ConsentChange{
				Purpose:       in.Body.Purpose,
				Granted:       in.Body.Granted,
				PolicyVersion: in.Body.PolicyVersion,
				// The engine contract uses lowercase source values.
				Source: strings.ToLower(source),
			})
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionConsentChanged,
				Resource:    "consent:" + in.Body.Purpose,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
				SubjectIDs:  []string{in.UserID},
			})
			return &consentStateOutput{Body: toConsentState(*out)}, nil
		})
}

func (r *registrar) registerDestinations() {
	const perm = iam.PermDestinationsManage

	huma.Register(r.api, r.op("createDestination", http.MethodPost, "/privacy/v1/destinations",
		"Create a destination", perm, "privacy", http.StatusCreated),
		func(ctx context.Context, in *createDestinationInput) (*destinationOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			secret := ""
			if in.Body.Secret != nil {
				secret = *in.Body.Secret
			}
			out, err := svc.CreateDestination(ctx, privacy.CreateDestinationInput{
				Type:   privacy.DestinationType(in.Body.Type),
				Name:   in.Body.Name,
				Config: in.Body.Config,
				Secret: secret,
			})
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionDestinationChanged,
				Resource:    "destination:" + out.ID,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
			})
			return &destinationOutput{
				Location: "/privacy/v1/destinations/" + out.ID,
				Body:     toDestination(*out),
			}, nil
		})

	huma.Register(r.api, r.op("listDestinations", http.MethodGet, "/privacy/v1/destinations",
		"List destinations", perm, "privacy", http.StatusOK),
		func(ctx context.Context, in *listDestinationsInput) (*destinationPageOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			page, err := svc.ListDestinations(ctx, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			items := mapItems(page.Items, toDestination)
			// Destinations are configuration, not subject-scoped records: no
			// subject manifest (§5.3) is recorded for them.
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionDestinationRead,
				Resource:    "destinations",
				AccessLevel: audit.AccessMasked,
				ResultCount: len(items),
			})
			return &destinationPageOutput{Body: DestinationPage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})

	huma.Register(r.api, r.op("getDestination", http.MethodGet, "/privacy/v1/destinations/{destinationId}",
		"Get a destination", perm, "privacy", http.StatusOK),
		func(ctx context.Context, in *destinationIDInput) (*destinationBodyOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			out, err := svc.GetDestination(ctx, in.DestinationID)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			// Not subject-scoped: no subject manifest (§5.3).
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionDestinationRead,
				Resource:    "destination:" + out.ID,
				AccessLevel: audit.AccessMasked,
				ResultCount: 1,
			})
			return &destinationBodyOutput{Body: toDestination(*out)}, nil
		})

	huma.Register(r.api, r.op("updateDestination", http.MethodPatch, "/privacy/v1/destinations/{destinationId}",
		"Update a destination", perm, "privacy", http.StatusOK),
		func(ctx context.Context, in *updateDestinationInput) (*destinationBodyOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			out, err := svc.UpdateDestination(ctx, in.DestinationID, in.Body.Enabled, in.Body.Config)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionDestinationChanged,
				Resource:    "destination:" + out.ID,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
			})
			return &destinationBodyOutput{Body: toDestination(*out)}, nil
		})

	huma.Register(r.api, r.op("deleteDestination", http.MethodDelete, "/privacy/v1/destinations/{destinationId}",
		"Delete a destination", perm, "privacy", http.StatusNoContent),
		func(ctx context.Context, in *destinationIDInput) (*struct{}, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			if err := svc.DeleteDestination(ctx, in.DestinationID); err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionDestinationChanged,
				Resource:    "destination:" + in.DestinationID,
				AccessLevel: audit.AccessNA,
			})
			return nil, nil
		})
}

func (r *registrar) registerHolds() {
	const perm = iam.PermHoldsManage

	huma.Register(r.api, r.op("createLegalHold", http.MethodPost, "/privacy/v1/holds",
		"Create a legal hold", perm, "privacy", http.StatusCreated),
		func(ctx context.Context, in *createLegalHoldInput) (*legalHoldOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			out, err := svc.CreateHold(ctx, privacy.CreateHoldInput{
				UserID:    in.Body.UserID,
				Domain:    in.Body.Domain,
				Reason:    in.Body.Reason,
				Basis:     in.Body.Basis,
				CreatedBy: requestInfoFrom(ctx).Actor.ID,
			})
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionHoldCreated,
				Resource:    "legal_hold:" + out.ID,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
				SubjectIDs:  []string{out.UserID},
			})
			return &legalHoldOutput{
				Location: "/privacy/v1/holds/" + out.ID,
				Body:     toLegalHold(*out),
			}, nil
		})

	huma.Register(r.api, r.op("listLegalHolds", http.MethodGet, "/privacy/v1/holds",
		"List legal holds", perm, "privacy", http.StatusOK),
		func(ctx context.Context, in *listLegalHoldsInput) (*legalHoldPageOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			var userID *string
			if in.UserID != "" {
				userID = &in.UserID
			}
			page, err := svc.ListHolds(ctx, userID, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			items := mapItems(page.Items, toLegalHold)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionHoldListRead,
				Resource:    "legal_holds",
				AccessLevel: audit.AccessMasked,
				ResultCount: len(items),
				SubjectIDs:  subjectsOf(items, func(h LegalHold) string { return h.UserID }),
			})
			return &legalHoldPageOutput{Body: LegalHoldPage{Items: items, NextCursor: page.NextCursor}}, nil
		})

	huma.Register(r.api, r.op("releaseLegalHold", http.MethodPost, "/privacy/v1/holds/{holdId}/release",
		"Release a legal hold", perm, "privacy", http.StatusOK),
		func(ctx context.Context, in *releaseLegalHoldInput) (*legalHoldBodyOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			out, err := svc.ReleaseHold(ctx, in.HoldID, requestInfoFrom(ctx).Actor.ID)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionHoldReleased,
				Resource:    "legal_hold:" + out.ID,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
				SubjectIDs:  []string{out.UserID},
			})
			return &legalHoldBodyOutput{Body: toLegalHold(*out)}, nil
		})
}
