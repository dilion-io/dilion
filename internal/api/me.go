package api

// Self-service surface (/privacy/v1/me/*, docs/use-cases.md 제안 P2).
//
// §2.11 separates two planes: the management plane (RBAC, deny-by-default) and
// the end-user's own resources, where ownership *is* the authority
// (sub == user_id). These operations implement the second plane: any valid
// `role=authenticated` access token may act, but only ever on the subject the
// token names. No RBAC role is consulted and none is required — which is
// exactly why API keys and service_role tokens are rejected here: they carry
// no subject identity to scope the request to (they use the admin surface).
//
// Every operation still lands in the audit log with the subject manifest, so
// "누가 이 요청을 만들었나"는 self-service에서도 추적된다.

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-project/dilion/httpapi"
	"github.com/dilion-project/dilion/internal/audit"
	"github.com/dilion-project/dilion/internal/iam"
	"github.com/dilion-project/dilion/internal/privacy"
)

// ---- DTOs ----

// CreateMeRequestBody is the self-service DSR payload: the subject comes from
// the token, never from the body.
type CreateMeRequestBody struct {
	Type      string `json:"type" enum:"DELETION,EXPORT,CONSENT_WITHDRAWAL" doc:"Request type."`
	Immediate *bool  `json:"immediate,omitempty" doc:"Skip the grace period (즉시 파기 요청, §2.9)."`
}

// UpdateMeConsentBody appends one ledger entry for the token's subject. Source
// is fixed to UI: a self-service change is by definition the subject acting.
type UpdateMeConsentBody struct {
	Purpose       string `json:"purpose" minLength:"1" doc:"Consent purpose key."`
	Granted       bool   `json:"granted" doc:"true = grant, false = withdraw."`
	PolicyVersion string `json:"policy_version" minLength:"1" doc:"Policy version presented to the subject."`
}

// ---- inputs / outputs ----

type createMeRequestInput struct {
	IdempotencyKey string `header:"Idempotency-Key" required:"false" doc:"Retry-safe key: replaying the same key returns the original response."`
	Body           CreateMeRequestBody
}

type listMeRequestsInput struct {
	Limit  int    `query:"limit" default:"20" minimum:"1" maximum:"100" doc:"Page size."`
	Cursor string `query:"cursor" doc:"Opaque cursor from a previous response."`
	Status string `query:"status" enum:"REQUESTED,PROCESSING,DONE,MANUAL_REVIEW,CANCELED" doc:"Filter by status."`
}

type meRequestIDInput struct {
	RequestID string `path:"requestId" pattern:"^pr_[0-9a-f]{32}$"`
}

type updateMeConsentInput struct {
	Body UpdateMeConsentBody
}

// ---- guard ----

// selfGuard authenticates an end-user access token and nothing else. There is
// no permission parameter: the handler scopes every call to the token subject.
func (r *registrar) selfGuard() huma.Middlewares {
	return huma.Middlewares{func(ctx huma.Context, next func(huma.Context)) {
		ri := &requestInfo{
			RequestID: firstNonEmpty(ctx.Header("X-Request-Id"), httpapi.NewID("req")),
			IP:        clientIP(ctx.RemoteAddr(), ctx.Header("X-Forwarded-For")),
			UserAgent: ctx.Header("User-Agent"),
		}
		token, ok := bearerToken(ctx.Header("Authorization"))
		if !ok {
			ctx.SetHeader("WWW-Authenticate", `Bearer realm="dilion"`)
			huma.WriteErr(r.api, ctx, http.StatusUnauthorized, "missing bearer credentials")
			return
		}
		if strings.HasPrefix(token, iam.TokenPrefix) {
			// An API key names no data subject; nothing here could be scoped.
			huma.WriteErr(r.api, ctx, http.StatusForbidden,
				"the self-service surface requires an end-user access token; "+
					"use the admin surface with an API key")
			return
		}
		if r.d.Verifier == nil {
			ctx.SetHeader("WWW-Authenticate", `Bearer realm="dilion"`)
			huma.WriteErr(r.api, ctx, http.StatusUnauthorized, "invalid bearer credentials")
			return
		}
		claims, err := r.d.Verifier.Verify(ctx.Context(), token)
		if err != nil || claims == nil {
			ctx.SetHeader("WWW-Authenticate", `Bearer realm="dilion"`)
			huma.WriteErr(r.api, ctx, http.StatusUnauthorized, "invalid bearer credentials")
			return
		}
		if claims.Role != iam.RoleAuthenticated || claims.Subject == "" {
			huma.WriteErr(r.api, ctx, http.StatusForbidden,
				"the self-service surface requires a `role=authenticated` access token "+
					"naming a subject")
			return
		}
		ri.Actor.ID = claims.Subject
		ri.Actor.Type = iam.ActorTypeUser
		ri.Actor.ProjectID = iam.DefaultProjectID
		next(huma.WithValue(ctx, ctxKey{}, ri))
	}}
}

// selfOp mirrors registrar.op for the ownership-authorized surface.
func (r *registrar) selfOp(id, method, path, summary string, status int) huma.Operation {
	return huma.Operation{
		OperationID: id,
		Method:      method,
		Path:        path,
		Summary:     summary,
		Description: "Self-service: requires a `role=authenticated` end-user access token and acts " +
			"only on that token's subject. No RBAC role is required (ownership is the authority, §2.11).",
		Tags:          []string{"me"},
		DefaultStatus: status,
		Errors:        errorStatuses,
		Security:      []map[string][]string{{securitySchemeName: {}}},
		Middlewares:   r.selfGuard(),
	}
}

// ---- registration ----

func (r *registrar) registerMe() {
	huma.Register(r.api, r.selfOp("createMePrivacyRequest", http.MethodPost, "/privacy/v1/me/requests",
		"Create my privacy request", http.StatusAccepted),
		func(ctx context.Context, in *createMeRequestInput) (*privacyRequestOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			sub := requestInfoFrom(ctx).Actor.ID
			out, err := svc.CreateRequest(ctx, privacy.CreateRequestInput{
				ProjectID:      projectOf(ctx),
				UserID:         sub,
				Type:           privacy.RequestType(in.Body.Type),
				Immediate:      in.Body.Immediate != nil && *in.Body.Immediate,
				IdempotencyKey: in.IdempotencyKey,
				RequestedBy:    sub,
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

	huma.Register(r.api, r.selfOp("listMePrivacyRequests", http.MethodGet, "/privacy/v1/me/requests",
		"List my privacy requests", http.StatusOK),
		func(ctx context.Context, in *listMeRequestsInput) (*privacyRequestPageOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			sub := requestInfoFrom(ctx).Actor.ID
			f := privacy.RequestFilter{UserID: &sub}
			if in.Status != "" {
				s := privacy.RequestStatus(in.Status)
				f.Status = &s
			}
			page, err := svc.ListRequests(ctx, projectOf(ctx), f, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			items := mapItems(page.Items, toPrivacyRequest)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionPrivacyRequestListRead,
				Resource:    "privacy_requests:me",
				AccessLevel: audit.AccessMasked,
				ResultCount: len(items),
				SubjectIDs:  []string{sub},
			})
			return &privacyRequestPageOutput{Body: PrivacyRequestPage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})

	huma.Register(r.api, r.selfOp("cancelMePrivacyRequest", http.MethodPost, "/privacy/v1/me/requests/{requestId}/cancel",
		"Cancel my privacy request", http.StatusOK),
		func(ctx context.Context, in *meRequestIDInput) (*privacyRequestBodyOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			sub := requestInfoFrom(ctx).Actor.ID
			// Ownership gate: another subject's request is indistinguishable
			// from a missing one (api-conventions: 존재 노출 방지).
			existing, err := svc.GetRequest(ctx, projectOf(ctx), in.RequestID)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			if existing.UserID != sub {
				return nil, NewProblem(http.StatusNotFound, httpapi.CodeNotFound, "resource not found")
			}
			out, err := svc.CancelRequest(ctx, projectOf(ctx), in.RequestID)
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

	huma.Register(r.api, r.selfOp("listMeConsents", http.MethodGet, "/privacy/v1/me/consents",
		"List my consent state", http.StatusOK),
		func(ctx context.Context, _ *struct{}) (*consentStatePageOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			sub := requestInfoFrom(ctx).Actor.ID
			states, err := svc.GetConsents(ctx, projectOf(ctx), sub)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			items := mapItems(states, toConsentState)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionConsentRead,
				Resource:    "consents:me",
				AccessLevel: audit.AccessMasked,
				ResultCount: len(items),
				SubjectIDs:  []string{sub},
			})
			return &consentStatePageOutput{Body: ConsentStatePage{Items: items}}, nil
		})

	huma.Register(r.api, r.selfOp("updateMeConsent", http.MethodPatch, "/privacy/v1/me/consents",
		"Record my consent change", http.StatusOK),
		func(ctx context.Context, in *updateMeConsentInput) (*consentStateOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			sub := requestInfoFrom(ctx).Actor.ID
			out, err := svc.UpdateConsent(ctx, projectOf(ctx), sub, privacy.ConsentChange{
				Purpose:       in.Body.Purpose,
				Granted:       in.Body.Granted,
				PolicyVersion: in.Body.PolicyVersion,
				Source:        "ui",
			})
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionConsentChanged,
				Resource:    "consent:" + in.Body.Purpose,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
				SubjectIDs:  []string{sub},
			})
			return &consentStateOutput{Body: toConsentState(*out)}, nil
		})
}
