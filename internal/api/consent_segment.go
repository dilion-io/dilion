package api

// Cross-user consent surface (docs/use-cases.md 제안 P1).
//
// Two tiers, deliberately separated:
//
//   - listConsentStates (`users.read`) — the segment projection. Returns
//     subject ids and consent state only, never contact identifiers.
//   - exportConsentAudience (`pii.export` + mandatory reason) — joins the
//     granted segment with auth.users email/phone. Extracting a recipient
//     list is bulk PII processing, so it is a privileged operation of the
//     same grade as a reveal (§5.2 "매우 민감") and each page is audited as
//     CONSENT_AUDIENCE_EXPORT with the subject manifest.

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-project/dilion/internal/audit"
	"github.com/dilion-project/dilion/internal/iam"
	"github.com/dilion-project/dilion/internal/privacy"
)

// ---- DTOs ----

// SubjectConsent is the current consent state of one purpose for one subject
// (the cross-user counterpart of ConsentState).
type SubjectConsent struct {
	UserID        string     `json:"user_id" format:"uuid" doc:"Canonical user id of the data subject."`
	Purpose       string     `json:"purpose" doc:"Consent purpose key."`
	Granted       bool       `json:"granted" doc:"Whether consent is currently granted."`
	PolicyVersion string     `json:"policy_version" doc:"Policy version the consent was recorded against."`
	UpdatedAt     time.Time  `json:"updated_at"`
	ReconfirmDue  *time.Time `json:"reconfirm_due" nullable:"true" doc:"When re-confirmation notice is due, or null."`
}

// SubjectConsentPage is the cursor-paginated segment envelope.
type SubjectConsentPage struct {
	Items      []SubjectConsent `json:"items" nullable:"false"`
	NextCursor *string          `json:"next_cursor" nullable:"true" doc:"Opaque cursor for the next page, or null. Pages may be shorter than limit while a reconfirm filter scans."`
}

// ExportConsentAudienceBody selects the audience and carries the mandatory
// justification. Pagination lives in the body because the operation is a POST.
type ExportConsentAudienceBody struct {
	Purpose string   `json:"purpose" minLength:"1" doc:"Consent purpose whose granted subjects form the audience."`
	Fields  []string `json:"fields,omitempty" uniqueItems:"true" doc:"Contact identifiers to include: email and/or phone. Defaults to [email]." enum:"email,phone"`
	Reason  string   `json:"reason" minLength:"1" maxLength:"500" doc:"Why the audience is being exported. Required and recorded in the audit log."`
	Limit   int      `json:"limit,omitempty" minimum:"1" maximum:"1000" doc:"Page size (default 100)."`
	Cursor  *string  `json:"cursor,omitempty" doc:"Opaque cursor from a previous response."`
}

// AudienceMember is one export row. Fields that were not requested are null —
// data minimization applies to exports too.
type AudienceMember struct {
	UserID string  `json:"user_id" format:"uuid"`
	Email  *string `json:"email" nullable:"true" doc:"Auth email, empty string if the account has none, null when not requested."`
	Phone  *string `json:"phone" nullable:"true" doc:"Auth phone, empty string if the account has none, null when not requested."`
}

// AudiencePage is the export envelope.
type AudiencePage struct {
	Items      []AudienceMember `json:"items" nullable:"false"`
	NextCursor *string          `json:"next_cursor" nullable:"true"`
}

// ---- inputs / outputs ----

type listConsentStatesInput struct {
	Limit              int       `query:"limit" default:"20" minimum:"1" maximum:"100" doc:"Page size."`
	Cursor             string    `query:"cursor" doc:"Opaque cursor from a previous response."`
	Purpose            string    `query:"purpose" doc:"Filter by purpose key, e.g. marketing."`
	Granted            string    `query:"granted" enum:"true,false" doc:"true = currently granted, false = withdrawn. Omit for both."`
	ReconfirmDueBefore time.Time `query:"reconfirm_due_before" required:"false" doc:"Only rows whose re-confirmation notice is due before this time (재동의 고지 대상자 추출)."`
}

type subjectConsentPageOutput struct {
	Body SubjectConsentPage
}

type exportConsentAudienceInput struct {
	Body ExportConsentAudienceBody
}

type audiencePageOutput struct {
	Body AudiencePage
}

// ---- registration ----

func (r *registrar) registerConsentSegments() {
	listOp := r.op("listConsentStates", http.MethodGet, "/privacy/v1/consents",
		"List consent state across subjects", iam.PermUsersRead, "privacy", http.StatusOK)
	listOp.Description += "\n\nCross-user segment projection of the consent ledger (\"who currently " +
		"grants marketing?\"), ordered by (user_id, purpose). Returns subject ids and consent state " +
		"only — contact identifiers require `exportConsentAudience`. With `reconfirm_due_before` a " +
		"page may hold fewer than `limit` rows while the scan continues; keep following `next_cursor`."
	huma.Register(r.api, listOp,
		func(ctx context.Context, in *listConsentStatesInput) (*subjectConsentPageOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			f := privacy.ConsentSegmentFilter{
				Purpose:            in.Purpose,
				ReconfirmDueBefore: optionalTime(in.ReconfirmDueBefore),
			}
			if in.Granted != "" {
				granted := in.Granted == "true"
				f.Granted = &granted
			}
			page, err := svc.ListConsentStates(ctx, projectOf(ctx), f, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			items := mapItems(page.Items, toSubjectConsent)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionConsentSegmentRead,
				Resource:    "consents",
				AccessLevel: audit.AccessMasked,
				ResultCount: len(items),
				SubjectIDs:  subjectsOf(items, func(s SubjectConsent) string { return s.UserID }),
			})
			return &subjectConsentPageOutput{Body: SubjectConsentPage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})

	exportOp := r.op("exportConsentAudience", http.MethodPost, "/privacy/v1/consents/export",
		"Export a consent audience", iam.PermPIIExport, "privacy", http.StatusOK)
	exportOp.Description += "\n\nPrivileged bulk export (§5.2): pages the subjects whose latest " +
		"ledger entry for `purpose` is GRANT, joined with the requested auth.users contact " +
		"identifiers. Erased/deleted accounts are excluded. `reason` is mandatory and every page " +
		"is recorded as `CONSENT_AUDIENCE_EXPORT` with the subject manifest."
	huma.Register(r.api, exportOp,
		func(ctx context.Context, in *exportConsentAudienceInput) (*audiencePageOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			fields := in.Body.Fields
			if len(fields) == 0 {
				fields = []string{"email"}
			}
			limit := in.Body.Limit
			if limit == 0 {
				limit = 100
			}
			cursor := ""
			if in.Body.Cursor != nil {
				cursor = *in.Body.Cursor
			}
			// The engine caps ListParams at the shared MaxLimit; audience export
			// deliberately pages larger, so page through the engine as needed.
			page, err := exportAudiencePages(ctx, svc, projectOf(ctx), in.Body.Purpose, limit, cursor)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			items := make([]AudienceMember, 0, len(page.Items))
			for _, m := range page.Items {
				out := AudienceMember{UserID: m.UserID}
				if slices.Contains(fields, "email") {
					email := m.Email
					out.Email = &email
				}
				if slices.Contains(fields, "phone") {
					phone := m.Phone
					out.Phone = &phone
				}
				items = append(items, out)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionConsentAudienceExport,
				Resource:    "consent_audience:" + in.Body.Purpose,
				AccessLevel: audit.AccessFull,
				ResultCount: len(items),
				SubjectIDs:  subjectsOf(items, func(m AudienceMember) string { return m.UserID }),
				Reason:      in.Body.Reason,
			})
			return &audiencePageOutput{Body: AudiencePage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})
}

func toSubjectConsent(in privacy.SubjectConsent) SubjectConsent {
	return SubjectConsent{
		UserID:        in.UserID,
		Purpose:       in.Purpose,
		Granted:       in.Granted,
		PolicyVersion: in.PolicyVersion,
		UpdatedAt:     in.UpdatedAt,
		ReconfirmDue:  in.ReconfirmDue,
	}
}

// exportAudiencePages accumulates engine pages (capped at httpapi.MaxLimit
// each) until the requested export page size is reached or the segment ends.
func exportAudiencePages(ctx context.Context, svc privacy.Service, projectID, purpose string, limit int, cursor string) (struct {
	Items      []privacy.AudienceMember
	NextCursor *string
}, error) {
	var out struct {
		Items      []privacy.AudienceMember
		NextCursor *string
	}
	for len(out.Items) < limit {
		page, err := svc.ExportConsentAudience(ctx, projectID, purpose,
			listParams(limit-len(out.Items), cursor, ""))
		if err != nil {
			return out, err
		}
		out.Items = append(out.Items, page.Items...)
		out.NextCursor = page.NextCursor
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	return out, nil
}
