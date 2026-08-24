package api

// Exact-match user search (docs/use-cases.md 제안 P4).
//
// The compat surface (/auth/v1/admin/users) stays paginate-only per the
// upstream contract; the management plane searches here instead. Auth
// identifiers (email/phone) match against auth.users, vault profile fields
// through the blind search index — the masked-by-default principle holds
// because results carry subject ids only, never values, and the search value
// itself is never written to the audit log (§5.1, same rule as `q`).

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-project/dilion/internal/audit"
	"github.com/dilion-project/dilion/internal/iam"
	"github.com/dilion-project/dilion/internal/privacy"
)

// ---- DTOs ----

// UserMatch is one search hit: which subject matched and through which
// identifier. Field values are never returned — follow up with the masked
// profile, or a privileged reveal, as a separate audited read.
type UserMatch struct {
	UserID   string  `json:"user_id" format:"uuid" doc:"Canonical user id of the matched subject."`
	Source   string  `json:"source" enum:"AUTH_EMAIL,AUTH_PHONE,PROFILE_FIELD" doc:"Which identifier matched."`
	FieldKey *string `json:"field_key" nullable:"true" doc:"The vault field that matched, or null for auth identifiers."`
}

// UserMatchPage is the cursor-paginated search envelope.
type UserMatchPage struct {
	Items      []UserMatch `json:"items" nullable:"false"`
	NextCursor *string     `json:"next_cursor" nullable:"true" doc:"Opaque cursor for the next page, or null."`
}

// ---- inputs / outputs ----

type searchUsersInput struct {
	Limit  int    `query:"limit" default:"20" minimum:"1" maximum:"100" doc:"Page size."`
	Cursor string `query:"cursor" doc:"Opaque cursor from a previous response."`
	Email  string `query:"email" doc:"Exact-match auth email (case-insensitive)."`
	Phone  string `query:"phone" doc:"Exact-match auth phone; spacing and punctuation are ignored."`
	Field  string `query:"field" doc:"Vault profile field key to match, e.g. name. Requires value."`
	Value  string `query:"value" doc:"Exact value for the field search (trimmed, case-folded). Never recorded in the audit log."`
}

type userMatchPageOutput struct {
	Body UserMatchPage
}

// ---- registration ----

func (r *registrar) registerUserSearch() {
	op := r.op("searchUsers", http.MethodGet, "/privacy/v1/users",
		"Search users by identifier", iam.PermUsersRead, "privacy", http.StatusOK)
	op.Description += "\n\nExact-match lookup by **exactly one** criterion: `email`, `phone`, or " +
		"`field`+`value` (a vault profile field, matched via a keyed blind index — equality only). " +
		"Results carry subject ids, never field values. Recorded as `USER_SEARCH` with the matched " +
		"subjects; the search value itself is never written to the audit log."
	huma.Register(r.api, op,
		func(ctx context.Context, in *searchUsersInput) (*userMatchPageOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			page, err := svc.SearchUsers(ctx, projectOf(ctx), privacy.UserSearchQuery{
				Email:      in.Email,
				Phone:      in.Phone,
				FieldKey:   in.Field,
				FieldValue: in.Value,
			}, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			items := mapItems(page.Items, toUserMatch)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionUserSearch,
				Resource:    "users:search",
				AccessLevel: audit.AccessMasked,
				ResultCount: len(items),
				SubjectIDs:  subjectsOf(items, func(m UserMatch) string { return m.UserID }),
			})
			return &userMatchPageOutput{Body: UserMatchPage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})
}

func toUserMatch(in privacy.UserMatch) UserMatch {
	out := UserMatch{UserID: in.UserID, Source: in.Source}
	if in.FieldKey != "" {
		fk := in.FieldKey
		out.FieldKey = &fk
	}
	return out
}
