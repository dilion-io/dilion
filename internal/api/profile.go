package api

// PII profile surface (/privacy/v1/users/{userId}/profile, project.md §2.6–§2.7).
//
// Masked-by-default (§2.11 deny-by-default): the plain GET always returns the
// hint-based masked projection, and the unmasked original is a separate
// privileged operation that requires `pii.reveal` *and* a written reason, and
// is recorded as PII_FULL_READ (§5.2). Writing personal data is a third,
// distinct authority (`pii.write`, PII_UPDATE).

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/privacy"
)

// ---- DTOs ----

// ProfileField is one PII field of a subject's profile. In a MASKED profile the
// value is the hint-based projection (§2.6); in a FULL profile it is the
// original.
type ProfileField struct {
	Value string `json:"value" doc:"Field value: masked projection or original, depending on the profile view."`
	Hint  string `json:"hint" enum:"EMAIL,NAME,PHONE,ADDRESS,GENERIC" doc:"Masking hint that decides how the value is projected when masked."`
}

// Profile is a data subject's PII profile. Custom field keys are supported, so
// `fields` is an open key→field map.
type Profile struct {
	UserID    string                  `json:"user_id" format:"uuid" doc:"Canonical user id of the data subject."`
	Fields    map[string]ProfileField `json:"fields" nullable:"false" doc:"PII fields keyed by field name."`
	View      string                  `json:"view" enum:"MASKED,FULL" doc:"MASKED = hint-based projection, FULL = original values."`
	UpdatedAt *time.Time              `json:"updated_at" nullable:"true" doc:"When the profile was last written, or null."`
}

// RevealUserProfileBody carries the mandatory justification for an unmasked
// read. The reason is stored on the PII_FULL_READ audit event (§5.2).
type RevealUserProfileBody struct {
	Reason string `json:"reason" minLength:"1" maxLength:"500" doc:"Why the original values are being viewed. Required and recorded in the audit log."`
}

// ProfileFieldWrite is one field of a profile write. Unlike the response
// ProfileField the masking hint is optional: an instance may pin its PII field
// definitions (ports.InstanceResolver.PIIFields), in which case the hint is
// taken from the definition and may be omitted — supplying a different one is
// rejected. Instances without definitions keep free-form fields, where the hint
// is required.
type ProfileFieldWrite struct {
	Value string  `json:"value" doc:"Field value (the original, never a masked projection)."`
	Hint  *string `json:"hint,omitempty" enum:"EMAIL,NAME,PHONE,ADDRESS,GENERIC" doc:"Masking hint. Required unless the instance defines this field, in which case it may be omitted and must otherwise match the definition."`
}

// UpdateUserProfileBody is a partial write: `set` upserts fields, `remove`
// deletes them. At least one of the two must be present.
type UpdateUserProfileBody struct {
	Set    map[string]ProfileFieldWrite `json:"set,omitempty" doc:"Fields to upsert, keyed by field name."`
	Remove []string                     `json:"remove,omitempty" doc:"Field names to delete."`
}

// ---- conversions ----

func toProfile(in privacy.Profile) Profile {
	fields := make(map[string]ProfileField, len(in.Fields))
	for k, v := range in.Fields {
		fields[k] = ProfileField{Value: v.Value, Hint: string(v.Hint)}
	}
	return Profile{
		UserID:    in.UserID,
		Fields:    fields,
		View:      string(in.View),
		UpdatedAt: in.UpdatedAt,
	}
}

// toProfileFields maps a write patch onto the engine type. An omitted hint
// becomes the empty FieldHint, which the engine resolves from the instance's
// field definitions (and rejects when there are none).
func toProfileFields(in map[string]ProfileFieldWrite) map[string]privacy.ProfileField {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]privacy.ProfileField, len(in))
	for k, v := range in {
		hint := ""
		if v.Hint != nil {
			hint = *v.Hint
		}
		out[k] = privacy.ProfileField{Value: v.Value, Hint: privacy.FieldHint(hint)}
	}
	return out
}

// ---- inputs / outputs ----

type userProfileInput struct {
	UserID string `path:"userId" format:"uuid"`
}

type revealUserProfileInput struct {
	UserID string `path:"userId" format:"uuid"`
	Body   RevealUserProfileBody
}

type updateUserProfileInput struct {
	UserID string `path:"userId" format:"uuid"`
	Body   UpdateUserProfileBody
}

type profileOutput struct {
	Body Profile
}

// ---- registration ----

func (r *registrar) registerProfiles() {
	getOp := r.op("getUserProfile", http.MethodGet, "/privacy/v1/users/{userId}/profile",
		"Get a user's masked PII profile", iam.PermUsersRead, "privacy", http.StatusOK)
	getOp.Description += "\n\nAlways returns the **masked** projection (`view: MASKED`): field " +
		"values are projected from their masking hint (§2.6). Use `revealUserProfile` for the " +
		"original values. Recorded as `PII_MASKED_READ`."
	huma.Register(r.api, getOp,
		func(ctx context.Context, in *userProfileInput) (*profileOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			out, err := svc.GetProfile(ctx, in.UserID, false)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionPIIMaskedRead,
				Resource:    "user_profile:" + in.UserID,
				AccessLevel: audit.AccessMasked,
				ResultCount: 1,
				SubjectIDs:  []string{in.UserID},
			})
			return &profileOutput{Body: toProfile(*out)}, nil
		})

	revealOp := r.op("revealUserProfile", http.MethodPost, "/privacy/v1/users/{userId}/profile/reveal",
		"Reveal a user's original PII", iam.PermPIIReveal, "privacy", http.StatusOK)
	revealOp.Description += "\n\nPrivileged operation (§5.2): returns the **unmasked** profile " +
		"(`view: FULL`). A `reason` is mandatory and is stored on the `PII_FULL_READ` audit event " +
		"together with the subject manifest."
	huma.Register(r.api, revealOp,
		func(ctx context.Context, in *revealUserProfileInput) (*profileOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			out, err := svc.GetProfile(ctx, in.UserID, true)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionPIIFullRead,
				Resource:    "user_profile:" + in.UserID,
				AccessLevel: audit.AccessFull,
				ResultCount: 1,
				SubjectIDs:  []string{in.UserID},
				Reason:      in.Body.Reason,
			})
			return &profileOutput{Body: toProfile(*out)}, nil
		})

	updateOp := r.op("updateUserProfile", http.MethodPatch, "/privacy/v1/users/{userId}/profile",
		"Update a user's PII profile", iam.PermPIIWrite, "privacy", http.StatusOK)
	updateOp.Description += "\n\nPartial write: `set` upserts fields, `remove` deletes them. At " +
		"least one of the two is required. Recorded as `PII_UPDATE`; the response is the **masked** " +
		"projection — writing personal data never reveals it.\n\nWhen the instance pins its PII " +
		"field definitions, only the defined keys may be written, `hint` may be omitted, and a " +
		"supplied `hint` must equal the defined one; the stored hint always comes from the " +
		"definition. Otherwise fields are free-form and `hint` is required."
	huma.Register(r.api, updateOp,
		func(ctx context.Context, in *updateUserProfileInput) (*profileOutput, error) {
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}
			if len(in.Body.Set) == 0 && len(in.Body.Remove) == 0 {
				return nil, NewProblem(http.StatusUnprocessableEntity, httpapi.CodeValidationFailed,
					"at least one of set or remove is required",
					&huma.ErrorDetail{Message: "expected at least one field to set or remove", Location: "body"})
			}
			out, err := svc.UpdateProfile(ctx, in.UserID,
				toProfileFields(in.Body.Set), in.Body.Remove)
			if err != nil {
				return nil, mapPrivacyError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionPIIUpdate,
				Resource:    "user_profile:" + in.UserID,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
				SubjectIDs:  []string{in.UserID},
			})
			return &profileOutput{Body: toProfile(*out)}, nil
		})
}
