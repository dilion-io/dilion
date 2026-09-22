package api

// Batch masked profile read (/privacy/v1/profiles).
//
// This exists so a screen that lists subjects — a role assignment report, a
// consent segment, a search result — can label them in ONE request instead of
// one per subject. It is deliberately a separate call rather than an `expand`
// on those reports: personal data stays on the surface that is permissioned and
// audited for it, and reading it stays a decision the caller makes explicitly.
//
// It is the plural form of getUserProfile and nothing more. Same permission,
// same masked projection, same audit action, with one access record covering
// the whole batch. The unmasked original is still a separate privileged
// operation per subject (revealUserProfile), because a reason must be recorded
// against each one.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/privacy"
)

// maxBatchProfiles bounds one request. The work is per subject regardless of
// batching — each profile is sealed under its own key — so the limit keeps a
// single request from turning into an unbounded amount of decryption.
const maxBatchProfiles = 100

// ProfileBatch is the batch response. Subjects with no stored profile are named
// in Missing rather than omitted silently, so a caller can tell "no profile"
// apart from "id you did not ask about".
type ProfileBatch struct {
	Items   []Profile `json:"items" nullable:"false" doc:"Masked profiles, in the order the ids were given."`
	Missing []string  `json:"missing" nullable:"false" doc:"Requested ids with no stored profile."`
}

type listProfilesInput struct {
	UserIDs []string `query:"user_ids" doc:"Canonical user ids, comma separated. At most 100, duplicates collapsed."`
}

type profileBatchOutput struct {
	Body ProfileBatch
}

func (r *registrar) registerProfileBatch() {
	op := r.op("listUserProfiles", http.MethodGet, "/privacy/v1/profiles",
		"Get several users' masked PII profiles", iam.PermUsersRead, "privacy", http.StatusOK)
	op.Description += "\n\nThe plural form of `getUserProfile`: always the **masked** projection " +
		"(`view: MASKED`), for up to 100 subjects in one request. Recorded as a single " +
		"`PII_MASKED_READ` whose subject manifest lists every profile actually returned. " +
		"Use `revealUserProfile` for original values; revealing stays one subject at a time " +
		"because each reveal needs its own recorded reason."
	huma.Register(r.api, op,
		func(ctx context.Context, in *listProfilesInput) (*profileBatchOutput, error) {
			ids, err := batchUserIDs(in.UserIDs)
			if err != nil {
				return nil, err
			}
			svc, err := r.privacy(ctx)
			if err != nil {
				return nil, err
			}

			items := make([]Profile, 0, len(ids))
			missing := []string{}
			found := make([]string, 0, len(ids))
			for _, id := range ids {
				out, err := svc.GetProfile(ctx, id, false)
				if errors.Is(err, privacy.ErrNotFound) {
					missing = append(missing, id)
					continue
				}
				if err != nil {
					return nil, mapPrivacyError(ctx, err)
				}
				items = append(items, toProfile(*out))
				found = append(found, id)
			}

			// One access record for the batch, listing exactly the subjects
			// whose data was returned (§5.3). Subjects that had no profile are
			// not in the manifest: nothing of theirs was read.
			if len(found) > 0 {
				r.d.emit(ctx, auditOpts{
					Action:      audit.ActionPIIMaskedRead,
					Resource:    "user_profiles:batch",
					AccessLevel: audit.AccessMasked,
					ResultCount: len(found),
					SubjectIDs:  found,
				})
			}
			return &profileBatchOutput{Body: ProfileBatch{Items: items, Missing: missing}}, nil
		})
}

// splitCommas splits one query value on commas and trims the parts, so both
// ?user_ids=a,b and ?user_ids=a&user_ids=b work. Empty parts are dropped.
func splitCommas(v string) []string {
	out := []string{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// batchUserIDs normalises the requested ids: comma separated values are split,
// blanks dropped, duplicates collapsed, order preserved.
func batchUserIDs(raw []string) ([]string, error) {
	ids := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, v := range raw {
		for _, id := range splitCommas(v) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, NewProblem(http.StatusUnprocessableEntity, httpapi.CodeValidationFailed,
			"user_ids is required")
	}
	if len(ids) > maxBatchProfiles {
		return nil, NewProblem(http.StatusUnprocessableEntity, httpapi.CodeValidationFailed,
			"user_ids holds more ids than one request may ask for")
	}
	return ids, nil
}
