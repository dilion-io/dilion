package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/privacy"
)

func decodeBatch(t *testing.T, body []byte) ProfileBatch {
	t.Helper()
	var b ProfileBatch
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("decode batch: %v (body=%s)", err, body)
	}
	return b
}

// The batch read is the plural form of the single masked read: masked view,
// one access record naming every subject returned, no reveal.
func TestListUserProfilesReturnsMaskedAndAuditsOnce(t *testing.T) {
	sink := &recordingSink{}
	var asked []string
	svc := &fakePrivacy{
		getProfile: func(_ context.Context, user string, full bool) (*privacy.Profile, error) {
			if full {
				t.Error("batch read asked for the unmasked profile")
			}
			asked = append(asked, user)
			if user == otherUserID {
				return nil, privacy.ErrNotFound
			}
			p := maskedProfile()
			p.UserID = user
			return p, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Get("/privacy/v1/profiles?user_ids="+testUserID+","+otherUserID, bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	if len(asked) != 2 || asked[0] != testUserID || asked[1] != otherUserID {
		t.Errorf("GetProfile calls = %v, want both ids in order", asked)
	}

	body := decodeBatch(t, resp.Body.Bytes())
	if len(body.Items) != 1 || body.Items[0].UserID != testUserID {
		t.Fatalf("items = %+v, want just the subject that has a profile", body.Items)
	}
	if body.Items[0].View != "MASKED" {
		t.Errorf("view = %q, want MASKED", body.Items[0].View)
	}
	if len(body.Missing) != 1 || body.Missing[0] != otherUserID {
		t.Errorf("missing = %v, want [%s]", body.Missing, otherUserID)
	}

	// Exactly one access record, and it names only the subject actually read.
	var reads int
	for _, e := range sink.events {
		if e.Action != audit.ActionPIIMaskedRead {
			continue
		}
		reads++
		if e.AccessLevel != audit.AccessMasked {
			t.Errorf("access level = %q, want masked", e.AccessLevel)
		}
		if len(e.SubjectIDs) != 1 || e.SubjectIDs[0] != testUserID {
			t.Errorf("subject manifest = %v, want only the subject read", e.SubjectIDs)
		}
	}
	if reads != 1 {
		t.Errorf("PII_MASKED_READ events = %d, want 1 for the whole batch", reads)
	}
}

// Duplicates collapse, blanks are dropped, and the batch is bounded.
func TestListUserProfilesValidatesIDs(t *testing.T) {
	sink := &recordingSink{}
	var calls int
	svc := &fakePrivacy{
		getProfile: func(_ context.Context, user string, _ bool) (*privacy.Profile, error) {
			calls++
			p := maskedProfile()
			p.UserID = user
			return p, nil
		},
	}
	tapi := newAPI(t, svc, serviceRoleDeps(sink))

	resp := tapi.Get("/privacy/v1/profiles?user_ids="+testUserID+",,"+testUserID, bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	if calls != 1 {
		t.Errorf("GetProfile calls = %d, want 1 after collapsing the duplicate", calls)
	}

	// One more DISTINCT id than a request may carry; duplicates would have
	// collapsed and never reached the limit.
	tooMany := make([]string, 0, maxBatchProfiles+1)
	for i := 0; i <= maxBatchProfiles; i++ {
		tooMany = append(tooMany, fmt.Sprintf("%s%03d", testUserID[:33], i))
	}

	for name, query := range map[string]string{
		"empty":    "",
		"too many": strings.Join(tooMany, ","),
	} {
		resp := tapi.Get("/privacy/v1/profiles?user_ids="+query, bearer)
		if resp.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status = %d, want 422 (body=%s)", name, resp.Code, resp.Body.String())
		}
		if p := decodeProblem(t, resp.Body.Bytes()); p.Code != httpapi.CodeValidationFailed {
			t.Errorf("%s: code = %q, want %q", name, p.Code, httpapi.CodeValidationFailed)
		}
	}
}

// It is the same authority as the single masked read, and nothing weaker.
func TestListUserProfilesRequiresUsersRead(t *testing.T) {
	sink := &recordingSink{}
	svc := &fakePrivacy{
		getProfile: func(_ context.Context, user string, _ bool) (*privacy.Profile, error) {
			t.Error("profile was read without users.read")
			return maskedProfile(), nil
		},
	}
	tapi := newAPI(t, svc, permDeps(sink, iam.PermAuditRead))

	resp := tapi.Get("/privacy/v1/profiles?user_ids="+testUserID, bearer)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", resp.Code, resp.Body.String())
	}
}
