package privacy

// Integration tests for the cross-user consent projections (use-cases.md P1),
// exact-match user search with the blind index (P4), and the list filters
// added for P3 / holds. Same harness rules as engine_db_test.go.

import (
	"testing"
	"time"

	"github.com/dilion-io/dilion/httpapi"
)

func (env *testEnv) grant(t *testing.T, user, purpose string, granted bool) {
	t.Helper()
	if _, err := env.e.UpdateConsent(env.ctx, "default", user, ConsentChange{
		Purpose: purpose, Granted: granted, PolicyVersion: "v1", Source: "ui",
	}); err != nil {
		t.Fatalf("consent %s=%v: %v", purpose, granted, err)
	}
	env.clock.Advance(time.Second)
}

func TestConsentSegmentProjection(t *testing.T) {
	env := newTestEngine(t, "")
	a, b, c := env.newUser(t), env.newUser(t), env.newUser(t)

	env.grant(t, a, "marketing", true)
	env.grant(t, b, "marketing", true)
	env.grant(t, b, "marketing", false) // withdrawn: latest entry wins
	env.grant(t, c, "newsletter", true)

	page, err := env.e.ListConsentStates(env.ctx, "default",
		ConsentSegmentFilter{Purpose: "marketing"}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("marketing segment = %+v, want 2 rows", page.Items)
	}
	byUser := map[string]bool{}
	for _, sc := range page.Items {
		byUser[sc.UserID] = sc.Granted
	}
	if !byUser[a] || byUser[b] {
		t.Fatalf("granted projection wrong: %v (a=%s granted, b=%s withdrawn)", byUser, a, b)
	}

	granted := true
	page, err = env.e.ListConsentStates(env.ctx, "default",
		ConsentSegmentFilter{Purpose: "marketing", Granted: &granted}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].UserID != a {
		t.Fatalf("granted filter = %+v, want only %s", page.Items, a)
	}

	// Pagination across purposes: 3 (user, purpose) states in total.
	var seen []SubjectConsent
	cursor := ""
	for i := 0; i < 10; i++ {
		p, err := env.e.ListConsentStates(env.ctx, "default", ConsentSegmentFilter{},
			httpapi.ListParams{Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, p.Items...)
		if p.NextCursor == nil {
			break
		}
		cursor = *p.NextCursor
	}
	if len(seen) != 3 {
		t.Fatalf("paged segment rows = %d, want 3 (a:marketing, b:marketing, c:newsletter)", len(seen))
	}
}

func TestConsentSegmentReconfirmDueFilter(t *testing.T) {
	env := newTestEngine(t, "")
	due, notDue := env.newUser(t), env.newUser(t)
	env.setPolicy(t, due, "kr") // builtin kr: marketing.* reconfirm P2Y

	env.grant(t, due, "marketing.email", true)
	env.grant(t, notDue, "marketing.email", true) // default policy: no reconfirm

	horizon := env.clock.Now().AddDate(3, 0, 0)
	page, err := env.e.ListConsentStates(env.ctx, "default",
		ConsentSegmentFilter{ReconfirmDueBefore: &horizon}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].UserID != due {
		t.Fatalf("reconfirm filter = %+v, want only %s", page.Items, due)
	}
	if page.Items[0].ReconfirmDue == nil {
		t.Fatal("matched row must carry reconfirm_due")
	}

	soon := env.clock.Now().AddDate(1, 0, 0) // P2Y not yet reached
	page, err = env.e.ListConsentStates(env.ctx, "default",
		ConsentSegmentFilter{ReconfirmDueBefore: &soon}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("nothing is due within 1y, got %+v", page.Items)
	}
}

func TestExportConsentAudience(t *testing.T) {
	env := newTestEngine(t, "")
	granted, withdrawn, deleted := env.newUser(t), env.newUser(t), env.newUser(t)

	env.grant(t, granted, "marketing", true)
	env.grant(t, withdrawn, "marketing", true)
	env.grant(t, withdrawn, "marketing", false)
	env.grant(t, deleted, "marketing", true)
	if _, err := env.pool.Exec(env.ctx,
		`update auth.users set deleted_at = now() where id = $1::uuid`, deleted); err != nil {
		t.Fatal(err)
	}

	page, err := env.e.ExportConsentAudience(env.ctx, "default", "marketing", httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].UserID != granted {
		t.Fatalf("audience = %+v, want only %s (withdrawn and deleted excluded)", page.Items, granted)
	}
	if page.Items[0].Email == "" || page.Items[0].Phone == "" {
		t.Fatalf("audience must carry auth contact identifiers: %+v", page.Items[0])
	}

	if _, err := env.e.ExportConsentAudience(env.ctx, "default", "  ", httpapi.ListParams{}); err == nil {
		t.Fatal("empty purpose must be rejected")
	}
}

func TestSearchUsersByAuthIdentifier(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	var email string
	if err := env.pool.QueryRow(env.ctx,
		`select email from auth.users where id = $1::uuid`, user).Scan(&email); err != nil {
		t.Fatal(err)
	}

	page, err := env.e.SearchUsers(env.ctx, "default",
		UserSearchQuery{Email: "  " + email + " "}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].UserID != user || page.Items[0].Source != MatchAuthEmail {
		t.Fatalf("email search = %+v", page.Items)
	}

	page, err = env.e.SearchUsers(env.ctx, "default",
		UserSearchQuery{Phone: "+82 10-0000-0000"}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range page.Items {
		if m.UserID == user {
			found = true
			if m.Source != MatchAuthPhone {
				t.Fatalf("source = %s, want AUTH_PHONE", m.Source)
			}
		}
	}
	if !found {
		t.Fatalf("phone search missed %s: %+v", user, page.Items)
	}

	// Erased accounts never match.
	if _, err := env.pool.Exec(env.ctx,
		`update auth.users set deleted_at = now() where id = $1::uuid`, user); err != nil {
		t.Fatal(err)
	}
	page, err = env.e.SearchUsers(env.ctx, "default", UserSearchQuery{Email: email}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("deleted account matched: %+v", page.Items)
	}

	// Exactly one criterion.
	if _, err := env.e.SearchUsers(env.ctx, "default",
		UserSearchQuery{Email: email, Phone: "+821000000000"}, httpapi.ListParams{}); err == nil {
		t.Fatal("two criteria must be rejected")
	}
	if _, err := env.e.SearchUsers(env.ctx, "default", UserSearchQuery{}, httpapi.ListParams{}); err == nil {
		t.Fatal("no criterion must be rejected")
	}
	if _, err := env.e.SearchUsers(env.ctx, "default",
		UserSearchQuery{FieldKey: "name"}, httpapi.ListParams{}); err == nil {
		t.Fatal("field search without value must be rejected")
	}
}

func TestSearchUsersByProfileFieldAndIndexLifecycle(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newProfileUser(t)

	if _, err := env.e.UpdateProfile(env.ctx, "default", user, map[string]ProfileField{
		"name":     {Value: "홍길동", Hint: HintName},
		"nickname": {Value: "Dilion-Dev", Hint: HintGeneric},
	}, nil); err != nil {
		t.Fatal(err)
	}

	q := UserSearchQuery{FieldKey: "name", FieldValue: "홍길동"}
	page, err := env.e.SearchUsers(env.ctx, "default", q, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].UserID != user ||
		page.Items[0].Source != MatchProfileField || page.Items[0].FieldKey != "name" {
		t.Fatalf("field search = %+v", page.Items)
	}

	// The token folds case/whitespace but is strictly equality.
	page, err = env.e.SearchUsers(env.ctx, "default",
		UserSearchQuery{FieldKey: "nickname", FieldValue: "  dilion-dev "}, httpapi.ListParams{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("case-folded search = %+v (%v)", page.Items, err)
	}
	page, err = env.e.SearchUsers(env.ctx, "default",
		UserSearchQuery{FieldKey: "name", FieldValue: "홍길"}, httpapi.ListParams{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("prefix must not match: %+v (%v)", page.Items, err)
	}

	// Rewriting the value moves the index; removing the field clears it.
	if _, err := env.e.UpdateProfile(env.ctx, "default", user, map[string]ProfileField{
		"name": {Value: "김철수", Hint: HintName},
	}, nil); err != nil {
		t.Fatal(err)
	}
	page, _ = env.e.SearchUsers(env.ctx, "default", q, httpapi.ListParams{})
	if len(page.Items) != 0 {
		t.Fatalf("stale index entry after rewrite: %+v", page.Items)
	}
	page, _ = env.e.SearchUsers(env.ctx, "default",
		UserSearchQuery{FieldKey: "name", FieldValue: "김철수"}, httpapi.ListParams{})
	if len(page.Items) != 1 {
		t.Fatalf("rewritten value must match: %+v", page.Items)
	}

	if _, err := env.e.UpdateProfile(env.ctx, "default", user, nil, []string{"name", "nickname"}); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := env.pool.QueryRow(env.ctx,
		`select count(*) from dilion_pii.profile_search_index where user_id = $1::uuid`, user).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("index rows after removing every field = %d, want 0", rows)
	}
}

func TestErasureClearsSearchIndex(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newProfileUser(t)
	if _, err := env.e.UpdateProfile(env.ctx, "default", user, map[string]ProfileField{
		"name": {Value: "홍길동", Hint: HintName},
	}, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := env.e.CreateRequest(env.ctx, CreateRequestInput{
		UserID: user, Type: RequestDeletion, Immediate: true,
	}); err != nil {
		t.Fatal(err)
	}
	env.drain(t, 3)

	var rows int
	if err := env.pool.QueryRow(env.ctx,
		`select count(*) from dilion_pii.profile_search_index where user_id = $1::uuid`, user).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("search index must not outlive the erased profile (%d rows)", rows)
	}
}

func TestListRequestsFilters(t *testing.T) {
	env := newTestEngine(t, "")
	a, b := env.newUser(t), env.newUser(t)

	t0 := env.clock.Now()
	mk := func(user string, typ RequestType) *Request {
		r, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: typ})
		if err != nil {
			t.Fatalf("create %s/%s: %v", user, typ, err)
		}
		env.clock.Advance(time.Hour)
		return r
	}
	ra := mk(a, RequestDeletion)
	rb := mk(b, RequestExport)
	mk(b, RequestConsentWithdrawal)

	byUser, err := env.e.ListRequests(env.ctx, "default", RequestFilter{UserID: &a}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(byUser.Items) != 1 || byUser.Items[0].ID != ra.ID {
		t.Fatalf("user filter = %+v", byUser.Items)
	}

	exp := RequestExport
	byType, err := env.e.ListRequests(env.ctx, "default", RequestFilter{Type: &exp}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(byType.Items) != 1 || byType.Items[0].ID != rb.ID {
		t.Fatalf("type filter = %+v", byType.Items)
	}

	after := t0.Add(30 * time.Minute)
	before := t0.Add(90 * time.Minute)
	window, err := env.e.ListRequests(env.ctx, "default",
		RequestFilter{RequestedAfter: &after, RequestedBefore: &before}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(window.Items) != 1 || window.Items[0].ID != rb.ID {
		t.Fatalf("time window = %+v, want only the request at t0+1h", window.Items)
	}
}

func TestListHoldsActiveFilter(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)

	h1, err := env.e.CreateHold(env.ctx, CreateHoldInput{
		UserID: user, Reason: "lawsuit", Basis: "basis-1", CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := env.e.CreateHold(env.ctx, CreateHoldInput{
		UserID: user, Reason: "audit", Basis: "basis-2", CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.e.ReleaseHold(env.ctx, "default", h1.ID, "admin"); err != nil {
		t.Fatal(err)
	}

	active := true
	page, err := env.e.ListHolds(env.ctx, "default", HoldFilter{Active: &active}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != h2.ID {
		t.Fatalf("active=true = %+v, want only %s", page.Items, h2.ID)
	}

	released := false
	page, err = env.e.ListHolds(env.ctx, "default", HoldFilter{Active: &released}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != h1.ID {
		t.Fatalf("active=false = %+v, want only %s", page.Items, h1.ID)
	}

	page, err = env.e.ListHolds(env.ctx, "default", HoldFilter{}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("no filter = %d holds, want 2", len(page.Items))
	}
}
