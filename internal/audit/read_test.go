package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/ports"
)

const (
	subjectA = "6a1f2b3c-4d5e-4f70-8192-a3b4c5d6e7f8"
	subjectB = "7b2f3c4d-5e6f-4a81-9203-b4c5d6e7f8a9"
)

var seedBase = time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)

// seedEvents writes three events, oldest first, and returns the reader.
//
//	#1 admin_alice PII_FULL_READ   subjects [A]     reason recorded
//	#2 admin_bob   USER_LIST_READ  subjects [A, B]
//	#3 admin_alice PII_MASKED_READ subjects [B]
func seedEvents(t *testing.T, pool *pgxpool.Pool) *Reader {
	t.Helper()
	ctx := context.Background()
	sink := NewSink(pool)
	events := []ports.AuditEvent{
		{
			ActorID: "admin_alice", ActorType: "admin", Action: ActionPIIFullRead,
			Resource: "user_profile:" + subjectA, AccessLevel: AccessFull, ResultCount: 1,
			SubjectIDs: []string{subjectA}, Reason: "CS ticket #4417",
			OccurredAt: seedBase,
		},
		{
			ActorID: "admin_bob", ActorType: "admin", Action: ActionUserListRead,
			Resource: "privacy_requests", AccessLevel: AccessMasked, ResultCount: 2,
			SubjectIDs: []string{subjectA, subjectB},
			OccurredAt: seedBase.Add(time.Minute),
		},
		{
			ActorID: "admin_alice", ActorType: "admin", Action: ActionPIIMaskedRead,
			Resource: "user_profile:" + subjectB, AccessLevel: AccessMasked, ResultCount: 1,
			SubjectIDs: []string{subjectB},
			OccurredAt: seedBase.Add(2 * time.Minute),
		},
	}
	for i, e := range events {
		if err := sink.Append(ctx, e); err != nil {
			t.Fatalf("seed event %d: %v", i, err)
		}
	}
	return NewReader(pool)
}

func ptr(s string) *string { return &s }

func actionsOf(items []Event) []string {
	out := make([]string, 0, len(items))
	for _, e := range items {
		out = append(out, e.Action)
	}
	return out
}

func TestListEventsNewestFirstAndFiltered(t *testing.T) {
	pool := testPool(t)
	r := seedEvents(t, pool)
	ctx := context.Background()

	all, err := r.ListEvents(ctx, DefaultProjectID, EventFilter{}, httpapi.ListParams{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := actionsOf(all.Items); len(got) != 3 ||
		got[0] != ActionPIIMaskedRead || got[2] != ActionPIIFullRead {
		t.Fatalf("actions = %v, want newest first", got)
	}
	if all.NextCursor != nil {
		t.Errorf("next_cursor = %v, want null on a complete page", *all.NextCursor)
	}
	// The subject manifest is not inlined in list rows (§5.3).
	for _, e := range all.Items {
		if len(e.SubjectIDs) != 0 {
			t.Errorf("event %s inlined subjects %v in a list response", e.ID, e.SubjectIDs)
		}
	}

	cases := []struct {
		name string
		f    EventFilter
		want []string
	}{
		{"actor", EventFilter{ActorID: ptr("admin_alice")},
			[]string{ActionPIIMaskedRead, ActionPIIFullRead}},
		{"action", EventFilter{Action: ptr(ActionPIIFullRead)},
			[]string{ActionPIIFullRead}},
		{"unknown actor", EventFilter{ActorID: ptr("nobody")}, nil},
		{"actor + action", EventFilter{ActorID: ptr("admin_alice"), Action: ptr(ActionPIIMaskedRead)},
			[]string{ActionPIIMaskedRead}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := r.ListEvents(ctx, DefaultProjectID, tc.f, httpapi.ListParams{})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			got := actionsOf(page.Items)
			if len(got) != len(tc.want) {
				t.Fatalf("actions = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("actions = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// The reverse lookup of §5.3: "who accessed subject X".
func TestListEventsBySubjectReverseLookup(t *testing.T) {
	pool := testPool(t)
	r := seedEvents(t, pool)
	ctx := context.Background()

	page, err := r.ListEvents(ctx, DefaultProjectID, EventFilter{SubjectID: ptr(subjectA)}, httpapi.ListParams{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := actionsOf(page.Items)
	if len(got) != 2 || got[0] != ActionUserListRead || got[1] != ActionPIIFullRead {
		t.Fatalf("subject A events = %v, want [USER_LIST_READ PII_FULL_READ]", got)
	}

	// An event with several subjects must not be returned twice.
	page, err = r.ListEvents(ctx, DefaultProjectID, EventFilter{SubjectID: ptr(subjectB)}, httpapi.ListParams{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range page.Items {
		if seen[e.ID] {
			t.Fatalf("event %s returned twice by the subject join", e.ID)
		}
		seen[e.ID] = true
	}
	if len(page.Items) != 2 {
		t.Errorf("subject B events = %v, want 2", actionsOf(page.Items))
	}

	// Combining the reverse lookup with an actor filter answers
	// "did admin_alice access subject A".
	page, err = r.ListEvents(ctx, DefaultProjectID,
		EventFilter{SubjectID: ptr(subjectA), ActorID: ptr("admin_alice")}, httpapi.ListParams{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Action != ActionPIIFullRead {
		t.Errorf("alice→A events = %v, want [PII_FULL_READ]", actionsOf(page.Items))
	}

	// Unknown subject: empty, never null.
	page, err = r.ListEvents(ctx, DefaultProjectID, EventFilter{SubjectID: ptr("no-such-subject")}, httpapi.ListParams{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Items == nil || len(page.Items) != 0 {
		t.Errorf("items = %v, want an empty slice", page.Items)
	}
}

func TestListEventsPaginatesWithoutOverlap(t *testing.T) {
	pool := testPool(t)
	r := seedEvents(t, pool)
	ctx := context.Background()

	first, err := r.ListEvents(ctx, DefaultProjectID, EventFilter{}, httpapi.ListParams{Limit: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(first.Items) != 2 || first.NextCursor == nil {
		t.Fatalf("first page = %d items, cursor %v", len(first.Items), first.NextCursor)
	}
	second, err := r.ListEvents(ctx, DefaultProjectID, EventFilter{},
		httpapi.ListParams{Limit: 2, Cursor: *first.NextCursor})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(second.Items) != 1 || second.NextCursor != nil {
		t.Fatalf("second page = %d items, cursor %v", len(second.Items), second.NextCursor)
	}
	for _, a := range first.Items {
		if a.ID == second.Items[0].ID {
			t.Error("pages overlap")
		}
	}
	if !second.Items[0].CreatedAt.Before(first.Items[1].CreatedAt) {
		t.Errorf("page 2 (%v) is not older than page 1 (%v)",
			second.Items[0].CreatedAt, first.Items[1].CreatedAt)
	}

	if _, err := r.ListEvents(ctx, DefaultProjectID, EventFilter{},
		httpapi.ListParams{Cursor: "!!not-base64!!"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("malformed cursor: err = %v, want ErrInvalid", err)
	}
}

func TestGetEventReturnsFullSubjectManifest(t *testing.T) {
	pool := testPool(t)
	r := seedEvents(t, pool)
	ctx := context.Background()

	page, err := r.ListEvents(ctx, DefaultProjectID, EventFilter{Action: ptr(ActionUserListRead)}, httpapi.ListParams{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list: %v (%d items)", err, len(page.Items))
	}
	ev, err := r.GetEvent(ctx, DefaultProjectID, page.Items[0].ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(ev.SubjectIDs) != 2 || ev.SubjectIDs[0] != subjectA || ev.SubjectIDs[1] != subjectB {
		t.Errorf("subject manifest = %v, want [%s %s]", ev.SubjectIDs, subjectA, subjectB)
	}
	if ev.ActorID == nil || *ev.ActorID != "admin_bob" {
		t.Errorf("actor_id = %v", ev.ActorID)
	}
	if ev.ResultCount == nil || *ev.ResultCount != 2 {
		t.Errorf("result_count = %v", ev.ResultCount)
	}
	if ev.Reason != nil {
		t.Errorf("reason = %v, want null for a list read", *ev.Reason)
	}
	if !ev.CreatedAt.Equal(seedBase.Add(time.Minute)) {
		t.Errorf("created_at = %v", ev.CreatedAt)
	}

	// Unknown id and another tenant's event are both 404-shaped.
	if _, err := r.GetEvent(ctx, DefaultProjectID, httpapi.NewID("evt")); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown event: err = %v, want ErrNotFound", err)
	}
	if _, err := r.GetEvent(ctx, "other-project", page.Items[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-project read: err = %v, want ErrNotFound", err)
	}
}

// The reason column added by 0301 round-trips through the sink and the reader.
func TestReasonIsPersistedAndReturned(t *testing.T) {
	pool := testPool(t)
	r := seedEvents(t, pool)
	ctx := context.Background()

	page, err := r.ListEvents(ctx, DefaultProjectID, EventFilter{Action: ptr(ActionPIIFullRead)}, httpapi.ListParams{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list: %v (%d items)", err, len(page.Items))
	}
	got := page.Items[0]
	if got.Reason == nil || *got.Reason != "CS ticket #4417" {
		t.Errorf("reason = %v, want the recorded justification", got.Reason)
	}
	if got.AccessLevel == nil || *got.AccessLevel != AccessFull {
		t.Errorf("access_level = %v, want full", got.AccessLevel)
	}
}

func TestSystemEventHasNullActor(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := NewSink(pool).Append(ctx, ports.AuditEvent{Action: ActionServiceRoleUse}); err != nil {
		t.Fatalf("append: %v", err)
	}
	page, err := NewReader(pool).ListEvents(ctx, DefaultProjectID, EventFilter{}, httpapi.ListParams{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list: %v (%d items)", err, len(page.Items))
	}
	e := page.Items[0]
	if e.ActorID != nil || e.Resource != nil || e.Reason != nil || e.IP != nil {
		t.Errorf("unset fields must be null, got %+v", e)
	}
	if e.ProjectID != DefaultProjectID {
		t.Errorf("project_id = %q", e.ProjectID)
	}
}

func TestReaderRequiresPool(t *testing.T) {
	r := NewReader(nil)
	if _, err := r.ListEvents(context.Background(), DefaultProjectID, EventFilter{}, httpapi.ListParams{}); err == nil {
		t.Error("expected an error with a nil pool")
	}
	if _, err := r.GetEvent(context.Background(), DefaultProjectID, "evt_x"); err == nil {
		t.Error("expected an error with a nil pool")
	}
}

func TestEventCursorRoundTrip(t *testing.T) {
	at := time.Date(2026, 8, 12, 3, 4, 5, 123456000, time.UTC)
	id := httpapi.NewID("evt")
	gotAt, gotID, err := decodeEventCursor(encodeEventCursor(at, id))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotAt == nil || !gotAt.Equal(at) || gotID != id {
		t.Errorf("round trip = (%v,%q), want (%v,%q)", gotAt, gotID, at, id)
	}
	if at, id, err := decodeEventCursor(""); at != nil || id != "" || err != nil {
		t.Errorf("empty cursor = (%v,%q,%v), want (nil,\"\",nil)", at, id, err)
	}
}
