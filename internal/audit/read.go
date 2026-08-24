package audit

// Audit read path (project.md §5.3). The sink is append-only; this file is the
// only place that SELECTs from dilion_audit.*.
//
// Two questions must be answerable from the recorded evidence:
//
//	"what did actor A do"      → EventFilter{ActorID: &a}
//	"who accessed subject X"   → EventFilter{SubjectID: &x}  (reverse lookup)
//
// Reading the audit log is deliberately *not* itself an audited action: an
// access record for every access record recurses without adding evidence.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/httpapi"
)

// ---- Sentinel errors (internal/api maps these to problem+json codes) ----

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrNotFound Error = "audit: not found"
	ErrInvalid  Error = "audit: invalid argument"
)

// Event is one recorded access event. Field values that were not supplied are
// null rather than empty, so "not recorded" stays distinguishable from "empty
// string" in the evidence (§5.1).
type Event struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id"`
	ActorID     *string   `json:"actor_id"`
	ActorType   *string   `json:"actor_type"`
	Action      string    `json:"action"`
	Resource    *string   `json:"resource"`
	AccessLevel *string   `json:"access_level"`
	RequestID   *string   `json:"request_id"`
	ResultCount *int      `json:"result_count"`
	Reason      *string   `json:"reason"`
	IP          *string   `json:"ip"`
	UserAgent   *string   `json:"user_agent"`
	CreatedAt   time.Time `json:"created_at"`
	// SubjectIDs is the subject manifest (§5.3). It is populated by GetEvent
	// only: a list response must not inline N subject ids per row.
	SubjectIDs []string `json:"subject_ids"`
}

// EventFilter narrows ListEvents. A nil field means "no filter"; the zero value
// lists the whole project newest-first.
type EventFilter struct {
	ActorID   *string
	Action    *string
	SubjectID *string    // reverse lookup against the subject manifest (§5.3)
	From      *time.Time // created_at >= (inclusive) — 정기 점검 리포트용 기간 창
	To        *time.Time // created_at < (exclusive)
}

// Reader is the read side of the audit log. It issues SELECTs only.
type Reader struct {
	pools PoolFunc
}

// NewReader returns the Postgres-backed audit reader over one fixed pool.
// Constructing it performs no I/O, so it is safe to build with a nil pool
// (spec generation).
func NewReader(pool *pgxpool.Pool) *Reader { return &Reader{pools: StaticPool(pool)} }

// NewReaderFor returns the audit reader over a per-request pool provider.
func NewReaderFor(pools PoolFunc) *Reader { return &Reader{pools: pools} }

func (r *Reader) db(ctx context.Context) (*pgxpool.Pool, error) {
	if r == nil {
		return nil, fmt.Errorf("audit: nil pool")
	}
	return resolvePool(ctx, r.pools)
}

const eventColumns = `e.event_id, e.project_id, e.actor_id, e.actor_type, e.action,
	e.resource, e.access_level, e.request_id, e.result_count, e.reason,
	e.ip, e.user_agent, e.created_at`

func scanEvent(row pgx.Row) (Event, error) {
	var e Event
	err := row.Scan(&e.ID, &e.ProjectID, &e.ActorID, &e.ActorType, &e.Action,
		&e.Resource, &e.AccessLevel, &e.RequestID, &e.ResultCount, &e.Reason,
		&e.IP, &e.UserAgent, &e.CreatedAt)
	if err != nil {
		return Event{}, err
	}
	e.CreatedAt = e.CreatedAt.UTC()
	e.SubjectIDs = []string{}
	return e, nil
}

// ListEvents returns one page of events, newest first. The subject manifest is
// not inlined (§5.3) — use GetEvent for a single event's full subject list.
func (r *Reader) ListEvents(ctx context.Context, projectID string, f EventFilter, p httpapi.ListParams) (httpapi.Page[Event], error) {
	var page httpapi.Page[Event]
	pool, err := r.db(ctx)
	if err != nil {
		return page, err
	}
	p = p.Norm()
	at, id, err := decodeEventCursor(p.Cursor)
	if err != nil {
		return page, err
	}

	// The subject filter is a semi-join against the manifest: an event with
	// several subjects must still appear exactly once.
	rows, err := pool.Query(ctx, `
		select `+eventColumns+`
		from dilion_audit.events e
		where e.project_id = $1
		  and ($2::text is null or e.actor_id = $2)
		  and ($3::text is null or e.action = $3)
		  and ($4::text is null or exists (
		        select 1 from dilion_audit.subjects s
		        where s.event_id = e.event_id and s.subject_id = $4))
		  and ($5::timestamptz is null or e.created_at >= $5)
		  and ($6::timestamptz is null or e.created_at < $6)
		  and ($7::timestamptz is null or (e.created_at, e.event_id) < ($7, $8))
		order by e.created_at desc, e.event_id desc
		limit $9`,
		projectOr(projectID), f.ActorID, f.Action, f.SubjectID, f.From, f.To, at, id, p.Limit+1)
	if err != nil {
		return page, fmt.Errorf("audit: list events: %w", err)
	}
	defer rows.Close()
	items := []Event{}
	for rows.Next() {
		it, err := scanEvent(rows)
		if err != nil {
			return page, fmt.Errorf("audit: list events: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return page, fmt.Errorf("audit: list events: %w", err)
	}

	page.Items = items
	if len(items) > p.Limit {
		page.Items = items[:p.Limit]
		last := page.Items[len(page.Items)-1]
		c := encodeEventCursor(last.CreatedAt, last.ID)
		page.NextCursor = &c
	}
	return page, nil
}

// GetEvent returns one event together with its full subject manifest. Events of
// another project are reported as not found (존재 노출 방지).
func (r *Reader) GetEvent(ctx context.Context, projectID, eventID string) (*Event, error) {
	pool, err := r.db(ctx)
	if err != nil {
		return nil, err
	}
	e, err := scanEvent(pool.QueryRow(ctx, `
		select `+eventColumns+`
		from dilion_audit.events e
		where e.project_id = $1 and e.event_id = $2`, projectOr(projectID), eventID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("audit: get event: %w", err)
	}

	rows, err := pool.Query(ctx, `
		select subject_id from dilion_audit.subjects
		where event_id = $1 order by subject_id asc`, e.ID)
	if err != nil {
		return nil, fmt.Errorf("audit: get event subjects: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("audit: get event subjects: %w", err)
		}
		e.SubjectIDs = append(e.SubjectIDs, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: get event subjects: %w", err)
	}
	return &e, nil
}

// ---- helpers ----

func projectOr(p string) string {
	if p == "" {
		return DefaultProjectID
	}
	return p
}

// encodeEventCursor packs the keyset position (created_at, event_id) into the
// opaque cursor string of docs/api-conventions.md.
func encodeEventCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(at.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodeEventCursor(c string) (*time.Time, string, error) {
	if c == "" {
		return nil, "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, "", fmt.Errorf("%w: malformed cursor", ErrInvalid)
	}
	ts, id, ok := strings.Cut(string(raw), "|")
	if !ok || id == "" {
		return nil, "", fmt.Errorf("%w: malformed cursor", ErrInvalid)
	}
	at, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return nil, "", fmt.Errorf("%w: malformed cursor", ErrInvalid)
	}
	at = at.UTC()
	return &at, id, nil
}
