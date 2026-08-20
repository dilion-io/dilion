import { useCallback, useEffect, useState } from 'react'
import {
  getAuditEvent,
  listAuditEvents,
  toProblem,
  type AuditEvent,
  type AuditEventPage,
  type Problem,
} from '../api/client'
import { PAGE_SIZE, usePagedList } from '../lib/usePagedList'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'
import { Pager } from '../components/Pager'
import { formatDateTime } from '../lib/format'
import { navigate } from '../lib/router'
import { stash, takeStash } from '../lib/handoff'

/**
 * Mirror of the action constants in `internal/audit/audit.go` (§5.2), grouped
 * the way an operator thinks about them. Read actions name the RECORD KIND that
 * was read, not the screen: `USER_*` is the account directory only, while
 * subject-scoped reads under `/privacy/v1` each have their own action.
 *
 * The list is only a convenience for the picker — `action` is a free-text
 * filter, so an action this build has never heard of is still typeable, and
 * anything the server actually returns is folded in below.
 */
const ACTION_GROUPS: readonly { readonly label: string; readonly actions: readonly string[] }[] = [
  {
    label: 'Accounts',
    actions: [
      'USER_LIST_READ',
      'USER_DETAIL_READ',
      'USER_CREATED',
      'USER_UPDATED',
      'USER_DELETED',
    ],
  },
  {
    label: 'PII',
    actions: ['PII_MASKED_READ', 'PII_FULL_READ', 'PII_UPDATE', 'PII_EXPORT'],
  },
  {
    label: 'Privacy requests',
    actions: [
      'PRIVACY_REQUEST_CREATED',
      'PRIVACY_REQUEST_CANCELED',
      'PRIVACY_REQUEST_LIST_READ',
      'PRIVACY_REQUEST_DETAIL_READ',
    ],
  },
  {
    label: 'Consent',
    actions: ['CONSENT_CHANGED', 'CONSENT_READ'],
  },
  {
    label: 'Holds & destinations',
    actions: [
      'HOLD_CREATED',
      'HOLD_RELEASED',
      'LEGAL_HOLD_LIST_READ',
      'DESTINATION_CHANGED',
      'DESTINATION_READ',
    ],
  },
  {
    label: 'IAM',
    actions: [
      'ROLE_GRANTED',
      'ROLE_REVOKED',
      'ROLE_CREATED',
      'PERMISSION_CREATED',
      'API_KEY_CREATED',
      'API_KEY_REVOKED',
      'IAM_READ',
    ],
  },
  {
    label: 'Security',
    actions: ['SERVICE_ROLE_USED', 'PERMISSION_DENIED'],
  },
]

const KNOWN_ACTIONS: ReadonlySet<string> = new Set(ACTION_GROUPS.flatMap((g) => g.actions))

/**
 * The "매우 민감" grade of §5.2: actions that either disclose unmasked personal
 * data or change who is allowed to. They get a quiet marker in the table so an
 * eye scanning a page of events lands on them first.
 */
const HIGH_SENSITIVITY: ReadonlySet<string> = new Set([
  'PII_FULL_READ',
  'PII_EXPORT',
  'USER_DELETED',
  'USER_UPDATED',
  'CONSENT_CHANGED',
  'ROLE_GRANTED',
  'ROLE_REVOKED',
  'ROLE_CREATED',
  'PERMISSION_CREATED',
  'API_KEY_CREATED',
  'API_KEY_REVOKED',
  'SERVICE_ROLE_USED',
])

/**
 * A denial is not a sensitivity grade — it is the opposite outcome — so it is
 * kept visually distinct from the "매우 민감" marker.
 */
function actionCue(action: string): { className: string; text: string; title: string } | null {
  if (action === 'PERMISSION_DENIED') {
    return {
      className: 'tag tag-denied',
      text: 'denied',
      title: 'The request was refused — no data was disclosed.',
    }
  }
  if (HIGH_SENSITIVITY.has(action)) {
    return {
      className: 'tag',
      text: '매우 민감',
      title: '§5.2 매우 민감 — unmasked disclosure or a change to who may access.',
    }
  }
  return null
}

/** `access_level` is a free string on the wire; colour the three it uses. */
function accessBadge(level: string | null): string {
  switch (level) {
    case 'full':
      return 'badge badge-manual_review'
    case 'masked':
      return 'badge badge-done'
    default:
      return 'badge badge-canceled'
  }
}

type Filters = { actorId: string; action: string; subjectId: string }

const NO_FILTERS: Filters = { actorId: '', action: '', subjectId: '' }

export function AdminAuditPage() {
  // A subject handed over from the Users screen ("who looked at this user?").
  const [filters, setFilters] = useState<Filters>(() => ({
    ...NO_FILTERS,
    subjectId: takeStash('auditSubjectId'),
  }))
  const [draft, setDraft] = useState<Filters>(filters)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // Actions observed in results that this build does not know about, so the
  // picker grows with whatever the server records.
  const [extraActions, setExtraActions] = useState<readonly string[]>([])

  const load = useCallback(
    (cursor?: string): Promise<AuditEventPage> =>
      listAuditEvents({
        limit: PAGE_SIZE,
        ...(cursor ? { cursor } : {}),
        ...(filters.actorId ? { actor_id: filters.actorId } : {}),
        ...(filters.action ? { action: filters.action } : {}),
        ...(filters.subjectId ? { subject_id: filters.subjectId } : {}),
      }),
    [filters],
  )
  const events = usePagedList<AuditEvent>(load, JSON.stringify(filters))

  useEffect(() => {
    setExtraActions((prev) => {
      const next = new Set(prev)
      for (const e of events.items) {
        if (!KNOWN_ACTIONS.has(e.action)) next.add(e.action)
      }
      return next.size === prev.length ? prev : [...next].sort()
    })
  }, [events.items])

  const active = filters.actorId || filters.action || filters.subjectId

  function apply(e: React.FormEvent) {
    e.preventDefault()
    setSelectedId(null)
    setFilters({
      actorId: draft.actorId.trim(),
      action: draft.action.trim(),
      subjectId: draft.subjectId.trim(),
    })
  }

  return (
    <>
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Audit trail</h2>
            <p className="muted">
              <code>GET /iam/v1/audit/events</code> — the append-only record of who did what to
              whom (§5.2). Events come back newest first. The log has <strong>no</strong> write
              endpoint, and reading it is deliberately not itself audited: an access event per
              audit read would recurse without adding evidence (§5.4).
            </p>
          </div>
        </div>
        <PermissionHint permission="audit.read" />

        <form className="form" onSubmit={apply}>
          <div className="row">
            <label className="select">
              actor_id — who acted
              <input
                value={draft.actorId}
                onChange={(e) => setDraft({ ...draft, actorId: e.target.value })}
                placeholder="00000000-0000-0000-0000-000000000000 or key_…"
              />
            </label>
            <label className="select">
              action
              <input
                list="audit-actions"
                value={draft.action}
                onChange={(e) => setDraft({ ...draft, action: e.target.value })}
                placeholder="PII_FULL_READ (or type any action)"
              />
              <datalist id="audit-actions">
                {ACTION_GROUPS.map((group) =>
                  group.actions.map((a) => <option key={a} value={a} label={group.label} />),
                )}
                {extraActions.map((a) => (
                  <option key={a} value={a} label="Seen in results" />
                ))}
              </datalist>
            </label>
            <label className="select">
              subject_id — 이 사용자를 누가 봤는가
              <input
                value={draft.subjectId}
                onChange={(e) => setDraft({ ...draft, subjectId: e.target.value })}
                placeholder="user_id of the data subject"
              />
            </label>
          </div>
          <p className="muted small">
            <code>subject_id</code> is the reverse lookup of §5.3: it matches against each
            event&rsquo;s <em>subject manifest</em>, so it answers &ldquo;who accessed this data
            subject&rdquo; rather than &ldquo;what did this operator do&rdquo;. The manifest itself
            is only returned by the single-event read below.
          </p>
          <div className="row">
            <button className="btn" type="submit" disabled={events.loading}>
              Apply filters
            </button>
            {active && (
              <button
                className="btn btn-ghost"
                type="button"
                onClick={() => {
                  setDraft(NO_FILTERS)
                  setFilters(NO_FILTERS)
                  setSelectedId(null)
                }}
              >
                Clear
              </button>
            )}
          </div>
        </form>

        {events.problem && <ProblemAlert problem={events.problem} />}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>created_at</th>
                <th>action</th>
                <th>actor</th>
                <th>access_level</th>
                <th>reason</th>
                <th>result_count</th>
              </tr>
            </thead>
            <tbody>
              {events.items.map((e) => (
                <tr
                  key={e.id}
                  className={`row-clickable${e.id === selectedId ? ' is-mine' : ''}`}
                  onClick={() => setSelectedId(e.id === selectedId ? null : e.id)}
                >
                  <td className="small">{formatDateTime(e.created_at)}</td>
                  <td>
                    <code>{e.action}</code>
                    <ActionCue action={e.action} />
                  </td>
                  <td className="small">
                    <code>{e.actor_id ?? '—'}</code>
                    {e.actor_type && <span className="muted"> · {e.actor_type}</span>}
                  </td>
                  <td>
                    <span className={accessBadge(e.access_level)}>{e.access_level ?? 'n/a'}</span>
                  </td>
                  <td className="cell-wrap">{e.reason ?? <span className="muted">—</span>}</td>
                  <td>{e.result_count ?? <span className="muted">—</span>}</td>
                </tr>
              ))}
              {events.items.length === 0 && !events.loading && (
                <tr>
                  <td colSpan={6} className="muted">
                    No audit events{active ? ' for these filters' : ''}.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pager list={events} unit="event" />
      </section>

      {selectedId && (
        <AuditEventDetail
          key={selectedId}
          eventId={selectedId}
          onFilterSubject={(subjectId) => {
            setDraft({ ...NO_FILTERS, subjectId })
            setFilters({ ...NO_FILTERS, subjectId })
            setSelectedId(null)
          }}
        />
      )}
    </>
  )
}

/**
 * `GET /iam/v1/audit/events/{eventId}` — the only read that carries the subject
 * manifest. List rows always report `subject_ids: []`, so a row click is not
 * cosmetic: it is a second request for evidence the list withholds.
 */
function AuditEventDetail({
  eventId,
  onFilterSubject,
}: {
  eventId: string
  onFilterSubject: (subjectId: string) => void
}) {
  const [event, setEvent] = useState<AuditEvent | null>(null)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    setLoading(true)
    getAuditEvent(eventId)
      .then((e) => {
        if (!active) return
        setEvent(e)
        setProblem(null)
      })
      .catch((err: unknown) => {
        if (active) setProblem(toProblem(err))
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [eventId])

  return (
    <section className="card">
      <h3>Event detail</h3>
      <p className="muted">
        <code>
          GET /iam/v1/audit/events/{'{'}eventId{'}'}
        </code>{' '}
        — same row as above plus its <code>subject_ids</code> manifest: every data subject the
        action touched.
      </p>
      <PermissionHint permission="audit.read" />

      {problem && <ProblemAlert problem={problem} />}
      {loading && !event && <p className="muted">Loading…</p>}

      {event && (
        <>
          <dl className="kv">
            <dt>Event id</dt>
            <dd>
              <code>{event.id}</code>
            </dd>
            <dt>Action</dt>
            <dd>
              <code>{event.action}</code>
              <ActionCue action={event.action} />
            </dd>
            <dt>Access level</dt>
            <dd>
              <span className={accessBadge(event.access_level)}>{event.access_level ?? 'n/a'}</span>
            </dd>
            <dt>Actor</dt>
            <dd>
              <code>{event.actor_id ?? '— (system)'}</code>
              {event.actor_type && <span className="muted"> · {event.actor_type}</span>}
            </dd>
            <dt>Resource</dt>
            <dd>
              <code>{event.resource ?? '—'}</code>
            </dd>
            <dt>Reason</dt>
            <dd>{event.reason ?? <span className="muted">— (none recorded)</span>}</dd>
            <dt>Result count</dt>
            <dd>{event.result_count ?? '—'}</dd>
            <dt>Request id</dt>
            <dd>
              <code>{event.request_id ?? '—'}</code>
            </dd>
            <dt>IP</dt>
            <dd>
              <code>{event.ip ?? '—'}</code>
            </dd>
            <dt>User agent</dt>
            <dd className="small">{event.user_agent ?? '—'}</dd>
            <dt>Created at</dt>
            <dd>{formatDateTime(event.created_at)}</dd>
          </dl>

          <h4>Subject manifest</h4>
          {event.subject_ids.length === 0 ? (
            <p className="muted small">
              No data subject was touched by this action — infrastructure events (
              <code>SERVICE_ROLE_USED</code>, <code>ROLE_GRANTED</code>, …) carry an empty
              manifest.
            </p>
          ) : (
            <ul className="manifest">
              {event.subject_ids.map((subjectId) => (
                <li key={subjectId}>
                  <code>{subjectId}</code>
                  <div className="row row-tight">
                    <button
                      className="btn btn-ghost btn-sm"
                      type="button"
                      onClick={() => {
                        stash('userId', subjectId)
                        navigate('admin-users')
                      }}
                    >
                      PII profile
                    </button>
                    <button
                      className="btn btn-ghost btn-sm"
                      type="button"
                      onClick={() => onFilterSubject(subjectId)}
                    >
                      Who else saw them
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}

          <details className="raw">
            <summary className="muted small">Raw event</summary>
            <pre className="json">{JSON.stringify(event, null, 2)}</pre>
          </details>
        </>
      )}
    </section>
  )
}

/** The §5.2 sensitivity / denial marker next to an action name. */
function ActionCue({ action }: { action: string }) {
  const cue = actionCue(action)
  if (!cue) return null
  return (
    <span className={cue.className} title={cue.title}>
      {cue.text}
    </span>
  )
}
