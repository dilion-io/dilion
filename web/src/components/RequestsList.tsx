import { useCallback, useState } from 'react'
import {
  listPrivacyRequests,
  type PrivacyRequest,
  type PrivacyRequestPage,
  type PrivacyRequestStatus,
} from '../api/client'
import { ProblemAlert } from './ProblemAlert'
import { Pager } from './Pager'
import { PAGE_SIZE, usePagedList } from '../lib/usePagedList'
import { formatDateTime } from '../lib/format'

const STATUSES: PrivacyRequestStatus[] = [
  'REQUESTED',
  'PROCESSING',
  'DONE',
  'MANUAL_REVIEW',
  'CANCELED',
]

/**
 * The management list of data-subject requests, shared by the Privacy Center
 * and the admin console. `userId` only highlights rows; the endpoint always
 * returns every subject. `onSelect` turns rows into a drill-down.
 */
export function RequestsList({
  userId,
  reloadToken,
  onSelect,
  selectedId,
}: {
  userId?: string
  reloadToken: number
  onSelect?: (request: PrivacyRequest) => void
  selectedId?: string
}) {
  const [status, setStatus] = useState<PrivacyRequestStatus | ''>('')

  const load = useCallback(
    (cursor?: string): Promise<PrivacyRequestPage> =>
      listPrivacyRequests({
        limit: PAGE_SIZE,
        sort: '-requested_at',
        ...(cursor ? { cursor } : {}),
        ...(status ? { status } : {}),
      }),
    [status],
  )
  const list = usePagedList<PrivacyRequest>(load, `${status}|${reloadToken}`)

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Privacy requests</h2>
          <p className="muted">
            <code>GET /privacy/v1/requests</code> — cursor pagination (
            <code>{'{ items, next_cursor }'}</code>), <code>limit={PAGE_SIZE}</code>,{' '}
            <code>sort=-requested_at</code>. This is the management view, so it lists every data
            subject{userId ? '; rows for the signed-in user are highlighted' : ''}.
          </p>
        </div>
        <label className="select">
          Status
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as PrivacyRequestStatus | '')}
          >
            <option value="">All</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </div>

      {list.problem && <ProblemAlert problem={list.problem} />}

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Request</th>
              <th>Subject</th>
              <th>Type</th>
              <th>Status</th>
              <th>Requested</th>
              <th>Scheduled</th>
              {onSelect && <th />}
            </tr>
          </thead>
          <tbody>
            {list.items.map((r) => (
              <tr
                key={r.id}
                className={r.user_id === userId || r.id === selectedId ? 'is-mine' : ''}
              >
                <td>
                  <code className="small">{r.id}</code>
                </td>
                <td>
                  <code className="small">{r.user_id.slice(0, 8)}…</code>
                  {r.user_id === userId && <span className="tag">you</span>}
                </td>
                <td>{r.type}</td>
                <td>
                  <span className={`badge badge-${r.status.toLowerCase()}`}>{r.status}</span>
                </td>
                <td className="small">{formatDateTime(r.requested_at)}</td>
                <td className="small">{formatDateTime(r.scheduled_at)}</td>
                {onSelect && (
                  <td>
                    <button className="btn btn-ghost btn-sm" type="button" onClick={() => onSelect(r)}>
                      Inspect
                    </button>
                  </td>
                )}
              </tr>
            ))}
            {list.items.length === 0 && !list.loading && (
              <tr>
                <td colSpan={onSelect ? 7 : 6} className="muted">
                  No requests.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <Pager list={list} unit="row" />
    </section>
  )
}
