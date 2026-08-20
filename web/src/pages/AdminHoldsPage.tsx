import { useCallback, useState } from 'react'
import {
  createLegalHold,
  listLegalHolds,
  releaseLegalHold,
  toProblem,
  type CreateLegalHoldBody,
  type LegalHold,
  type LegalHoldPage,
  type Problem,
} from '../api/client'
import { PAGE_SIZE, usePagedList } from '../lib/usePagedList'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'
import { Pager } from '../components/Pager'
import { formatDateTime } from '../lib/format'
import { navigate } from '../lib/router'
import { stash, takeStash } from '../lib/handoff'

export function AdminHoldsPage() {
  const [userFilter, setUserFilter] = useState(() => takeStash('userId'))
  const [userDraft, setUserDraft] = useState(userFilter)

  const load = useCallback(
    (cursor?: string): Promise<LegalHoldPage> =>
      listLegalHolds({
        limit: PAGE_SIZE,
        ...(cursor ? { cursor } : {}),
        ...(userFilter ? { user_id: userFilter } : {}),
      }),
    [userFilter],
  )
  const holds = usePagedList<LegalHold>(load, userFilter)

  const [userId, setUserId] = useState('')
  const [reason, setReason] = useState('')
  const [basis, setBasis] = useState('')
  const [domain, setDomain] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setProblem(null)
    setNotice(null)
    try {
      const body: CreateLegalHoldBody = {
        user_id: userId.trim(),
        reason: reason.trim(),
        basis: basis.trim(),
        ...(domain.trim() ? { domain: domain.trim() } : {}),
      }
      const created = await createLegalHold(body)
      setNotice(
        `Hold ${created.id} placed on ${created.user_id}. A DELETION request for this subject will now park in MANUAL_REVIEW instead of erasing.`,
      )
      setReason('')
      setBasis('')
      setDomain('')
      holds.reload()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  async function release(hold: LegalHold) {
    setBusy(true)
    setProblem(null)
    setNotice(null)
    try {
      const released = await releaseLegalHold(hold.id)
      setNotice(
        `Released ${released.id} at ${formatDateTime(released.released_at)}. Requests parked in MANUAL_REVIEW for ${released.user_id} can now be re-driven.`,
      )
      holds.reload()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Legal holds</h2>
            <p className="muted">
              <code>GET /privacy/v1/holds</code> — a hold suspends erasure for a data subject (or a
              single data domain). It outranks a deletion request: while one is active the pipeline
              refuses to destroy and the request parks in <code>MANUAL_REVIEW</code>.
            </p>
          </div>
        </div>
        <PermissionHint permission="holds.manage" />

        <div className="row">
          <label className="select">
            Filter by user_id
            <input
              value={userDraft}
              onChange={(e) => setUserDraft(e.target.value)}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </label>
          <button
            className="btn btn-ghost btn-sm"
            type="button"
            onClick={() => setUserFilter(userDraft.trim())}
          >
            Apply filter
          </button>
          {userFilter && (
            <button
              className="btn btn-ghost btn-sm"
              type="button"
              onClick={() => {
                setUserDraft('')
                setUserFilter('')
              }}
            >
              Clear
            </button>
          )}
        </div>

        {holds.problem && <ProblemAlert problem={holds.problem} />}
        {problem && <ProblemAlert problem={problem} />}
        {notice && <div className="alert alert-info">{notice}</div>}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Hold</th>
                <th>Subject</th>
                <th>Domain</th>
                <th>Reason</th>
                <th>Basis</th>
                <th>Created</th>
                <th>Released</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {holds.items.map((h) => (
                <tr key={h.id}>
                  <td>
                    <code className="small">{h.id}</code>
                  </td>
                  <td>
                    <code className="small">{h.user_id}</code>
                  </td>
                  <td>{h.domain ?? <span className="muted">whole subject</span>}</td>
                  <td className="cell-wrap">{h.reason}</td>
                  <td className="cell-wrap">{h.basis}</td>
                  <td className="small">{formatDateTime(h.created_at)}</td>
                  <td className="small">
                    {h.released_at ? (
                      formatDateTime(h.released_at)
                    ) : (
                      <span className="badge badge-manual_review">ACTIVE</span>
                    )}
                  </td>
                  <td>
                    <div className="row row-tight">
                      {h.released_at === null && (
                        <button
                          className="btn btn-ghost btn-sm"
                          type="button"
                          disabled={busy}
                          onClick={() => void release(h)}
                        >
                          Release
                        </button>
                      )}
                      <button
                        className="btn btn-ghost btn-sm"
                        type="button"
                        onClick={() => {
                          stash('userId', h.user_id)
                          navigate('admin-requests')
                        }}
                      >
                        Requests
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {holds.items.length === 0 && !holds.loading && (
                <tr>
                  <td colSpan={8} className="muted">
                    No holds.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pager list={holds} unit="hold" />
      </section>

      <section className="card">
        <h3>Place a legal hold</h3>
        <p className="muted">
          <code>POST /privacy/v1/holds</code> with{' '}
          <code>{'{ user_id, reason, basis, domain? }'}</code>. <code>reason</code> is the
          operational note, <code>basis</code> the legal ground (litigation hold, tax retention,
          regulatory request). Omit <code>domain</code> to hold the whole subject.{' '}
          <code>POST /privacy/v1/holds/{'{id}'}/release</code> lifts it.
        </p>
        <PermissionHint permission="holds.manage" />

        <form className="form" onSubmit={(e) => void submit(e)}>
          <label>
            user_id (UUID)
            <input
              required
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </label>
          <label>
            reason
            <input
              required
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Litigation hold — case 2026-114"
            />
          </label>
          <label>
            basis
            <input
              required
              value={basis}
              onChange={(e) => setBasis(e.target.value)}
              placeholder="Court preservation order"
            />
          </label>
          <label>
            domain (optional)
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="billing"
            />
          </label>
          <div className="row">
            <button
              className="btn btn-danger"
              type="submit"
              disabled={busy || !userId.trim() || !reason.trim() || !basis.trim()}
            >
              {busy ? 'Placing…' : 'Place hold'}
            </button>
          </div>
        </form>
      </section>
    </>
  )
}
