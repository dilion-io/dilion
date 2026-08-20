import { useEffect, useState } from 'react'
import {
  cancelPrivacyRequest,
  getPrivacyRequest,
  toProblem,
  type PrivacyRequest,
  type Problem,
} from '../api/client'
import { ProblemAlert } from './ProblemAlert'
import { RequestTimeline } from './RequestTimeline'
import { PermissionHint } from './PermissionHint'
import { formatDateTime } from '../lib/format'

const POLL_INTERVAL_MS = 2000
const TERMINAL: ReadonlyArray<PrivacyRequest['status']> = ['DONE', 'CANCELED', 'MANUAL_REVIEW']

/**
 * Admin drill-down for a single request: `GET /privacy/v1/requests/{id}`,
 * polled until the status settles, plus `POST .../cancel`. Same timeline
 * component the user-facing Privacy Center renders.
 */
export function RequestInspector({
  requestId,
  onChanged,
  onClose,
}: {
  requestId: string
  onChanged: () => void
  onClose: () => void
}) {
  const [request, setRequest] = useState<PrivacyRequest | null>(null)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let active = true
    setRequest(null)
    getPrivacyRequest(requestId)
      .then((r) => {
        if (!active) return
        setRequest(r)
        setProblem(null)
      })
      .catch((err: unknown) => {
        if (active) setProblem(toProblem(err))
      })
    return () => {
      active = false
    }
  }, [requestId])

  const polling = request !== null && !TERMINAL.includes(request.status)

  useEffect(() => {
    if (!polling) return
    let active = true
    const timer = setInterval(() => {
      getPrivacyRequest(requestId)
        .then((next) => {
          if (!active) return
          setRequest((current) => (current?.status === next.status ? current : next))
          if (TERMINAL.includes(next.status)) onChanged()
        })
        .catch((err: unknown) => {
          if (!active) return
          setProblem(toProblem(err))
          clearInterval(timer)
        })
    }, POLL_INTERVAL_MS)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [polling, requestId, onChanged])

  async function cancel() {
    setBusy(true)
    setProblem(null)
    try {
      setRequest(await cancelPrivacyRequest(requestId))
      onChanged()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h3>Request inspector</h3>
          <p className="muted">
            <code>GET /privacy/v1/requests/{'{id}'}</code>, polled every 2s while the status is
            non-terminal, and <code>POST /privacy/v1/requests/{'{id}'}/cancel</code>. A request that
            hits an active legal hold parks in <code>MANUAL_REVIEW</code> — that is the hold doing
            its job, not a failure.
          </p>
        </div>
        <button className="btn btn-ghost btn-sm" type="button" onClick={onClose}>
          Close
        </button>
      </div>
      <PermissionHint permission="privacy.requests.manage" />

      {problem && <ProblemAlert problem={problem} />}

      {!request ? (
        <p className="muted">Loading {requestId}…</p>
      ) : (
        <>
          <dl className="kv">
            <dt>Request id</dt>
            <dd>
              <code>{request.id}</code>
            </dd>
            <dt>Subject</dt>
            <dd>
              <code>{request.user_id}</code>
            </dd>
            <dt>Type</dt>
            <dd>{request.type}</dd>
            <dt>Status</dt>
            <dd>
              <span className={`badge badge-${request.status.toLowerCase()}`}>
                {request.status}
              </span>
              {polling && <span className="muted small"> · polling every 2s</span>}
            </dd>
            <dt>Policy</dt>
            <dd>
              <code>{request.policy_id}</code>
            </dd>
            <dt>Requested at</dt>
            <dd>{formatDateTime(request.requested_at)}</dd>
            <dt>Scheduled at</dt>
            <dd>{formatDateTime(request.scheduled_at)}</dd>
            <dt>Completed at</dt>
            <dd>{formatDateTime(request.completed_at)}</dd>
          </dl>

          <RequestTimeline request={request} />

          <div className="row">
            <button
              className="btn btn-ghost"
              type="button"
              disabled={busy || TERMINAL.includes(request.status)}
              onClick={() => void cancel()}
            >
              {busy ? 'Working…' : 'Cancel request'}
            </button>
          </div>
        </>
      )}
    </section>
  )
}
