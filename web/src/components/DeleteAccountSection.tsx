import { useEffect, useRef, useState } from 'react'
import {
  cancelPrivacyRequest,
  createMyPrivacyRequest,
  getPrivacyRequest,
  newIdempotencyKey,
  toProblem,
  type PrivacyRequest,
  type Problem,
} from '../api/client'
import { ProblemAlert } from './ProblemAlert'
import { RequestTimeline } from './RequestTimeline'
import { formatDateTime, formatDuration } from '../lib/format'
import { navigate } from '../lib/router'
import { supabase } from '../lib/supabase'

const POLL_INTERVAL_MS = 2000
const TERMINAL: ReadonlyArray<PrivacyRequest['status']> = ['DONE', 'CANCELED', 'MANUAL_REVIEW']

export function DeleteAccountSection({
  userId,
  onChanged,
}: {
  userId: string
  onChanged: () => void
}) {
  const [request, setRequest] = useState<PrivacyRequest | null>(null)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [polling, setPolling] = useState(false)
  // Kept across retries: replaying the same key returns the original response
  // instead of opening a second deletion request.
  const idempotencyKey = useRef<string>(newIdempotencyKey())

  // Poll until the request reaches a terminal status.
  useEffect(() => {
    if (!request || TERMINAL.includes(request.status)) {
      setPolling(false)
      return
    }
    setPolling(true)
    let active = true
    const timer = setInterval(async () => {
      try {
        const next = await getPrivacyRequest(request.id)
        if (!active) return
        setRequest(next)
        if (TERMINAL.includes(next.status)) onChanged()
      } catch (err) {
        if (!active) return
        setProblem(toProblem(err))
        setPolling(false)
        clearInterval(timer)
      }
    }, POLL_INTERVAL_MS)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [request, onChanged])

  async function submit() {
    setBusy(true)
    setProblem(null)
    try {
      const { data } = await supabase.auth.getSession()
      const token = data.session?.access_token
      if (!token) throw new Error('Sign in to delete your account.')
      const created = await createMyPrivacyRequest(
        token,
        { type: 'DELETION' },
        idempotencyKey.current,
      )
      setRequest(created)
      setConfirming(false)
      onChanged()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  async function cancel() {
    if (!request) return
    setBusy(true)
    setProblem(null)
    try {
      setRequest(await cancelPrivacyRequest(request.id))
      idempotencyKey.current = newIdempotencyKey()
      onChanged()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  const graceMs = request
    ? new Date(request.scheduled_at).getTime() - new Date(request.requested_at).getTime()
    : 0

  return (
    <section className="card">
      <h2>Delete my account</h2>
      <p className="muted">
        <code>POST /privacy/v1/me/requests</code> with <code>{'{ type: "DELETION" }'}</code>,
        your own access token and an <code>Idempotency-Key</code> header. It needs a recent
        sign-in (<code>DILION_AUTH_SECURITY_DELETION_REAUTH_WINDOW</code>, 10 minutes by default);
        an older one answers <code>403 reauthentication_needed</code>.
        The server answers <code>202 Accepted</code> — erasure is orchestrated asynchronously
        across every registered destination, and this page polls{' '}
        <code>GET /privacy/v1/requests/{'{id}'}</code> until it settles.
      </p>

      {problem && <ProblemAlert problem={problem} />}
      {problem?.code === 'reauthentication_needed' && (
        <div className="row">
          <button
            className="btn"
            type="button"
            onClick={() => void supabase.auth.signOut().then(() => navigate('signin'))}
          >
            Sign in again
          </button>
        </div>
      )}

      {!request && (
        <>
          {!confirming ? (
            <button className="btn btn-danger" onClick={() => setConfirming(true)}>
              Request account deletion
            </button>
          ) : (
            <div className="confirm">
              <p>
                This opens a compliance deletion request for{' '}
                <code>{userId}</code>. After the grace period expires, your account and the
                personal data held in every connected destination are erased. This cannot be
                undone once processing starts.
              </p>
              <div className="row">
                <button className="btn btn-danger" onClick={() => void submit()} disabled={busy}>
                  {busy ? 'Submitting…' : 'Yes, delete my account'}
                </button>
                <button
                  className="btn btn-ghost"
                  onClick={() => setConfirming(false)}
                  disabled={busy}
                >
                  Keep my account
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {request && (
        <div className="request-detail">
          <dl className="kv">
            <dt>Request id</dt>
            <dd>
              <code>{request.id}</code>
            </dd>
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

          <p className="muted small">
            <strong>Grace period:</strong>{' '}
            {graceMs > 1000 ? (
              <>
                erasure is scheduled {formatDuration(graceMs)} after the request (
                {formatDateTime(request.scheduled_at)}). Until then the request can be cancelled
                and nothing has been destroyed — this is what lets a user change their mind, and
                what a legal hold suspends.
              </>
            ) : (
              <>
                the policy applied to this request (<code>{request.policy_id}</code>) schedules
                erasure immediately, so the pipeline starts without a cancellation window. A
                production policy usually keeps a grace window of days.
              </>
            )}
          </p>

          <div className="row">
            {!TERMINAL.includes(request.status) && (
              <button className="btn btn-ghost" onClick={() => void cancel()} disabled={busy}>
                Cancel request
              </button>
            )}
            <button
              className="btn btn-ghost"
              onClick={() => {
                setRequest(null)
                setProblem(null)
                idempotencyKey.current = newIdempotencyKey()
              }}
            >
              Start over
            </button>
          </div>
        </div>
      )}
    </section>
  )
}
