import { useCallback, useState } from 'react'
import {
  createPrivacyRequest,
  newIdempotencyKey,
  toProblem,
  type PrivacyRequest,
  type PrivacyRequestType,
  type Problem,
} from '../api/client'
import { RequestsList } from '../components/RequestsList'
import { RequestInspector } from '../components/RequestInspector'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'
import { takeStash } from '../lib/handoff'

const TYPES: PrivacyRequestType[] = ['DELETION', 'EXPORT', 'CONSENT_WITHDRAWAL']

export function AdminRequestsPage() {
  const [reloadToken, setReloadToken] = useState(0)
  const reload = useCallback(() => setReloadToken((n) => n + 1), [])
  const [selected, setSelected] = useState<string | null>(null)

  const [userId, setUserId] = useState(() => takeStash('userId'))
  const [type, setType] = useState<PrivacyRequestType>('DELETION')
  const [immediate, setImmediate] = useState(false)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [created, setCreated] = useState<PrivacyRequest | null>(null)

  const [lookup, setLookup] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setProblem(null)
    try {
      const request = await createPrivacyRequest(
        { user_id: userId.trim(), type, ...(immediate ? { immediate: true } : {}) },
        newIdempotencyKey(),
      )
      setCreated(request)
      setSelected(request.id)
      reload()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <section className="card">
        <h2>Data-subject requests</h2>
        <p className="muted">
          The operator view of the same endpoints the Privacy Center calls on the subject&rsquo;s
          behalf: open a request for any <code>user_id</code>, inspect its lifecycle, cancel it
          while it is still inside the grace window.
        </p>
        <PermissionHint permission="privacy.requests.manage" />
      </section>

      <section className="card">
        <h3>Open a request</h3>
        <p className="muted">
          <code>POST /privacy/v1/requests</code> with{' '}
          <code>{'{ user_id, type, immediate? }'}</code> and an <code>Idempotency-Key</code> header
          (<code>202 Accepted</code>). <code>immediate: true</code> skips the grace period, which is
          what makes the erasure pipeline observable in a demo.
        </p>

        {problem && <ProblemAlert problem={problem} />}
        {created && (
          <div className="alert alert-info">
            Accepted <code>{created.id}</code> — <strong>{created.status}</strong>, scheduled{' '}
            {new Date(created.scheduled_at).toLocaleString()} under policy{' '}
            <code>{created.policy_id}</code>.
          </div>
        )}

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
            Type
            <select value={type} onChange={(e) => setType(e.target.value as PrivacyRequestType)}>
              {TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label className="switch">
            <input
              type="checkbox"
              checked={immediate}
              onChange={(e) => setImmediate(e.target.checked)}
            />
            <span>immediate — skip the grace period</span>
          </label>
          <div className="row">
            <button className="btn" type="submit" disabled={busy || userId.trim().length === 0}>
              {busy ? 'Submitting…' : 'Create request'}
            </button>
          </div>
        </form>
      </section>

      <section className="card">
        <h3>Inspect by id</h3>
        <p className="muted">
          Paste a <code>pr_…</code> id (from a log line, a webhook payload, a support ticket) to
          open it directly.
        </p>
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault()
            if (lookup.trim()) setSelected(lookup.trim())
          }}
        >
          <label>
            Request id
            <input
              value={lookup}
              onChange={(e) => setLookup(e.target.value)}
              placeholder="pr_1f0c0b6a7d5e4a2b9c8d7e6f5a4b3c2d"
            />
          </label>
          <div className="row">
            <button className="btn btn-ghost" type="submit" disabled={lookup.trim().length === 0}>
              Open
            </button>
          </div>
        </form>
      </section>

      {selected && (
        <RequestInspector
          key={selected}
          requestId={selected}
          onChanged={reload}
          onClose={() => setSelected(null)}
        />
      )}

      <RequestsList
        reloadToken={reloadToken}
        onSelect={(r) => setSelected(r.id)}
        selectedId={selected ?? undefined}
      />
    </>
  )
}
