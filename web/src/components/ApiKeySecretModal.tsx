import { useState } from 'react'
import {
  listPrivacyRequestsAs,
  toProblem,
  type ApiKeyWithToken,
  type Problem,
} from '../api/client'
import { ProblemAlert } from './ProblemAlert'
import { formatDateTime } from '../lib/format'

type Verify = { state: 'idle' | 'busy' } | { state: 'ok'; count: number } | { state: 'failed' }

/**
 * `POST /iam/v1/api-keys` is the only response that ever contains the plaintext
 * `dk_` token — the server stores a hash. This modal is therefore the one and
 * only chance to copy it, and says so.
 */
export function ApiKeySecretModal({
  issued,
  onClose,
}: {
  issued: ApiKeyWithToken
  onClose: () => void
}) {
  const [copied, setCopied] = useState(false)
  const [verify, setVerify] = useState<Verify>({ state: 'idle' })
  const [problem, setProblem] = useState<Problem | null>(null)

  async function copy() {
    try {
      await navigator.clipboard.writeText(issued.token)
      setCopied(true)
    } catch {
      // Clipboard permission denied (or a non-secure context): the token is
      // rendered in full below, so selecting it by hand still works.
      setCopied(false)
    }
  }

  async function callWithKey() {
    setVerify({ state: 'busy' })
    setProblem(null)
    try {
      const page = await listPrivacyRequestsAs(issued.token, { limit: 1 })
      setVerify({ state: 'ok', count: page.items.length })
    } catch (err) {
      setProblem(toProblem(err))
      setVerify({ state: 'failed' })
    }
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="New API key">
      <div className="modal">
        <h3>API key issued — copy it now</h3>
        <div className="alert alert-error" role="alert">
          <strong>This token is shown once.</strong> Dilion stores only a hash of it. If you close
          this dialog without copying, the key cannot be recovered — revoke it and issue another.
        </div>

        <label className="form">
          Plaintext token
          <input className="mono" readOnly value={issued.token} onFocus={(e) => e.target.select()} />
        </label>

        <div className="row">
          <button className="btn" onClick={() => void copy()} type="button">
            {copied ? 'Copied ✓' : 'Copy to clipboard'}
          </button>
          <button
            className="btn btn-ghost"
            onClick={() => void callWithKey()}
            disabled={verify.state === 'busy'}
            type="button"
          >
            {verify.state === 'busy' ? 'Calling…' : 'Use it: GET /privacy/v1/requests'}
          </button>
        </div>

        {verify.state === 'ok' && (
          <div className="alert alert-info">
            The key authenticated: <code>GET /privacy/v1/requests?limit=1</code> returned{' '}
            {verify.count} row{verify.count === 1 ? '' : 's'} with{' '}
            <code>Authorization: Bearer dk_…</code> instead of the service JWT.
          </div>
        )}
        {problem && <ProblemAlert problem={problem} />}

        <dl className="kv">
          <dt>Key id</dt>
          <dd>
            <code>{issued.id}</code>
          </dd>
          <dt>Name</dt>
          <dd>{issued.name ?? '—'}</dd>
          <dt>Scopes</dt>
          <dd>
            {issued.scopes.map((s) => (
              <code key={s} className="chip">
                {s}
              </code>
            ))}
          </dd>
          <dt>Expires</dt>
          <dd>{formatDateTime(issued.expires_at)}</dd>
        </dl>

        <div className="row">
          <button className="btn btn-ghost" onClick={onClose} type="button">
            I have stored the token — close
          </button>
        </div>
      </div>
    </div>
  )
}
