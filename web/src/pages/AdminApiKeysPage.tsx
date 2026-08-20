import { useCallback, useState } from 'react'
import {
  createApiKey,
  listApiKeys,
  revokeApiKey,
  toProblem,
  type ApiKey,
  type ApiKeyPage,
  type ApiKeyWithToken,
  type CreateApiKeyBody,
  type Problem,
} from '../api/client'
import { PAGE_SIZE, usePagedList } from '../lib/usePagedList'
import { usePermissionCatalog } from '../lib/usePermissionCatalog'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'
import { Pager } from '../components/Pager'
import { MultiSelect } from '../components/MultiSelect'
import { ApiKeySecretModal } from '../components/ApiKeySecretModal'
import { formatDateTime } from '../lib/format'

/** `<input type="datetime-local">` gives local wall time; the API wants RFC 3339 UTC. */
function toRfc3339(local: string): string | null {
  if (!local) return null
  const d = new Date(local)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

function keyState(key: ApiKey): { label: string; badge: string } {
  if (key.revoked_at !== null) return { label: 'REVOKED', badge: 'badge-canceled' }
  if (key.expires_at !== null && new Date(key.expires_at).getTime() < Date.now()) {
    return { label: 'EXPIRED', badge: 'badge-manual_review' }
  }
  return { label: 'ACTIVE', badge: 'badge-done' }
}

export function AdminApiKeysPage() {
  const load = useCallback(
    (cursor?: string): Promise<ApiKeyPage> =>
      listApiKeys({ limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) }),
    [],
  )
  const keys = usePagedList<ApiKey>(load)
  const catalog = usePermissionCatalog()

  const [name, setName] = useState('')
  const [scopes, setScopes] = useState<string[]>([])
  const [expiresLocal, setExpiresLocal] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [issued, setIssued] = useState<ApiKeyWithToken | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setProblem(null)
    try {
      const expires = toRfc3339(expiresLocal)
      const body: CreateApiKeyBody = {
        scopes,
        ...(name.trim() ? { name: name.trim() } : {}),
        ...(expires ? { expires_at: expires } : {}),
      }
      setIssued(await createApiKey(body))
      setName('')
      setScopes([])
      setExpiresLocal('')
      keys.reload()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  async function revoke(key: ApiKey) {
    setBusy(true)
    setProblem(null)
    try {
      await revokeApiKey(key.id)
      keys.reload()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      {issued && <ApiKeySecretModal issued={issued} onClose={() => setIssued(null)} />}

      <section className="card">
        <h2>API keys</h2>
        <p className="muted">
          <code>GET /iam/v1/api-keys</code> — scoped <code>dk_</code> credentials for the
          management plane. Only the hash is stored, so the list can show metadata (scopes,
          expiry, <code>last_used_at</code>) but never the token.
        </p>
        <PermissionHint permission="audit.read" />

        {problem && <ProblemAlert problem={problem} />}
        {keys.problem && <ProblemAlert problem={keys.problem} />}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Key</th>
                <th>Name</th>
                <th>Scopes</th>
                <th>State</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {keys.items.map((key) => {
                const state = keyState(key)
                return (
                  <tr key={key.id}>
                    <td>
                      <code className="small">{key.id}</code>
                    </td>
                    <td>{key.name ?? '—'}</td>
                    <td className="cell-wrap">
                      {key.scopes.map((s) => (
                        <code key={s} className="chip">
                          {s}
                        </code>
                      ))}
                    </td>
                    <td>
                      <span className={`badge ${state.badge}`}>{state.label}</span>
                    </td>
                    <td className="small">{formatDateTime(key.created_at)}</td>
                    <td className="small">{formatDateTime(key.expires_at)}</td>
                    <td className="small">{formatDateTime(key.last_used_at)}</td>
                    <td>
                      {key.revoked_at === null && (
                        <button
                          className="btn btn-ghost btn-sm"
                          type="button"
                          disabled={busy}
                          onClick={() => void revoke(key)}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
              {keys.items.length === 0 && !keys.loading && (
                <tr>
                  <td colSpan={8} className="muted">
                    No API keys.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pager list={keys} unit="key" />
      </section>

      <section className="card">
        <h3>Issue an API key</h3>
        <p className="muted">
          <code>POST /iam/v1/api-keys</code> with{' '}
          <code>{'{ name?, scopes[], expires_at? }'}</code>. The response is the only place the
          plaintext <code>dk_…</code> token ever appears — the dialog that opens on success is your
          one chance to copy it. Scope to least privilege:{' '}
          <code>DELETE /iam/v1/api-keys/{'{id}'}</code> is the only remedy afterwards.
        </p>
        <PermissionHint permission="keys.manage" />

        {catalog.problem && <ProblemAlert problem={catalog.problem} />}

        <form className="form" onSubmit={(e) => void submit(e)}>
          <label>
            Name (optional)
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="nightly-export-job"
            />
          </label>

          <MultiSelect
            label="Scopes"
            hint="At least one is required (minItems: 1). A key can never exceed these permissions."
            disabled={catalog.loading}
            options={catalog.permissions.map((p) => ({
              value: p.name,
              note: p.builtin ? '· builtin' : '· custom',
            }))}
            selected={scopes}
            onChange={setScopes}
          />

          <label>
            Expires at (optional — omit for a non-expiring key)
            <input
              type="datetime-local"
              value={expiresLocal}
              onChange={(e) => setExpiresLocal(e.target.value)}
            />
          </label>
          {expiresLocal && (
            <p className="muted small">
              sent as <code>{toRfc3339(expiresLocal) ?? 'invalid date'}</code>
            </p>
          )}

          <div className="row">
            <button className="btn" type="submit" disabled={busy || scopes.length === 0}>
              {busy ? 'Issuing…' : 'Issue key'}
            </button>
          </div>
        </form>
      </section>
    </>
  )
}
