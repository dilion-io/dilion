/**
 * The two unauthenticated `/auth/v1` endpoints, fetched raw.
 *
 * `supabase-js` has no wrapper for either, and neither is part of
 * `openapi.yaml`, so this is plain `fetch` against the app's own origin — the
 * Vite proxy forwards `/auth/*` to Dilion.
 */
import { useCallback, useEffect, useState } from 'react'

type Fetched = { status: number; body: unknown } | null

const ENDPOINTS = [
  { path: '/auth/v1/health', label: 'Health' },
  { path: '/auth/v1/.well-known/jwks.json', label: 'JWKS' },
] as const

export function ServerInfoCard() {
  const [results, setResults] = useState<Record<string, Fetched>>({})
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const entries = await Promise.all(
        ENDPOINTS.map(async ({ path }) => {
          const response = await fetch(path, { headers: { Accept: 'application/json' } })
          const text = await response.text()
          let body: unknown = text
          try {
            body = JSON.parse(text)
          } catch {
            /* keep the raw text — a non-JSON body is itself the finding */
          }
          return [path, { status: response.status, body }] as const
        }),
      )
      setResults(Object.fromEntries(entries))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request failed')
    } finally {
      setBusy(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <section className="card">
      <div className="card-head">
        <h3>Server info</h3>
        <button className="btn btn-ghost btn-sm" onClick={() => void load()} disabled={busy}>
          {busy ? 'Loading…' : 'Reload'}
        </button>
      </div>
      <p className="muted">
        <code>GET /auth/v1/health</code> and <code>GET /auth/v1/.well-known/jwks.json</code> — both
        public, no <code>Authorization</code> header. An empty <code>keys</code> array is expected
        while the dev server signs with the HS256 shared secret: there is no public key to publish.
      </p>
      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}
      {ENDPOINTS.map(({ path, label }) => {
        const result = results[path]
        return (
          <div key={path}>
            <h4>
              {label} <code className="code-chip">{path}</code>
              {result && <span className="muted small"> HTTP {result.status}</span>}
            </h4>
            <pre className="json">{result ? JSON.stringify(result.body, null, 2) : '…'}</pre>
          </div>
        )
      })}
    </section>
  )
}
