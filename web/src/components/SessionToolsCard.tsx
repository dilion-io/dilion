/**
 * Session tools: what a client can do with the *session* rather than the user.
 *
 * - `POST /auth/v1/token?grant_type=refresh_token` — `supabase.auth.refreshSession()`
 * - `POST /auth/v1/logout?scope=global|local|others` — `supabase.auth.signOut({ scope })`
 * - the access token's own claims, decoded in the browser for display only.
 */
import { useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { supabase } from '../lib/supabase'
import { problemFromAuthError } from '../api/authAdmin'
import type { Problem } from '../api/client'
import { decodeJwtPayload, describeExpiry } from '../lib/jwt'
import { navigate } from '../lib/router'
import { ProblemAlert } from './ProblemAlert'

/** gotrue's three logout scopes, with what each one actually kills. */
const SCOPES = [
  { value: 'global', label: 'global — every session of this user' },
  { value: 'local', label: 'local — only this browser session' },
  { value: 'others', label: 'others — every session except this one' },
] as const

type Scope = (typeof SCOPES)[number]['value']

export function SessionToolsCard({ session }: { session: Session }) {
  const [scope, setScope] = useState<Scope>('global')
  const [busy, setBusy] = useState<'refresh' | 'signout' | null>(null)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const claims = decodeJwtPayload(session.access_token)

  async function onRefresh() {
    setBusy('refresh')
    setProblem(null)
    setNotice(null)
    try {
      const { data, error } = await supabase.auth.refreshSession()
      if (error) setProblem(problemFromAuthError(error))
      else if (data.session) {
        // A refresh mints a *new* access token and rotates the refresh token;
        // the new expiry is the visible proof that it happened.
        setNotice(`New access token expires ${describeExpiry(data.session.expires_at)}.`)
      } else {
        setNotice('No session was returned — sign in again.')
      }
    } catch (err) {
      setProblem(problemFromAuthError(err))
    } finally {
      setBusy(null)
    }
  }

  async function onSignOut() {
    setBusy('signout')
    setProblem(null)
    setNotice(null)
    try {
      const { error } = await supabase.auth.signOut({ scope })
      if (error) {
        setProblem(problemFromAuthError(error))
      } else if (scope === 'others') {
        // The only scope that leaves this browser signed in.
        setNotice('Other sessions signed out. This session is still valid.')
      } else {
        navigate('signin')
      }
    } catch (err) {
      setProblem(problemFromAuthError(err))
    } finally {
      setBusy(null)
    }
  }

  return (
    <section className="card">
      <h3>Session tools</h3>
      <p className="muted">
        Refresh, scoped sign-out, and the claims this browser is currently presenting.
      </p>

      <dl className="kv">
        <dt>Access token expires</dt>
        <dd>{describeExpiry(session.expires_at)}</dd>
        <dt>Token type</dt>
        <dd>{session.token_type}</dd>
        <dt>Refresh token</dt>
        <dd>
          <code>{session.refresh_token ? `${session.refresh_token.slice(0, 8)}…` : '—'}</code>
        </dd>
      </dl>

      <div className="row">
        <button className="btn" onClick={() => void onRefresh()} disabled={busy !== null}>
          {busy === 'refresh' ? 'Refreshing…' : 'Refresh session'}
        </button>
      </div>

      <h4>Sign out</h4>
      <div className="row">
        <label className="select">
          Scope
          <select value={scope} onChange={(e) => setScope(e.target.value as Scope)}>
            {SCOPES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
        <button
          className="btn btn-danger"
          onClick={() => void onSignOut()}
          disabled={busy !== null}
        >
          {busy === 'signout' ? 'Signing out…' : `Sign out (${scope})`}
        </button>
      </div>

      <h4>Access token claims</h4>
      {claims ? (
        <>
          <dl className="kv">
            <dt>sub</dt>
            <dd>
              <code>{typeof claims.sub === 'string' ? claims.sub : '—'}</code>
            </dd>
            <dt>role</dt>
            <dd>
              <code>{typeof claims.role === 'string' ? claims.role : '—'}</code>
            </dd>
            <dt>exp</dt>
            <dd>{describeExpiry(typeof claims.exp === 'number' ? claims.exp : undefined)}</dd>
          </dl>
          <details>
            <summary className="muted small">All claims</summary>
            <pre className="json">{JSON.stringify(claims, null, 2)}</pre>
          </details>
          <p className="muted small">
            Decoded client-side for display only — the signature is <strong>not</strong> verified
            here. Only the server may act on these claims.
          </p>
        </>
      ) : (
        <p className="muted">The access token could not be decoded.</p>
      )}

      {problem && <ProblemAlert problem={problem} />}
      {notice && <div className="alert alert-info">{notice}</div>}
    </section>
  )
}
