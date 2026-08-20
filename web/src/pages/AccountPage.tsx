import { useEffect, useState } from 'react'
import type { Session, User } from '@supabase/supabase-js'
import { authErrorMessage, supabase } from '../lib/supabase'
import { UpdateUserSection } from '../components/UpdateUserSection'
import { SessionToolsCard } from '../components/SessionToolsCard'
import { ServerInfoCard } from '../components/ServerInfoCard'

export function AccountPage({ session }: { session: Session }) {
  const [user, setUser] = useState<User | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    setLoading(true)
    supabase.auth
      .getUser()
      .then(({ data, error }) => {
        if (!active) return
        if (error) setError(authErrorMessage(error))
        else setUser(data.user)
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [session.user.id])

  // Every self-service write answers with the updated user, so the page never
  // needs a re-read to stay truthful.
  const current = user ?? session.user

  return (
    <>
      <section className="card">
        <h2>My account</h2>
        <p className="muted">
          <code>GET /auth/v1/user</code> via <code>supabase.auth.getUser()</code>. The{' '}
          <code>id</code> below is the canonical <code>user_id</code> the privacy API is keyed on.
        </p>
        <dl className="kv">
          <dt>User id</dt>
          <dd>
            <code>{current.id}</code>
          </dd>
          <dt>Email</dt>
          <dd>{current.email ?? '—'}</dd>
          <dt>Provider</dt>
          <dd>{String(current.app_metadata?.provider ?? '—')}</dd>
          <dt>Created</dt>
          <dd>{current.created_at ? new Date(current.created_at).toLocaleString() : '—'}</dd>
          <dt>Last updated</dt>
          <dd>{current.updated_at ? new Date(current.updated_at).toLocaleString() : '—'}</dd>
        </dl>
        {error && (
          <div className="alert alert-error" role="alert">
            {error}
          </div>
        )}
      </section>

      <UpdateUserSection user={current} onUserChanged={setUser} />

      <SessionToolsCard session={session} />

      <ServerInfoCard />

      <section className="card">
        <h3>Raw user object</h3>
        {loading && <p className="muted">Loading…</p>}
        {user && <pre className="json">{JSON.stringify(user, null, 2)}</pre>}
      </section>
    </>
  )
}
