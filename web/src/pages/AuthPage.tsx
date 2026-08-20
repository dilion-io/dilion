import { useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { authErrorMessage, supabase } from '../lib/supabase'
import { navigate } from '../lib/router'

type Mode = 'signin' | 'signup'

export function AuthPage({ session }: { session: Session | null }) {
  const [mode, setMode] = useState<Mode>('signin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      if (mode === 'signup') {
        const { data, error } = await supabase.auth.signUp({ email, password })
        if (error) {
          setError(authErrorMessage(error))
        } else if (data.session) {
          navigate('account')
        } else {
          setNotice('Account created. Confirm the email address, then sign in.')
          setMode('signin')
        }
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password })
        if (error) setError(authErrorMessage(error))
        else navigate('account')
      }
    } catch (err) {
      setError(authErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  if (session) {
    return (
      <section className="card">
        <h2>Signed in</h2>
        <dl className="kv">
          <dt>User id</dt>
          <dd>
            <code>{session.user.id}</code>
          </dd>
          <dt>Email</dt>
          <dd>{session.user.email ?? '—'}</dd>
          <dt>Access token expires</dt>
          <dd>
            {session.expires_at ? new Date(session.expires_at * 1000).toLocaleString() : '—'}
          </dd>
        </dl>
        <div className="row">
          <button className="btn" onClick={() => navigate('account')}>
            My account
          </button>
          <button className="btn btn-ghost" onClick={() => navigate('privacy')}>
            Privacy center
          </button>
        </div>
      </section>
    )
  }

  return (
    <section className="card card-narrow">
      <div className="tabs">
        <button
          className={mode === 'signin' ? 'tab tab-active' : 'tab'}
          onClick={() => {
            setMode('signin')
            setError(null)
          }}
        >
          Sign in
        </button>
        <button
          className={mode === 'signup' ? 'tab tab-active' : 'tab'}
          onClick={() => {
            setMode('signup')
            setError(null)
          }}
        >
          Sign up
        </button>
      </div>

      <p className="muted">
        Handled entirely by <code>@supabase/supabase-js</code> against Dilion&rsquo;s
        Supabase-Auth-compatible <code>/auth/v1</code> surface.
      </p>

      <form onSubmit={onSubmit} className="form">
        <label>
          Email
          <input
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
          />
        </label>
        <label>
          Password
          <input
            type="password"
            required
            minLength={6}
            autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
          />
        </label>
        <button className="btn" type="submit" disabled={busy}>
          {busy ? 'Working…' : mode === 'signup' ? 'Create account' : 'Sign in'}
        </button>
      </form>

      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}
      {notice && <div className="alert alert-info">{notice}</div>}
    </section>
  )
}
