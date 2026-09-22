import { useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { authErrorMessage, supabase, wipe } from '../lib/supabase'
import { useAuthSettings } from '../lib/useAuthSettings'
import { navigate } from '../lib/router'

type Mode = 'signin' | 'signup'

/**
 * How the credential is proved. All three end in the same place — an ordinary
 * Supabase session this app then uses everywhere else — and differ only in what
 * the server learns on the way there.
 */
type Method = 'password' | 'opaque' | 'passkey'

const METHODS: { id: Method; label: string; blurb: string }[] = [
  {
    id: 'password',
    // "Password grant", not "Password": a control whose accessible name is the
    // same as the password field's is ambiguous to anyone navigating by name.
    label: 'Password grant',
    blurb:
      'The Supabase Auth password grant. The password is sent to the server, which verifies it against a hash.',
  },
  {
    id: 'opaque',
    label: 'OPAQUE',
    blurb:
      'RFC 9807 aPAKE. The password never leaves the browser, in any form: the server stores a credential it cannot test offline, and both sides derive keys only a real password produces.',
  },
  {
    id: 'passkey',
    label: 'Passkey',
    blurb:
      'WebAuthn with a discoverable credential. There is no password at all — the authenticator signs a challenge, and the private key never leaves the device.',
  },
]

export function AuthPage({ session }: { session: Session | null }) {
  const [mode, setMode] = useState<Mode>('signin')
  const [method, setMethod] = useState<Method>('password')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const { settings } = useAuthSettings()

  const passkeysOff = settings !== null && !settings.passkeys_enabled

  function reset() {
    setError(null)
    setNotice(null)
  }

  async function submitPassword() {
    if (mode === 'signup') {
      const { data, error } = await supabase.auth.signUp({ email, password })
      if (error) return setError(authErrorMessage(error))
      if (data.session) return navigate('account')
      setNotice('Account created. Confirm the email address, then sign in.')
      setMode('signin')
      return
    }
    const { error } = await supabase.auth.signInWithPassword({ email, password })
    if (error) return setError(authErrorMessage(error))
    navigate('account')
  }

  async function submitOpaque() {
    if (mode === 'signup') {
      const { data, error } = await supabase.auth.opaque.signUp({ email, password })
      if (error) return setError(authErrorMessage(error))
      // The registration export key is NOT proof that the account exists, and
      // must not be used before a successful OPAQUE login (docs/opaque.md), so
      // the sample zeroes it here rather than holding on to it.
      wipe(data.export_key)
      setNotice(
        data.confirmation_required
          ? 'Registered. Confirm the email address, then sign in with OPAQUE to establish a session.'
          : 'Registered. Registration does not authenticate — sign in with OPAQUE now.',
      )
      setMode('signin')
      return
    }

    const { data, error } = await supabase.auth.opaque.signInWithPassword({ email, password })
    if (error) return setError(authErrorMessage(error))
    // Two 64-byte secrets belong to the browser: session_key, which the server
    // derived independently, and export_key, which it never sees. A real app
    // would derive purpose-bound keys from them with HKDF. This sample has
    // nothing to encrypt, so it reports the shape and wipes them immediately.
    const { key_id, session_key, export_key } = data
    wipe(session_key, export_key)
    sessionStorage.setItem('dilion:lastOpaqueKeyId', key_id)
    navigate('account')
  }

  async function submitPasskey() {
    if (mode === 'signup') {
      setError(
        'A passkey is added to an existing account. Create the account first, then register a passkey from the account page.',
      )
      return
    }
    // The discoverable-credential ceremony: no email is typed, the
    // authenticator offers whichever passkey it holds for this site.
    const { data, error } = await supabase.auth.signInWithPasskey()
    if (error) return setError(authErrorMessage(error))
    if (!data.session) return setError('The passkey was verified but no session was issued.')
    navigate('account')
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    reset()
    try {
      if (method === 'password') await submitPassword()
      else if (method === 'opaque') await submitOpaque()
      else await submitPasskey()
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

  const active = METHODS.find((m) => m.id === method)!
  const needsPassword = method !== 'passkey'

  return (
    <section className="card card-narrow">
      <div className="tabs">
        <button
          className={mode === 'signin' ? 'tab tab-active' : 'tab'}
          onClick={() => {
            setMode('signin')
            reset()
          }}
        >
          Sign in
        </button>
        <button
          className={mode === 'signup' ? 'tab tab-active' : 'tab'}
          onClick={() => {
            setMode('signup')
            reset()
          }}
        >
          Sign up
        </button>
      </div>

      <p className="muted">
        Handled by <code>@dilion-io/auth-js</code>, which is <code>@supabase/supabase-js</code>{' '}
        plus an <code>auth.opaque</code> namespace, against Dilion&rsquo;s{' '}
        <code>/auth/v1</code> surface.
      </p>

      <fieldset className="cred-select">
        <legend>Method</legend>
        <div className="cred-options">
          {METHODS.map((m) => (
            <label
              key={m.id}
              className={m.id === method ? 'cred-option cred-option-active' : 'cred-option'}
            >
              <input
                type="radio"
                name="auth-method"
                checked={m.id === method}
                onChange={() => {
                  setMethod(m.id)
                  reset()
                }}
              />
              <span>
                <strong>{m.label}</strong>
                {m.id === 'passkey' && passkeysOff && (
                  <span className="cred-option-hint muted">disabled on this server</span>
                )}
              </span>
            </label>
          ))}
        </div>
        <p className="cred-note muted small">{active.blurb}</p>
      </fieldset>

      <form onSubmit={(e) => void onSubmit(e)} className="form">
        {needsPassword && (
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
        )}
        {needsPassword && (
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
        )}
        {method === 'passkey' && (
          <p className="muted small">
            Nothing to type: the browser asks the authenticator which passkey it holds for this
            site. Register one from the account page after signing in another way.
          </p>
        )}
        <button className="btn" type="submit" disabled={busy}>
          {busy
            ? 'Working…'
            : method === 'passkey'
              ? 'Use a passkey'
              : mode === 'signup'
                ? 'Create account'
                : 'Sign in'}
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
