/**
 * OPAQUE enrollment for an account that already exists.
 *
 * `auth.opaque.register()` adds an OPAQUE credential to the signed-in account,
 * which is the path for a user who signed up with a password or an OTP and now
 * wants one the server cannot test offline. Creating a NEW account with OPAQUE
 * and no prior session is `auth.opaque.signUp()`, on the auth page.
 *
 * The server gates this deliberately (docs/opaque.md): a confirmed, non-SSO,
 * non-anonymous account, the same session for both steps, authenticated within
 * the last five minutes, and AAL2 when the account has a verified MFA factor.
 * The sample does not try to pre-empt those checks — it shows the server's
 * refusal, which is the thing an integrator actually has to handle.
 */
import { useState } from 'react'
import { authErrorMessage, supabase, wipe } from '../lib/supabase'

/** Set by the auth page after an OPAQUE login. An identifier, not key material. */
const LAST_KEY_ID = 'dilion:lastOpaqueKeyId'

export function OpaqueSection() {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const keyId = sessionStorage.getItem(LAST_KEY_ID)

  async function enrol(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      const { data, error } = await supabase.auth.opaque.register({ password })
      if (error) {
        setError(authErrorMessage(error))
        return
      }
      // Enrollment yields an export_key, but it is provisional until a real
      // OPAQUE login proves the credential works, so nothing may be encrypted
      // under it yet. Wipe it and make the user sign in.
      wipe(data.export_key)
      setPassword('')
      setNotice(
        'OPAQUE credential enrolled. Sign out and sign back in with the OPAQUE method to establish a session and derive the shared key.',
      )
    } catch (err) {
      setError(authErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h3>OPAQUE credential</h3>
          <p className="muted">
            <code>supabase.auth.opaque.register()</code> against{' '}
            <code>/auth/v1/opaque/registration/*</code>. The password is never sent: the browser
            and the server run RFC 9807 and the server ends up storing a record it cannot mount an
            offline guessing attack against.
          </p>
        </div>
      </div>

      {keyId && (
        <p className="muted small">
          This browser&rsquo;s last OPAQUE login derived shared key <code>{keyId}</code>. The key
          bytes themselves were wiped immediately — an app that needs them would derive
          purpose-bound keys with HKDF and bind them to this id.
        </p>
      )}

      <form className="form" onSubmit={(e) => void enrol(e)}>
        <label>
          Password to enrol
          <input
            type="password"
            required
            minLength={6}
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
          />
        </label>
        <div className="row">
          <button className="btn" type="submit" disabled={busy || password.length === 0}>
            {busy ? 'Working…' : 'Enrol OPAQUE credential'}
          </button>
          <span className="muted small">
            Needs a sign-in from the last five minutes, and AAL2 if this account has MFA.
          </span>
        </div>
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
