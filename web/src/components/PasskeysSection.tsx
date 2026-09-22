/**
 * Passkey management for the signed-in account: list, add, rename, remove.
 *
 * Every call is `supabase.auth.passkey.*` from `@supabase/auth-js`, which is
 * the same code an app would run against Supabase — Dilion serves the
 * `/auth/v1/passkeys/*` routes the SDK expects. `registerPasskey()` performs
 * the whole WebAuthn ceremony (options, `navigator.credentials.create()`,
 * verify); the two-step `startRegistration` / `verifyRegistration` pair exists
 * for apps that want to drive the ceremony themselves.
 *
 * Signing IN with a passkey lives on the auth page, because it needs no
 * session: the credential is discoverable and identifies the user by itself.
 */
import { useCallback, useEffect, useState } from 'react'
import type { PasskeyListItem } from '@supabase/supabase-js'
import { authErrorMessage, supabase } from '../lib/supabase'
import { useAuthSettings } from '../lib/useAuthSettings'

export function PasskeysSection() {
  const { settings } = useAuthSettings()
  const [passkeys, setPasskeys] = useState<PasskeyListItem[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [renaming, setRenaming] = useState<string | null>(null)
  const [draftName, setDraftName] = useState('')

  const reload = useCallback(async () => {
    const { data, error } = await supabase.auth.passkey.list()
    if (error) {
      setError(authErrorMessage(error))
      return
    }
    setPasskeys(data ?? [])
  }, [])

  useEffect(() => {
    void reload()
  }, [reload])

  async function run(what: () => Promise<string | null>) {
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      const message = await what()
      if (message) setNotice(message)
      await reload()
    } catch (err) {
      setError(authErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  function add() {
    return run(async () => {
      // The browser prompts here. A user who dismisses the prompt produces an
      // ordinary error, not a half-registered credential: the server only
      // stores one after verifying the attestation it issued a challenge for.
      const { error } = await supabase.auth.registerPasskey()
      if (error) throw error
      return 'Passkey registered. It can sign you in from the auth page without a password.'
    })
  }

  function rename(passkeyId: string, friendlyName: string) {
    return run(async () => {
      const { error } = await supabase.auth.passkey.update({ passkeyId, friendlyName })
      if (error) throw error
      setRenaming(null)
      return 'Renamed.'
    })
  }

  function remove(passkeyId: string) {
    return run(async () => {
      const { error } = await supabase.auth.passkey.delete({ passkeyId })
      if (error) throw error
      return 'Passkey removed. The credential on the device is now useless for this site.'
    })
  }

  const disabled = settings !== null && !settings.passkeys_enabled

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h3>Passkeys</h3>
          <p className="muted">
            <code>supabase.auth.registerPasskey()</code> and{' '}
            <code>supabase.auth.passkey.*</code> against <code>/auth/v1/passkeys</code>. A passkey
            is a WebAuthn credential whose private half never leaves the authenticator, so there
            is no shared secret for this server to lose.
          </p>
        </div>
      </div>

      {disabled ? (
        <p className="muted">
          This server reports <code>passkeys_enabled: false</code>. Start it with{' '}
          <code>DILION_AUTH_PASSKEY_ENABLED=true</code> and a WebAuthn relying party
          (<code>make dev</code> does both).
        </p>
      ) : (
        <>
          <div className="row">
            <button className="btn" type="button" disabled={busy} onClick={() => void add()}>
              {busy ? 'Working…' : 'Add a passkey'}
            </button>
            <span className="muted small">
              Registration needs the session you already have; signing in with the passkey later
              needs nothing at all.
            </span>
          </div>

          {error && (
            <div className="alert alert-error" role="alert">
              {error}
            </div>
          )}
          {notice && <div className="alert alert-info">{notice}</div>}

          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Added</th>
                  <th>Last used</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(passkeys ?? []).map((k) => (
                  <tr key={k.id}>
                    <td>
                      {renaming === k.id ? (
                        <input
                          autoFocus
                          value={draftName}
                          maxLength={120}
                          onChange={(e) => setDraftName(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' && draftName.trim())
                              void rename(k.id, draftName.trim())
                            if (e.key === 'Escape') setRenaming(null)
                          }}
                        />
                      ) : (
                        (k.friendly_name ?? <span className="muted">unnamed</span>)
                      )}
                    </td>
                    <td className="small">{new Date(k.created_at).toLocaleString()}</td>
                    <td className="small">
                      {k.last_used_at ? new Date(k.last_used_at).toLocaleString() : 'never'}
                    </td>
                    <td>
                      <div className="row row-tight">
                        {renaming === k.id ? (
                          <button
                            className="btn btn-ghost btn-sm"
                            type="button"
                            disabled={busy || draftName.trim().length === 0}
                            onClick={() => void rename(k.id, draftName.trim())}
                          >
                            Save
                          </button>
                        ) : (
                          <button
                            className="btn btn-ghost btn-sm"
                            type="button"
                            disabled={busy}
                            onClick={() => {
                              setRenaming(k.id)
                              setDraftName(k.friendly_name ?? '')
                            }}
                          >
                            Rename
                          </button>
                        )}
                        <button
                          className="btn btn-ghost btn-sm"
                          type="button"
                          disabled={busy}
                          onClick={() => void remove(k.id)}
                        >
                          Remove
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {passkeys !== null && passkeys.length === 0 && (
                  <tr>
                    <td colSpan={4} className="muted">
                      No passkeys yet. Add one, sign out, and the auth page can sign you back in
                      without a password.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  )
}
