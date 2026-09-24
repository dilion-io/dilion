import { useCallback, useEffect, useState } from 'react'
import {
  AuthAdminError,
  deleteAuthHook,
  listAuthHooks,
  putAuthHook,
  type AuthHookSetting,
  type AuthHookSettingBody,
} from '../api/authAdmin'
import { toProblem, type Problem } from '../api/client'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'

/** What each hook is for, in upstream's terms. */
const PURPOSE: Record<AuthHookSetting['name'], string> = {
  custom_access_token: 'rewrites the access token claims before signing',
  send_email: 'delivers auth emails instead of the built-in mailer',
  send_sms: 'delivers auth SMS instead of the built-in provider',
  before_user_created: 'may reject a signup before the user is written',
  after_user_created: 'observes a new user after the signup commits',
  mfa_verification_attempt: 'may reject an MFA verification',
  password_verification_attempt: 'may reject a password check',
}

function problemOf(err: unknown): Problem {
  return err instanceof AuthAdminError ? err.problem : toProblem(err)
}

export function AdminHooksPage() {
  const [hooks, setHooks] = useState<AuthHookSetting[]>([])
  const [problem, setProblem] = useState<Problem | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<AuthHookSetting['name'] | null>(null)

  const reload = useCallback(() => {
    setLoading(true)
    listAuthHooks()
      .then((list) => {
        setHooks(list)
        setProblem(null)
      })
      .catch((err: unknown) => setProblem(problemOf(err)))
      .finally(() => setLoading(false))
  }, [])

  useEffect(reload, [reload])

  const current = hooks.find((h) => h.name === selected)

  return (
    <>
      <section className="card">
        <h2>Auth hooks</h2>
        <p className="muted">
          <code>GET /auth/v1/admin/hooks</code> — Supabase&rsquo;s auth hooks as they run for{' '}
          <em>this instance</em>. The server&rsquo;s own configuration (<code>GOTRUE_HOOK_*</code>)
          is the default; an instance setting replaces it, including switching it off. The operator
          can lock a hook to the server setting, and by default an instance&rsquo;s webhook may only
          reach public addresses.
        </p>
        <PermissionHint permission="users.admin" />

        {problem && <ProblemAlert problem={problem} />}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Hook</th>
                <th>Source</th>
                <th>State</th>
                <th>URI</th>
                <th>Secrets</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {hooks.map((h) => (
                <tr key={h.name} className={h.name === selected ? 'is-mine' : ''}>
                  <td>
                    <code>{h.name}</code>
                    <div className="muted small">{PURPOSE[h.name]}</div>
                  </td>
                  <td>
                    <span className="tag">{h.source}</span>
                    {h.locked && <span className="tag">locked</span>}
                  </td>
                  <td>
                    <span className={`badge ${h.enabled ? 'badge-done' : 'badge-canceled'}`}>
                      {h.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </td>
                  <td>
                    {h.uri ? (
                      <code className="small">{h.uri}</code>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>{h.secrets_count}</td>
                  <td>
                    <button
                      className="btn btn-ghost btn-sm"
                      type="button"
                      onClick={() => setSelected(h.name === selected ? null : h.name)}
                    >
                      {h.name === selected ? 'Close' : h.locked ? 'View' : 'Edit'}
                    </button>
                  </td>
                </tr>
              ))}
              {hooks.length === 0 && !loading && !problem && (
                <tr>
                  <td colSpan={6} className="muted">
                    No hooks reported.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {current && <HookEditor key={current.name} hook={current} onSaved={reload} />}
    </>
  )
}

function HookEditor({ hook, onSaved }: { hook: AuthHookSetting; onSaved: () => void }) {
  const [enabled, setEnabled] = useState(hook.enabled)
  const [uri, setUri] = useState(hook.uri)
  const [secretsDraft, setSecretsDraft] = useState('')
  const [clearSecrets, setClearSecrets] = useState(false)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  // Follow the saved setting after a save or a return to the server's.
  useEffect(() => {
    setEnabled(hook.enabled)
    setUri(hook.uri)
  }, [hook.enabled, hook.uri])

  const newSecrets = secretsDraft
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)

  async function run(action: () => Promise<AuthHookSetting>, message: string) {
    setBusy(true)
    setProblem(null)
    setNotice(null)
    try {
      await action()
      setSecretsDraft('')
      setClearSecrets(false)
      setNotice(message)
      onSaved()
    } catch (err) {
      setProblem(problemOf(err))
    } finally {
      setBusy(false)
    }
  }

  function save(e: React.FormEvent) {
    e.preventDefault()
    const body: AuthHookSettingBody = { enabled, uri: uri.trim() }
    if (newSecrets.length > 0) body.secrets = newSecrets
    else if (clearSecrets) body.secrets = []
    void run(() => putAuthHook(hook.name, body), 'Saved — this instance now uses its own setting.')
  }

  return (
    <section className="card">
      <h3>
        <code>{hook.name}</code>
      </h3>
      <p className="muted">
        <code>PUT /auth/v1/admin/hooks/{hook.name}</code> sets this instance&rsquo;s own setting;{' '}
        <code>DELETE</code> returns to the server&rsquo;s. The URI is <code>https://…</code>,{' '}
        <code>http://…</code> or{' '}
        <code>pg-functions://&lt;db&gt;/&lt;schema&gt;/&lt;function&gt;</code> (a function in this
        instance&rsquo;s own database). The operator&rsquo;s policy checks it on save and on every
        call.
      </p>
      <PermissionHint permission="users.admin" />

      {problem && <ProblemAlert problem={problem} />}
      {notice && <div className="alert alert-info">{notice}</div>}

      {hook.locked ? (
        <div className="alert alert-info">
          The operator locked this hook to the server setting
          {hook.enabled ? (
            <>
              {' '}
              (<code>{hook.uri}</code>)
            </>
          ) : (
            ' (disabled)'
          )}
          . It cannot be replaced or switched off for this instance.
        </div>
      ) : (
        <form className="form" onSubmit={save}>
          <label className="switch">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>
              enabled — off here switches the hook off for this instance, even if the server has one
            </span>
          </label>
          <label>
            URI
            <input
              value={uri}
              onChange={(e) => setUri(e.target.value)}
              placeholder="https://hooks.example.com/auth"
              required={enabled}
            />
          </label>
          <label>
            Secrets (write-only, one per line)
            <textarea
              rows={3}
              className="mono"
              value={secretsDraft}
              onChange={(e) => setSecretsDraft(e.target.value)}
              placeholder="v1,whsec_…"
              spellCheck={false}
            />
          </label>
          <p className="muted small">
            {hook.source === 'instance'
              ? `${hook.secrets_count} secret(s) stored. Leave empty to keep them; every secret signs each call, so add the new one before removing the old when rotating.`
              : 'Standard Webhooks keys that sign each call. Not used by pg-functions hooks.'}
          </p>
          {hook.source === 'instance' && hook.secrets_count > 0 && newSecrets.length === 0 && (
            <label className="switch">
              <input
                type="checkbox"
                checked={clearSecrets}
                onChange={(e) => setClearSecrets(e.target.checked)}
              />
              <span>remove the stored secrets</span>
            </label>
          )}
          <div className="row">
            <button className="btn" type="submit" disabled={busy || (enabled && uri.trim() === '')}>
              {busy ? 'Saving…' : 'Save for this instance'}
            </button>
            {hook.source === 'instance' && (
              <button
                className="btn btn-ghost"
                type="button"
                disabled={busy}
                onClick={() =>
                  void run(
                    () => deleteAuthHook(hook.name),
                    'Removed — this instance follows the server setting again.',
                  )
                }
              >
                Use server setting
              </button>
            )}
          </div>
        </form>
      )}
    </section>
  )
}
