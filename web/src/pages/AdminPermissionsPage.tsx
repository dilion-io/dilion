import { useCallback, useEffect, useState } from 'react'
import {
  createPermission,
  listPermissionHolders,
  listPermissions,
  toProblem,
  type Permission,
  type PermissionHolder,
  type PermissionPage,
  type Problem,
} from '../api/client'
import { PAGE_SIZE, usePagedList } from '../lib/usePagedList'
import { usePermissionCatalog } from '../lib/usePermissionCatalog'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'
import { Pager } from '../components/Pager'
import { formatDateTime } from '../lib/format'
import { takeStash } from '../lib/handoff'

/**
 * Mirror of `iam.customPermissionRe` (internal/iam/iam.go): a custom permission
 * must be namespaced. Un-namespaced names are the builtin reserve.
 */
const CUSTOM_PERMISSION_RE = /^[a-z][a-z0-9-]*\.[a-z0-9.-]+$/

/**
 * Client-side copy of `ValidateCustomPermission`. The server is still the
 * authority — a 422 from it is rendered by <ProblemAlert /> exactly as any
 * other validation failure — but checking here keeps the round trip out of the
 * obvious cases.
 */
function validateName(name: string, builtins: readonly string[]): string | null {
  if (name.length === 0) return null
  if (!CUSTOM_PERMISSION_RE.test(name)) {
    return 'Must be namespaced and lower-case, e.g. myapp.orders.refund (pattern ^[a-z][a-z0-9-]*\\.[a-z0-9.-]+$).'
  }
  if (builtins.includes(name)) {
    return `"${name}" collides with a builtin permission — builtin (un-namespaced) names are reserved.`
  }
  return null
}

export function AdminPermissionsPage() {
  const load = useCallback(
    (cursor?: string): Promise<PermissionPage> =>
      listPermissions({ limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) }),
    [],
  )
  const permissions = usePagedList<Permission>(load)
  // The paged list is what the table shows; validation and the recertification
  // picker need the *whole* catalog, not whichever page happens to be visible.
  const catalog = usePermissionCatalog()

  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [created, setCreated] = useState<Permission | null>(null)

  const builtins = catalog.permissions.filter((p) => p.builtin).map((p) => p.name)
  const localError = validateName(name.trim(), builtins)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (localError) return
    setBusy(true)
    setProblem(null)
    try {
      setCreated(await createPermission({ name: name.trim() }))
      setName('')
      permissions.reload()
      catalog.reload()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <section className="card">
        <h2>Permissions</h2>
        <p className="muted">
          <code>GET /iam/v1/permissions</code> — the catalog every role and API key scope is
          validated against. Builtin permissions are seeded by Dilion; custom ones must be
          namespaced.
        </p>
        <PermissionHint permission="audit.read" />

        {permissions.problem && <ProblemAlert problem={permissions.problem} />}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Permission</th>
                <th>Kind</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {permissions.items.map((p) => (
                <tr key={p.name}>
                  <td>
                    <code>{p.name}</code>
                  </td>
                  <td>
                    <span className={`badge ${p.builtin ? 'badge-requested' : 'badge-done'}`}>
                      {p.builtin ? 'BUILTIN' : 'CUSTOM'}
                    </span>
                  </td>
                  <td className="small">{formatDateTime(p.created_at)}</td>
                </tr>
              ))}
              {permissions.items.length === 0 && !permissions.loading && (
                <tr>
                  <td colSpan={3} className="muted">
                    No permissions.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pager list={permissions} unit="permission" />
      </section>

      <section className="card">
        <h3>Register a custom permission</h3>
        <p className="muted">
          <code>POST /iam/v1/permissions</code> with <code>{'{ name }'}</code>. Two rules, both
          enforced server-side and pre-checked here: the name must be namespaced, and it may not
          collide with a builtin.
        </p>
        <PermissionHint permission="keys.manage" />

        {catalog.problem && <ProblemAlert problem={catalog.problem} />}
        {problem && <ProblemAlert problem={problem} />}
        {created && (
          <div className="alert alert-info">
            Registered <code>{created.name}</code>. It can now be bundled into a role or used as an
            API key scope.
          </div>
        )}

        <form className="form" onSubmit={(e) => void submit(e)}>
          <label>
            Permission name
            <input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="myapp.orders.refund"
              aria-invalid={localError !== null}
            />
          </label>
          {localError && (
            <p className="field-error small" role="alert">
              {localError}
            </p>
          )}
          <div className="row">
            <button
              className="btn"
              type="submit"
              disabled={busy || name.trim().length === 0 || localError !== null}
            >
              {busy ? 'Registering…' : 'Register permission'}
            </button>
            <button
              className="btn btn-ghost"
              type="button"
              onClick={() => setName('users.read')}
              disabled={busy}
            >
              Try a rejected name
            </button>
          </div>
        </form>
      </section>

      <HoldersReport permissions={catalog.permissions} />
    </>
  )
}

/** Recertification: who can do X today, and through which role? */
function HoldersReport({ permissions }: { permissions: readonly Permission[] }) {
  const [selected, setSelected] = useState<string>(() => takeStash('permission'))
  const [holders, setHolders] = useState<PermissionHolder[] | null>(null)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (selected === '' && permissions.length > 0) setSelected(permissions[0].name)
  }, [permissions, selected])

  useEffect(() => {
    if (!selected) return
    let active = true
    setLoading(true)
    listPermissionHolders(selected)
      .then((page) => {
        if (!active) return
        setHolders(page.items)
        setProblem(null)
      })
      .catch((err: unknown) => {
        if (active) {
          setHolders(null)
          setProblem(toProblem(err))
        }
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [selected])

  const rows = holders ?? []

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h3>Recertification report</h3>
          <p className="muted">
            <code>GET /iam/v1/permissions/{'{name}'}/holders</code> — every actor that currently
            holds this permission, and the role it comes from. Revoked grants are excluded and{' '}
            <code>next_cursor</code> is always <code>null</code>: an access review needs the whole
            set, not a page of it.
          </p>
        </div>
        <label className="select">
          Permission
          <select value={selected} onChange={(e) => setSelected(e.target.value)}>
            {permissions.map((p) => (
              <option key={p.name} value={p.name}>
                {p.name}
              </option>
            ))}
            {permissions.length === 0 && <option value="">—</option>}
          </select>
        </label>
      </div>
      <PermissionHint permission="audit.read" />

      {problem && <ProblemAlert problem={problem} />}

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Actor</th>
              <th>Via role</th>
              <th>Role id</th>
              <th>Granted by</th>
              <th>Granted at</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((h) => (
              <tr key={`${h.actor_id}-${h.role_id}`}>
                <td>
                  <code className="small">{h.actor_id}</code>
                </td>
                <td>{h.role_name}</td>
                <td>
                  <code className="small">{h.role_id}</code>
                </td>
                <td className="small">
                  <code>{h.granted_by ?? '—'}</code>
                </td>
                <td className="small">{formatDateTime(h.granted_at)}</td>
              </tr>
            ))}
            {rows.length === 0 && !loading && (
              <tr>
                <td colSpan={5} className="muted">
                  Nobody holds <code>{selected || '—'}</code>. Note that the{' '}
                  <code>service_role</code> JWT this console uses bypasses RBAC entirely, so it
                  never appears here.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="muted small">
        {loading ? 'Loading…' : `${rows.length} holder${rows.length === 1 ? '' : 's'}`}
      </p>
    </section>
  )
}
