import { useCallback, useState } from 'react'
import {
  createRole,
  listRoles,
  toProblem,
  type Problem,
  type Role,
  type RolePage,
} from '../api/client'
import { PAGE_SIZE, usePagedList } from '../lib/usePagedList'
import { usePermissionCatalog } from '../lib/usePermissionCatalog'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'
import { Pager } from '../components/Pager'
import { MultiSelect } from '../components/MultiSelect'
import { formatDateTime } from '../lib/format'
import { navigate } from '../lib/router'
import { stash } from '../lib/handoff'

export function AdminRolesPage() {
  const load = useCallback(
    (cursor?: string): Promise<RolePage> =>
      listRoles({ limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) }),
    [],
  )
  const roles = usePagedList<Role>(load)
  const catalog = usePermissionCatalog()

  const [name, setName] = useState('')
  const [permissions, setPermissions] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [created, setCreated] = useState<Role | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setProblem(null)
    try {
      const role = await createRole({ name: name.trim(), permissions })
      setCreated(role)
      setName('')
      setPermissions([])
      roles.reload()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Roles</h2>
            <p className="muted">
              <code>GET /iam/v1/roles</code> — cursor pagination, <code>limit={PAGE_SIZE}</code>. A
              role is a named bundle of permissions; builtin roles are seeded by Dilion and cannot
              be redefined.
            </p>
          </div>
        </div>
        <PermissionHint permission="audit.read" />

        {roles.problem && <ProblemAlert problem={roles.problem} />}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Role</th>
                <th>Name</th>
                <th>Permissions</th>
                <th>Kind</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {roles.items.map((role) => (
                <tr key={role.id}>
                  <td>
                    <code className="small">{role.id}</code>
                  </td>
                  <td>
                    <strong>{role.name}</strong>
                  </td>
                  <td className="cell-wrap">
                    {role.permissions.map((p) => (
                      <code key={p} className="chip">
                        {p}
                      </code>
                    ))}
                  </td>
                  <td>
                    <span className={`badge ${role.builtin ? 'badge-requested' : 'badge-done'}`}>
                      {role.builtin ? 'BUILTIN' : 'CUSTOM'}
                    </span>
                  </td>
                  <td className="small">{formatDateTime(role.created_at)}</td>
                  <td>
                    <button
                      className="btn btn-ghost btn-sm"
                      type="button"
                      onClick={() => {
                        stash('roleId', role.id)
                        navigate('admin-assignments')
                      }}
                    >
                      Assignments
                    </button>
                  </td>
                </tr>
              ))}
              {roles.items.length === 0 && !roles.loading && (
                <tr>
                  <td colSpan={6} className="muted">
                    No roles.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pager list={roles} unit="role" />
      </section>

      <section className="card">
        <h3>Create a role</h3>
        <p className="muted">
          <code>POST /iam/v1/roles</code> with{' '}
          <code>{'{ name, permissions[] }'}</code>. Every permission must already be registered —
          the picker below is fed by <code>GET /iam/v1/permissions</code> for exactly that reason.
        </p>
        <PermissionHint permission="keys.manage" />

        {catalog.problem && <ProblemAlert problem={catalog.problem} />}
        {problem && <ProblemAlert problem={problem} />}
        {created && (
          <div className="alert alert-info">
            Created <code>{created.id}</code> — <strong>{created.name}</strong> with{' '}
            {created.permissions.length} permission{created.permissions.length === 1 ? '' : 's'}.
          </div>
        )}

        <form className="form" onSubmit={(e) => void submit(e)}>
          <label>
            Role name
            <input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="refund-desk"
            />
          </label>

          <MultiSelect
            label="Permissions"
            hint="At least one is required (minItems: 1)."
            disabled={catalog.loading}
            options={catalog.permissions.map((p) => ({
              value: p.name,
              note: p.builtin ? '· builtin' : '· custom',
            }))}
            selected={permissions}
            onChange={setPermissions}
          />

          <div className="row">
            <button
              className="btn"
              type="submit"
              disabled={busy || permissions.length === 0 || name.trim().length === 0}
            >
              {busy ? 'Creating…' : 'Create role'}
            </button>
          </div>
        </form>
      </section>
    </>
  )
}
