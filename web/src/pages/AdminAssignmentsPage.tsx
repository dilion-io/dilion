import { useCallback, useEffect, useState } from 'react'
import {
  createRoleAssignment,
  listRoleAssignments,
  listRoles,
  revokeRoleAssignment,
  toProblem,
  type Problem,
  type Role,
  type RoleAssignment,
  type RoleAssignmentPage,
} from '../api/client'
import { PAGE_SIZE, usePagedList } from '../lib/usePagedList'
import { ActorCell, ExpandActorToggle } from '../components/ActorCell'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'
import { Pager } from '../components/Pager'
import { formatDateTime } from '../lib/format'
import { takeStash } from '../lib/handoff'

const EMPTY_PAGE: RoleAssignmentPage = { items: [], next_cursor: null }
const ROLE_LIMIT = 100

export function AdminAssignmentsPage() {
  const [roles, setRoles] = useState<Role[]>([])
  const [rolesProblem, setRolesProblem] = useState<Problem | null>(null)
  const [roleId, setRoleId] = useState<string>(() => takeStash('roleId'))

  const [actorFilter, setActorFilter] = useState('')
  const [actorDraft, setActorDraft] = useState('')
  const [includeRevoked, setIncludeRevoked] = useState(true)
  const [expandActor, setExpandActor] = useState(false)

  const [actorId, setActorId] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    listRoles({ limit: ROLE_LIMIT })
      .then((page) => {
        if (!active) return
        setRoles(page.items)
        setRoleId((current) =>
          current && page.items.some((r) => r.id === current)
            ? current
            : (page.items[0]?.id ?? ''),
        )
        setRolesProblem(null)
      })
      .catch((err: unknown) => {
        if (active) setRolesProblem(toProblem(err))
      })
    return () => {
      active = false
    }
  }, [])

  const load = useCallback(
    (cursor?: string): Promise<RoleAssignmentPage> => {
      if (!roleId) return Promise.resolve(EMPTY_PAGE)
      return listRoleAssignments(roleId, {
        limit: PAGE_SIZE,
        ...(cursor ? { cursor } : {}),
        ...(actorFilter ? { actor_id: actorFilter } : {}),
        ...(includeRevoked ? { include_revoked: true } : {}),
        ...(expandActor ? { expand: 'actor' as const } : {}),
      })
    },
    [roleId, actorFilter, includeRevoked, expandActor],
  )
  const assignments = usePagedList<RoleAssignment>(
    load,
    `${roleId}|${actorFilter}|${String(includeRevoked)}|${String(expandActor)}`,
  )

  const role = roles.find((r) => r.id === roleId) ?? null

  async function grant(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setProblem(null)
    setNotice(null)
    try {
      const created = await createRoleAssignment(roleId, { actor_id: actorId.trim() })
      setNotice(
        `Granted ${role?.name ?? roleId} to ${created.actor_id} (assignment #${created.id}).`,
      )
      setActorId('')
      assignments.reload()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  async function revoke(assignment: RoleAssignment) {
    setBusy(true)
    setProblem(null)
    setNotice(null)
    try {
      await revokeRoleAssignment(assignment.id)
      setNotice(
        `Revoked assignment #${assignment.id} (${assignment.actor_id}). The row is kept with revoked_at set — grant history is never deleted.`,
      )
      assignments.reload()
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
            <h2>Role assignments</h2>
            <p className="muted">
              <code>GET /iam/v1/roles/{'{roleId}'}/assignments</code> — who holds this role. Grants
              are never hard-deleted: revoking stamps <code>revoked_at</code> /{' '}
              <code>revoked_by</code> so the history stays auditable (
              <code>include_revoked=true</code>). <code>expand=actor</code> adds whether each
              actor can still use its grant — a revoked assignment and a banned operator are
              different things, and the ledger alone only shows the first.
            </p>
          </div>
        </div>
        <PermissionHint permission={expandActor ? ['audit.read', 'users.read'] : 'audit.read'} />

        {rolesProblem && <ProblemAlert problem={rolesProblem} />}

        <div className="row">
          <label className="select">
            Role
            <select value={roleId} onChange={(e) => setRoleId(e.target.value)}>
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} {r.builtin ? '(builtin)' : ''}
                </option>
              ))}
              {roles.length === 0 && <option value="">No roles</option>}
            </select>
          </label>
          <label className="select">
            Filter by actor_id
            <input
              value={actorDraft}
              onChange={(e) => setActorDraft(e.target.value)}
              placeholder="ops@example.com or key_…"
            />
          </label>
          <button
            className="btn btn-ghost btn-sm"
            type="button"
            onClick={() => setActorFilter(actorDraft.trim())}
          >
            Apply filter
          </button>
          <label className="switch">
            <input
              type="checkbox"
              checked={includeRevoked}
              onChange={(e) => setIncludeRevoked(e.target.checked)}
            />
            <span>include revoked</span>
          </label>
          <ExpandActorToggle expanded={expandActor} onChange={setExpandActor} />
        </div>

        {role && (
          <p className="muted small">
            <code>{role.id}</code> grants{' '}
            {role.permissions.map((p) => (
              <code key={p} className="chip">
                {p}
              </code>
            ))}
          </p>
        )}

        {assignments.problem && <ProblemAlert problem={assignments.problem} />}
        {problem && <ProblemAlert problem={problem} />}
        {notice && <div className="alert alert-info">{notice}</div>}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>#</th>
                <th>Actor</th>
                {expandActor && <th>Actor state</th>}
                <th>Granted by</th>
                <th>Granted at</th>
                <th>Revoked by</th>
                <th>Revoked at</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {assignments.items.map((a) => {
                const active = a.revoked_at === null
                return (
                  <tr key={a.id}>
                    <td className="small">{a.id}</td>
                    <td>
                      <code className="small">{a.actor_id}</code>
                    </td>
                    {expandActor && (
                      <td>
                        <ActorCell actor={a.actor} />
                      </td>
                    )}
                    <td className="small">
                      <code>{a.granted_by ?? '—'}</code>
                    </td>
                    <td className="small">{formatDateTime(a.granted_at)}</td>
                    <td className="small">
                      <code>{a.revoked_by ?? '—'}</code>
                    </td>
                    <td className="small">{formatDateTime(a.revoked_at)}</td>
                    <td>
                      <span className={`badge ${active ? 'badge-done' : 'badge-canceled'}`}>
                        {active ? 'ACTIVE' : 'REVOKED'}
                      </span>
                    </td>
                    <td>
                      {active && (
                        <button
                          className="btn btn-ghost btn-sm"
                          type="button"
                          disabled={busy}
                          onClick={() => void revoke(a)}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
              {assignments.items.length === 0 && !assignments.loading && (
                <tr>
                  <td colSpan={expandActor ? 9 : 8} className="muted">
                    No assignments for this role.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pager list={assignments} unit="assignment" />
      </section>

      <section className="card">
        <h3>Grant this role</h3>
        <p className="muted">
          <code>POST /iam/v1/roles/{'{roleId}'}/assignments</code> with{' '}
          <code>{'{ actor_id }'}</code>. An actor is an operator identity or an API key id —
          whatever your organisation authenticates; Dilion stores the string as given.{' '}
          <code>DELETE /iam/v1/assignments/{'{id}'}</code> revokes it.
        </p>
        <PermissionHint permission="keys.manage" />

        <form className="form" onSubmit={(e) => void grant(e)}>
          <label>
            actor_id
            <input
              required
              value={actorId}
              onChange={(e) => setActorId(e.target.value)}
              placeholder="ops@example.com"
            />
          </label>
          <div className="row">
            <button
              className="btn"
              type="submit"
              disabled={busy || !roleId || actorId.trim().length === 0}
            >
              {busy ? 'Working…' : `Grant ${role?.name ?? 'role'}`}
            </button>
          </div>
        </form>
      </section>
    </>
  )
}
