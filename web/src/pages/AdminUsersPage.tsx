import { useCallback, useEffect, useState } from 'react'
import {
  createAuthUser,
  deleteAuthUser,
  getAuthUser,
  listAuthUsers,
  updateAuthUser,
  type AuthUser,
  type AuthUserAttributes,
} from '../api/authAdmin'
import { AuthAdminError } from '../api/authAdmin'
import type { Problem } from '../api/client'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'
import { ConsentSection } from '../components/ConsentSection'
import { ProfileSection } from '../components/ProfileSection'
import { useCredentialMode } from '../lib/credentialMode'
import { formatDateTime } from '../lib/format'
import { navigate } from '../lib/router'
import { stash, takeStash } from '../lib/handoff'

const PER_PAGE = 10

function problemOf(err: unknown): Problem {
  if (err instanceof AuthAdminError) return err.problem
  return {
    code: 'internal',
    title: 'Auth admin error',
    detail: err instanceof Error ? err.message : 'The request could not be completed.',
  }
}

export function AdminUsersPage() {
  const [users, setUsers] = useState<AuthUser[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [nextPage, setNextPage] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [problem, setProblem] = useState<Problem | null>(null)
  // A subject handed over from another screen (e.g. an audit event's subject
  // manifest) opens straight into the standalone PII profile lookup below —
  // the auth list is paginated and may not even contain that page.
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)
  // The auth admin surface accepts either credential (a user token needs
  // `users.admin`), so switching the selector re-runs the listing as that
  // identity.
  const mode = useCredentialMode()

  const reload = useCallback(() => setReloadToken((n) => n + 1), [])

  // Drop rows fetched as the other identity before the new listing lands.
  const [lastMode, setLastMode] = useState(mode)
  if (lastMode !== mode) {
    setLastMode(mode)
    setUsers([])
  }

  useEffect(() => {
    let active = true
    setLoading(true)
    listAuthUsers(page, PER_PAGE)
      .then((result) => {
        if (!active) return
        setUsers(result.users)
        setTotal(result.total)
        setNextPage(result.nextPage)
        setProblem(null)
      })
      .catch((err: unknown) => {
        if (active) setProblem(problemOf(err))
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [page, reloadToken, mode])

  return (
    <>
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Users (Auth admin)</h2>
            <p className="muted">
              <code>GET /auth/v1/admin/users</code> through{' '}
              <code>supabase.auth.admin.listUsers()</code>. This surface is{' '}
              <strong>not</strong> in <code>openapi.yaml</code>: it is Supabase-Auth compatible, so
              it keeps gotrue&rsquo;s <code>page</code>/<code>per_page</code> pagination and its{' '}
              <code>Link</code> / <code>X-Total-Count</code> headers rather than the cursor
              envelope the management plane uses.
            </p>
          </div>
        </div>
        <PermissionHint permission="service_role JWT (gotrue admin, not an RBAC permission)" />

        {problem && <ProblemAlert problem={problem} />}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>User id</th>
                <th>Email</th>
                <th>Confirmed</th>
                <th>Created</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const deleted = Boolean((u as { deleted_at?: string }).deleted_at)
                const banned = Boolean(u.banned_until)
                return (
                  <tr key={u.id} className={u.id === selectedId ? 'is-mine' : ''}>
                    <td>
                      <code className="small">{u.id}</code>
                    </td>
                    <td>{u.email || <span className="muted">—</span>}</td>
                    <td className="small">{formatDateTime(u.email_confirmed_at)}</td>
                    <td className="small">{formatDateTime(u.created_at)}</td>
                    <td>
                      <span
                        className={`badge ${deleted ? 'badge-canceled' : banned ? 'badge-manual_review' : 'badge-done'}`}
                      >
                        {deleted ? 'SOFT-DELETED' : banned ? 'BANNED' : 'ACTIVE'}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn btn-ghost btn-sm"
                        type="button"
                        onClick={() => setSelectedId(u.id === selectedId ? null : u.id)}
                      >
                        {u.id === selectedId ? 'Close' : 'Open'}
                      </button>
                    </td>
                  </tr>
                )
              })}
              {users.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} className="muted">
                    No users.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="row row-between">
          <span className="muted small">
            {loading ? 'Loading…' : `page ${page} · ${users.length} of ${total} user(s)`}
          </span>
          <div className="row">
            <button className="btn btn-ghost btn-sm" type="button" onClick={reload}>
              Refresh
            </button>
            <button
              className="btn btn-ghost btn-sm"
              type="button"
              disabled={page <= 1 || loading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Previous
            </button>
            <button
              className="btn btn-ghost btn-sm"
              type="button"
              disabled={nextPage === null || loading}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>
      </section>

      {selectedId && (
        <UserDetail
          key={selectedId}
          userId={selectedId}
          onChanged={reload}
          onDeleted={() => {
            setSelectedId(null)
            reload()
          }}
        />
      )}

      <ProfileLookup />

      <CreateUserForm
        onCreated={(user) => {
          reload()
          setSelectedId(user.id)
        }}
      />
    </>
  )
}

/**
 * The PII profile keyed by user id alone, without going through the auth list.
 * A subject id handed over from the audit trail lands here — the audit log
 * knows subjects the gotrue user list may no longer contain.
 */
function ProfileLookup() {
  const [handoff] = useState(() => takeStash('userId'))
  const [draft, setDraft] = useState(handoff)
  const [userId, setUserId] = useState(handoff)

  return (
    <>
      <section className="card">
        <h3>PII profile by user id</h3>
        <p className="muted">
          The profile plane is keyed on <code>user_id</code>, not on an auth account: paste any
          subject id (the audit trail&rsquo;s subject manifest links here) to read its masked
          profile without opening the account row.
        </p>
        <div className="row">
          <label className="select">
            user_id (UUID)
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </label>
          <button
            className="btn btn-ghost btn-sm"
            type="button"
            onClick={() => setUserId(draft.trim())}
          >
            Open profile
          </button>
          {userId && (
            <button
              className="btn btn-ghost btn-sm"
              type="button"
              onClick={() => {
                setDraft('')
                setUserId('')
              }}
            >
              Close
            </button>
          )}
        </div>
      </section>

      {userId && <ProfileSection key={userId} userId={userId} />}
    </>
  )
}

function UserDetail({
  userId,
  onChanged,
  onDeleted,
}: {
  userId: string
  onChanged: () => void
  onDeleted: () => void
}) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [softDelete, setSoftDelete] = useState(false)
  const [deleted, setDeleted] = useState(false)

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [banDuration, setBanDuration] = useState('')

  useEffect(() => {
    let active = true
    getAuthUser(userId)
      .then((u) => {
        if (!active) return
        setUser(u)
        setEmail(u.email ?? '')
        setProblem(null)
      })
      .catch((err: unknown) => {
        if (active) setProblem(problemOf(err))
      })
    return () => {
      active = false
    }
  }, [userId])

  async function save(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setProblem(null)
    setNotice(null)
    try {
      const attributes: AuthUserAttributes = {
        ...(email && email !== user?.email ? { email, email_confirm: true } : {}),
        ...(password ? { password } : {}),
        ...(banDuration ? { ban_duration: banDuration } : {}),
      }
      const updated = await updateAuthUser(userId, attributes)
      setUser(updated)
      setPassword('')
      setNotice('Updated. A password or ban change also revokes every session for this user.')
      onChanged()
    } catch (err) {
      setProblem(problemOf(err))
    } finally {
      setBusy(false)
    }
  }

  async function remove() {
    setBusy(true)
    setProblem(null)
    try {
      await deleteAuthUser(userId, softDelete)
      setDeleted(true)
      setConfirming(false)
      onChanged()
    } catch (err) {
      setProblem(problemOf(err))
    } finally {
      setBusy(false)
    }
  }

  if (deleted) {
    return (
      <section className="card">
        <h3>User deleted — the erasure pipeline is running</h3>
        <div className="alert alert-info">
          <p>
            <code>DELETE /auth/v1/admin/users/{userId}</code> succeeded. In the{' '}
            <strong>same transaction</strong> Dilion wrote a <code>user.deleted</code> row to{' '}
            <code>dilion_privacy.outbox</code>; the privacy engine picks it up and opens a{' '}
            <code>DELETION</code> privacy request for this subject, which then fans out to every
            enabled destination.
          </p>
          <p>
            Deletion of the account row is <em>not</em> what erases the data downstream — the
            request is. Watch it settle:
          </p>
        </div>
        <div className="row">
          <button
            className="btn"
            type="button"
            onClick={() => {
              stash('userId', userId)
              navigate('admin-requests')
            }}
          >
            Watch the DELETION request
          </button>
          <button className="btn btn-ghost" type="button" onClick={onDeleted}>
            Back to the list
          </button>
        </div>
      </section>
    )
  }

  return (
    <>
      <section className="card">
        <h3>User detail</h3>
        <p className="muted">
          <code>supabase.auth.admin.getUserById()</code> /{' '}
          <code>updateUserById()</code> / <code>deleteUser()</code> —{' '}
          <code>GET</code>/<code>PUT</code>/<code>DELETE /auth/v1/admin/users/{'{id}'}</code>.
          gotrue uses <code>PUT</code> here, not <code>PATCH</code>; the body is still a partial
          update.
        </p>

        {problem && <ProblemAlert problem={problem} />}
        {notice && <div className="alert alert-info">{notice}</div>}

        {!user ? (
          <p className="muted">Loading…</p>
        ) : (
          <>
            <dl className="kv">
              <dt>User id</dt>
              <dd>
                <code>{user.id}</code>
              </dd>
              <dt>Email</dt>
              <dd>{user.email || '—'}</dd>
              <dt>Confirmed at</dt>
              <dd>{formatDateTime(user.email_confirmed_at)}</dd>
              <dt>Last sign-in</dt>
              <dd>{formatDateTime(user.last_sign_in_at)}</dd>
              <dt>Banned until</dt>
              <dd>{formatDateTime(user.banned_until)}</dd>
            </dl>

            <form className="form" onSubmit={(e) => void save(e)}>
              <label>
                Email
                <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
              </label>
              <label>
                New password (optional)
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="leave empty to keep"
                />
              </label>
              <label>
                Ban duration (Go duration, or <code>none</code> to lift)
                <input
                  value={banDuration}
                  onChange={(e) => setBanDuration(e.target.value)}
                  placeholder="24h"
                />
              </label>
              <div className="row">
                <button className="btn" type="submit" disabled={busy}>
                  {busy ? 'Saving…' : 'Save changes'}
                </button>
                <button
                  className="btn btn-ghost"
                  type="button"
                  onClick={() => {
                    stash('auditSubjectId', userId)
                    navigate('admin-audit')
                  }}
                >
                  View audit trail
                </button>
              </div>
            </form>
            <p className="muted small">
              &ldquo;View audit trail&rdquo; opens <code>GET /iam/v1/audit/events</code> filtered
              by <code>subject_id</code> — the reverse lookup of §5.3, i.e.{' '}
              <strong>이 사용자를 누가 봤는가</strong>, not what this operator did.
            </p>

            <details className="raw">
              <summary className="muted small">Raw user object</summary>
              <pre className="json">{JSON.stringify(user, null, 2)}</pre>
            </details>

            <h4>Danger zone</h4>
            {!confirming ? (
              <div className="row">
                <button className="btn btn-danger" type="button" onClick={() => setConfirming(true)}>
                  Delete user
                </button>
              </div>
            ) : (
              <div className="confirm">
                <p>
                  <strong>This triggers the erasure pipeline.</strong> Deleting{' '}
                  <code>{user.email || user.id}</code> writes a <code>user.deleted</code> event to
                  the privacy outbox in the same transaction as the account removal. Dilion turns
                  that into a <code>DELETION</code> privacy request and fans it out to every enabled
                  destination — personal data in connected systems is erased, and the compliance
                  record of the request is kept. There is no undo.
                </p>
                <p className="muted small">
                  An active legal hold on this subject will park the resulting request in{' '}
                  <code>MANUAL_REVIEW</code> instead of erasing.
                </p>
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={softDelete}
                    onChange={(e) => setSoftDelete(e.target.checked)}
                  />
                  <span>
                    should_soft_delete — keep the row, obfuscate the identifiers (the outbox event
                    is written either way)
                  </span>
                </label>
                <div className="row">
                  <button
                    className="btn btn-danger"
                    type="button"
                    disabled={busy}
                    onClick={() => void remove()}
                  >
                    {busy ? 'Deleting…' : 'Yes, delete and start erasure'}
                  </button>
                  <button
                    className="btn btn-ghost"
                    type="button"
                    disabled={busy}
                    onClick={() => setConfirming(false)}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </section>

      {user && <ProfileSection userId={user.id} />}
      {user && <ConsentSection userId={user.id} />}
    </>
  )
}

function CreateUserForm({ onCreated }: { onCreated: (user: AuthUser) => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState(true)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [created, setCreated] = useState<AuthUser | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setProblem(null)
    try {
      const user = await createAuthUser({
        email: email.trim(),
        ...(password ? { password } : {}),
        email_confirm: confirm,
      })
      setCreated(user)
      setEmail('')
      setPassword('')
      onCreated(user)
    } catch (err) {
      setProblem(problemOf(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h3>Create a user</h3>
      <p className="muted">
        <code>supabase.auth.admin.createUser()</code> — <code>POST /auth/v1/admin/users</code>. No
        confirmation mail is sent; <code>email_confirm: true</code> marks the address verified
        outright, which is what makes the account immediately usable for a demo.
      </p>

      {problem && <ProblemAlert problem={problem} />}
      {created && (
        <div className="alert alert-info">
          Created <code>{created.id}</code> — {created.email}. That id is the canonical{' '}
          <code>user_id</code> every privacy endpoint is keyed on.
        </div>
      )}

      <form className="form" onSubmit={(e) => void submit(e)}>
        <label>
          Email
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="new.user@example.com"
          />
        </label>
        <label>
          Password (optional)
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            minLength={6}
            placeholder="at least 6 characters"
          />
        </label>
        <label className="switch">
          <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
          <span>email_confirm — mark the address verified</span>
        </label>
        <div className="row">
          <button className="btn" type="submit" disabled={busy || email.trim().length === 0}>
            {busy ? 'Creating…' : 'Create user'}
          </button>
        </div>
      </form>
    </section>
  )
}
