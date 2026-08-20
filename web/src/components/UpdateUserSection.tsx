/**
 * Self-service `PUT /auth/v1/user`, split into the three things a user actually
 * does with it: change the email, change the password, edit `user_metadata`.
 *
 * All three are the *same* endpoint — `supabase.auth.updateUser()` — but they
 * have different consequences, so they get different cards and different
 * warnings rather than one "save profile" button that quietly signs you out of
 * your phone.
 */
import { useEffect, useState } from 'react'
import type { User } from '@supabase/supabase-js'
import { supabase } from '../lib/supabase'
import { problemFromAuthError } from '../api/authAdmin'
import type { Problem } from '../api/client'
import { ProblemAlert } from './ProblemAlert'

type Feedback = { problem: Problem | null; notice: string | null }

const QUIET: Feedback = { problem: null, notice: null }

/** All three cards, sharing one "the user changed" callback. */
export function UpdateUserSection({
  user,
  onUserChanged,
}: {
  user: User
  onUserChanged: (user: User) => void
}) {
  return (
    <>
      <ChangeEmailCard user={user} onUserChanged={onUserChanged} />
      <ChangePasswordCard onUserChanged={onUserChanged} />
      <EditMetadataCard user={user} onUserChanged={onUserChanged} />
    </>
  )
}

function ChangeEmailCard({
  user,
  onUserChanged,
}: {
  user: User
  onUserChanged: (user: User) => void
}) {
  const [email, setEmail] = useState(user.email ?? '')
  const [busy, setBusy] = useState(false)
  const [feedback, setFeedback] = useState<Feedback>(QUIET)

  // Keep the field in step when the user object is replaced from elsewhere.
  useEffect(() => {
    setEmail(user.email ?? '')
  }, [user.email])

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setFeedback(QUIET)
    try {
      const { data, error } = await supabase.auth.updateUser({ email })
      if (error) {
        setFeedback({ problem: problemFromAuthError(error), notice: null })
      } else if (data.user) {
        onUserChanged(data.user)
        setFeedback({ problem: null, notice: `Email is now ${data.user.email ?? '—'}.` })
      }
    } catch (err) {
      setFeedback({ problem: problemFromAuthError(err), notice: null })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h3>Change email</h3>
      <p className="muted">
        <code>PUT /auth/v1/user</code> via <code>supabase.auth.updateUser({'{ email }'})</code>.
        Wave 1 has email confirmation disabled, so the new address applies immediately and the{' '}
        <em>old</em> address is notified. A duplicate address answers{' '}
        <code>422 email_exists</code>.
      </p>
      <form className="form" onSubmit={onSubmit}>
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
        <button className="btn" type="submit" disabled={busy || email === (user.email ?? '')}>
          {busy ? 'Saving…' : 'Update email'}
        </button>
      </form>
      <CardFeedback feedback={feedback} />
    </section>
  )
}

function ChangePasswordCard({ onUserChanged }: { onUserChanged: (user: User) => void }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [feedback, setFeedback] = useState<Feedback>(QUIET)

  const mismatch = confirm.length > 0 && confirm !== password

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (mismatch) return
    setBusy(true)
    setFeedback(QUIET)
    try {
      const { data, error } = await supabase.auth.updateUser({ password })
      if (error) {
        setFeedback({ problem: problemFromAuthError(error), notice: null })
      } else if (data.user) {
        onUserChanged(data.user)
        setPassword('')
        setConfirm('')
        setFeedback({
          problem: null,
          notice: 'Password changed. Every other session has been signed out; this one survives.',
        })
      }
    } catch (err) {
      setFeedback({ problem: problemFromAuthError(err), notice: null })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h3>Change password</h3>
      <p className="muted">
        <code>PUT /auth/v1/user</code> via <code>supabase.auth.updateUser({'{ password }'})</code>.
        Reusing the current password answers <code>422 same_password</code>.
      </p>
      <form className="form" onSubmit={onSubmit}>
        <label>
          New password
          <input
            type="password"
            required
            minLength={6}
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
          />
          <span className="muted small">
            변경 시 다른 세션이 폐기됩니다 — 이 브라우저 세션만 유지되고, 다른 기기의 refresh
            token은 모두 무효화됩니다.
          </span>
        </label>
        <label>
          Confirm new password
          <input
            type="password"
            required
            minLength={6}
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="••••••••"
          />
          {mismatch && <span className="field-error">Passwords do not match.</span>}
        </label>
        <button className="btn" type="submit" disabled={busy || mismatch || password.length === 0}>
          {busy ? 'Saving…' : 'Update password'}
        </button>
      </form>
      <CardFeedback feedback={feedback} />
    </section>
  )
}

function EditMetadataCard({
  user,
  onUserChanged,
}: {
  user: User
  onUserChanged: (user: User) => void
}) {
  const serverJson = JSON.stringify(user.user_metadata ?? {}, null, 2)
  const [draft, setDraft] = useState(serverJson)
  const [busy, setBusy] = useState(false)
  const [feedback, setFeedback] = useState<Feedback>(QUIET)

  useEffect(() => {
    setDraft(serverJson)
  }, [serverJson])

  // Client-side validation first: the textarea must hold a JSON *object*.
  let parsed: Record<string, unknown> | null = null
  let syntaxError: string | null = null
  try {
    const value: unknown = JSON.parse(draft)
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      syntaxError = 'user_metadata must be a JSON object, not an array or a scalar.'
    } else {
      parsed = value as Record<string, unknown>
    }
  } catch (err) {
    syntaxError = err instanceof Error ? err.message : 'Invalid JSON'
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!parsed) return
    setBusy(true)
    setFeedback(QUIET)
    try {
      const { data, error } = await supabase.auth.updateUser({ data: parsed })
      if (error) {
        setFeedback({ problem: problemFromAuthError(error), notice: null })
      } else if (data.user) {
        onUserChanged(data.user)
        setFeedback({ problem: null, notice: 'user_metadata saved.' })
      }
    } catch (err) {
      setFeedback({ problem: problemFromAuthError(err), notice: null })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h3>Edit user_metadata</h3>
      <p className="muted">
        <code>PUT /auth/v1/user</code> via <code>supabase.auth.updateUser({'{ data }'})</code>. The
        server <strong>merges</strong> this object into the existing metadata and a{' '}
        <code>null</code> value deletes that key — so this is a patch, not a replace.{' '}
        <code>app_metadata</code> is deliberately not editable here: only the admin surface may
        change it.
      </p>
      <form className="form" onSubmit={onSubmit}>
        <label>
          user_metadata (JSON object)
          <textarea
            className="mono"
            rows={8}
            spellCheck={false}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
          />
          {syntaxError ? (
            <span className="field-error">{syntaxError}</span>
          ) : (
            <span className="muted small">Valid JSON object.</span>
          )}
        </label>
        <div className="row">
          <button className="btn" type="submit" disabled={busy || parsed === null}>
            {busy ? 'Saving…' : 'Save metadata'}
          </button>
          <button
            className="btn btn-ghost"
            type="button"
            onClick={() => setDraft(serverJson)}
            disabled={draft === serverJson}
          >
            Reset
          </button>
        </div>
      </form>
      <CardFeedback feedback={feedback} />
    </section>
  )
}

function CardFeedback({ feedback }: { feedback: Feedback }) {
  return (
    <>
      {feedback.problem && <ProblemAlert problem={feedback.problem} />}
      {feedback.notice && <div className="alert alert-info">{feedback.notice}</div>}
    </>
  )
}
