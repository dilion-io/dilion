import { useCallback, useEffect, useRef, useState } from 'react'
import {
  getUserProfile,
  revealUserProfile,
  toProblem,
  updateUserProfile,
  type Problem,
  type Profile,
  type ProfileField,
  type ProfileFieldHint,
  type UpdateUserProfileBody,
} from '../api/client'
import { ProblemAlert } from './ProblemAlert'
import { PermissionHint } from './PermissionHint'
import { formatDateTime } from '../lib/format'
import { navigate } from '../lib/router'
import { stash } from '../lib/handoff'

/** Mirror of `profileKeyRe` in `internal/privacy/profile.go`. */
const FIELD_KEY_RE = /^[a-z][a-z0-9_.-]{0,63}$/

const HINTS: ReadonlyArray<{ value: ProfileFieldHint; note: string }> = [
  { value: 'EMAIL', note: 'a***@example.com' },
  { value: 'NAME', note: '홍**' },
  { value: 'PHONE', note: '010-****-1234' },
  { value: 'ADDRESS', note: 'first token only' },
  { value: 'GENERIC', note: 'fully replaced' },
]

/**
 * Client-side copy of the server rule. The server is still the authority — its
 * 422 renders through <ProblemAlert /> like any other validation failure — but
 * checking here keeps the obvious typos out of the round trip.
 */
function validateKey(key: string): string | null {
  if (key.length === 0) return null
  if (!FIELD_KEY_RE.test(key)) {
    return 'Must match ^[a-z][a-z0-9_.-]{0,63}$ — lower-case, starting with a letter.'
  }
  return null
}

type Staged = {
  /** Fields to upsert, keyed by field name. */
  set: Record<string, ProfileField>
  /** Field names to delete. */
  remove: string[]
}

const NOTHING_STAGED: Staged = { set: {}, remove: [] }

function stagedCount(staged: Staged): number {
  return Object.keys(staged.set).length + staged.remove.length
}

type Row = {
  key: string
  field: ProfileField
  /** Not stored yet — a staged upsert of a key the profile does not have. */
  isNew: boolean
  isEdited: boolean
  isRemoved: boolean
}

/**
 * A data subject's PII profile (§2.6–§2.7), masked by default.
 *
 * Three distinct authorities meet in this one card, which is the whole point of
 * the design: `users.read` sees the hint-based projection, `pii.reveal` plus a
 * written reason sees the originals (and leaves a `PII_FULL_READ` behind), and
 * `pii.write` changes them (`PII_UPDATE`). None of the three implies another.
 */
export function ProfileSection({ userId }: { userId: string }) {
  const [profile, setProfile] = useState<Profile | null>(null)
  const [missing, setMissing] = useState(false)
  const [loading, setLoading] = useState(true)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [staged, setStaged] = useState<Staged>(NOTHING_STAGED)
  const [revealing, setRevealing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [reloadToken, setReloadToken] = useState(0)
  const keyInput = useRef<HTMLInputElement>(null)

  /** Back to the masked projection: re-read, which is a fresh PII_MASKED_READ. */
  const remask = useCallback(() => {
    setNotice(null)
    setReloadToken((n) => n + 1)
  }, [])

  // A different subject is a different profile: staged edits must not follow.
  useEffect(() => {
    setStaged(NOTHING_STAGED)
    setNotice(null)
  }, [userId])

  useEffect(() => {
    let active = true
    setLoading(true)
    getUserProfile(userId)
      .then((next) => {
        if (!active) return
        setProfile(next)
        setMissing(false)
        setProblem(null)
      })
      .catch((err: unknown) => {
        if (!active) return
        const p = toProblem(err)
        // 404 is not a failure here: the subject simply has no profile row yet.
        if (p.code === 'not_found') {
          setProfile(null)
          setMissing(true)
          setProblem(null)
        } else {
          setProblem(p)
        }
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [userId, reloadToken])

  const full = profile?.view === 'FULL'

  function stageSet(key: string, field: ProfileField) {
    setStaged((prev) => ({
      set: { ...prev.set, [key]: field },
      remove: prev.remove.filter((k) => k !== key),
    }))
  }

  function toggleRemove(key: string) {
    setStaged((prev) => {
      if (prev.remove.includes(key)) {
        return { ...prev, remove: prev.remove.filter((k) => k !== key) }
      }
      const { [key]: _dropped, ...rest } = prev.set
      return { set: rest, remove: [...prev.remove, key] }
    })
  }

  function unstage(key: string) {
    setStaged((prev) => {
      const { [key]: _dropped, ...rest } = prev.set
      return { set: rest, remove: prev.remove.filter((k) => k !== key) }
    })
  }

  async function reveal(reason: string) {
    setProblem(null)
    setNotice(null)
    try {
      const revealed = await revealUserProfile(userId, { reason })
      setProfile(revealed)
      setMissing(false)
      setRevealing(false)
      setNotice(
        `PII_FULL_READ recorded for this subject with the reason you gave. It is visible on the audit trail immediately.`,
      )
    } catch (err) {
      setProblem(toProblem(err))
      setRevealing(false)
    }
  }

  async function save() {
    setSaving(true)
    setProblem(null)
    setNotice(null)
    try {
      const body: UpdateUserProfileBody = {
        ...(Object.keys(staged.set).length > 0 ? { set: staged.set } : {}),
        ...(staged.remove.length > 0 ? { remove: staged.remove } : {}),
      }
      // The response is the masked projection of the result: writing personal
      // data never reveals it, so this also drops us out of the FULL view.
      const updated = await updateUserProfile(userId, body)
      setProfile(updated)
      setMissing(Object.keys(updated.fields).length === 0)
      setStaged(NOTHING_STAGED)
      setNotice(
        `Saved as one PATCH (PII_UPDATE). The response is the MASKED projection — a write never echoes the originals back.`,
      )
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setSaving(false)
    }
  }

  const stored = profile?.fields ?? {}
  const rows: Row[] = [
    ...Object.keys(stored)
      .sort()
      .map((key) => ({
        key,
        field: staged.set[key] ?? stored[key],
        isNew: false,
        isEdited: key in staged.set,
        isRemoved: staged.remove.includes(key),
      })),
    ...Object.keys(staged.set)
      .filter((key) => !(key in stored))
      .sort()
      .map((key) => ({
        key,
        field: staged.set[key],
        isNew: true,
        isEdited: true,
        isRemoved: false,
      })),
  ]

  const pending = stagedCount(staged)

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>
            PII profile{' '}
            <span className={full ? 'tag tag-danger' : 'tag'}>
              {full ? 'FULL — audited (PII_FULL_READ)' : 'MASKED'}
            </span>
          </h2>
          <p className="muted">
            <code>
              GET /privacy/v1/users/{'{'}userId{'}'}/profile
            </code>{' '}
            is masked by default (§2.6): each value is projected from its masking hint, never
            fetched and then hidden in the browser. The originals are a separate operation with a
            separate permission and a mandatory reason.
          </p>
        </div>
        <button className="btn btn-ghost btn-sm" type="button" onClick={remask}>
          Refresh
        </button>
      </div>
      <PermissionHint permission={['users.read', 'pii.reveal', 'pii.write']} />

      {problem && <ProblemAlert problem={problem} />}
      {notice && <div className="alert alert-info">{notice}</div>}

      {full && (
        <div className="alert alert-error" role="alert">
          <strong>Showing original values.</strong> This view exists because{' '}
          <code>POST …/profile/reveal</code> succeeded with a written reason; the reason and this
          subject&rsquo;s id are already on a <code>PII_FULL_READ</code> event. Mask it again as
          soon as you are done.
        </div>
      )}

      {loading && !profile && !missing && <p className="muted">Loading…</p>}

      {missing && pending === 0 ? (
        <div className="alert alert-info">
          <p>
            <strong>프로필 없음</strong> — <code>404 not_found</code>. This subject has no PII
            profile row at all; that is a different thing from an empty one, because Dilion deletes
            the row (and shreds its key) rather than storing an empty envelope.
          </p>
          <div className="row">
            <button
              className="btn"
              type="button"
              onClick={() => keyInput.current?.focus()}
            >
              Add the first field
            </button>
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Field</th>
                <th>{full ? 'Original value' : 'Masked value'}</th>
                <th>Hint</th>
                <th>Staged</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key} className={row.isRemoved ? 'is-struck' : ''}>
                  <td>
                    <code>{row.key}</code>
                  </td>
                  <td className="cell-wrap">
                    {row.isNew || row.isEdited ? (
                      <code>{row.field.value}</code>
                    ) : (
                      <code className={full ? 'pii-full' : ''}>{row.field.value}</code>
                    )}
                  </td>
                  <td>
                    <span className="badge badge-requested">{row.field.hint}</span>
                  </td>
                  <td className="small">
                    {row.isRemoved ? (
                      <span className="badge badge-manual_review">REMOVE</span>
                    ) : row.isNew ? (
                      <span className="badge badge-processing">NEW</span>
                    ) : row.isEdited ? (
                      <span className="badge badge-processing">EDIT</span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    <div className="row row-tight">
                      {(row.isNew || row.isEdited || row.isRemoved) && (
                        <button
                          className="btn btn-ghost btn-sm"
                          type="button"
                          onClick={() => unstage(row.key)}
                        >
                          Undo
                        </button>
                      )}
                      {!row.isNew && !row.isRemoved && (
                        <button
                          className="btn btn-ghost btn-sm"
                          type="button"
                          onClick={() => toggleRemove(row.key)}
                        >
                          Remove
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && !loading && (
                <tr>
                  <td colSpan={5} className="muted">
                    No fields.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="row row-between">
        <span className="muted small">
          {loading
            ? 'Loading…'
            : `${rows.length} field${rows.length === 1 ? '' : 's'} · last written ${formatDateTime(profile?.updated_at)}`}
        </span>
        <div className="row">
          {full ? (
            <button className="btn btn-ghost" type="button" onClick={remask}>
              다시 마스킹
            </button>
          ) : (
            <button
              className="btn btn-danger"
              type="button"
              disabled={missing && pending === 0}
              onClick={() => setRevealing(true)}
            >
              원본 보기
            </button>
          )}
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
      </div>

      <StageFieldForm
        keyRef={keyInput}
        existing={Object.keys(stored)}
        onStage={stageSet}
        disabled={saving}
      />

      <div className="row row-between">
        <span className="muted small">
          {pending === 0
            ? 'Nothing staged. Changes are batched and sent as a single PATCH.'
            : `${pending} change${pending === 1 ? '' : 's'} staged: ${Object.keys(staged.set).length} set, ${staged.remove.length} remove.`}
        </span>
        <div className="row">
          <button
            className="btn btn-ghost"
            type="button"
            disabled={pending === 0 || saving}
            onClick={() => setStaged(NOTHING_STAGED)}
          >
            Discard staged
          </button>
          <button
            className="btn"
            type="button"
            disabled={pending === 0 || saving}
            onClick={() => void save()}
          >
            {saving ? 'Saving…' : 'Save staged changes'}
          </button>
        </div>
      </div>

      {revealing && (
        <RevealModal
          userId={userId}
          onCancel={() => setRevealing(false)}
          onConfirm={(reason) => void reveal(reason)}
        />
      )}
    </section>
  )
}

/** Add a new field or replace an existing one — both are `set` on the wire. */
function StageFieldForm({
  keyRef,
  existing,
  onStage,
  disabled,
}: {
  keyRef: React.RefObject<HTMLInputElement | null>
  existing: readonly string[]
  onStage: (key: string, field: ProfileField) => void
  disabled?: boolean
}) {
  const [key, setKey] = useState('')
  const [value, setValue] = useState('')
  const [hint, setHint] = useState<ProfileFieldHint>('GENERIC')

  const trimmed = key.trim()
  const keyError = validateKey(trimmed)
  const replaces = existing.includes(trimmed)

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (keyError || trimmed.length === 0 || value.length === 0) return
    onStage(trimmed, { value, hint })
    setKey('')
    setValue('')
    setHint('GENERIC')
  }

  return (
    <>
      <h3>Add or replace a field</h3>
      <p className="muted">
        <code>
          PATCH /privacy/v1/users/{'{'}userId{'}'}/profile
        </code>{' '}
        with <code>{'{ set, remove }'}</code>. Field keys are arbitrary — the profile is an open
        key→field map, not a fixed schema — but the key must match{' '}
        <code>^[a-z][a-z0-9_.-]{'{0,63}'}$</code> and the hint decides how the value looks to
        everyone who lacks <code>pii.reveal</code>.
      </p>
      <PermissionHint permission="pii.write" />

      <form className="form" onSubmit={submit}>
        <div className="row">
          <label className="select">
            Field key
            <input
              ref={keyRef}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="name / email / billing.vat_id"
              aria-invalid={keyError !== null}
              disabled={disabled}
            />
          </label>
          <label className="select">
            Value
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="original value — it is encrypted at rest"
              disabled={disabled}
            />
          </label>
          <label className="select">
            Masking hint
            <select
              value={hint}
              onChange={(e) => setHint(e.target.value as ProfileFieldHint)}
              disabled={disabled}
            >
              {HINTS.map((h) => (
                <option key={h.value} value={h.value}>
                  {h.value} — {h.note}
                </option>
              ))}
            </select>
          </label>
        </div>
        {keyError && (
          <p className="field-error small" role="alert">
            {keyError}
          </p>
        )}
        {replaces && keyError === null && (
          <p className="muted small">
            <code>{trimmed}</code> already exists — staging this replaces its value and hint.
          </p>
        )}
        <div className="row">
          <button
            className="btn"
            type="submit"
            disabled={disabled || trimmed.length === 0 || value.length === 0 || keyError !== null}
          >
            Stage {replaces ? 'replacement' : 'field'}
          </button>
        </div>
      </form>
    </>
  )
}

/**
 * The reason is not a formality: it is the only human-readable justification the
 * `PII_FULL_READ` event will ever carry, so the reveal is blocked until one is
 * typed (server-side rule `minLength: 1`, checked here too).
 */
function RevealModal({
  userId,
  onCancel,
  onConfirm,
}: {
  userId: string
  onCancel: () => void
  onConfirm: (reason: string) => void
}) {
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const ok = reason.trim().length > 0 && reason.length <= 500

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Reveal original PII">
      <div className="modal">
        <h3>원본 보기 — 사유가 필요합니다</h3>
        <div className="alert alert-error" role="alert">
          <strong>This is a privileged read.</strong> <code>POST …/profile/reveal</code> requires{' '}
          <code>pii.reveal</code> and writes a <code>PII_FULL_READ</code> event carrying your
          reason, this subject&rsquo;s id and the access level <code>full</code>. It cannot be
          taken back.
        </div>

        <dl className="kv">
          <dt>Data subject</dt>
          <dd>
            <code>{userId}</code>
          </dd>
        </dl>

        <label className="form">
          Reason (recorded, 1–500 characters)
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            maxLength={500}
            placeholder="Support ticket #4821 — subject asked us to confirm the phone number on file."
            aria-invalid={reason.length > 0 && !ok}
          />
        </label>
        <p className="muted small">{reason.trim().length}/500</p>

        <div className="row">
          <button
            className="btn btn-danger"
            type="button"
            disabled={!ok || busy}
            onClick={() => {
              setBusy(true)
              onConfirm(reason.trim())
            }}
          >
            {busy ? 'Revealing…' : 'Reveal originals'}
          </button>
          <button className="btn btn-ghost" type="button" disabled={busy} onClick={onCancel}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}
