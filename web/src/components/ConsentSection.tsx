import { useCallback, useEffect, useState } from 'react'
import {
  listUserConsents,
  toProblem,
  updateUserConsent,
  type ConsentState,
  type Problem,
} from '../api/client'
import { ProblemAlert } from './ProblemAlert'

/** Policy version presented to the subject — pinned per release in a real app. */
const POLICY_VERSION = '2026-01-01'

/** Purposes this sample surfaces, whether or not the ledger has a record yet. */
const PURPOSES: ReadonlyArray<{ key: string; label: string; description: string }> = [
  {
    key: 'marketing',
    label: 'Marketing emails',
    description: 'Product news and offers sent to your email address.',
  },
  {
    key: 'analytics',
    label: 'Product analytics',
    description: 'Usage events tied to your account, used to improve the product.',
  },
]

type Row = {
  purpose: string
  label: string
  description: string
  state: ConsentState | null
}

export function ConsentSection({ userId }: { userId: string }) {
  const [consents, setConsents] = useState<ConsentState[]>([])
  const [problem, setProblem] = useState<Problem | null>(null)
  const [loading, setLoading] = useState(true)
  const [pending, setPending] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)
  const load = useCallback(() => setReloadToken((n) => n + 1), [])

  // Guarded so a reload that is still in flight when the user toggles a switch
  // cannot land afterwards and overwrite the fresher PATCH result.
  useEffect(() => {
    let active = true
    setLoading(true)
    listUserConsents(userId)
      .then((items) => {
        if (!active) return
        setConsents(items)
        setProblem(null)
      })
      .catch((err: unknown) => {
        if (active) setProblem(toProblem(err))
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [userId, reloadToken])

  async function toggle(purpose: string, granted: boolean) {
    setPending(purpose)
    try {
      const updated = await updateUserConsent(userId, {
        purpose,
        granted,
        policy_version: POLICY_VERSION,
        source: 'UI',
      })
      setConsents((prev) => {
        const rest = prev.filter((c) => c.purpose !== updated.purpose)
        return [...rest, updated].sort((a, b) => a.purpose.localeCompare(b.purpose))
      })
      setProblem(null)
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setPending(null)
    }
  }

  const known = new Map(consents.map((c) => [c.purpose, c]))
  const rows: Row[] = [
    ...PURPOSES.map((p) => ({
      purpose: p.key,
      label: p.label,
      description: p.description,
      state: known.get(p.key) ?? null,
    })),
    // Purposes recorded server-side that this build doesn't know about.
    ...consents
      .filter((c) => !PURPOSES.some((p) => p.key === c.purpose))
      .map((c) => ({
        purpose: c.purpose,
        label: c.purpose,
        description: 'Recorded outside this UI.',
        state: c,
      })),
  ]

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Consents</h2>
          <p className="muted">
            <code>GET/PATCH /privacy/v1/users/{'{userId}'}/consents</code> — the consent ledger is
            append-only, so each toggle records a new entry with the policy version and{' '}
            <code>source: &quot;UI&quot;</code>. What you see here is the derived current state.
          </p>
        </div>
        <button className="btn btn-ghost" onClick={load} disabled={loading}>
          Refresh
        </button>
      </div>

      {problem && <ProblemAlert problem={problem} />}

      <ul className="consent-list">
        {rows.map((row) => {
          const granted = row.state?.granted ?? false
          return (
            <li key={row.purpose} className="consent-row">
              <div>
                <strong>{row.label}</strong>
                <div className="muted small">{row.description}</div>
                <div className="muted small">
                  <code>{row.purpose}</code>
                  {row.state ? (
                    <>
                      {' · policy '}
                      <code>{row.state.policy_version}</code>
                      {' · updated '}
                      {new Date(row.state.updated_at).toLocaleString()}
                      {row.state.reconfirm_due && (
                        <>
                          {' · reconfirm due '}
                          {new Date(row.state.reconfirm_due).toLocaleDateString()}
                        </>
                      )}
                    </>
                  ) : (
                    ' · never recorded'
                  )}
                </div>
              </div>
              <label className="switch">
                <input
                  type="checkbox"
                  checked={granted}
                  disabled={pending === row.purpose || loading}
                  onChange={(e) => void toggle(row.purpose, e.target.checked)}
                />
                <span>{granted ? 'Granted' : 'Withdrawn'}</span>
              </label>
            </li>
          )
        })}
      </ul>
    </section>
  )
}
