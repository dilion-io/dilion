/**
 * The two pieces that render {@link useSubjectLabels}: the control that asks
 * for the batch, and one subject's masked fields.
 *
 * They are split from the list they annotate so a screen keeps whatever row
 * layout it already has — the audit event's subject manifest still shows its
 * own per-subject actions, with the label slotted in.
 */
import { MAX_BATCH_PROFILES } from '../api/client'
import type { SubjectLabel, SubjectLabels } from '../lib/useSubjectLabels'
import { ProblemAlert } from './ProblemAlert'

/**
 * The control that triggers the batch, with the cost stated up front: which
 * permission it needs, and that it is recorded.
 */
export function SubjectLabelsButton({
  labels,
  subjectIds,
}: {
  labels: SubjectLabels
  subjectIds: readonly string[]
}) {
  const count = Math.min(subjectIds.length, MAX_BATCH_PROFILES)
  return (
    <>
      {labels.problem && <ProblemAlert problem={labels.problem} />}
      <p className="row row-tight">
        <button
          className="btn btn-ghost btn-sm"
          type="button"
          disabled={labels.loading || count === 0}
          onClick={() => void labels.load(subjectIds)}
        >
          {labels.loading
            ? 'Loading…'
            : labels.loaded
              ? 'Reload names'
              : `Show masked names (${count})`}
        </button>
        <span className="muted small">
          One <code>GET /privacy/v1/profiles</code> for all of them, recorded as a single{' '}
          <code>PII_MASKED_READ</code>. Requires <code>users.read</code>.
        </span>
      </p>
      {labels.skipped > 0 && (
        <p className="muted small">
          {labels.skipped} further subject{labels.skipped === 1 ? '' : 's'} left unlabelled: one
          request carries at most {MAX_BATCH_PROFILES}.
        </p>
      )}
    </>
  )
}

/** One subject's masked fields, or why there are none. Empty before a load. */
export function SubjectLabelFields({ label }: { label: SubjectLabel }) {
  if (label.state === 'unknown') return null
  if (label.state === 'missing') {
    return <span className="muted small">no vault profile stored</span>
  }
  const fields = Object.entries(label.profile.fields)
  if (fields.length === 0) return <span className="muted small">empty profile</span>
  return (
    <span className="small">
      {fields.map(([key, field]) => (
        <code key={key} className="chip">
          {key}: {field.value}
        </code>
      ))}
    </span>
  )
}
