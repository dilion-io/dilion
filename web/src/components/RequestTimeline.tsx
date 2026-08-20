import type { PrivacyRequest, PrivacyRequestStatus } from '../api/client'

const HAPPY_PATH: PrivacyRequestStatus[] = ['REQUESTED', 'PROCESSING', 'DONE']

const STEP_COPY: Record<PrivacyRequestStatus, string> = {
  REQUESTED: 'Accepted (202). Grace period running.',
  PROCESSING: 'Erasure pipeline fanning out to destinations.',
  DONE: 'All destinations reported completion.',
  MANUAL_REVIEW: 'A destination needs a human decision.',
  CANCELED: 'Withdrawn before the grace deadline expired.',
}

function stageIndex(status: PrivacyRequestStatus): number {
  const i = HAPPY_PATH.indexOf(status)
  // Terminal off-path states sit at the end of the pipeline.
  return i === -1 ? HAPPY_PATH.length - 1 : i
}

export function RequestTimeline({ request }: { request: PrivacyRequest }) {
  const current = stageIndex(request.status)
  const offPath = !HAPPY_PATH.includes(request.status)

  return (
    <ol className="timeline">
      {HAPPY_PATH.map((step, i) => {
        const done = i < current || (i === current && request.status === 'DONE')
        const active = i === current && !offPath
        return (
          <li
            key={step}
            className={`timeline-step ${done ? 'is-done' : ''} ${active ? 'is-active' : ''}`}
          >
            <span className="timeline-dot" aria-hidden="true" />
            <div>
              <strong>{step}</strong>
              <div className="muted small">{STEP_COPY[step]}</div>
            </div>
          </li>
        )
      })}
      {offPath && (
        <li className="timeline-step is-terminal">
          <span className="timeline-dot" aria-hidden="true" />
          <div>
            <strong>{request.status}</strong>
            <div className="muted small">{STEP_COPY[request.status]}</div>
          </div>
        </li>
      )}
    </ol>
  )
}
