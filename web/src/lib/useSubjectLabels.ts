import { useCallback, useState } from 'react'
import {
  MAX_BATCH_PROFILES,
  listUserProfiles,
  toProblem,
  type Problem,
  type Profile,
} from '../api/client'

/** What {@link useSubjectLabels} knows about one id once a batch has loaded. */
export type SubjectLabel =
  | { state: 'unknown' }
  | { state: 'missing' }
  | { state: 'profile'; profile: Profile }

export type SubjectLabels = {
  loaded: boolean
  loading: boolean
  problem: Problem | null
  /** Ids beyond the per-request maximum, which the last batch left out. */
  skipped: number
  load: (subjectIds: readonly string[]) => Promise<void>
  labelFor: (subjectId: string) => SubjectLabel
}

/**
 * Labels a list of subject ids with their MASKED vault profiles through one
 * `GET /privacy/v1/profiles` (`listUserProfiles`) rather than one request per
 * subject.
 *
 * `load` is called from an interaction, never on render. Reading personal data
 * is an audited act — the server records a single `PII_MASKED_READ` naming
 * these subjects — so a screen that happens to list subject ids must not
 * quietly produce another access record. The operator asks, and the request
 * happens.
 *
 * Values are the masked projection. Originals need `pii.reveal`, a written
 * reason, and one request per subject, which is the profile screen's job.
 */
export function useSubjectLabels(): SubjectLabels {
  const [byId, setById] = useState<Map<string, Profile> | null>(null)
  const [missing, setMissing] = useState<Set<string>>(() => new Set())
  const [problem, setProblem] = useState<Problem | null>(null)
  const [loading, setLoading] = useState(false)
  const [skipped, setSkipped] = useState(0)

  const load = useCallback(async (subjectIds: readonly string[]) => {
    const ids = subjectIds.slice(0, MAX_BATCH_PROFILES)
    setLoading(true)
    setProblem(null)
    setSkipped(subjectIds.length - ids.length)
    try {
      const batch = await listUserProfiles(ids)
      setById(new Map(batch.items.map((p) => [p.user_id, p])))
      setMissing(new Set(batch.missing))
    } catch (err) {
      setProblem(toProblem(err))
      setById(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const labelFor = useCallback(
    (subjectId: string): SubjectLabel => {
      const profile = byId?.get(subjectId)
      if (profile) return { state: 'profile', profile }
      if (missing.has(subjectId)) return { state: 'missing' }
      return { state: 'unknown' }
    },
    [byId, missing],
  )

  return { loaded: byId !== null, loading, problem, skipped, load, labelFor }
}
