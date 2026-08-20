/**
 * One-shot values handed from one admin screen to the next.
 *
 * The hash router carries a route and nothing else, so "show me the assignments
 * of *this* role" / "watch the DELETION request for *this* user" park their
 * argument here and the destination screen consumes it once on mount.
 */
export type HandoffKey =
  | 'roleId'
  | 'userId'
  | 'permission'
  | 'requestId'
  /** Subject to pre-filter the audit trail by ("who looked at this user"). */
  | 'auditSubjectId'

const PREFIX = 'dilion.admin.'

export function stash(key: HandoffKey, value: string): void {
  window.sessionStorage.setItem(PREFIX + key, value)
}

/** Read and clear — a handoff must not resurrect on the next visit. */
export function takeStash(key: HandoffKey): string {
  const value = window.sessionStorage.getItem(PREFIX + key)
  if (value !== null) window.sessionStorage.removeItem(PREFIX + key)
  return value ?? ''
}
