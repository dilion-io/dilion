export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/** Human duration for a grace window, e.g. "30 days" / "12 hours" / "immediate". */
export function formatDuration(ms: number): string {
  if (ms <= 1000) return 'immediate'
  const units: ReadonlyArray<[label: string, size: number]> = [
    ['day', 86_400_000],
    ['hour', 3_600_000],
    ['minute', 60_000],
    ['second', 1000],
  ]
  for (const [label, size] of units) {
    const n = Math.round(ms / size)
    if (n >= 1) return `${n} ${label}${n === 1 ? '' : 's'}`
  }
  return 'immediate'
}
