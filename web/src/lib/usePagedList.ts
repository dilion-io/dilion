import { useCallback, useEffect, useState } from 'react'
import { toProblem, type CursorPage, type Problem } from '../api/client'
import { useCredentialMode } from './credentialMode'

/** Rows per page for the admin console lists. */
export const PAGE_SIZE = 10

export type PagedList<T> = {
  items: T[]
  nextCursor: string | null
  loading: boolean
  problem: Problem | null
  setProblem: (problem: Problem | null) => void
  hasPrev: boolean
  hasNext: boolean
  next: () => void
  prev: () => void
  /** Re-fetch the current page (after a create/revoke). */
  reload: () => void
}

/**
 * The cursor-stack pagination used across the app, factored out so every list
 * behaves identically: the API only hands back `next_cursor`, so "Previous" is
 * implemented by remembering the cursor of each page already visited.
 *
 * `load` must be a stable callback (`useCallback`); `resetKey` is any string
 * that identifies the current filter set — when it changes the stack is dropped
 * and the list jumps back to page one.
 */
export function usePagedList<T>(
  load: (cursor?: string) => Promise<CursorPage<T>>,
  resetKey = '',
): PagedList<T> {
  const [page, setPage] = useState<CursorPage<T> | null>(null)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [loading, setLoading] = useState(true)
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [history, setHistory] = useState<Array<string | undefined>>([])
  const [reloadToken, setReloadToken] = useState(0)
  // Switching the credential changes who is asking, so the current page is
  // re-fetched under the new identity instead of showing the old result.
  const mode = useCredentialMode()

  // Filters changed: drop the cursor stack during render, before the fetch
  // effect runs, so only one request goes out.
  const [lastKey, setLastKey] = useState(resetKey)
  if (lastKey !== resetKey) {
    setLastKey(resetKey)
    setCursor(undefined)
    setHistory([])
    // Bump the token too: if the cursor was already undefined nothing else
    // would change and the fetch effect would not re-run.
    setReloadToken((n) => n + 1)
  }

  // Same trick for the credential: rows fetched as one identity must not stay
  // on screen under the other identity's error.
  const [lastMode, setLastMode] = useState(mode)
  if (lastMode !== mode) {
    setLastMode(mode)
    setPage(null)
  }

  useEffect(() => {
    let active = true
    setLoading(true)
    load(cursor)
      .then((next) => {
        if (!active) return
        setPage(next)
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
  }, [load, cursor, reloadToken, mode])

  const nextCursor = page?.next_cursor ?? null

  const next = useCallback(() => {
    if (!nextCursor) return
    setHistory((h) => [...h, cursor])
    setCursor(nextCursor)
  }, [nextCursor, cursor])

  const prev = useCallback(() => {
    if (history.length === 0) return
    setCursor(history[history.length - 1])
    setHistory((h) => h.slice(0, -1))
  }, [history])

  const reload = useCallback(() => setReloadToken((n) => n + 1), [])

  return {
    items: page?.items ?? [],
    nextCursor,
    loading,
    problem,
    setProblem,
    hasPrev: history.length > 0,
    hasNext: Boolean(nextCursor),
    next,
    prev,
    reload,
  }
}
