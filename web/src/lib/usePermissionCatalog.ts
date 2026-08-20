import { useCallback, useEffect, useState } from 'react'
import { listPermissions, toProblem, type Permission, type Problem } from '../api/client'
import { useCredentialMode } from './credentialMode'

/** `limit` maximum from docs/api-conventions.md — one page holds the catalog. */
const CATALOG_LIMIT = 100

/**
 * The full permission catalog, used to populate the role-permission and API-key
 * scope pickers. Both screens must only offer names the server has registered:
 * `createRole` rejects unknown permissions, and an API key scoped to a
 * nonexistent permission would authenticate but authorize nothing.
 */
export function usePermissionCatalog(): {
  permissions: Permission[]
  loading: boolean
  problem: Problem | null
  reload: () => void
} {
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [problem, setProblem] = useState<Problem | null>(null)
  const [loading, setLoading] = useState(true)
  const [token, setToken] = useState(0)
  // Re-read the catalog when the credential changes: the two identities may not
  // see the same thing (`permissions.read` is RBAC-gated for a user token).
  const mode = useCredentialMode()

  useEffect(() => {
    let active = true
    setLoading(true)
    listPermissions({ limit: CATALOG_LIMIT })
      .then((page) => {
        if (!active) return
        setPermissions(page.items)
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
  }, [token, mode])

  const reload = useCallback(() => setToken((n) => n + 1), [])

  return { permissions, loading, problem, reload }
}
