/**
 * Which credential the management-plane calls are signed with.
 *
 * The sample can drive `/privacy/v1`, `/iam/v1` and `/auth/v1/admin/*` two ways:
 *
 * - **SERVICE** — the dev `service_role` JWT from `VITE_DILION_SERVICE_TOKEN`.
 *   It is a full-tenant credential and bypasses RBAC entirely.
 * - **SESSION** — the access token of the currently signed-in user. The server
 *   authorizes it through `role_assignments` (deny by default), so the account
 *   needs a role granting the endpoint's permission — `users.admin` for the auth
 *   admin surface — or the call answers `403 permission_denied` / `not_admin`.
 *
 * The choice is a tiny external store (no dependency, no context) so that the
 * API client, the supabase admin client and the Swagger interceptor can read it
 * synchronously outside React while every component re-renders on change.
 */
import { useSyncExternalStore } from 'react'
import { supabase } from './supabase'

export type CredentialMode = 'SERVICE' | 'SESSION'

const STORAGE_KEY = 'dilion.admin.credentialMode'

/** Management token, read from Vite env. Never set this in a production build. */
export const SERVICE_TOKEN: string = import.meta.env.VITE_DILION_SERVICE_TOKEN ?? ''
export const hasServiceToken = SERVICE_TOKEN.length > 0

function readStored(): CredentialMode {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === 'SESSION' ? 'SESSION' : 'SERVICE'
  } catch {
    // Private-mode / disabled storage: fall back to the default.
    return 'SERVICE'
  }
}

let mode: CredentialMode = readStored()
const listeners = new Set<() => void>()

function emit(): void {
  for (const listener of listeners) listener()
}

export function getCredentialMode(): CredentialMode {
  return mode
}

export function setCredentialMode(next: CredentialMode): void {
  if (next === mode) return
  mode = next
  try {
    window.localStorage.setItem(STORAGE_KEY, next)
  } catch {
    // Not persisting is survivable; the in-memory mode still applies.
  }
  emit()
}

export function subscribeCredentialMode(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

// Keep tabs in sync: switching credential in one tab is a global decision.
window.addEventListener('storage', (event) => {
  if (event.key !== STORAGE_KEY) return
  const next = readStored()
  if (next === mode) return
  mode = next
  emit()
})

/** The active mode, re-rendering the component whenever it changes. */
export function useCredentialMode(): CredentialMode {
  return useSyncExternalStore(subscribeCredentialMode, getCredentialMode, () => 'SERVICE')
}

/**
 * The bearer token the current mode prescribes, or `null` when there is none
 * (SERVICE without `VITE_DILION_SERVICE_TOKEN`, or SESSION while signed out).
 * Callers must then send **no** `Authorization` header at all — an empty bearer
 * would read as a malformed credential rather than as an anonymous call.
 */
export async function resolveManagementToken(): Promise<string | null> {
  if (mode === 'SERVICE') return hasServiceToken ? SERVICE_TOKEN : null
  const { data } = await supabase.auth.getSession()
  return data.session?.access_token ?? null
}
