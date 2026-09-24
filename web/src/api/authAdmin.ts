/**
 * Auth admin surface (`/auth/v1/admin/users`).
 *
 * This is Supabase-Auth-compatible, *not* part of `openapi.yaml` — its contract
 * is upstream gotrue's, so it is driven with `@supabase/supabase-js` rather than
 * the generated client. The point of the sample is exactly that: ordinary
 * supabase-js admin code runs against Dilion unchanged.
 *
 * The admin methods need a privileged credential, so this module builds a
 * *second* supabase client. The end-user client in `src/lib/supabase.ts` keeps
 * the anon key and the signed-in session; the two never share storage.
 *
 * The credential is **not** a fixed global header: which one is sent is the
 * operator's choice (see `src/lib/credentialMode.ts`), and that choice can
 * change between two calls of the same page. So the client is created once with
 * a `global.fetch` wrapper that resolves the active credential at request time
 * and rewrites `Authorization` on the way out — no client re-creation, no stale
 * header, and gotrue's own headers (`apikey`, content type) survive untouched.
 *
 * DEV ONLY, for the same reason as `src/api/client.ts`: a service token in a
 * browser is a full-tenant credential.
 */
import { createClient, type AuthError, type User } from '@supabase/supabase-js'
import { resolveManagementToken } from '../lib/credentialMode'
import { type Problem } from './client'

const ANON_KEY: string = import.meta.env.VITE_DILION_ANON_KEY ?? 'dev-anon-key'

/**
 * supabase-js sets `Authorization: Bearer <anon key>` itself; replacing it with
 * the active management credential is what promotes this client to the admin
 * surface. With no credential the header is dropped entirely, so the call is
 * anonymous and gotrue answers `401` rather than misreading an empty bearer.
 */
const adminFetch: typeof fetch = async (input, init) => {
  const token = await resolveManagementToken()
  const headers = new Headers(init?.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)
  else headers.delete('Authorization')
  return fetch(input, { ...init, headers })
}

const serviceClient = createClient(window.location.origin, ANON_KEY, {
  auth: {
    // A management client has no session of its own: never persist, never
    // refresh, never touch the storage key the user-facing client owns.
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false,
    storageKey: 'dilion-admin-console',
  },
  global: { fetch: adminFetch },
})

/** `supabase.auth.admin` — gotrue's GoTrueAdminApi, pointed at Dilion. */
export const authAdmin = serviceClient.auth.admin

export type AuthUser = User

/** Attributes wave 1 honours on create/update (`internal/auth/admin.go`). */
export type AuthUserAttributes = {
  email?: string
  password?: string
  email_confirm?: boolean
  role?: string
  ban_duration?: string
  user_metadata?: Record<string, unknown>
  app_metadata?: Record<string, unknown>
}

export type AuthUsersPage = {
  users: AuthUser[]
  total: number
  nextPage: number | null
  lastPage: number
}

/**
 * gotrue errors are not RFC 9457, so map them onto `Problem` and reuse
 * `<ProblemAlert />` — one error renderer for the whole console.
 */
export function problemFromAuthError(error: unknown): Problem {
  const e = error as Partial<AuthError> & { code?: string }
  const status = typeof e?.status === 'number' ? e.status : undefined
  const code: Problem['code'] =
    status === 401
      ? 'unauthenticated'
      : status === 403
        ? 'permission_denied'
        : status === 404
          ? 'not_found'
          : status === 409
            ? 'conflict'
            : status === 400 || status === 422
              ? 'validation_failed'
              : 'internal'
  const gotrueCode = typeof e?.code === 'string' ? e.code : undefined
  const message = typeof e?.message === 'string' ? e.message : 'Auth admin call failed'
  return {
    code,
    status,
    title: gotrueCode ? `gotrue: ${gotrueCode}` : 'Auth admin error',
    detail: message,
  }
}

/** Throwable carrying an already-mapped Problem, so callers use one catch. */
export class AuthAdminError extends Error {
  readonly problem: Problem

  constructor(error: unknown) {
    const problem = problemFromAuthError(error)
    super(problem.detail ?? problem.title ?? problem.code)
    this.name = 'AuthAdminError'
    this.problem = problem
  }
}

/**
 * `GET /auth/v1/admin/users` — gotrue paginates with `page`/`per_page` and puts
 * the totals in `Link` / `X-Total-Count` headers, not in a cursor envelope.
 * That is upstream's contract, so the console does not pretend otherwise.
 */
export async function listAuthUsers(page: number, perPage: number): Promise<AuthUsersPage> {
  const { data, error } = await authAdmin.listUsers({ page, perPage })
  if (error) throw new AuthAdminError(error)
  return {
    users: data.users,
    total: data.total,
    nextPage: data.nextPage,
    lastPage: data.lastPage,
  }
}

/** `POST /auth/v1/admin/users`. */
export async function createAuthUser(attributes: AuthUserAttributes): Promise<AuthUser> {
  const { data, error } = await authAdmin.createUser(attributes)
  if (error) throw new AuthAdminError(error)
  if (!data.user) throw new AuthAdminError({ message: 'Server returned no user', status: 500 })
  return data.user
}

/** `GET /auth/v1/admin/users/{id}`. */
export async function getAuthUser(userId: string): Promise<AuthUser> {
  const { data, error } = await authAdmin.getUserById(userId)
  if (error) throw new AuthAdminError(error)
  if (!data.user) throw new AuthAdminError({ message: 'User not found', status: 404 })
  return data.user
}

/** `PUT /auth/v1/admin/users/{id}` (gotrue uses PUT, not PATCH). */
export async function updateAuthUser(
  userId: string,
  attributes: AuthUserAttributes,
): Promise<AuthUser> {
  const { data, error } = await authAdmin.updateUserById(userId, attributes)
  if (error) throw new AuthAdminError(error)
  if (!data.user) throw new AuthAdminError({ message: 'Server returned no user', status: 500 })
  return data.user
}

/**
 * `DELETE /auth/v1/admin/users/{id}`.
 *
 * Wave-1 deviation from gotrue's OpenAPI: the server answers `200 {}` (as
 * upstream's *implementation* does), so there is no user object to return. What
 * matters is the side effect — in the same transaction Dilion writes a
 * `user.deleted` row to `dilion_privacy.outbox`, which the privacy engine turns
 * into a `DELETION` request for this `user_id`.
 */
export async function deleteAuthUser(userId: string, softDelete = false): Promise<void> {
  const { error } = await authAdmin.deleteUser(userId, softDelete)
  if (error) throw new AuthAdminError(error)
}

/**
 * Per-instance auth hooks (`/auth/v1/admin/hooks`) — a Dilion extension, so
 * supabase-js has no method for it. It is called with the same management
 * credential and answers the same gotrue error envelope.
 */
export type AuthHookName =
  | 'custom_access_token'
  | 'send_email'
  | 'send_sms'
  | 'before_user_created'
  | 'after_user_created'
  | 'mfa_verification_attempt'
  | 'password_verification_attempt'

export type AuthHookSetting = {
  name: AuthHookName
  /** `instance`: this instance's own setting; `server`: the server-wide one. */
  source: 'instance' | 'server'
  enabled: boolean
  uri: string
  /** Secrets are write-only; only their number comes back. */
  secrets_count: number
  /** The operator pinned the server-wide setting: it cannot be replaced here. */
  locked: boolean
  updated_at?: string
}

export type AuthHookSettingBody = {
  enabled: boolean
  uri?: string
  /** Omit to keep the stored secrets; `[]` removes them. */
  secrets?: string[]
}

async function hooksCall<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await adminFetch(`${window.location.origin}/auth/v1/admin/hooks${path}`, {
    ...init,
    headers: { apikey: ANON_KEY, 'Content-Type': 'application/json' },
  })
  const body: unknown = await res.json().catch(() => null)
  if (!res.ok) {
    const e = (body ?? {}) as { error_code?: string; msg?: string }
    throw new AuthAdminError({
      status: res.status,
      code: e.error_code,
      message: e.msg ?? `HTTP ${res.status}`,
    })
  }
  return body as T
}

/** `GET /auth/v1/admin/hooks` — every hook as it runs for this instance. */
export async function listAuthHooks(): Promise<AuthHookSetting[]> {
  return (await hooksCall<{ hooks: AuthHookSetting[] }>('')).hooks
}

/** `PUT /auth/v1/admin/hooks/{name}` — set this instance's own setting. */
export function putAuthHook(
  name: AuthHookName,
  body: AuthHookSettingBody,
): Promise<AuthHookSetting> {
  return hooksCall(`/${name}`, { method: 'PUT', body: JSON.stringify(body) })
}

/** `DELETE /auth/v1/admin/hooks/{name}` — back to the server-wide setting. */
export function deleteAuthHook(name: AuthHookName): Promise<AuthHookSetting> {
  return hooksCall(`/${name}`, { method: 'DELETE' })
}
