/**
 * Auth client pointed at this app's own origin.
 *
 * `@dilion-io/auth-js` is `@supabase/supabase-js` plus `auth.opaque`. It wraps
 * the SAME upstream client and session manager, so every ordinary Supabase call
 * on this page is upstream behaviour, not a fork: `signInWithPassword`,
 * `signInWithPasskey`, session persistence and refresh all come from
 * `@supabase/auth-js`. Only the OPAQUE namespace is Dilion's own.
 *
 * supabase-js appends `/auth/v1` to the URL it is given, and the Vite dev proxy
 * forwards `/auth/*` to the Dilion server — so the SDK talks to Dilion's
 * Supabase-Auth-compatible surface with zero CORS involved.
 *
 * Passkeys need no client-side switch: they are on by default from auth-js
 * 2.117. Whether they work is the SERVER's call, reported by GET
 * /auth/v1/settings as `passkeys_enabled` (see useAuthSettings).
 */
import { createClient } from '@dilion-io/auth-js'

const ANON_KEY: string = import.meta.env.VITE_DILION_ANON_KEY ?? 'dev-anon-key'

export const supabase = createClient(window.location.origin, ANON_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    // No OAuth redirect surface in this sample: don't parse the URL fragment.
    detectSessionInUrl: false,
    flowType: 'implicit',
  },
})

/** Human-readable message for a gotrue error. */
export function authErrorMessage(error: unknown): string {
  if (error && typeof error === 'object') {
    const e = error as { message?: unknown; code?: unknown; status?: unknown }
    const message = typeof e.message === 'string' ? e.message : 'Authentication failed'
    const code = typeof e.code === 'string' ? e.code : undefined
    return code ? `${message} (${code})` : message
  }
  return 'Authentication failed'
}

/**
 * Wipes key material the caller owns. OPAQUE hands the browser a `session_key`
 * and an `export_key`; both are secrets that must never reach storage, a log or
 * the network, and the sample zeroes them the moment it is done looking at
 * them. See docs/opaque.md for what they are for.
 */
export function wipe(...keys: (Uint8Array | undefined)[]) {
  for (const key of keys) key?.fill(0)
}
