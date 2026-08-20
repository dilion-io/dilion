/**
 * Supabase Auth client pointed at this app's own origin.
 *
 * supabase-js appends `/auth/v1` to the URL it is given, and the Vite dev proxy
 * forwards `/auth/*` to the Dilion server — so the SDK talks to Dilion's
 * Supabase-Auth-compatible surface with zero CORS involved. This is the same
 * code you would ship against a real Supabase project.
 */
import { createClient } from '@supabase/supabase-js'

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
