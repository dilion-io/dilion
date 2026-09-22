import { useEffect, useState } from 'react'

/**
 * The part of `GET /auth/v1/settings` this sample reads. The endpoint is the
 * deployment's public description of what it allows, so the UI can say "this
 * server has passkeys turned off" instead of offering a button that 404s.
 */
export type AuthSettings = {
  passkeys_enabled: boolean
  mailer_autoconfirm: boolean
  disable_signup: boolean
}

/**
 * OPAQUE is deliberately absent. `GET /auth/v1/settings` is the upstream
 * Supabase contract and Dilion does not add fields to it, so there is nothing
 * to read: the sample offers OPAQUE, and a deployment without the master key
 * configured answers the first request with `404 feature_disabled`, which the
 * form shows like any other server error.
 */
export function useAuthSettings(): { settings: AuthSettings | null; loading: boolean } {
  const [settings, setSettings] = useState<AuthSettings | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    fetch('/auth/v1/settings', { headers: { accept: 'application/json' } })
      .then((res) => (res.ok ? (res.json() as Promise<AuthSettings>) : null))
      .then((body) => {
        if (active) setSettings(body)
      })
      .catch(() => {
        // A settings read that fails is not worth an error banner: every
        // feature it gates reports its own failure when actually used.
        if (active) setSettings(null)
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [])

  return { settings, loading }
}
