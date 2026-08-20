/**
 * Client-side JWT payload decoding — for *display only*.
 *
 * The browser never verifies the signature here: it cannot, and it must not
 * pretend to. Everything below is "what does the token I am holding claim",
 * which is exactly what a session-inspection UI wants; every authorization
 * decision still happens on the server, which does verify.
 */

/** The claims Dilion's access tokens carry (superset kept open on purpose). */
export type AccessTokenClaims = {
  sub?: string
  role?: string
  aud?: string | string[]
  exp?: number
  iat?: number
  email?: string
  session_id?: string
  [claim: string]: unknown
}

/** Decode the payload segment of a JWT, or `null` if it is not decodable. */
export function decodeJwtPayload(token: string): AccessTokenClaims | null {
  const segments = token.split('.')
  if (segments.length < 2) return null
  try {
    // base64url -> base64, then percent-decode so non-ASCII claims survive.
    const base64 = segments[1].replace(/-/g, '+').replace(/_/g, '/')
    const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='))
    const json = decodeURIComponent(
      Array.from(binary, (ch) => `%${ch.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''),
    )
    const parsed: unknown = JSON.parse(json)
    if (typeof parsed !== 'object' || parsed === null) return null
    return parsed as AccessTokenClaims
  } catch {
    return null
  }
}

/** `exp` (seconds since epoch) rendered as a local timestamp plus a countdown. */
export function describeExpiry(exp: number | undefined, now = Date.now()): string {
  if (exp === undefined) return '—'
  const at = new Date(exp * 1000)
  const seconds = Math.round((at.getTime() - now) / 1000)
  const relative =
    seconds <= 0
      ? 'expired'
      : seconds < 60
        ? `in ${seconds}s`
        : `in ${Math.floor(seconds / 60)}m ${seconds % 60}s`
  return `${at.toLocaleString()} (${relative})`
}
