import { useEffect, useState } from 'react'

/** User-facing pages. */
export const USER_ROUTES = ['signin', 'account', 'privacy', 'docs'] as const

/**
 * Admin console pages. Every route here drives the management plane with the
 * dev token, not with the signed-in user's session.
 */
export const ADMIN_ROUTES = [
  'admin-users',
  'admin-hooks',
  'admin-requests',
  'admin-destinations',
  'admin-holds',
  'admin-roles',
  'admin-assignments',
  'admin-permissions',
  'admin-keys',
  'admin-audit',
] as const

export const ROUTES = [...USER_ROUTES, ...ADMIN_ROUTES] as const
export type Route = (typeof ROUTES)[number]
export type AdminRoute = (typeof ADMIN_ROUTES)[number]

function isRoute(value: string): value is Route {
  return (ROUTES as readonly string[]).includes(value)
}

export function isAdminRoute(route: Route): route is AdminRoute {
  return (ADMIN_ROUTES as readonly string[]).includes(route)
}

function readHash(): Route {
  const raw = window.location.hash.replace(/^#\/?/, '')
  return isRoute(raw) ? raw : 'signin'
}

export function navigate(route: Route): void {
  window.location.hash = `#/${route}`
}

/** Minimal hash router — no extra dependency for a dozen pages. */
export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(readHash)

  useEffect(() => {
    const onHashChange = () => setRoute(readHash())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  return route
}
