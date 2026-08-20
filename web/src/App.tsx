import { Suspense, lazy, useEffect } from 'react'
import { supabase } from './lib/supabase'
import { useSession } from './lib/useSession'
import { isAdminRoute, navigate, useRoute, type Route } from './lib/router'
import { DevTokenBanner } from './components/DevTokenBanner'
import { CredentialModeBadge } from './components/CredentialModeSelect'
import { AuthPage } from './pages/AuthPage'
import { AccountPage } from './pages/AccountPage'
import { PrivacyCenterPage } from './pages/PrivacyCenterPage'
import { AdminConsole } from './pages/AdminConsole'
import './styles.css'

const NAV: ReadonlyArray<{ route: Route; label: string; requiresAuth: boolean }> = [
  { route: 'signin', label: 'Session', requiresAuth: false },
  { route: 'account', label: 'My account', requiresAuth: true },
  { route: 'privacy', label: 'Privacy center', requiresAuth: true },
  { route: 'docs', label: 'API Docs', requiresAuth: false },
]

/**
 * Swagger UI is ~1.5 MB of vendor bundle. Code-split it so opening the app does
 * not pay for the docs page nobody has asked for yet.
 */
const DocsPage = lazy(() => import('./pages/DocsPage').then((m) => ({ default: m.DocsPage })))

/** Entry point of the Admin group; the console renders its own sub-navigation. */
const ADMIN_ENTRY: Route = 'admin-users'

export default function App() {
  const { session, loading } = useSession()
  const route = useRoute()

  // Protected routes fall back to the auth page once the session is gone.
  // Admin routes are deliberately not session-gated: they are driven by the
  // management token, not by the signed-in user.
  useEffect(() => {
    if (loading) return
    const target = NAV.find((n) => n.route === route)
    if (!session && target?.requiresAuth) navigate('signin')
  }, [loading, session, route])

  const onAdmin = isAdminRoute(route)

  return (
    <div className="app">
      <DevTokenBanner />
      <CredentialModeBadge />

      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <div>
            <strong>Dilion Sample Service</strong>
            <div className="muted small">Supabase-compatible auth + privacy orchestration</div>
          </div>
        </div>

        <nav className="nav">
          {NAV.filter((n) => !n.requiresAuth || session).map((n) => (
            <a
              key={n.route}
              href={`#/${n.route}`}
              className={route === n.route ? 'nav-link nav-link-active' : 'nav-link'}
            >
              {n.label}
            </a>
          ))}
          <a
            href={`#/${ADMIN_ENTRY}`}
            className={onAdmin ? 'nav-link nav-link-admin nav-link-active' : 'nav-link nav-link-admin'}
          >
            Admin
          </a>
        </nav>

        <div className="session-chip">
          {session ? (
            <>
              <span className="muted small">{session.user.email}</span>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => {
                  void supabase.auth.signOut().then(() => navigate('signin'))
                }}
              >
                Sign out
              </button>
            </>
          ) : (
            <span className="muted small">Signed out</span>
          )}
        </div>
      </header>

      <main className="main">
        {onAdmin ? (
          <AdminConsole route={route} />
        ) : route === 'docs' ? (
          <Suspense
            fallback={
              <section className="card">
                <p className="muted">Loading Swagger UI…</p>
              </section>
            }
          >
            <DocsPage />
          </Suspense>
        ) : loading ? (
          <section className="card">
            <p className="muted">Restoring session…</p>
          </section>
        ) : route === 'account' && session ? (
          <AccountPage session={session} />
        ) : route === 'privacy' && session ? (
          <PrivacyCenterPage session={session} />
        ) : (
          <AuthPage session={session} />
        )}
      </main>

      <footer className="footer muted small">
        Auth calls use <code>@supabase/supabase-js</code>; privacy and IAM calls use{' '}
        <code>openapi-fetch</code> typed by <code>npm run gen:api</code> output. Both reach the
        Dilion server through the Vite dev proxy.
      </footer>
    </div>
  )
}
