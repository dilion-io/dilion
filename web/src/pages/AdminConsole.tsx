import { hasServiceToken } from '../api/client'
import { useCredentialMode } from '../lib/credentialMode'
import { CredentialModeSelect } from '../components/CredentialModeSelect'
import { MissingTokenSetup } from '../components/DevTokenBanner'
import type { AdminRoute } from '../lib/router'
import { AdminUsersPage } from './AdminUsersPage'
import { AdminHooksPage } from './AdminHooksPage'
import { AdminRequestsPage } from './AdminRequestsPage'
import { AdminDestinationsPage } from './AdminDestinationsPage'
import { AdminHoldsPage } from './AdminHoldsPage'
import { AdminRolesPage } from './AdminRolesPage'
import { AdminAssignmentsPage } from './AdminAssignmentsPage'
import { AdminPermissionsPage } from './AdminPermissionsPage'
import { AdminApiKeysPage } from './AdminApiKeysPage'
import { AdminAuditPage } from './AdminAuditPage'

const ADMIN_NAV: ReadonlyArray<{ route: AdminRoute; label: string; group: string }> = [
  { route: 'admin-users', label: 'Users', group: 'Auth' },
  { route: 'admin-hooks', label: 'Hooks', group: 'Auth' },
  { route: 'admin-requests', label: 'Requests', group: 'Privacy' },
  { route: 'admin-destinations', label: 'Destinations', group: 'Privacy' },
  { route: 'admin-holds', label: 'Legal holds', group: 'Privacy' },
  { route: 'admin-roles', label: 'Roles', group: 'IAM' },
  { route: 'admin-assignments', label: 'Assignments', group: 'IAM' },
  { route: 'admin-permissions', label: 'Permissions', group: 'IAM' },
  { route: 'admin-keys', label: 'API keys', group: 'IAM' },
  { route: 'admin-audit', label: 'Audit', group: 'IAM' },
]

function screen(route: AdminRoute) {
  switch (route) {
    case 'admin-users':
      return <AdminUsersPage />
    case 'admin-hooks':
      return <AdminHooksPage />
    case 'admin-requests':
      return <AdminRequestsPage />
    case 'admin-destinations':
      return <AdminDestinationsPage />
    case 'admin-holds':
      return <AdminHoldsPage />
    case 'admin-roles':
      return <AdminRolesPage />
    case 'admin-assignments':
      return <AdminAssignmentsPage />
    case 'admin-permissions':
      return <AdminPermissionsPage />
    case 'admin-keys':
      return <AdminApiKeysPage />
    case 'admin-audit':
      return <AdminAuditPage />
  }
}

/**
 * The admin console: the management plane driven straight from the browser.
 *
 * Which credential signs those calls is the operator's choice — the dev
 * `service_role` token (bypasses RBAC) or the signed-in user's access token
 * (authorized through `role_assignments`). The selector below is rendered on
 * every admin screen so the active identity is never in doubt.
 */
export function AdminConsole({ route }: { route: AdminRoute }) {
  const groups = [...new Set(ADMIN_NAV.map((n) => n.group))]
  const mode = useCredentialMode()
  // SESSION mode needs no service token at all, so the setup screen only stands
  // in when SERVICE is selected and the env var is missing.
  const usable = mode === 'SESSION' || hasServiceToken

  return (
    <>
      <section className="card admin-head">
        <div>
          <h2>
            Admin console <span className="tag">management plane</span>
          </h2>
          <p className="muted">
            Every screen here calls Dilion with{' '}
            <code>Authorization: Bearer &lt;token&gt;</code> — either the dev{' '}
            <code>service_role</code> JWT (the credential your backend would hold) or the token of
            the user signed in to this browser, authorized by RBAC. IAM and privacy administration
            go through the generated OpenAPI client; the Users screen goes through{' '}
            <code>supabase-js</code>, because <code>/auth/v1</code> follows the upstream Supabase
            contract instead of this project&rsquo;s OpenAPI conventions.
          </p>
          <CredentialModeSelect />
        </div>
      </section>

      <nav className="subnav">
        {groups.map((group) => (
          <div key={group} className="subnav-group">
            <span className="subnav-label">{group}</span>
            {ADMIN_NAV.filter((n) => n.group === group).map((n) => (
              <a
                key={n.route}
                href={`#/${n.route}`}
                className={route === n.route ? 'nav-link nav-link-active' : 'nav-link'}
              >
                {n.label}
              </a>
            ))}
          </div>
        ))}
      </nav>

      {usable ? screen(route) : <MissingTokenSetup />}
    </>
  )
}
