/**
 * The credential switch for every management-plane call.
 *
 * Two very different identities can drive the admin console, and which one is
 * active changes what the server allows — so the choice is explicit, always on
 * screen, and mirrored by a compact badge next to the dev banner.
 */
import {
  hasServiceToken,
  setCredentialMode,
  useCredentialMode,
  type CredentialMode,
} from '../lib/credentialMode'
import { useSession } from '../lib/useSession'

const OPTIONS: ReadonlyArray<{ mode: CredentialMode; label: string; hint: string }> = [
  {
    mode: 'SERVICE',
    label: 'dev service_role token',
    hint: 'VITE_DILION_SERVICE_TOKEN · RBAC 우회 (전체 테넌트 권한)',
  },
  {
    mode: 'SESSION',
    label: '로그인한 내 토큰',
    hint: '현재 세션 access_token · RBAC 필요 (role_assignments 로 인가)',
  },
]

/** The option box itself — rendered in the admin console header. */
export function CredentialModeSelect() {
  const mode = useCredentialMode()
  const { session, loading } = useSession()
  const signedOut = !loading && !session

  return (
    <fieldset className="cred-select">
      <legend>관리 API 자격증명</legend>
      <div className="cred-options">
        {OPTIONS.map((option) => (
          <label
            key={option.mode}
            className={mode === option.mode ? 'cred-option cred-option-active' : 'cred-option'}
          >
            <input
              type="radio"
              name="credential-mode"
              value={option.mode}
              checked={mode === option.mode}
              onChange={() => setCredentialMode(option.mode)}
            />
            <span>
              <strong>{option.label}</strong>
              <span className="muted small cred-option-hint">{option.hint}</span>
            </span>
          </label>
        ))}
      </div>

      {mode === 'SESSION' && signedOut && (
        <p className="cred-warn" role="status">
          로그인 필요 — 요청은 401이 됩니다. <a href="#/signin">로그인하러 가기</a>
        </p>
      )}
      {mode === 'SESSION' && session && (
        <p className="muted small cred-note">
          현재 계정 <code>{session.user.email}</code> 의 토큰으로 호출합니다. 권한이 없으면{' '}
          <code>403 permission_denied</code> — Auth admin 화면은 <code>users.admin</code> 권한이
          필요합니다.
        </p>
      )}
      {mode === 'SERVICE' && !hasServiceToken && (
        <p className="cred-warn" role="status">
          <code>VITE_DILION_SERVICE_TOKEN</code> 이 설정되지 않았습니다 — 요청은 401이 됩니다.
        </p>
      )}
    </fieldset>
  )
}

/** Compact always-visible mirror of the same state, shown under the dev banner. */
export function CredentialModeBadge() {
  const mode = useCredentialMode()
  const { session, loading } = useSession()
  const broken = mode === 'SESSION' ? !loading && !session : !hasServiceToken

  return (
    <div className={broken ? 'cred-badge cred-badge-warn' : 'cred-badge'}>
      <span className="cred-badge-tag">관리 API 자격증명</span>
      <code>{mode}</code>
      <span className="muted small">
        {mode === 'SERVICE'
          ? 'dev service_role token (RBAC 우회)'
          : session
            ? `로그인한 내 토큰 · ${session.user.email} (RBAC 필요)`
            : '로그인한 내 토큰 — 로그인 필요, 요청은 401이 됩니다'}
      </span>
      <a className="cred-badge-link" href="#/admin-users">
        변경
      </a>
    </div>
  )
}
