import type { Problem } from '../api/client'
import { useCredentialMode } from '../lib/credentialMode'

/**
 * gotrue's auth-admin refusal (`not_admin`) is not RFC 9457, so it arrives
 * mapped onto `permission_denied` with the original code in `title`. Both shapes
 * mean the same thing for the operator: this identity lacks the permission.
 */
function isAuthorizationRefusal(problem: Problem): boolean {
  return (
    problem.code === 'permission_denied' ||
    problem.status === 403 ||
    (problem.title ?? '').includes('not_admin')
  )
}

/**
 * Renders RFC 9457 problem+json the way a service should consume it: branch on
 * the machine-readable `code`, show `detail` to the operator, and list per-field
 * validation `errors[]`.
 *
 * It also knows about the credential selector: a 403 in SESSION mode is almost
 * always "my account has no role yet", which is fixable from inside the console.
 */
export function ProblemAlert({ problem }: { problem: Problem }) {
  const mode = useCredentialMode()
  const sessionDenied = mode === 'SESSION' && isAuthorizationRefusal(problem)

  return (
    <div className="alert alert-error" role="alert">
      <div className="alert-head">
        <code className="code-chip">{problem.code}</code>
        {problem.status !== undefined && <span className="muted">HTTP {problem.status}</span>}
        {problem.title && <strong>{problem.title}</strong>}
      </div>
      {problem.detail && <p className="alert-detail">{problem.detail}</p>}
      {problem.errors && problem.errors.length > 0 && (
        <ul className="alert-list">
          {problem.errors.map((detail, i) => (
            <li key={`${detail.location ?? 'field'}-${i}`}>
              <code>{detail.location ?? '(body)'}</code> — {detail.message ?? 'invalid'}
            </li>
          ))}
        </ul>
      )}
      {problem.code === 'unauthenticated' && (
        <p className="alert-hint">
          {mode === 'SESSION'
            ? '로그인한 내 토큰으로 호출했지만 세션이 없거나 만료되었습니다 — 다시 로그인하세요.'
            : 'The management token is missing, expired or invalid. Mint a fresh one and restart the dev server (see web/README.md).'}
        </p>
      )}
      {problem.code === 'permission_denied' && !sessionDenied && (
        <p className="alert-hint">
          The token authenticated but lacks the permission this endpoint requires.
        </p>
      )}
      {sessionDenied && (
        <p className="alert-hint">
          내 계정에 role이 필요합니다 — <a href="#/admin-roles">Admin → IAM → Roles</a>에서 할당
          하세요. (Auth admin 화면은 <code>users.admin</code> 권한이 필요합니다. 자격증명을{' '}
          <code>SERVICE</code>로 잠시 바꾸면 role을 스스로 부여할 수 있습니다.)
        </p>
      )}
    </div>
  )
}
