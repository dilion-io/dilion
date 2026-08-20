import { hasServiceToken } from '../api/client'

/**
 * Deliberately loud: this sample ships a management-plane token to the browser
 * so that the privacy API can be demonstrated end to end from a static app.
 * A real service must never do this.
 */
export function DevTokenBanner() {
  return (
    <div className={`dev-banner ${hasServiceToken ? '' : 'dev-banner-missing'}`}>
      <span className="dev-banner-tag">DEV ONLY</span>
      {hasServiceToken ? (
        <p>
          Privacy, IAM and Auth-admin calls on this page are signed in the browser — with{' '}
          <code>VITE_DILION_SERVICE_TOKEN</code> or with the signed-in user&rsquo;s token, whichever
          the <strong>관리 API 자격증명</strong> selector (Admin console) points at. In production
          the management token{' '}
          <strong>must never ship to a browser</strong> — proxy <code>/privacy/v1/*</code>,{' '}
          <code>/iam/v1/*</code> and <code>/auth/v1/admin/*</code> through your own backend, which
          holds the token and authorizes the end user first.
        </p>
      ) : (
        <p>
          <code>VITE_DILION_SERVICE_TOKEN</code> is not set, so the Privacy Center and the{' '}
          <code>SERVICE</code> credential are disabled. Add it to <code>web/.env.local</code> and
          restart <code>npm run dev</code> — or switch the <strong>관리 API 자격증명</strong>{' '}
          selector to <code>SESSION</code> and drive the Admin console with your own (RBAC
          authorized) token.
        </p>
      )}
    </div>
  )
}

/** Setup instructions shown wherever a management-plane screen has no token. */
export function MissingTokenSetup() {
  return (
    <section className="card">
      <h2>Management token required</h2>
      <p className="muted">
        The Privacy Center and the Admin console call <code>/privacy/v1/*</code>,{' '}
        <code>/iam/v1/*</code> and <code>/auth/v1/admin/*</code>, which require a{' '}
        <code>service_role</code> JWT or a <code>dk_</code> API key. Create{' '}
        <code>web/.env.local</code> (gitignored) with:
      </p>
      <pre>
        <code>VITE_DILION_SERVICE_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</code>
      </pre>
      <p className="muted">Mint a development token (dev server secret is `devsecret-e2e`):</p>
      <pre>
        <code>{`node -e "const c=require('crypto'),h=o=>Buffer.from(JSON.stringify(o)).toString('base64url'),\\
p=h({alg:'HS256',typ:'JWT'})+'.'+h({role:'service_role',sub:'dev-console',exp:Math.floor(Date.now()/1e3)+86400});\\
console.log(p+'.'+c.createHmac('sha256','devsecret-e2e').update(p).digest('base64url'))"`}</code>
      </pre>
      <p className="muted">Then restart the dev server so Vite picks up the new env var.</p>
    </section>
  )
}
