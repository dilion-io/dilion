import { useCallback, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { hasServiceToken } from '../api/client'
import { MissingTokenSetup } from '../components/DevTokenBanner'
import { ConsentSection } from '../components/ConsentSection'
import { DeleteAccountSection } from '../components/DeleteAccountSection'
import { RequestsList } from '../components/RequestsList'

export function PrivacyCenterPage({ session }: { session: Session }) {
  const [reloadToken, setReloadToken] = useState(0)
  const reload = useCallback(() => setReloadToken((n) => n + 1), [])

  if (!hasServiceToken) {
    return (
      <>
        <section className="card">
          <h2>Privacy center</h2>
          <p className="muted">
            Consent management and data-subject requests for{' '}
            <code>{session.user.id}</code>.
          </p>
        </section>
        <MissingTokenSetup />
      </>
    )
  }

  return (
    <>
      <section className="card">
        <h2>Privacy center</h2>
        <p className="muted">
          Everything below is served by the Dilion management plane through the{' '}
          <strong>generated OpenAPI client</strong> (<code>src/api/client.ts</code>, typed by{' '}
          <code>src/api/schema.d.ts</code>), keyed on the canonical <code>user_id</code>{' '}
          <code>{session.user.id}</code>.
        </p>
      </section>

      <ConsentSection userId={session.user.id} />
      <DeleteAccountSection userId={session.user.id} onChanged={reload} />
      <RequestsList userId={session.user.id} reloadToken={reloadToken} />
    </>
  )
}
