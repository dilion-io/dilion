import { useEffect, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { supabase } from './supabase'

export type SessionState = {
  session: Session | null
  loading: boolean
}

/** Current auth session, kept in sync with supabase-js auth state changes. */
export function useSession(): SessionState {
  const [state, setState] = useState<SessionState>({ session: null, loading: true })

  useEffect(() => {
    let active = true

    supabase.auth.getSession().then(({ data }) => {
      if (active) setState({ session: data.session, loading: false })
    })

    const { data: sub } = supabase.auth.onAuthStateChange((_event, session) => {
      if (active) setState({ session, loading: false })
    })

    return () => {
      active = false
      sub.subscription.unsubscribe()
    }
  }, [])

  return state
}
