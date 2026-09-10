import * as upstream from '@supabase/supabase-js'
import { AuthClient as UpstreamAuth } from '@supabase/auth-js'
import { createClient, AuthClient, withOpaque } from '../src/index.js'

// These assignments deliberately do NOT use casts or skipLibCheck.
const compatibleFactory: typeof upstream.createClient = createClient
const compatibleAuthConstructor: typeof UpstreamAuth = AuthClient
void compatibleFactory
void compatibleAuthConstructor

type Schema = {
  Tables: {
    profiles: {
      Row: { id: number; name: string }
      Insert: { id?: number; name: string }
      Update: { name?: string }
      Relationships: []
    }
  }
  Views: {}
  Functions: { greeting: { Args: { name: string }; Returns: string } }
  Enums: {}
  CompositeTypes: {}
}
type Database = { public: Schema; custom: Schema }
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false
type Assert<T extends true> = T

function fixtures() {
  const original = upstream.createClient<Database>('https://example.test', 'anon')
  const client = createClient<Database>('https://example.test', 'anon')
  const assignable: typeof original = client
  const auth: typeof original.auth = client.auth
  const standalone: InstanceType<typeof UpstreamAuth> = new AuthClient({ url: 'https://example.test/auth/v1' })
  const extended = withOpaque(original, { url: 'https://example.test/auth/v1' })
  const custom = createClient<Database, 'custom'>('https://example.test', 'anon')
  const versioned = createClient<Database, { PostgrestVersion: '12' }>('https://example.test', 'anon')
  const query = client.from('profiles').select('id, name')
  const upstreamQuery = original.from('profiles').select('id, name')
  type QuerySame = Assert<Equal<upstream.QueryData<typeof query>, upstream.QueryData<typeof upstreamQuery>>>
  type PasswordSame = Assert<Equal<typeof client.auth.signInWithPassword, typeof original.auth.signInWithPassword>>
  type SignupSame = Assert<Equal<typeof client.auth.signUp, typeof original.auth.signUp>>
  type SessionSame = Assert<Equal<typeof client.auth.setSession, typeof original.auth.setSession>>
  type OAuthSame = Assert<Equal<typeof client.auth.signInWithOAuth, typeof original.auth.signInWithOAuth>>
  type MFASame = Assert<Equal<typeof client.auth.mfa, typeof original.auth.mfa>>
  type AdminSame = Assert<Equal<typeof client.auth.admin, typeof original.auth.admin>>
  // Catch accidental widening to any, including schema inference.
  // @ts-expect-error table does not exist
  client.from('missing_table')
  // @ts-expect-error name must be a string
  client.from('profiles').insert({ name: 123 })
  // @ts-expect-error wrong RPC argument type
  client.rpc('greeting', { name: 123 })
  // @ts-expect-error password is required
  client.auth.opaque.signInWithPassword({ email: 'a@example.test' })
  // @ts-expect-error signup password is required
  client.auth.opaque.signUp({ email: 'a@example.test' })
  client.auth.opaque.signUp({ email: 'a@example.test', password: 'secret', options: { data: { name: 'Alice' }, captchaToken: 'captcha' } })
  void [assignable, auth, standalone, extended, custom, versioned]
  const assertions: [QuerySame, PasswordSame, SignupSame, SessionSame, OAuthSame, MFASame, AdminSame] = [true, true, true, true, true, true, true]
  return assertions
}
void fixtures
