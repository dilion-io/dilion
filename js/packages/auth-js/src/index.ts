export * from '@supabase/supabase-js'
export { AuthClient, GoTrueClient } from './auth.js'
export * from './opaque.js'
import { createClient as upstreamCreateClient, type SupabaseClientOptions, type SupabaseClient } from '@supabase/supabase-js'
import { withOpaque, type WithOpaque } from './opaque.js'

// Preserve upstream's database/schema generics; compatibility fixtures check
// inference as well as the public method signatures against new releases.
export function createClient<
  Database = any,
  SchemaNameOrClientOptions extends (string & keyof Omit<Database, '__InternalSupabase'>)
    | { PostgrestVersion: string } = 'public' extends keyof Omit<Database, '__InternalSupabase'>
      ? 'public' : string & keyof Omit<Database, '__InternalSupabase'>,
  SchemaName extends string & keyof Omit<Database, '__InternalSupabase'> =
    SchemaNameOrClientOptions extends string & keyof Omit<Database, '__InternalSupabase'>
      ? SchemaNameOrClientOptions : 'public' extends keyof Omit<Database, '__InternalSupabase'>
        ? 'public' : string & keyof Omit<Database, '__InternalSupabase'>,
>(supabaseUrl: string, supabaseKey: string, options?: SupabaseClientOptions<SchemaName>): WithOpaque<SupabaseClient<Database, SchemaNameOrClientOptions, SchemaName>> {
  const client = upstreamCreateClient<Database, SchemaNameOrClientOptions, SchemaName>(supabaseUrl, supabaseKey, options)
  // Upstream explicitly disables ALL auth APIs in external-accessToken mode.
  // Do not touch its throwing auth proxy just to attach an unused extension.
  if (options?.accessToken) return client as WithOpaque<typeof client>
  return withOpaque(client, {
    url: supabaseUrl.trim().replace(/\/+$/, '') + '/auth/v1',
    headers: { apikey: supabaseKey, ...options?.global?.headers },
    fetch: options?.global?.fetch,
  })
}
