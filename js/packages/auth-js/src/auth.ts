export * from '@supabase/auth-js'
export * from './opaque.js'
import { AuthClient as UpstreamAuthClient, type GoTrueClientOptions } from '@supabase/auth-js'
import { OpaqueAuth } from './opaque.js'

export class AuthClient extends UpstreamAuthClient {
  readonly opaque: OpaqueAuth
  constructor(options: GoTrueClientOptions) {
    super(options)
    this.opaque = new OpaqueAuth(this, {
      url: options.url ?? 'http://localhost:9999',
      headers: options.headers, fetch: options.fetch,
    })
  }
}
export { AuthClient as GoTrueClient }
