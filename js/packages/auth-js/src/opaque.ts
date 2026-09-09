import { AuthError, AuthClient, type Session, type User } from '@supabase/auth-js'

type UpstreamAuth = InstanceType<typeof AuthClient>

const SUITE = 'ristretto255-sha512-argon2id-v1'
const stretching = { 'argon2id-custom': { memory: 65536, iterations: 3, parallelism: 4 } } as const

export class OpaqueAuthError extends AuthError {
  constructor(message: string, status = 400, code = 'opaque_error') {
    super(message, status, code)
    this.name = 'OpaqueAuthError'
  }
}

export type OpaqueResult<T> =
  | { data: T; error: null }
  | { data: null; error: AuthError }

/** These bytes belong to the caller. Never persist them in a JWT/session store. */
export interface OpaqueKeys {
  session_key: Uint8Array
  export_key: Uint8Array
}

export interface OpaqueLoginData extends OpaqueKeys {
  session: Session
  user: User
  key_id: string
}

export interface OpaqueOptions {
  /** Auth base URL, including /auth/v1, NOT /auth/v1/opaque. */
  url: string
  headers?: Record<string, string>
  fetch?: typeof globalThis.fetch
  /** Optional identity pin, in addition to HTTPS server authentication. */
  serverIdentity?: string
}

type Start = {
  handshake_id: string
  suite: string
  client_identity: string
  server_identity: string
}

function decodeKey(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new OpaqueAuthError('Invalid OPAQUE key encoding')
  const bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
  if (bytes.length !== 64) throw new OpaqueAuthError('Invalid OPAQUE key length')
  return bytes
}

/** Composition over the upstream auth instance: no duplicate session manager. */
export class OpaqueAuth {
  private busy = false
  private disposed = false
  private epoch = 0
  private readonly unsubscribe: () => void
  private readonly base: string
  private readonly request: typeof globalThis.fetch

  constructor(private readonly auth: UpstreamAuth, private readonly options: OpaqueOptions) {
    const url = new URL(options.url)
    this.base = url.toString().replace(/\/$/, '') + '/opaque'
    this.request = options.fetch ?? globalThis.fetch.bind(globalThis)
    const { data } = auth.onAuthStateChange(event => {
      if (event === 'SIGNED_OUT' || event === 'SIGNED_IN' || event === 'PASSWORD_RECOVERY') this.epoch++
    })
    this.unsubscribe = () => data.subscription.unsubscribe()
  }

  /** Detach only this extension. Does not sign out or stop the upstream client. */
  dispose(): void {
    this.disposed = true
    this.epoch++
    this.unsubscribe()
  }

  private validateStart(data: Start): void {
    if (data.suite !== SUITE || typeof data.handshake_id !== 'string' || !data.handshake_id ||
      typeof data.client_identity !== 'string' || !data.client_identity ||
      typeof data.server_identity !== 'string' || !data.server_identity ||
      (this.options.serverIdentity !== undefined && data.server_identity !== this.options.serverIdentity)) {
      throw new OpaqueAuthError('Unsupported OPAQUE configuration or identity')
    }
  }

  private async post<T>(path: string, body: unknown, signal: AbortSignal, bearer?: string): Promise<T> {
    const url = new URL(this.base)
    if (url.search || url.hash || url.username || url.password ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
      throw new OpaqueAuthError('OPAQUE requires a trusted HTTPS URL (or HTTP loopback)')
    }
    const headers = new Headers(this.options.headers)
    headers.set('Content-Type', 'application/json')
    if (bearer) headers.set('Authorization', 'Bearer ' + bearer)
    const response = await this.request(this.base + path, {
      method: 'POST', headers, body: JSON.stringify(body), signal,
      credentials: 'omit', redirect: 'error', cache: 'no-store',
    })
    if (!response.ok) {
      // Never echo protocol material or untrusted server error text into logs.
      throw new OpaqueAuthError('OPAQUE request failed', response.status, 'opaque_request_failed')
    }
    const reader = response.body?.getReader()
    if (!reader) throw new OpaqueAuthError('Empty OPAQUE response')
    const chunks: Uint8Array[] = []
    let size = 0
    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        size += value.length
        if (size > 65536) {
          await reader.cancel()
          throw new OpaqueAuthError('OPAQUE response exceeds size limit')
        }
        chunks.push(value)
      }
    } finally {
      reader.releaseLock()
    }
    const data = new Uint8Array(size)
    let offset = 0
    for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length }
    return JSON.parse(new TextDecoder().decode(data)) as T
  }

  private async run<T>(fn: (signal: AbortSignal, epoch: number) => Promise<T>, signal?: AbortSignal): Promise<OpaqueResult<T>> {
    if (this.disposed) return { data: null, error: new OpaqueAuthError('OPAQUE extension is disposed') }
    if (this.busy) return { data: null, error: new OpaqueAuthError('OPAQUE operation already in progress') }
    this.busy = true
    try {
      const combined = AbortSignal.any([AbortSignal.timeout(60_000), ...(signal ? [signal] : [])])
      combined.throwIfAborted()
      return { data: await fn(combined, this.epoch), error: null }
    } catch (error) {
      return { data: null, error: error instanceof AuthError ? error : new OpaqueAuthError('OPAQUE authentication failed') }
    } finally {
      this.busy = false
    }
  }

  /** Enrol a verified signed-in account; never sends the plaintext password. */
  register(input: { password: string; signal?: AbortSignal }): Promise<OpaqueResult<{ export_key: Uint8Array }>> {
    return this.run(async (signal, epoch) => {
      const { data, error } = await this.auth.getSession()
      if (error) throw error
      if (!data.session) throw new OpaqueAuthError('Sign in and verify your account before OPAQUE enrolment')
      const opaque = await import('@serenity-kit/opaque')
      await opaque.ready
      const start = opaque.client.startRegistration({ password: input.password })
      const reply = await this.post<Start & { registration_response: string }>('/registration/start',
        { registration_request: start.registrationRequest }, signal, data.session.access_token)
      this.validateStart(reply)
      const result = opaque.client.finishRegistration({
        clientRegistrationState: start.clientRegistrationState,
        registrationResponse: reply.registration_response,
        password: input.password, keyStretching: stretching,
        identifiers: { client: reply.client_identity, server: reply.server_identity },
      })
      const key = decodeKey(result.exportKey)
      try {
        if (this.epoch !== epoch) throw new OpaqueAuthError('Auth session changed during OPAQUE registration')
        const finished = await this.post<{ success: boolean }>('/registration/finish', {
          handshake_id: reply.handshake_id, registration_record: result.registrationRecord,
        }, signal, data.session.access_token)
        if (finished?.success !== true) throw new OpaqueAuthError('Invalid registration acknowledgement')
        signal.throwIfAborted()
        if (this.epoch !== epoch) throw new OpaqueAuthError('Auth session changed during OPAQUE registration')
        return { export_key: key }
      } catch (error) { key.fill(0); throw error }
    }, input.signal)
  }

  signInWithPassword(input: { email: string; password: string; captchaToken?: string; signal?: AbortSignal }): Promise<OpaqueResult<OpaqueLoginData>> {
    return this.run(async (signal, epoch) => {
      // Settle upstream initialization before observing concurrent auth changes.
      const initial = await this.auth.getSession()
      if (initial.error) throw initial.error
      const opaque = await import('@serenity-kit/opaque')
      await opaque.ready
      const start = opaque.client.startLogin({ password: input.password })
      const reply = await this.post<Start & { ke2: string }>('/login/start',
        { email: input.email, ke1: start.startLoginRequest,
          ...(input.captchaToken ? { gotrue_meta_security: { captcha_token: input.captchaToken } } : {}),
        }, signal)
      this.validateStart(reply)
      const result = opaque.client.finishLogin({
        clientLoginState: start.clientLoginState, loginResponse: reply.ke2,
        password: input.password, keyStretching: stretching,
        identifiers: { client: reply.client_identity, server: reply.server_identity },
      })
      if (!result) throw new OpaqueAuthError('Invalid OPAQUE credentials')
      const session_key = decodeKey(result.sessionKey)
      let export_key: Uint8Array | undefined
      try {
        export_key = decodeKey(result.exportKey)
        const finish = await this.post<{ access_token: string; refresh_token: string; key_id: string }>(
          '/login/finish', { handshake_id: reply.handshake_id, ke3: result.finishLoginRequest }, signal)
        signal.throwIfAborted()
        if (typeof finish.access_token !== 'string' || !finish.access_token ||
          typeof finish.refresh_token !== 'string' || !finish.refresh_token ||
          typeof finish.key_id !== 'string' || !finish.key_id) throw new OpaqueAuthError('Invalid session response')
        if (this.epoch !== epoch) throw new OpaqueAuthError('Auth session changed during OPAQUE login')
        // ONLY tokens enter upstream persistence and BroadcastChannel. No keys.
        const { data, error } = await this.auth.setSession({
          access_token: finish.access_token, refresh_token: finish.refresh_token,
        })
        if (error) throw error
        if (!data.session || !data.user) throw new OpaqueAuthError('No session after OPAQUE login')
        return { session: data.session, user: data.user, key_id: finish.key_id, session_key, export_key }
      } catch (error) {
        session_key.fill(0); export_key?.fill(0)
        throw error
      }
    }, input.signal)
  }
}

export type WithOpaque<T extends { auth: UpstreamAuth }> = T & { auth: T['auth'] & { opaque: OpaqueAuth } }

export function withOpaque<T extends { auth: UpstreamAuth }>(client: T, options: OpaqueOptions): WithOpaque<T> {
  if ('opaque' in client.auth) throw new Error('An OPAQUE extension is already attached')
  Object.defineProperty(client.auth, 'opaque', { value: new OpaqueAuth(client.auth, options), enumerable: false })
  return client as WithOpaque<T>
}
