import { describe, it, expect } from 'vitest'
import * as protocol from '@serenity-kit/opaque'
import { createClient as createUpstream, AuthError } from '@supabase/supabase-js'
import { createClient, withOpaque, AuthClient } from '../src/index.js'

const origin = 'https://dilion.test'
const password = 'correct horse battery staple'
const uid = '00000000-0000-4000-8000-000000000001'
const identities = { client: uid, server: 'dilion:test' }
const stretching = { 'argon2id-custom': { memory: 65536, iterations: 3, parallelism: 4 } } as const
const encoded = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = () => encoded({ alg: 'HS256', typ: 'JWT' }) + '.' +
  encoded({ sub: uid, role: 'authenticated', exp: Math.floor(Date.now() / 1000) + 3600 }) + '.test'
const user = { id: uid, aud: 'authenticated', role: 'authenticated', email: 'a@example.test',
  app_metadata: {}, user_metadata: {}, created_at: new Date().toISOString() }

async function fixture(options: { failFinish?: boolean; suite?: string; signupConfirmation?: boolean } = {}) {
  await protocol.ready
  const setup = protocol.server.createSetup()
  const registration = protocol.client.startRegistration({ password })
  const reply = protocol.server.createRegistrationResponse({ serverSetup: setup, userIdentifier: uid,
    registrationRequest: registration.registrationRequest })
  const record = protocol.client.finishRegistration({ password, clientRegistrationState: registration.clientRegistrationState,
    registrationResponse: reply.registrationResponse, identifiers: identities, keyStretching: stretching })
  let registrationRecord = record.registrationRecord
  let serverState = ''
  let serverKey = ''
  const requests: Array<{ path: string; body: Record<string, string>; authorization: string | null }> = []
  const persisted = new Map<string, string>()
  const base = { handshake_id: 'attempt-1', suite: options.suite ?? 'ristretto255-sha512-argon2id-v1',
    client_identity: uid, server_identity: identities.server }
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, string>
    requests.push({ path, body, authorization: new Headers(init?.headers).get('Authorization') })
    if (path.endsWith('/login/start')) {
      const result = protocol.server.startLogin({ serverSetup: setup, registrationRecord,
        userIdentifier: uid, startLoginRequest: body.ke1, identifiers: identities })
      serverState = result.serverLoginState
      return Response.json({ ...base, ke2: result.loginResponse })
    }
    if (path.endsWith('/login/finish')) {
      if (options.failFinish) return Response.json({ error: 'rejected' }, { status: 401 })
      serverKey = protocol.server.finishLogin({ serverLoginState: serverState, finishLoginRequest: body.ke3 }).sessionKey
      serverState = ''
      return Response.json({ access_token: token(), refresh_token: 'refresh', key_id: 'key-1' })
    }
    if (path.endsWith('/registration/start') || path.endsWith('/signup/start')) {
      const result = protocol.server.createRegistrationResponse({ serverSetup: setup, userIdentifier: uid,
        registrationRequest: body.registration_request })
      return Response.json({ ...base, registration_response: result.registrationResponse })
    }
    if (path.endsWith('/registration/finish')) {
      registrationRecord = body.registration_record
      return Response.json({ success: true })
    }
    if (path.endsWith('/signup/finish')) {
      if (options.failFinish) return Response.json({ error: 'rejected' }, { status: 422 })
      registrationRecord = body.registration_record
      return Response.json({ user, session: null, confirmation_required: options.signupConfirmation ?? false })
    }
    if (path.endsWith('/user')) return Response.json(user)
    if (path.endsWith('/logout')) return new Response(null, { status: 204 })
    throw new Error('Unexpected request: ' + path)
  }
  const client = createClient(origin, 'anon-key', {
    global: { fetch: fetcher },
    auth: { autoRefreshToken: false, detectSessionInUrl: false,
      storage: {
        getItem: key => persisted.get(key) ?? null,
        setItem: (key, value) => { persisted.set(key, value) },
        removeItem: key => { persisted.delete(key) },
      },
    },
  })
  return { client, fetcher, requests, persisted, record, serverKey: () => serverKey }
}

describe('Supabase delegation', () => {
  it('preserves the external accessToken mode and its upstream auth prohibition', () => {
    const client = createClient(origin, 'anon', { accessToken: async () => 'external-token' })
    expect(client.from).toBeTypeOf('function')
    expect(() => client.auth.getSession()).toThrow('accessToken')
  })
  it('keeps the exact existing auth instance and methods', () => {
    const upstream = createUpstream(origin, 'anon', { auth: { persistSession: false, autoRefreshToken: false } })
    const auth = upstream.auth
    const signIn = auth.signInWithPassword
    const extended = withOpaque(upstream, { url: origin + '/auth/v1' })
    expect(extended).toBe(upstream)
    expect(extended.auth).toBe(auth)
    expect(extended.auth.signInWithPassword).toBe(signIn)
    expect(extended.storage).toBe(upstream.storage)
    expect(extended.realtime).toBe(upstream.realtime)
    extended.auth.opaque.dispose()
  })

  it('does not reject an upstream HTTP URL until OPAQUE is used', async () => {
    const auth = new AuthClient({ url: 'http://private.example/auth/v1', persistSession: false, autoRefreshToken: false })
    expect(auth.signInWithPassword).toBeTypeOf('function')
    const result = await auth.opaque.signInWithPassword({ email: user.email, password })
    expect(result.error).toBeInstanceOf(AuthError)
    auth.opaque.dispose()
  })
})

describe('OPAQUE signup', () => {
  it('creates without a prior session, preserves options, then recovers the export key on login', async () => {
    const f = await fixture()
    const signup = await f.client.auth.opaque.signUp({ email: user.email, password,
      options: { data: { name: 'Alice' }, emailRedirectTo: 'https://app.test/welcome', captchaToken: 'test-captcha' },
    })
    expect(signup.error).toBeNull()
    expect(signup.data?.session).toBeNull()
    expect(signup.data?.confirmation_required).toBe(false)
    expect(signup.data?.export_key).toHaveLength(64)
    expect((await f.client.auth.getSession()).data.session).toBeNull()
    expect(f.persisted.size).toBe(0)
    expect(f.requests.map(r => r.path)).toEqual(['/auth/v1/opaque/signup/start', '/auth/v1/opaque/signup/finish'])
    expect(f.requests[0].body).toMatchObject({ email: user.email, data: { name: 'Alice' }, redirect_to: 'https://app.test/welcome', gotrue_meta_security: { captcha_token: 'test-captcha' } })
    expect(JSON.stringify(f.requests)).not.toContain(password)
    const login = await f.client.auth.opaque.signInWithPassword({ email: user.email, password })
    expect(login.error).toBeNull()
    expect(login.data?.export_key).toEqual(signup.data?.export_key)
    f.client.auth.opaque.dispose()
  })
  it('leaves email confirmation and session establishment to explicit follow-up steps', async () => {
    const f = await fixture({ signupConfirmation: true })
    const result = await f.client.auth.opaque.signUp({ email: user.email, password })
    expect(result.error).toBeNull()
    expect(result.data?.confirmation_required).toBe(true)
    expect(result.data?.session).toBeNull()
    expect(f.requests).toHaveLength(2)
    expect(f.persisted.size).toBe(0)
    f.client.auth.opaque.dispose()
  })
  it('returns no keys on rejection and rejects empty passwords or cancellation', async () => {
    const f = await fixture({ failFinish: true })
    const failed = await f.client.auth.opaque.signUp({ email: user.email, password })
    expect(failed.error).toBeInstanceOf(AuthError)
    expect(failed.data).toBeNull()
    expect(f.persisted.size).toBe(0)
    const before = f.requests.length
    expect((await f.client.auth.opaque.signUp({ email: user.email, password: '' })).error).toBeInstanceOf(AuthError)
    expect((await f.client.auth.opaque.signUp({ email: user.email, password, signal: AbortSignal.abort() })).error).toBeInstanceOf(AuthError)
    expect(f.requests).toHaveLength(before)
    f.client.auth.opaque.dispose()
  })
})

describe('OPAQUE protocol (real WASM, simulated HTTP adapter)', () => {
  it('derives the same session key on both sides without persisting keys or sending passwords', async () => {
    const f = await fixture()
    const events: unknown[] = []
    f.client.auth.onAuthStateChange((event, session) => events.push({ event, session }))
    const result = await f.client.auth.opaque.signInWithPassword({ email: user.email, password })
    expect(result.error).toBeNull()
    if (!result.data) throw result.error
    expect(Buffer.from(result.data.session_key).toString('base64url')).toBe(f.serverKey())
    expect(Buffer.from(result.data.export_key).toString('base64url')).toBe(f.record.exportKey)
    expect(result.data.session.user.id).toBe(uid)
    expect(JSON.stringify(f.requests)).not.toContain(password)
    expect(f.requests[0].path).toBe('/auth/v1/opaque/login/start')
    for (const secret of [f.serverKey(), f.record.exportKey, 'session_key', 'export_key']) {
      expect(JSON.stringify([...f.persisted])).not.toContain(secret)
      expect(JSON.stringify(events)).not.toContain(secret)
    }
    const firstKey = Buffer.from(result.data.session_key).toString('hex')
    const again = await f.client.auth.opaque.signInWithPassword({ email: user.email, password })
    expect(again.error).toBeNull()
    expect(Buffer.from(again.data!.session_key).toString('hex')).not.toBe(firstKey)
    expect(again.data!.export_key).toEqual(result.data.export_key)
    f.client.auth.opaque.dispose()
  })

  it('never finalizes wrong credentials and never falls back to a password grant', async () => {
    const f = await fixture()
    const result = await f.client.auth.opaque.signInWithPassword({ email: user.email, password: 'wrong' })
    expect(result.data).toBeNull()
    expect(result.error).toBeInstanceOf(AuthError)
    expect(f.requests.map(r => r.path)).toEqual(['/auth/v1/opaque/login/start'])
    f.client.auth.opaque.dispose()
  })

  it('does not expose keys or store a session before server finish succeeds', async () => {
    const f = await fixture({ failFinish: true })
    const result = await f.client.auth.opaque.signInWithPassword({ email: user.email, password })
    expect(result.data).toBeNull()
    expect(result.error?.status).toBe(401)
    expect((await f.client.auth.getSession()).data.session).toBeNull()
    f.client.auth.opaque.dispose()
  })

  it('rejects configuration downgrade', async () => {
    const f = await fixture({ suite: 'untrusted-low-cost-suite' })
    const result = await f.client.auth.opaque.signInWithPassword({ email: user.email, password })
    expect(result.data).toBeNull()
    expect(f.requests).toHaveLength(1)
    f.client.auth.opaque.dispose()
  })

  it('registers using an existing session and returns the client-only export key', async () => {
    const f = await fixture()
    await f.client.auth.setSession({ access_token: token(), refresh_token: 'refresh' })
    const result = await f.client.auth.opaque.register({ password: 'a new password' })
    expect(result.error).toBeNull()
    expect(result.data?.export_key.byteLength).toBe(64)
    const writes = f.requests.filter(r => r.path.includes('/opaque/'))
    expect(writes.every(r => r.authorization?.startsWith('Bearer '))).toBe(true)
    expect(JSON.stringify(writes)).not.toContain('a new password')
    const login = await f.client.auth.opaque.signInWithPassword({ email: user.email, password: 'a new password' })
    expect(login.data?.export_key).toEqual(result.data?.export_key)
    f.client.auth.opaque.dispose()
  })

  it('honors cancellation, disposal, and concurrent-operation rejection', async () => {
    const f = await fixture()
    const canceled = await f.client.auth.opaque.signInWithPassword({ email: user.email, password,
      signal: AbortSignal.abort() })
    expect(canceled.data).toBeNull()
    expect(f.requests).toHaveLength(0)
    const first = f.client.auth.opaque.signInWithPassword({ email: user.email, password })
    const second = await f.client.auth.opaque.signInWithPassword({ email: user.email, password })
    expect(second.error?.message).toContain('in progress')
    expect((await first).error).toBeNull()
    f.client.auth.opaque.dispose()
    expect((await f.client.auth.opaque.signInWithPassword({ email: user.email, password })).data).toBeNull()
  })
})
