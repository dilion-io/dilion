import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { createInterface } from 'node:readline'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import * as opaque from '@serenity-kit/opaque'

describe.skipIf(process.env.DILION_OPAQUE_GO_INTEROP !== '1')('Rust WASM ↔ native Go RFC 9807', () => {
  let process: ChildProcessWithoutNullStreams
  let replies: AsyncIterator<string>
  beforeAll(async () => {
    await opaque.ready
    process = spawn('go', ['run', '.'], { cwd: new URL('./interop/', import.meta.url) })
    replies = createInterface({ input: process.stdout })[Symbol.asyncIterator]()
    process.stderr.on('data', data => console.error(String(data)))
  }, 120_000)
  afterAll(() => {
    process?.stdin.end()
    process?.kill()
  })
  async function call(operation: string, message: string) {
    process.stdin.write(JSON.stringify({ Operation: operation, Message: message }) + '\n')
    const next = await replies.next()
    if (next.done) throw new Error('Go peer exited before replying')
    return JSON.parse(next.value) as { message: string; session_key: string; error?: string }
  }
  it('registers and authenticates with matching keys and rejects replay', async () => {
    const password = 'interop test password'
    const identifiers = { client: 'interop-user', server: 'dilion:interop' }
    const keyStretching = { 'argon2id-custom': { memory: 65536, iterations: 3, parallelism: 4 } } as const
    const registration = opaque.client.startRegistration({ password })
    const response = await call('register-start', registration.registrationRequest)
    expect(response.error).toBeUndefined()
    const record = opaque.client.finishRegistration({
      password, clientRegistrationState: registration.clientRegistrationState,
      registrationResponse: response.message, identifiers, keyStretching,
    })
    expect((await call('register-finish', record.registrationRecord)).error).toBeUndefined()
    const first = opaque.client.startLogin({ password })
    const second = await call('login-start', first.startLoginRequest)
    expect(second.error).toBeUndefined()
    const third = opaque.client.finishLogin({
      password, clientLoginState: first.clientLoginState, loginResponse: second.message, identifiers, keyStretching,
    })
    expect(third).toBeDefined()
    const finish = await call('login-finish', third!.finishLoginRequest)
    expect(finish.error).toBeUndefined()
    expect(finish.session_key).toBe(third!.sessionKey)
    expect(third!.exportKey).toBe(record.exportKey)
    expect((await call('login-finish', third!.finishLoginRequest)).error).toBeDefined()
  }, 120_000)
})
