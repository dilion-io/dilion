// Synthetic test credentials/keys only. Called by TestOpaqueSDKHTTP; never a
// production utility (it intentionally returns a test key to the Go assertion).
import assert from 'node:assert/strict'
import { createClient } from '../dist/index.js'

const [url, access_token, refresh_token] = process.argv.slice(2)
const client = createClient(url, 'test-anon-key', {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
})
const initial = await client.auth.setSession({ access_token, refresh_token })
assert.equal(initial.error, null)
const registration = await client.auth.opaque.register({ password: 'opaque-http-password' })
assert.equal(registration.error, null)
const login = await client.auth.opaque.signInWithPassword({ email: 'sdk-http@example.com', password: 'opaque-http-password' })
assert.equal(login.error, null)
assert.deepEqual(login.data.export_key, registration.data.export_key)
const wrong = await client.auth.opaque.signInWithPassword({ email: 'sdk-http@example.com', password: 'wrong-password' })
assert.notEqual(wrong.error, null)
assert.equal(wrong.data, null)
process.stdout.write(JSON.stringify({ Token: login.data.session.access_token, KeyID: login.data.key_id, Key: Buffer.from(login.data.session_key).toString('base64url') }))
client.auth.opaque.dispose()
await client.auth.stopAutoRefresh()
