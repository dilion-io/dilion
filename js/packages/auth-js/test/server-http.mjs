// Synthetic test credentials/keys only. Called by TestOpaqueSDKHTTP; never a
// production utility (it intentionally returns a test key to the Go assertion).
import assert from 'node:assert/strict'
import { createClient } from '../dist/index.js'

const [url, access_token, refresh_token] = process.argv.slice(2)
// A new client, no bootstrap token and no legacy password exchange.
const fresh = createClient(url, 'test-anon-key', {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
})
const signup = await fresh.auth.opaque.signUp({ email: 'sdk-signup@example.com', password: 'only-opaque-signup-password', options: { data: { name: 'Fresh account' } } })
assert.equal(signup.error, null)
assert.equal(signup.data.session, null)
assert.equal(signup.data.confirmation_required, false)
assert.equal((await fresh.auth.getSession()).data.session, null)
const signedIn = await fresh.auth.opaque.signInWithPassword({ email: 'sdk-signup@example.com', password: 'only-opaque-signup-password' })
assert.equal(signedIn.error, null)
assert.deepEqual(signedIn.data.export_key, signup.data.export_key)
assert.equal(signedIn.data.user.user_metadata.name, 'Fresh account')
const duplicate = await fresh.auth.opaque.signUp({ email: 'sdk-signup@example.com', password: 'do-not-replace' })
assert.notEqual(duplicate.error, null)
fresh.auth.opaque.dispose()
await fresh.auth.stopAutoRefresh()
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
