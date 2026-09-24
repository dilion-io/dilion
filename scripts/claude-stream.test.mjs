import { test } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { describeEvent, runClaude } from './claude-stream.mjs'

test('events are summarised without raw init details or full tool output', () => {
  assert.deepEqual(describeEvent({ type: 'system', subtype: 'init', model: 'opus', tools: ['WebSearch'], apiKeySource: 'secret' }), ['[init] model=opus tools=WebSearch'])
  assert.deepEqual(describeEvent({ type: 'assistant', message: { content: [
    { type: 'text', text: '검토합니다' },
    { type: 'tool_use', name: 'WebFetch', input: { url: 'https://law.go.kr' } },
  ] } }), ['[claude] 검토합니다', '[tool] WebFetch {"url":"https://law.go.kr"}'])
  const [line] = describeEvent({ type: 'user', message: { content: [{ type: 'tool_result', content: [{ type: 'text', text: 'x'.repeat(2000) }] }] } })
  assert.ok(line.startsWith('[tool result] xxx') && line.length < 600)
  assert.deepEqual(describeEvent({ type: 'result', subtype: 'success', num_turns: 3, total_cost_usd: 0.5, duration_ms: 4200 }), ['[done] success turns=3 cost=$0.5000 duration=4s'])
  assert.deepEqual(describeEvent({ type: 'stream_event' }), [])
})

test('runClaude streams progress, passes stream-json flags and returns the result event', async (t) => {
  const bin = mkdtempSync(join(tmpdir(), 'dilion-claude-stub-'))
  t.after(() => rmSync(bin, { recursive: true, force: true }))
  const script = join(bin, 'claude')
  const path = process.env.PATH
  t.after(() => { process.env.PATH = path })
  process.env.PATH = `${bin}:${path}`

  writeFileSync(script, `#!/bin/sh
input="$(cat)"
echo "stub stderr is dropped" >&2
echo '{"type":"system","subtype":"init","model":"stub","tools":[]}'
echo 'not json'
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"args: %s | input: %s"}]}}\\n' "$*" "$input"
echo '{"type":"result","subtype":"success","is_error":false,"result":"ok","num_turns":1}'
`)
  chmodSync(script, 0o755)
  const lines = []
  const result = await runClaude(['-p'], { cwd: bin, input: 'hello', timeout: 10_000, log: line => lines.push(line) })
  assert.equal(result.result, 'ok')
  assert.equal(lines[0], '[init] model=stub tools=(none)')
  assert.match(lines[1], /args: -p --output-format stream-json --verbose \| input: hello/)
  assert.match(lines[2], /^\[done\] success/)

  writeFileSync(script, '#!/bin/sh\nexit 3\n')
  await assert.rejects(runClaude([], { cwd: bin, input: '', timeout: 10_000, log: () => {} }), /failed \(3\)/)
  writeFileSync(script, '#!/bin/sh\nsleep 5\n')
  await assert.rejects(runClaude([], { cwd: bin, input: '', timeout: 200, log: () => {} }), /timed out/)
})
