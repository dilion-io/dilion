import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'

const clip = (text, limit) => text.length > limit ? `${text.slice(0, limit)}… (+${text.length - limit} chars)` : text
const oneLine = (text, limit) => clip(String(text).replace(/\s+/g, ' ').trim(), limit)
const resultText = (content) => typeof content === 'string'
  ? content
  : Array.isArray(content) ? content.map(part => part?.text ?? `[${part?.type}]`).join(' ') : JSON.stringify(content)

// describeEvent turns one stream-json event into console lines. It prints what
// Claude says and does, not the raw events: the init event carries account and
// environment details, and fetched web pages would flood the log.
export function describeEvent(event) {
  switch (event?.type) {
    case 'system':
      return event.subtype === 'init' ? [`[init] model=${event.model} tools=${(event.tools ?? []).join(',') || '(none)'}`] : []
    case 'assistant':
      return (event.message?.content ?? []).flatMap(block => {
        if (block.type === 'text' && block.text.trim()) return [`[claude] ${clip(block.text.trim(), 2000)}`]
        if (block.type === 'thinking' && block.thinking?.trim()) return [`[thinking] ${oneLine(block.thinking, 500)}`]
        if (block.type === 'tool_use' || block.type === 'server_tool_use') return [`[tool] ${block.name} ${oneLine(JSON.stringify(block.input), 500)}`]
        if (block.type?.endsWith('_tool_result')) return [`[tool result] ${block.type}`]
        return []
      })
    case 'user':
      return (event.message?.content ?? []).filter(block => block.type === 'tool_result')
        .map(block => `[tool result${block.is_error ? ' error' : ''}] ${oneLine(resultText(block.content), 500)}`)
    case 'result':
      return [`[done] ${event.subtype} turns=${event.num_turns} cost=$${Number(event.total_cost_usd ?? 0).toFixed(4)} duration=${Math.round((event.duration_ms ?? 0) / 1000)}s`]
    default:
      return []
  }
}

// runClaude runs `claude -p` with stream-json output, prints its progress to
// stderr as it happens and resolves with the final `result` event. stderr of the
// CLI itself is discarded; authentication diagnostics may contain account data.
export function runClaude(args, { cwd, input, timeout, log = line => console.error(line) }) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn('claude', [...args, '--output-format', 'stream-json', '--verbose'], { cwd, stdio: ['pipe', 'pipe', 'pipe'] })
    let result
    let timedOut = false
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGTERM') }, timeout)
    child.stderr.resume()
    child.stdin.on('error', () => {}) // the exit status reports why the CLI stopped reading
    child.stdin.end(input)
    createInterface({ input: child.stdout }).on('line', line => {
      let event
      try { event = JSON.parse(line) } catch { return }
      for (const text of describeEvent(event)) log(text)
      if (event.type === 'result') result = event
    })
    child.on('error', error => { clearTimeout(timer); reject(new Error(`claude -p could not start (${error.code}); check the CLI installation`)) })
    child.on('close', status => {
      clearTimeout(timer)
      if (timedOut) return reject(new Error('claude -p timed out'))
      if (status !== 0 && !result) return reject(new Error(`claude -p failed (${status}); check CLI installation/authentication and budget`))
      if (!result) return reject(new Error('claude -p ended without a result'))
      resolvePromise(result)
    })
  })
}
