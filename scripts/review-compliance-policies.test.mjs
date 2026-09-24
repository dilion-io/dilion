import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { review, validateReview, renderReport, policyFile } from './review-compliance-policies.mjs'

const source = 'compliance:\n  policies:\n    kr:\n      retention:\n        - domain: audit-log\n          period: P3Y\n          basis: "old §8"\n'
const source2 = { title: '개인정보의 안전성 확보조치 기준', url: 'https://www.law.go.kr/행정규칙/개인정보의안전성확보조치기준' }
const finding = (overrides = {}) => ({
  id: 'kr.retention.audit-log', policy: 'kr', status: 'ok', title: '접속기록 보관', analysis: '현행과 일치합니다.',
  sources: [source2], edits: [], ...overrides,
})
const outdated = finding({ status: 'outdated', analysis: '보관 기간이 바뀌었습니다. @someone', edits: [{ old: 'period: P3Y', new: 'period: P2Y' }] })

test('valid edits are applied and the untouched file is returned for ok findings', () => {
  assert.equal(validateReview({ summary: 's', findings: [finding()] }, source).proposed, source)
  assert.equal(validateReview({ summary: 's', findings: [outdated] }, source).proposed, source.replace('P3Y', 'P2Y'))
})

test('unsafe or ambiguous reviews are rejected', () => {
  const invalid = [
    {},
    { summary: 's', findings: [] },
    { summary: 's', findings: [finding(), finding()] },
    { summary: 's', findings: [finding({ status: 'maybe' })] },
    { summary: 's', findings: [finding({ sources: [] })] },
    { summary: 's', findings: [finding({ sources: [{ title: 'x', url: 'http://law.go.kr' }] })] },
    { summary: 's', findings: [finding({ sources: [{ title: 'x', url: 'javascript:alert(1)' }] })] },
    { summary: 's', findings: [finding({ edits: outdated.edits })] },
    { summary: 's', findings: [finding({ status: 'uncertain', edits: outdated.edits })] },
    { summary: 's', findings: [finding({ status: 'incorrect', edits: [{ old: 'P9Y', new: 'P2Y' }] })] },
    { summary: 's', findings: [finding({ status: 'incorrect', edits: [{ old: '  ', new: ' ' }] })] },
    { summary: 's', findings: [finding({ status: 'incorrect', edits: [{ old: 'P3Y', new: 'P3Y' }] })] },
    { summary: 's', findings: [finding({ status: 'incorrect', edits: [{ old: '"\n', new: '"' }] })] },
  ]
  for (const bad of invalid) assert.throws(() => validateReview(bad, source), undefined, JSON.stringify(bad))
})

test('report neutralises mentions, lists sources and shows proposed edits', () => {
  const { summary, findings, proposed } = validateReview({ summary: '요약', findings: [outdated, finding({ id: 'kr.consent' })] }, source)
  const report = renderReport({ date: '2026-09-24', model: 'opus', source, proposed, summary, findings, tests: { ok: false, failures: ['--- FAIL: TestBuiltinPoliciesLoad'] } })
  assert.ok(!report.includes('@someone'))
  assert.match(report, /개정됨 1/)
  assert.match(report, /- period: P3Y\n\+ period: P2Y/)
  assert.match(report, /\(<https:\/\/www\.law\.go\.kr\/%/)
  assert.match(report, /--- FAIL: TestBuiltinPoliciesLoad/)
  assert.match(report, /<summary>확인된 항목 1건<\/summary>/)
})

test('review writes accepted proposals, restores rejected ones and records metadata', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'dilion-compliance-test-'))
  const input = join(directory, policyFile)
  const out = join(directory, 'out')
  try {
    mkdirSync(join(directory, 'internal/privacy'), { recursive: true })
    writeFileSync(input, source)

    const calls = []
    const passing = (args) => { calls.push(args[0]); return { ok: true, output: '' } }
    let meta = await review({ directory, out, date: '2026-09-24', run: () => ({ summary: 's', findings: [finding()] }), go: passing })
    assert.deepEqual([meta.changed, meta.attention, calls.length], [false, false, 0])
    assert.equal(readFileSync(input, 'utf8'), source)

    meta = await review({ directory, out, date: '2026-09-24', run: () => ({ summary: 's', findings: [outdated] }), go: passing })
    assert.deepEqual([meta.changed, meta.attention, calls], [true, true, ['run', 'test']])
    assert.equal(readFileSync(input, 'utf8'), source.replace('P3Y', 'P2Y'))
    assert.equal(JSON.parse(readFileSync(join(out, 'review.json'), 'utf8')).counts.outdated, 1)
    assert.match(readFileSync(join(out, 'report.md'), 'utf8'), /go test .*통과/)

    writeFileSync(input, source)
    const rejecting = (args) => ({ ok: args[0] !== 'run', output: 'privacy: unknown action' })
    await assert.rejects(() => review({ directory, out, run: () => ({ summary: 's', findings: [outdated] }), go: rejecting }), /rejected by the policy loader/)
    assert.equal(readFileSync(input, 'utf8'), source)

    await assert.rejects(() => review({ directory, out, run: () => { writeFileSync(input, source + '# edited\n'); return { summary: 's', findings: [outdated] } }, go: passing }), /changed during the review/)
    await assert.rejects(() => review({ directory, out, run: () => { throw new Error('API down') } }), /API down/)
  } finally { rmSync(directory, { recursive: true, force: true }) }
})
