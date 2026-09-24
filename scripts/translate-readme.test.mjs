import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { translate, validateTranslation, protectMarkdown } from './translate-readme.mjs'

const source = '# Dilion\n\n## 소개\n\n프로젝트 설명입니다. `key` [문서](docs/opaque.md)\n\n```sh\nmake test\n```\n'
const english = '# Dilion\n\n## Introduction\n\nThis is a project description. `key` [Docs](docs/opaque.md)\n\n```sh\nmake test\n```\n'

test('protected Markdown is restored exactly and missing/duplicate placeholders fail', () => {
  const protectedMarkdown = protectMarkdown(source)
  assert.equal(protectedMarkdown.restore(protectedMarkdown.input), source)
  assert.ok(!protectedMarkdown.input.includes('make test'))
  assert.ok(!protectedMarkdown.input.includes('docs/opaque.md'))
  assert.ok(!protectedMarkdown.input.includes('`key`'))
  assert.throws(() => protectedMarkdown.restore('missing'))
  assert.throws(() => protectedMarkdown.restore(protectedMarkdown.input + protectedMarkdown.input))
})

test('translation validates structure, code and links', () => {
  validateTranslation(source, english)
  for (const invalid of ['', english.replace('make test', 'make down'), english.replace('`key`', '`secret`'), english.replace('docs/opaque.md', 'https://wrong.example'), english.replace('## Introduction', 'Introduction')]) {
    assert.throws(() => validateTranslation(source, invalid))
  }
})

test('atomic generation, freshness, force, failure and concurrent edits', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'dilion-translation-test-'))
  const output = join(directory, 'README.en.md')
  try {
    writeFileSync(join(directory, 'README.md'), source)
    await assert.rejects(() => translate({ directory, check: true }), /missing or stale/)
    await translate({ directory, run: () => english })
    const good = readFileSync(output, 'utf8')
    assert.match(good, /source-sha256: [a-f0-9]{64}/)
    assert.equal(await translate({ directory, check: true }), 'up to date')
    await translate({ directory, run: () => assert.fail('unnecessary API call') })
    let calls = 0
    await translate({ directory, force: true, run: () => { calls++; return english } })
    assert.equal(calls, 1)
    await assert.rejects(() => translate({ directory, force: true, run: () => { throw new Error('API down') } }), /API down/)
    assert.equal(readFileSync(output, 'utf8'), good)
    await assert.rejects(() => translate({ directory, force: true, run: () => 'bad output' }))
    assert.equal(readFileSync(output, 'utf8'), good)
    await assert.rejects(() => translate({ directory, force: true, run: () => {
      writeFileSync(join(directory, 'README.md'), source + '\n수정됨\n')
      return english
    } }), /changed during translation/)
    assert.equal(readFileSync(output, 'utf8'), good)
    await assert.rejects(() => translate({ directory, check: true }), /missing or stale/)
  } finally { rmSync(directory, { recursive: true, force: true }) }
})
