import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const fixturePath = join(root, 'tests', 'fixtures', 'handoff', 'legacy-evals.json');
const read = (path) => readFileSync(join(root, path), 'utf8');
const python = (args, options) => process.platform === 'win32'
  ? execFileSync('py', ['-3.11', ...args], options)
  : execFileSync('python3', args, options);
const cases = Object.values(JSON.parse(readFileSync(fixturePath, 'utf8')))
  .filter(Array.isArray)
  .flat();

test('all ten retired Handoff eval cases retain IDs, routing polarity, & assertions', () => {
  assert.equal(cases.length, 10);
  assert.deepEqual(cases.map(({ id }) => id), [
    'handoff-context-bloat', 'handoff-cold-start', 'handoff-bloated-thread-natural',
    'handoff-not-dispatch', 'handoff-not-summary', 'handoff-source-bootstrap',
    'handoff-target-ingest', 'handoff-no-secrets-clobber', 'handoff-no-summary-shortcut',
    'handoff-new-thread-wording',
  ]);
  for (const row of cases) {
    assert.equal(row.severity, 'error', row.id);
    assert.ok(['discovery', 'static'].includes(row.mode), row.id);
    assert.equal(typeof row.expected_behavior, 'string', row.id);
    assert.ok(row.expected_behavior.length > 40, row.id);
  }
  for (const row of cases.filter(({ id }) => id.startsWith('handoff-not-'))) {
    assert.ok(row.forbidden_skills.includes('handoff'), row.id);
  }
});

test('legacy source-bootstrap, target-ingest, safety, & pressure contracts bind to public Handoff surfaces', () => {
  const skill = read('skills/handoff/SKILL.md');
  const manual = read('skills/handoff/references/manual.md');
  const compiler = read('src/lib/handoff/transcript_handoff.py');
  const validator = read('src/lib/handoff/validate_handoff.py');
  const surface = `${skill}\n${manual}\n${compiler}\n${validator}`;
  for (const value of ['session_id', 'cutoff_bytes', 'sha256', 'TRANSCRIPT_INGEST', 'READBACK', 'validate-handoff.py']) {
    assert.match(surface, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'), value);
  }
  for (const value of ['Never ask old chat to summarize itself', 'secret', 'dirty state', 'services, processes', 'do not change']) {
    assert.match(surface, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'), value);
  }
});

test('Handoff continues to use shared Orthic transcript selftests', () => {
  const output = python(['src/lib/orthic_transcripts/selftest.py'], {
    cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  });
  assert.equal(output, '');
});
