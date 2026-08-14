import assert from 'node:assert/strict';
import test from 'node:test';

import { runCli } from '../lib/cli/run.mjs';

function output() {
  let value = '';
  return { stream: { write(chunk) { value += chunk; } }, read: () => value };
}

test('governance CLI reaches controls without making caller-built admission consumable', async () => {
  const cases = [
    ['execution', { operation: 'execution.retry.classify', input: { failure_class: 'AUTHENTICATION' } }, 'ARC_DIAGNOSTIC_ONLY'],
    ['delivery', { operation: 'dispatch-capacity', input: { readyTasks: [{ id: 't1' }], constraints: [] } }, 't1'],
    ['judgment', { operation: 'finding.verify-closure', payload: { finding: { controlId: 'control', subjectId: 'subject' }, closure: {}, evidence: {} } }, 'ARC_INTERNAL_ERROR'],
    ['judgment', { operation: 'deficit.classify', payload: { acceptanceItems: [] } }, 'ARC_INTERNAL_ERROR'],
  ];
  for (const [domain, request, marker] of cases) {
    const stdout = output(); const stderr = output();
    await runCli(['governance', domain, '--json', JSON.stringify(request)], { stdout: stdout.stream, stderr: stderr.stream, env: {}, cwd: process.cwd(), host: {} });
    assert.match(stdout.read(), new RegExp(marker));
  }
});

test('finding lifecycle persists across CLI invocations', async () => {
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const cwd = mkdtempSync(join(tmpdir(), 'legion-governance-'));
  const first = output(); const err = output();
  const upsert = { operation: 'finding.upsert', payload: { finding: { controlId: 'control', subjectId: 'subject' }, reviewRoundId: 'round-1' } };
  assert.equal((await runCli(['governance', 'judgment', '--json', JSON.stringify(upsert)], { stdout: first.stream, stderr: err.stream, env: {}, cwd, host: {} })).exitCode, 0);
  const second = output();
  assert.equal((await runCli(['governance', 'judgment', '--json', JSON.stringify({ operation: 'finding.records', payload: {} })], { stdout: second.stream, stderr: err.stream, env: {}, cwd, host: {} })).exitCode, 0);
  assert.match(second.read(), /round-1/);
});

test('governance CLI fails closed for unknown or caller-claimed authority', async () => {
  const stdout = output(); const stderr = output();
  const result = await runCli(['governance', 'judgment', '--json', JSON.stringify({ operation: 'advisory.query', payload: { expected: { authority: 'oracle' } } })], { stdout: stdout.stream, stderr: stderr.stream, env: { ARCANE_KEY_DIR: '/missing' }, cwd: process.cwd(), host: {} });
  assert.equal(result.exitCode, 2);
  assert.match(stdout.read(), /ARC_AUTH_KEY_UNAVAILABLE|ARC_STORE_CORRUPT/);
});
