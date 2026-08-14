import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { executeStage9Fixtures, stage9ProbeFor } from '../packages/arcane/lib/s09-runtime-executor.mjs';
import { capabilityIssuanceAudit } from '../packages/arcane/lib/policy.mjs';

const root = join(import.meta.dirname, '..');
const corpus = join(root, 'evals', 'architecture');

function runtimeRows() {
  return readdirSync(corpus).filter((name) => name.endsWith('.jsonl')).sort().flatMap((name) =>
    readFileSync(join(corpus, name), 'utf8').split(/\r?\n/).filter(Boolean).map(JSON.parse).filter((row) => row.execution === 'runtime'),
  );
}

test('S09 executor maps every pending architecture runtime case to one canonical Arcane guard', () => {
  const rows = runtimeRows();
  assert.equal(rows.length, 62);
  for (const row of rows) assert.ok(stage9ProbeFor(row.family), row.id);
});

test('S09 fixtures reject cancelled/replayed/stale/invalid/competing states while sanctioned paths remain executable', () => {
  const first = executeStage9Fixtures();
  const second = executeStage9Fixtures();
  assert.deepEqual(first, second);
  assert.equal(first.every((result) => result.status === 'PASS'), true);
  assert.equal(first.some((result) => result.reason.includes('epochs')), true);
  assert.equal(first.some((result) => result.reason.includes('replay')), true);
  assert.equal(first.some((result) => result.reason.includes('freshness')), true);
  assert.equal(first.some((result) => result.reason.includes('gate')), true);
  assert.equal(first.some((result) => result.reason.includes('ownership')), true);
  assert.equal(first.some((result) => result.reason.includes('budget')), true);
  assert.equal(first.some((result) => result.reason.includes('acceptance')), true);
  assert.equal(first.some((result) => result.reason.includes('ingress')), true);
});

test('S09 executor emits deterministic machine-readable runtime evidence without changing S11 corpus state', () => {
  const run = () => JSON.parse(execFileSync(process.execPath, ['scripts/run-stage9-runtime-evals.mjs'], { cwd: root, encoding: 'utf8' }));
  const first = run(); const second = run();
  assert.deepEqual(first, second);
  assert.equal(first.kind, 'arcane-s09-runtime-result');
  assert.ok(first.fixtureCount >= 9);
  assert.equal(first.passedFixtures, first.fixtureCount);
  assert.equal(first.failed, 0);
  assert.equal(first.coverageInventory.length, 62);
});

test('S09 capability audit exempts only const-bound authority-proof issuers', () => {
  const directory = mkdtempSync(join(tmpdir(), 's09-capability-audit-'));
  try {
    const legitimate = join(directory, 'legitimate.mjs');
    writeFileSync(legitimate, "const proofIssuer = new AuthorityInvocationProofIssuer({});\nproofIssuer.issue({ purpose: 'proof' });\n");
    assert.equal(capabilityIssuanceAudit([legitimate]).violations.length, 0);
    const disguised = join(directory, 'disguised.mjs');
    writeFileSync(disguised, "const proofIssuer = new AuthorityInvocationProofIssuer({});\nstore.issue({ capabilityId: 'forbidden' });\n");
    assert.equal(capabilityIssuanceAudit([disguised]).violations.length, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
