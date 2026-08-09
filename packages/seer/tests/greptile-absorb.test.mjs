import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { ReceiptStore } from '../../arcane/lib/receipt-store.mjs';
import { createSeer, traceDiffBlastRadius } from '../index.mjs';

const NOW = '2026-08-10T00:00:00.000Z';
const REVISION = '4e82122e713341f9a27545207a00ba45645d8e8f';

function auditRequest(changedPaths = ['src/a.mjs']) {
  return {
    schemaVersion: 1,
    kind: 'legion-operation-envelope',
    envelopeKind: 'request',
    operationId: 'seer.audit',
    operationVersion: '1.0.0',
    requestId: 'req_01J8Z3K9QG7X6M2N4P5R8S0T1V',
    runId: 'run_01J8Z3K9QG7X6M2N4P5R8S0T1V',
    sourceRevision: REVISION,
    requestedAt: NOW,
    input: {
      runIdentity: { runId: 'run_01J8Z3K9QG7X6M2N4P5R8S0T1V', workspace: 'D:/workspace', repository: 'tools/skills/legion', revision: REVISION },
      workingContext: { marker: 'isolated' },
      lens: { id: 'correctness', content: 'sealed lens', digest: `sha256:${createHash('sha256').update('sealed lens').digest('hex')}` },
      diff: { changedPaths },
    },
  };
}

test('Cortex traces every changed path through resolve then impact', async () => {
  const calls = [];
  const run = async (_root, args) => {
    calls.push(args);
    if (args[1] === 'resolve') return { status: 0, stdout: JSON.stringify({ id: `node:${args[3]}` }) };
    return { status: 0, stdout: JSON.stringify({ target: { id: args[3] }, impacted: [{ id: 'consumer' }], edges: [] }) };
  };
  const first = await traceDiffBlastRadius({ repoRoot: 'D:/repo', changedPaths: ['src/b.mjs', 'src/a.mjs', 'src/a.mjs'], run });
  const second = await traceDiffBlastRadius({ repoRoot: 'D:/repo', changedPaths: ['src/a.mjs', 'src/b.mjs'], run });
  assert.equal(first.state, 'ready');
  assert.deepEqual(first.changedPaths, ['src/a.mjs', 'src/b.mjs']);
  assert.equal(first.traces.length, 2);
  assert.equal(first.digest, second.digest);
  assert.deepEqual(calls.slice(0, 2).map((args) => args[1]), ['resolve', 'impact']);
  await assert.rejects(() => traceDiffBlastRadius({ repoRoot: 'D:/repo', changedPaths: ['../outside'], run }), /repository-relative/);
});

test('Seer forwards per-diff blast radius and appends verdict outcomes to Arcane receipts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'seer-feedback-'));
  try {
    const receiptStore = new ReceiptStore({ root });
    let forwarded;
    const traceDiff = async ({ changedPaths }) => Object.freeze({ schemaVersion: 1, kind: 'seer-cortex-diff-blast-radius', state: 'ready', changedPaths, traces: [], digest: `sha256:${'b'.repeat(64)}` });
    const seer = createSeer({
      receiptStore,
      traceDiff,
      clock: { now: () => new Date(NOW) },
      core: { audit: async (input) => (forwarded = input, { report: { claimBoundary: 'PARTIALLY_PROVEN', findings: [{ id: 'F-1', ruleId: 'correctness', verdict: 'confirmed', severity: 'high' }] } }) },
    });
    const pair = await seer.audit(auditRequest());
    assert.equal(forwarded.blastRadius.state, 'ready');
    assert.equal(pair.feedbackReceipt.record.kind, 'seer-verdict-outcome-receipt');
    assert.equal(pair.feedbackReceipt.record.blastRadiusDigest, pair.blastRadius.digest);
    assert.deepEqual(pair.feedbackReceipt.record.outcomes, [{ findingId: 'F-1', ruleId: 'correctness', verdict: 'confirmed', severity: 'high' }]);
    assert.deepEqual(receiptStore.list({ runId: pair.result.runId }), [pair.feedbackReceipt.record]);
    assert.equal(receiptStore.verifyChain().ok, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('unproven Cortex impact prevents a clean Seer claim', async () => {
  const seer = createSeer({
    traceDiff: async ({ changedPaths }) => ({ schemaVersion: 1, kind: 'seer-cortex-diff-blast-radius', state: 'unproven', changedPaths, traces: [], digest: `sha256:${'c'.repeat(64)}` }),
    core: { audit: async () => ({ claimBoundary: 'PROVEN' }) },
  });
  const pair = await seer.audit(auditRequest());
  assert.equal(pair.result.claimBoundary, 'UNPROVEN');
  assert.deepEqual(pair.result.warnings, ['cortex-blast-radius-unproven']);
});
