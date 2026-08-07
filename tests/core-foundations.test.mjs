import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { buildSealedPlan } from '../lib/core/build-plan.mjs';
import { fixedHost } from '../lib/host/fixed-host.mjs';
import { discoverBookTests, qualifyBook } from '../scripts/qualify-book.mjs';

test('default sealed planning retains Book 2 topology and control gates', async () => {
  const plan = await buildSealedPlan({
    root: '/repo',
    projection: { files: [] },
    declarations: [{ id: 'target:cli', kind: 'cli', root: '.', entrypoints: [] }],
    packs: [],
    claimLevel: 'source',
  }, fixedHost());

  assert.deepEqual(plan.requiredStageIds, ['product-topology', 'control-baseline']);
  assert.equal(plan.completeForRequestedClaim, true);
  assert.ok(plan.artifacts['product-topology']);
  assert.ok(plan.artifacts['control-baseline']);
});

test('incomplete required stage remains a typed claim gap', async () => {
  const plan = await buildSealedPlan({
    root: '/repo', claimLevel: 'source',
    stages: [{ id: 'control-baseline', requiredFor: 'source', async run() { return { complete: false, status: 'missing', detail: 'fixture-missing' }; } }],
  }, fixedHost());

  assert.equal(plan.completeForRequestedClaim, false);
  assert.deepEqual(plan.claimGaps, [{ stage: 'control-baseline', status: 'missing', detail: 'fixture-missing' }]);
});

test('duplicate or malformed stages cannot create an ambiguous sealed plan', async () => {
  const stage = { id: 'same', async run() { return { complete: true }; } };
  await assert.rejects(() => buildSealedPlan({ root: '/repo', stages: [stage, stage] }, fixedHost()), /duplicate plan stage/);
  await assert.rejects(() => buildSealedPlan({ root: '/repo', stages: [{ id: 'bad' }] }, fixedHost()), /requires id and run/);
});

test('book qualification discovers deterministic focused suites without running them', async () => {
  const tests = await discoverBookTests(2);
  assert.deepEqual(tests.map((path) => path.split('/').pop()), ['core-foundations.test.mjs', 'foundations.test.mjs']);
  const receipt = await qualifyBook(1, { execute: false });
  assert.equal(receipt.status, 'planned');
  assert.ok(receipt.tests.includes('tests/core-foundations.test.mjs'));
});

test('missing external source inputs remain explicit ledger states', async () => {
  for (const path of ['creator-audits-v1.json', 'platform-checklists-v1.json']) {
    const ledger = JSON.parse(await readFile(new URL(`../registry/controls/sources/${path}`, import.meta.url)));
    assert.equal(ledger.status, 'external-input-required');
    assert.deepEqual(ledger.items, []);
    assert.equal(ledger.nextEvidence.length, 1);
  }
});
