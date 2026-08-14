import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { buildSealedPlan } from '../lib/core/build-plan.mjs';
import { fixedHost } from '../lib/host/fixed-host.mjs';
import { discoverBookTests, qualifyBook } from '../scripts/qualify-book.mjs';

test('default sealed planning retains fixed source claim stages and fails closed without denominators', async () => {
  const plan = await buildSealedPlan({
    root: '/repo',
    projection: { files: [] },
    declarations: [{ id: 'target:cli', kind: 'cli', root: '.', entrypoints: [] }],
    packs: [],
    claimLevel: 'source',
  }, fixedHost());

  assert.equal(plan.requiredStageIds.length,9);
  assert.equal(plan.completeForRequestedClaim, false);
  assert.ok(plan.artifacts['product-portfolio']);
  assert.ok(plan.claimGaps.some(({stage})=>stage==='control-baseline'));
});

test('mutable partial stage lists cannot replace fixed planning order', async () => {
  await assert.rejects(()=>buildSealedPlan({root:'/repo',claimLevel:'source',stages:[{id:'control-baseline',requiredFor:'source',async run(){return{complete:false};}}]},fixedHost()),/fixed 12-stage order/);
});

test('duplicate or malformed stages cannot create an ambiguous sealed plan', async () => {
  const stage = { id: 'same', async run() { return { complete: true }; } };
  await assert.rejects(() => buildSealedPlan({ root: '/repo', stages: [stage, stage] }, fixedHost()), /duplicate plan stage/);
  await assert.rejects(() => buildSealedPlan({ root: '/repo', stages: [{ id: 'bad' }] }, fixedHost()), /requires id and run/);
});

test('book qualification discovers deterministic focused suites without running them', async () => {
  const tests = await discoverBookTests(2);
  assert.deepEqual(tests, [...tests].sort((left, right) => left.localeCompare(right)));
  assert.ok(tests.some((path) => path.endsWith('book-2-contracts.test.mjs')));
  assert.ok(tests.some((path) => path.endsWith('book-2-receipt.test.mjs')));
  assert.equal(tests.some((path) => path.endsWith('book-source-completion.test.mjs')), true);
  const receipt = await qualifyBook(1, { execute: false });
  assert.equal(receipt.status, 'planned');
  assert.deepEqual(receipt.command.slice(0, 3), ['node', '--test', '--test-concurrency=1']);
  assert.ok(receipt.tests.includes('tests/core-foundations.test.mjs'));
});

test('missing external source inputs remain explicit ledger states', async () => {
  for (const path of ['creator-audits-v1.json', 'platform-checklists-v1.json']) {
    const ledger = JSON.parse(await readFile(new URL(`../registry/controls/sources/${path}`, import.meta.url)));
    assert.equal(ledger.status, 'external-evidence-required');
    assert.ok(ledger.items.length > 0);
    assert.ok(ledger.items.every(({ rightsStatus }) => rightsStatus === 'unresolved'));
    assert.equal(ledger.nextEvidence.length, 1);
  }
});
