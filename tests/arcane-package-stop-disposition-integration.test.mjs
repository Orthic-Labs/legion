import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { evaluateHostStop } from '../src/lib/host/arcane/hook-adapter-core.mjs';
import { PendingTerminalOperationStore } from '../src/lib/verification/arcane/pending-terminal-operation-store.mjs';
import { generateTestKeyRing } from '../src/lib/guard/compat/host/keys.mjs';
import { stopOutcome } from '../src/lib/host/arcane/stop-disposition.mjs';

const digest = (character) => `sha256:${character.repeat(64)}`;
const binding = { runId: 'run-1', taskId: 'T-1', contractId: 'EC-603', contractVersion: 7, contractDigest: digest('c'), sourceRevision: '7f4adfeeb8dec603c9e60ea820a7f21052eef102' };
function mint(store, nonce) { return store.mint({ invocationProofDigest: digest('d'), producerAuthority: 'legion', ...binding, turnCorrelationDigest: digest('a'), expectedStopOrdinal: 1, outcomeSummaryDigest: digest('e'), artifactStateDigest: digest('f'), nonce }); }

test('EC603 Stop disposition matrix terminates bare/question/plan/pause & only matching terminal claim is genuine', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-stop-'));
  try {
    const keys = generateTestKeyRing(['k1']);
    const store = new PendingTerminalOperationStore({ root, keyRing: keys, keyId: 'k1', clock: () => '2026-08-12T00:00:00.000Z' });
    for (const intent of ['UNKNOWN', 'QUESTION', 'PLAN', 'PAUSE']) {
      const outcome = stopOutcome({ intent, authenticatedClaim: false });
      assert.equal(outcome.termination.allowed, true);
      assert.equal(outcome.certification, 'not_claimed');
    }
    const claim = store.append(mint(store, 'nonce-one-000000')).detail.claim;
    const abandoned = store.resolve({ claimId: claim.claimId, stopEventDigest: digest('b'), turnCorrelationDigest: claim.turnCorrelationDigest, stopOrdinal: 1, terminal: false });
    assert.equal(abandoned.detail.certification, 'not_claimed');
    assert.equal(abandoned.detail.record.state, 'ABANDONED');
    const second = store.append(mint(store, 'nonce-two-000000')).detail.claim;
    const consumed = store.resolve({ claimId: second.claimId, stopEventDigest: digest('b'), turnCorrelationDigest: second.turnCorrelationDigest, stopOrdinal: 1, terminal: true });
    assert.equal(consumed.detail.certification, 'genuine');
    assert.equal(store.resolve({ claimId: second.claimId, stopEventDigest: digest('b'), turnCorrelationDigest: second.turnCorrelationDigest, stopOrdinal: 1, terminal: true }).detail.idempotent, true);
    assert.equal(store.resolve({ claimId: second.claimId, stopEventDigest: digest('d'), turnCorrelationDigest: second.turnCorrelationDigest, stopOrdinal: 1, terminal: true }).code, 'ARC_REPLAY_NONCE_SEEN');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('genuine completion reaches completion gate; caller disposition cannot bypass it', () => {
  let calls = 0;
  const policy = { lockedDomainsFor: () => [], claimLevel: () => null, evaluateClaimPrerequisites: () => { calls += 1; return { allowed: true, detail: {} }; } };
  const receipts = { list: () => [{ authentication: { verificationMethod: 'capability-signature', perMessage: true } }] };
  const host = { runId: 'run-1', taskId: 'T-1' };
  assert.equal(evaluateHostStop(host, { policy, receiptStore: receipts, authenticatedClaim: true, intent: 'UNKNOWN', claimedLevel: 'release' }).allowed, true);
  assert.equal(calls, 1);
  const bare = evaluateHostStop(host, { policy, receiptStore: receipts, authenticatedClaim: false, disposition: 'completion', intent: 'UNKNOWN' });
  assert.equal(bare.detail.certification, 'not_claimed');
  assert.equal(bare.detail.termination.allowed, true);
});

test('locked completion evaluates deterministic policy without Covenant authority or release gate', () => {
  let received;
  const highRiskContext = { intentRestatement: 'preserve frozen host behavior', blastRadius: 'Arcane completion gate only', whySafe: 'deterministic evidence remains mandatory' };
  const policy = {
    lockedDomainsFor: () => [{ claimLevel: 'release' }],
    claimLevel: () => ({ requiredEvidenceClasses: ['deterministic'] }),
    evaluateClaimPrerequisites: (_level, context) => { received = context; return { allowed: true, detail: {}, enforcementHealth: 'strong' }; },
  };
  const result = evaluateHostStop({ runId: 'run-1', taskId: 'T-1' }, {
    policy,
    receiptStore: { list: () => [{ evidenceClass: 'deterministic', authentication: { verificationMethod: 'capability-signature', perMessage: true } }] },
    completionClaim: { highRiskContext },
    claimedLevel: 'release',
    intent: 'UNKNOWN',
    authenticatedClaim: true,
  });
  assert.equal(result.allowed, true);
  assert.deepEqual(received.fields, highRiskContext);
  assert.equal(Object.hasOwn(received, 'covenantVerdict'), false);
});
