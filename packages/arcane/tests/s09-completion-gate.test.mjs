// CONTRACT B — the completion gate (lib/completion-gate.mjs).
//
// evaluateCompletion() must never trust caller-asserted evidenceClasses /
// staleEvidenceCount / enforcementHealth — it derives all three from what
// ReceiptStore actually holds for the run, and forces extra claim-level
// prerequisites when a touched path falls inside the policy's lockedDomains.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { evaluateCompletion } from '../lib/completion-gate.mjs';
import { loadPolicy, PolicyEngine, DEFAULT_POLICY_PATH } from '../lib/policy.mjs';
import { ReceiptStore } from '../lib/receipt-store.mjs';
import { mintId } from '../lib/ids.mjs';

const RUN_ID = 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV';

function tempRoot() {
  const root = mkdtempSync(path.join(tmpdir(), 'arcane-completion-'));
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** A policy engine whose bundle carries one locked domain over docs/legal/**. */
function lockedPolicy() {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const bundle = {
    ...loaded.bundle,
    lockedDomains: [{ pattern: 'docs/legal/**', claimLevel: 'signoff', note: 'legal copy needs a real check' }],
  };
  return new PolicyEngine({ ...loaded, bundle });
}

function evidenceRecord({ runId = RUN_ID, evidenceClass = 'deterministic', stale = false, strong = true } = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-evidence-capability-receipt',
    evidenceId: mintId('evidenceReceipt'),
    runId,
    taskId: 'T-1',
    contractId: 'EC-44',
    producerAuthority: 'seer',
    capability: 'test-run',
    observation: { exitCode: 0 },
    evidenceClass,
    authentication: {
      issuerIdentity: 'k1',
      verificationMethod: strong ? 'capability-signature' : 'host-connection-trust',
      perMessage: strong,
      verifiedAt: new Date().toISOString(),
    },
    replayDefense: { nonce: `n-${Math.random()}`, sequence: 1, freshnessWindowSeconds: 900, freshAt: new Date().toISOString() },
    sourceRevision: '0123abcdef',
    dependsOn: [],
    stale,
    observedAt: new Date().toISOString(),
  };
}

test('S09: an unlocked path is unaffected — only the claimed level is checked', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = lockedPolicy();
    const receiptStore = new ReceiptStore({ root });
    receiptStore.append(evidenceRecord());

    const d = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'signoff', touchedPaths: ['src/exact.ts'] },
      { policy, receiptStore },
    );
    assert.equal(d.allowed, true, d.message);
    assert.deepEqual(d.detail.levelsChecked, ['signoff']);
    assert.equal(d.detail.lockedDomainMatches.length, 0);
  } finally {
    cleanup();
  }
});

test('S09: a locked-domain match forces prerequisite evaluation for the locked level', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = lockedPolicy();
    const receiptStore = new ReceiptStore({ root });
    // No evidence at all -> even though nothing was "claimed" beyond signoff,
    // the locked domain still forces the signoff check, which now fails.
    const d = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'signoff', touchedPaths: ['docs/legal/terms.md'] },
      { policy, receiptStore },
    );
    assert.equal(d.allowed, false);
    assert.equal(d.code, 'ARC_EVIDENCE_INSUFFICIENT');
    assert.equal(d.detail.level, 'signoff');
    assert.equal(d.detail.lockedDomainMatches.length, 1);
    assert.equal(d.detail.lockedDomainMatches[0].pattern, 'docs/legal/**');
  } finally {
    cleanup();
  }
});

test('S09: a claim with real receipts passes', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = lockedPolicy();
    const receiptStore = new ReceiptStore({ root });
    receiptStore.append(evidenceRecord({ evidenceClass: 'deterministic', strong: true }));

    const d = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'signoff', touchedPaths: ['docs/legal/terms.md'] },
      { policy, receiptStore },
    );
    assert.equal(d.allowed, true, d.message);
    assert.equal(d.enforcementHealth, 'strong');
    assert.deepEqual(d.detail.evidenceClasses, ['deterministic']);
  } finally {
    cleanup();
  }
});

test('S09: a claim with zero matching receipts is refused with ARC_EVIDENCE_INSUFFICIENT', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = lockedPolicy();
    const receiptStore = new ReceiptStore({ root });
    // Evidence exists, but for a DIFFERENT run — list({runId}) must not pick it up.
    receiptStore.append(evidenceRecord({ runId: 'run_00000000000000000000000000' }));

    const d = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'signoff', touchedPaths: [] },
      { policy, receiptStore },
    );
    assert.equal(d.allowed, false);
    assert.equal(d.code, 'ARC_EVIDENCE_INSUFFICIENT');
    assert.deepEqual(d.detail.missingClasses, ['deterministic']);
  } finally {
    cleanup();
  }
});

test('S09: enforcementHealth is derived from receipts, never from a caller-asserted field', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = lockedPolicy();
    const receiptStore = new ReceiptStore({ root });
    // Weakly-authenticated evidence -> enforcementHealth caps at read_only,
    // which fails signoff's requiredEnforcement:'strong' even though the
    // caller could try to assert 'strong' itself (and evaluateCompletion
    // accepts no such argument at all).
    receiptStore.append(evidenceRecord({ strong: false }));

    const d = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'signoff', touchedPaths: [] },
      { policy, receiptStore },
    );
    assert.equal(d.allowed, false);
    assert.equal(d.code, 'ARC_CLAIM_PREREQUISITE_UNMET');
    assert.equal(d.detail.required, 'strong');
    assert.equal(d.detail.actual, 'read_only');
  } finally {
    cleanup();
  }
});
