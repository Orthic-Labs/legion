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

// The shipped bundle's real `lockedDomains` — until now this was only ever
// exercised with an empty array (`lockedPolicy()` above swaps in a synthetic
// one). These tests run the ACTUAL policy/arcane-policy-v1.json end-to-end
// through evaluateCompletion, so populating lockedDomains is proven to bite.

function realPolicy() {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  return new PolicyEngine(loaded);
}

test('S09 (real bundle): a completion claim touching the enforcement plane without evidence is refused', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = realPolicy();
    const receiptStore = new ReceiptStore({ root });
    // No receipts at all for this run.
    const d = evaluateCompletion(
      // Claim a level the locked domain does NOT require, so the union's
      // extra member (highRisk, forced by the locked path) is what's under
      // test, not the claimed level itself. signoff is checked first in
      // iteration order and would also fail on zero evidence, so claim
      // 'release' here and assert the locked highRisk match is present.
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'release', touchedPaths: ['tools/rhook/hook.js'] },
      { policy, receiptStore },
    );
    assert.equal(d.allowed, false);
    assert.equal(d.detail.lockedDomainMatches.length, 1);
    assert.equal(d.detail.lockedDomainMatches[0].pattern, 'tools/rhook/**');
    assert.equal(d.detail.lockedDomainMatches[0].claimLevel, 'highRisk');
    assert.ok(['release', 'highRisk'].includes(d.detail.level));
  } finally {
    cleanup();
  }
});

test('S09 (real bundle): a completion claim touching the arcane package without evidence is refused', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = realPolicy();
    const receiptStore = new ReceiptStore({ root });
    const d = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'release', touchedPaths: ['tools/skills/legion/packages/arcane/lib/policy.mjs'] },
      { policy, receiptStore },
    );
    assert.equal(d.allowed, false);
    assert.equal(d.detail.lockedDomainMatches[0].pattern, 'tools/skills/legion/packages/arcane/**');
    assert.equal(d.detail.lockedDomainMatches[0].claimLevel, 'highRisk');
  } finally {
    cleanup();
  }
});

test('S09 (real bundle): a completion claim touching sealed qualification evidence without a receipt is refused, and with proper receipts passes', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = realPolicy();
    const receiptStore = new ReceiptStore({ root });

    const denied = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'signoff', touchedPaths: ['tools/skills/legion/qualification/book-1.json'] },
      { policy, receiptStore },
    );
    assert.equal(denied.allowed, false);
    assert.equal(denied.code, 'ARC_EVIDENCE_INSUFFICIENT');
    assert.equal(denied.detail.level, 'signoff');
    assert.equal(denied.detail.lockedDomainMatches[0].pattern, 'tools/skills/legion/qualification/**');

    receiptStore.append(evidenceRecord({ evidenceClass: 'deterministic', strong: true }));
    const allowed = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'signoff', touchedPaths: ['tools/skills/legion/qualification/book-1.json'] },
      { policy, receiptStore },
    );
    assert.equal(allowed.allowed, true, allowed.message);
    assert.equal(allowed.enforcementHealth, 'strong');
  } finally {
    cleanup();
  }
});

test('S09 (real bundle): an unrelated path (e.g. a docs file) forces no locked-domain prerequisite', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = realPolicy();
    const receiptStore = new ReceiptStore({ root });
    const d = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: 'signoff', touchedPaths: ['docs/README.md'] },
      { policy, receiptStore },
    );
    // No locked-domain match at all; still fails on signoff itself (no
    // evidence recorded), but for the ordinary reason, not a locked one.
    assert.equal(d.detail.lockedDomainMatches.length, 0);
  } finally {
    cleanup();
  }
});

test('S09: with no claimed level, a locked-domain touch still forces that domain\'s level', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = lockedPolicy();
    const receiptStore = new ReceiptStore({ root }); // no evidence at all
    const d = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: null, touchedPaths: ['docs/legal/terms.md'] },
      { policy, receiptStore },
    );
    assert.equal(d.allowed, false);
    assert.equal(d.detail.level, 'signoff');
    assert.equal(d.detail.lockedDomainMatches.length, 1);
  } finally {
    cleanup();
  }
});

test('S09: with no claimed level and no locked-domain touch, there is nothing to certify', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = lockedPolicy();
    const receiptStore = new ReceiptStore({ root });
    const d = evaluateCompletion(
      { runId: RUN_ID, taskId: 'T-1', claimedLevel: null, touchedPaths: ['src/app.mjs'] },
      { policy, receiptStore },
    );
    assert.equal(d.allowed, true);
    assert.deepEqual(d.detail.levelsChecked, []);
  } finally {
    cleanup();
  }
});
