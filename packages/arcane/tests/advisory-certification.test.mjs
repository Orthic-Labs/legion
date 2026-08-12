import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { AuthorityBindingStore } from '../lib/authority-binding-store.mjs';
import { digestValue } from '../lib/canonical.mjs';
import {
  findCurrentAdvisoryCertification, mintAdvisoryArtifactReceipt, mintAdvisoryCertificationReceipt,
  verifyAdvisoryArtifactReceipt, verifyAdvisoryCertification,
} from '../lib/advisory-certification.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
import { ReceiptStore } from '../lib/receipt-store.mjs';
import { evaluateCompletion } from '../lib/completion-gate.mjs';
import { loadPolicy, PolicyEngine, DEFAULT_POLICY_PATH } from '../lib/policy.mjs';

const at = '2026-08-12T08:00:00.000Z';
const later = new Date('2026-08-12T08:01:00.000Z');
const digest = (value) => digestValue({ value });
const execution = Object.freeze({ runId: 'run_0123456789ABCDEFGHJKMNPQRS', taskId: 'T-1', contractId: 'EC-602', contractVersion: 1, contractDigest: digest('contract'), sourceRevision: 'abcdef0' });
const input = Object.freeze({ ...execution, artifactDigest: digest('artifact'), briefDigest: digest('brief'), bundleId: 'research', bundleVersion: '1.0.0', profileId: 'authoring', manifestDigest: digest('manifest'), profileDigest: digest('profile'), adapter: 'codex', sessionId: 'producer-session' });
const checklistEvidence = Object.freeze([{ criterionId: 'accuracy', evidenceDigest: digest('accuracy') }, { criterionId: 'sources', evidenceDigest: digest('sources') }]);

function wire() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-advisory-cert-'));
  const keyRing = generateTestKeyRing(['host']);
  const bindings = new AuthorityBindingStore({ root: join(root, 'bindings'), clock: () => at });
  bindings.observe({ adapter: 'codex', sessionId: 'producer-session', agentId: 'producer-agent', agentType: 'alchemist', eventId: 'hev_0123456789ABCDEFGHJKMNPQ' });
  bindings.observe({ adapter: 'codex', sessionId: 'oracle-session', agentId: 'oracle-agent', agentType: 'oracle', eventId: 'hev_1123456789ABCDEFGHJKMNPQ' });
  const options = { keyRing, keyId: 'host', authorityBindingStore: bindings, clock: () => at, now: later };
  const artifactReceipt = mintAdvisoryArtifactReceipt(input, options);
  const certificationReceipt = mintAdvisoryCertificationReceipt({ artifactReceipt, checklistEvidence, adapter: 'codex', sessionId: 'oracle-session' }, options);
  return { root, keyRing, bindings, options, artifactReceipt, certificationReceipt };
}

test('authenticated artifact + independent Oracle certification join exact inputs', () => {
  const w = wire();
  try {
    assert.equal(verifyAdvisoryArtifactReceipt(w.artifactReceipt, execution, w.options).allowed, true);
    const result = verifyAdvisoryCertification({ artifactReceipt: w.artifactReceipt, certificationReceipt: w.certificationReceipt, expected: { ...execution, artifactDigest: input.artifactDigest, briefDigest: input.briefDigest, manifestDigest: input.manifestDigest, profileDigest: input.profileDigest } }, w.options);
    assert.equal(result.allowed, true, result.message);
    assert.notEqual(w.artifactReceipt.producerAgentIdDigest, w.certificationReceipt.certifierAgentIdDigest);
  } finally { rmSync(w.root, { recursive: true, force: true }); }
});

test('receipt store joins by artifact digest, not transcript claims', () => {
  const w = wire();
  try {
    const store = new ReceiptStore({ root: join(w.root, 'receipts') });
    store.append(w.artifactReceipt); store.append(w.certificationReceipt);
    assert.equal(findCurrentAdvisoryCertification({ receiptStore: store, artifactDigest: input.artifactDigest, expected: execution }, w.options).allowed, true);
    assert.equal(findCurrentAdvisoryCertification({ receiptStore: store, artifactDigest: digest('other'), expected: execution }, w.options).code, 'ARC_EVIDENCE_INSUFFICIENT');
    assert.equal(findCurrentAdvisoryCertification({ receiptStore: { verifyChain: () => ({ ok: false }), list: () => [] }, artifactDigest: input.artifactDigest, expected: execution }, w.options).code, 'ARC_STORE_CORRUPT');
    assert.equal(store.verifyChain().ok, true);
  } finally { rmSync(w.root, { recursive: true, force: true }); }
});

test('wrong artifact, brief, pack/profile, stale, forged, missing checklist & self-certification deny', () => {
  const w = wire();
  try {
    const cases = [
      [{ ...w.certificationReceipt, artifactDigest: digest('other') }, 'ARC_AUTH_FORGED'],
      [{ ...w.certificationReceipt, briefDigest: digest('other') }, 'ARC_AUTH_FORGED'],
      [{ ...w.certificationReceipt, profileDigest: digest('other') }, 'ARC_AUTH_FORGED'],
      [{ ...w.certificationReceipt, manifestDigest: digest('other') }, 'ARC_AUTH_FORGED'],
      [{ ...w.certificationReceipt, checklistEvidence: [] }, 'ARC_EVIDENCE_INSUFFICIENT'],
      [{ ...w.certificationReceipt, authentication: { ...w.certificationReceipt.authentication, mac: '0'.repeat(64) } }, 'ARC_AUTH_FORGED'],
    ];
    for (const [certificationReceipt, code] of cases) assert.equal(verifyAdvisoryCertification({ artifactReceipt: w.artifactReceipt, certificationReceipt }, w.options).code, code);
    for (const expected of [
      { artifactDigest: digest('expected-other') }, { briefDigest: digest('expected-other') },
      { bundleId: 'writing' }, { profileId: 'audit' }, { manifestDigest: digest('expected-other') }, { profileDigest: digest('expected-other') },
    ]) assert.equal(verifyAdvisoryCertification({ artifactReceipt: w.artifactReceipt, certificationReceipt: w.certificationReceipt, expected }, w.options).code, 'ARC_BINDING_MISMATCH');
    assert.equal(verifyAdvisoryCertification({ artifactReceipt: w.artifactReceipt, certificationReceipt: w.certificationReceipt }, { ...w.options, now: new Date('2026-08-14T08:00:00.000Z') }).code, 'ARC_REPLAY_STALE');

    const sameRecord = { schemaVersion: 1, kind: 'arcane-authority-binding', adapter: 'codex', sessionIdDigest: digest('session'), agentIdDigest: digest('same-agent'), observedEventId: 'hev_2123456789ABCDEFGHJKMNPQ', observedAt: at };
    const same = { findLatest({ adapter, sessionId, authority }) { return adapter === 'codex' && sessionId === 'shared' ? { ...sameRecord, agentType: authority, authority } : null; } };
    const producer = mintAdvisoryArtifactReceipt({ ...input, sessionId: 'shared' }, { ...w.options, authorityBindingStore: same });
    assert.throws(() => mintAdvisoryCertificationReceipt({ artifactReceipt: producer, checklistEvidence, adapter: 'codex', sessionId: 'shared' }, { ...w.options, authorityBindingStore: same }), (error) => error.code === 'ARC_CLAIM_PREREQUISITE_UNMET');
  } finally { rmSync(w.root, { recursive: true, force: true }); }
});

test('caller cannot inject authentication or host-derived identities', () => {
  const w = wire();
  try {
    for (const field of ['authentication', 'receiptId', 'producerAgentIdDigest', 'binding']) assert.throws(() => mintAdvisoryArtifactReceipt({ ...input, [field]: 'forged' }, w.options), (error) => error.code === 'ARC_AUTHORITY_MODEL_CLAIMED');
    assert.throws(() => mintAdvisoryArtifactReceipt({ ...input, extra: true }, w.options), (error) => error.code === 'ARC_SCHEMA_INVALID');
    assert.equal(verifyAdvisoryArtifactReceipt({ ...w.artifactReceipt, extra: true }, {}, w.options).code, 'ARC_SCHEMA_INVALID');
    assert.equal(verifyAdvisoryCertification({ artifactReceipt: w.artifactReceipt, certificationReceipt: { ...w.certificationReceipt, extra: true } }, w.options).code, 'ARC_EVIDENCE_INSUFFICIENT');
  } finally { rmSync(w.root, { recursive: true, force: true }); }
});

test('completion remains ambient without advisory claim & requires exact independent certification when claimed', () => {
  const w = wire();
  try {
    const policy = new PolicyEngine(loadPolicy({ path: DEFAULT_POLICY_PATH }));
    const store = new ReceiptStore({ root: join(w.root, 'receipts') });
    const base = { ...execution, claimedLevel: null, touchedPaths: [], completionClaim: null };
    assert.equal(evaluateCompletion(base, { policy, receiptStore: store }).allowed, true);

    const advisoryClaim = { required: true, ...Object.fromEntries(['artifactDigest', 'briefDigest', 'bundleId', 'bundleVersion', 'profileId', 'manifestDigest', 'profileDigest'].map((field) => [field, input[field]])) };
    const denied = evaluateCompletion({ ...base, completionClaim: { advisoryClaim } }, { policy, receiptStore: store, keyRing: w.keyRing, authorityBindingStore: w.bindings, now: later });
    assert.equal(denied.code, 'ARC_EVIDENCE_INSUFFICIENT');

    store.append(w.artifactReceipt);
    store.append(w.certificationReceipt);
    const allowed = evaluateCompletion({ ...base, completionClaim: { advisoryClaim } }, { policy, receiptStore: store, keyRing: w.keyRing, authorityBindingStore: w.bindings, now: later });
    assert.equal(allowed.allowed, true, allowed.message);
    assert.equal(allowed.detail.advisoryCertification.artifactDigest, input.artifactDigest);
  } finally { rmSync(w.root, { recursive: true, force: true }); }
});
