import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { ArcaneError } from '../lib/errors.mjs';
import { RuntimeSchemaSet } from '../lib/runtime-schema.mjs';
import { keyHex, stateFile, statePaths } from '../lib/state-paths.mjs';

const schemas = new RuntimeSchemaSet();
const schemaDir = join(import.meta.dirname, '..', 'schemas');
const ids = ['arcane-contract-seal-v1', 'arcane-authority-binding-v1', 'arcane-capability-grant-v1', 'arcane-capability-transition-v1', 'arcane-user-approval-v1', 'arcane-host-event-ledger-record-v1', 'arcane-advisory-artifact-receipt-v1', 'arcane-advisory-certification-receipt-v1', 'arcane-host-runtime-output-v1', 'arcane-host-runtime-result-v1'];
const digest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const capabilityId = 'cap_0123456789ABCDEFGHJKMNPQRS';
const eventId = 'hev_0123456789ABCDEFGHJKMNPQRS';
const now = '2026-08-09T12:00:00Z';

const samples = {
  'arcane-contract-seal-v1': { schemaVersion: 1, kind: 'arcane-contract-seal', contractId: 'EC-1', version: 1, sourceRevision: 'abcdef0', contractDigest: digest, dispatchDigest: null, sealedBy: { authority: 'sage', assertedBy: 'host', verificationMethod: 'capability-signature', perMessage: true }, sealedAt: now, contract: {} },
  'arcane-authority-binding-v1': { schemaVersion: 1, kind: 'arcane-authority-binding', adapter: 'codex', sessionIdDigest: digest, agentIdDigest: digest, agentType: 'sage', authority: 'sage', observedEventId: eventId, observedAt: now },
  'arcane-capability-grant-v1': { schemaVersion: 1, kind: 'arcane-capability-grant', capabilityId, runId: 'run_0123456789ABCDEFGHJKMNPQRS', taskId: 'T-1', workspace: '/repo', contractId: 'EC-1', contractVersion: 1, contractDigest: digest, sourceRevision: 'abcdef0', authority: 'alchemist', turnId: 'turn', operation: 'write', effectClass: 'FILE_WRITE', targets: ['/repo/a'], policyId: 'policy', policyVersion: 1, policyDigest: digest, advisoryProfile: null, approvalEvidence: null, issuedAt: now, expiresAt: now, ttlSeconds: 900, maxUses: 1, delegable: false, status: 'active', usedCount: 0 },
  'arcane-user-approval-v1': { schemaVersion: 1, kind: 'arcane-user-approval', keyId: 'host', sessionDigest: digest, runId: 'run_0123456789ABCDEFGHJKMNPQRS', taskId: 'T-1', contractId: 'EC-1', contractVersion: 1, contractDigest: digest, effectClass: 'FILE_DELETE', targetDigest: digest, userTurnDigest: digest, issuedAt: now, expiresAt: '2026-08-09T12:15:00Z', mac: 'a'.repeat(64) },
  'arcane-capability-transition-v1': { schemaVersion: 1, kind: 'arcane-capability-transition', capabilityId, state: 'consumed', at: now, requestId: 'req_0123456789ABCDEFGHJKMNPQRS' },
  'arcane-host-event-ledger-record-v1': { schemaVersion: 1, kind: 'arcane-host-event-ledger-record', eventId, eventSequence: 1, previousDigest: null, turnCorrelationDigest: digest, stopOrdinal: null, adapter: 'codex', eventType: 'SessionStart', sessionId: 'session', runId: null, taskId: null, contractId: null, contractVersion: null, contractDigest: null, sourceRevision: null, observedAuthority: 'alchemist', payloadDigest: digest, observedAt: now, authentication: { alg: 'HMAC-SHA256', keyId: 'k1', mac: 'a'.repeat(64), boundFieldsDigest: digest } },
  'arcane-advisory-artifact-receipt-v1': { schemaVersion: 1, kind: 'arcane-advisory-artifact-receipt', receiptId: digest, artifactDigest: digest, briefDigest: digest, bundleId: 'research', bundleVersion: '1.0.0', profileId: 'authoring', manifestDigest: digest, profileDigest: digest, producerAgentIdDigest: digest, runId: 'run_0123456789ABCDEFGHJKMNPQRS', taskId: 'T-1', contractId: 'EC-602', contractVersion: 1, contractDigest: digest, sourceRevision: 'abcdef0', binding: { adapter: 'codex', sessionId: 'producer-session', bindingDigest: digest }, issuedAt: now, expiresAt: '2026-08-09T12:15:00Z', nonce: 'a'.repeat(32), authentication: { alg: 'HMAC-SHA256', keyId: 'k1', mac: 'a'.repeat(64), macDomain: 'arcane.advisory-artifact-receipt.v1', boundFieldsDigest: digest } },
  'arcane-advisory-certification-receipt-v1': { schemaVersion: 1, kind: 'arcane-advisory-certification-receipt', receiptId: digest, artifactReceiptDigest: digest, artifactDigest: digest, briefDigest: digest, bundleId: 'research', bundleVersion: '1.0.0', profileId: 'authoring', manifestDigest: digest, profileDigest: digest, producerAgentIdDigest: digest, certifierAgentIdDigest: digest, runId: 'run_0123456789ABCDEFGHJKMNPQRS', taskId: 'T-1', contractId: 'EC-602', contractVersion: 1, contractDigest: digest, sourceRevision: 'abcdef0', checklistEvidence: [{ criterionId: 'accuracy', evidenceDigest: digest }], verdict: 'PASS', binding: { adapter: 'codex', sessionId: 'oracle-session', bindingDigest: digest }, issuedAt: now, expiresAt: '2026-08-09T12:15:00Z', nonce: 'b'.repeat(32), authentication: { alg: 'HMAC-SHA256', keyId: 'k1', mac: 'b'.repeat(64), macDomain: 'arcane.advisory-certification-receipt.v1', boundFieldsDigest: digest } },
  'arcane-host-runtime-output-v1': null,
  'arcane-host-runtime-result-v1': { schemaVersion: 1, kind: 'arcane-host-runtime-result', eventType: 'PreToolUse', allowed: false, code: 'ARC_DENY', publicReason: 'ARC_DENY: denied.', enforcementHealth: 'strong', receiptId: null, capabilityId: null, retrySignature: null, termination: 'continue', certification: 'rejected', missingClasses: [], responsibleProducer: null, remediationRoutes: [], missingEvidence: [], stdout: null },
};

test('B1 schemas are exact minified JSON with one LF', () => {
  for (const id of ids) {
    const raw = readFileSync(join(schemaDir, `${id.slice(7)}.schema.json`), 'utf8');
    assert.equal(raw, `${JSON.stringify(JSON.parse(raw))}\n`);
  }
});

test('B1 validates positive and negative runtime values', () => {
  for (const id of ids) {
    assert.deepEqual(schemas.validate(id, samples[id]), [], id);
    assert.ok(schemas.validate(id, {}).length > 0, `${id} rejects incomplete`);
  }
  const invalid = { ...samples['arcane-capability-transition-v1'], at: 'not-a-date' };
  assert.ok(schemas.validate('arcane-capability-transition-v1', invalid).some((issue) => issue.includes('RFC3339')));
  const selfAsserted = { ...samples['arcane-host-event-ledger-record-v1'], authority: 'alchemist' };
  assert.ok(schemas.validate('arcane-host-event-ledger-record-v1', selfAsserted).length > 0, 'ledger schema rejects self-asserted authority before generic authentication');
  const profile = { schemaVersion: 1, kind: 'arcane-advisory-profile-binding', bundleId: 'research', bundleVersion: '1.0.0', profileId: 'audit', manifestDigest: digest, profileDigest: digest, mutationAllowed: false, publishAllowed: false, externalOnly: false };
  assert.deepEqual(schemas.validate('arcane-capability-grant-v1', { ...samples['arcane-capability-grant-v1'], advisoryProfile: profile }), []);
  assert.ok(schemas.validate('arcane-capability-grant-v1', { ...samples['arcane-capability-grant-v1'], advisoryProfile: { ...profile, callerManifestPath: 'x' } }).length > 0);
  assert.throws(() => schemas.validate('unknown', {}), (error) => error instanceof ArcaneError && error.code === 'ARC_SCHEMA_INVALID');
});

test('B1 state paths and keys use domains without raw identifiers', () => {
  const paths = statePaths('/workspace');
  assert.equal(paths.root, join('/workspace', '.audit', 'arcane'));
  assert.deepEqual(Object.values(paths).slice(1), [join(paths.root, 'receipts'), join(paths.root, 'replay'), join(paths.root, 'capabilities', 'grants'), join(paths.root, 'capabilities', 'transitions'), join(paths.root, 'contract-seals'), join(paths.root, 'authority-bindings'), join(paths.root, 'session-bindings'), join(paths.root, 'pre-effect-correlations')]);
  const domains = [['arcane.contract-seal.key.v1', ['EC-1', 1]], ['arcane.capability.key.v1', [capabilityId]], ['arcane.authority.session.v1', ['codex', 'raw-session']], ['arcane.authority.agent.v1', ['codex', 'raw-session', null]], ['arcane.authority.binding-key.v1', ['codex', 'raw-session', null]]];
  for (const [domain, values] of domains) {
    const key = keyHex(domain, values);
    assert.match(key, /^[0-9a-f]{64}$/);
    assert.equal(stateFile(paths.authorityBindings, domain, values), join(paths.authorityBindings, `${key}.json`));
    assert.equal(stateFile(paths.authorityBindings, domain, values).includes('raw-session'), false);
  }
  assert.equal(keyHex('arcane.contract-seal.key.v1', ['EC-1', 1]), keyHex('arcane.contract-seal.key.v1', ['EC-1', 1]));
});
