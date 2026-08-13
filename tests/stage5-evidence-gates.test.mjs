import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { AcceptanceEvidenceRegistry } from '../packages/arcane/lib/evidence-registry.mjs';
import { compileSealReachability } from '../packages/arcane/lib/seal-reachability.mjs';
import { verifyExternalProviderCapability } from '../packages/arcane/lib/provider-capability.mjs';
import { executeValidatedGate, validateGate } from '../packages/arcane/lib/gate-validity.mjs';
import { buildAssurancePacket } from '../packages/arcane/lib/assurance-packet.mjs';
import { ContractSealStore } from '../packages/arcane/lib/contract-seal-store.mjs';
import { ReplayGuard } from '../packages/arcane/lib/replay.mjs';

const state = { revision: 'abc', integration: 'main' };
const now = new Date('2026-08-14T12:00:00.000Z');
const contract = () => ({ schemaVersion: 1, kind: 'legion-execution-contract', contractId: 'EC-5', version: 1, sourceRevision: 'abcdef0', objective: 's05', currentState: 'candidate', desiredState: 'closed', requirements: [], decisions: [], invariants: [], nonGoals: [], scope: { own: [], read: [], forbidden: [] }, artifacts: { exact: [{ id: 'a', path: 'x', latitude: 'EXACT', content: 'x' }], bounded: [{ id: 'b', path: 'y', latitude: 'BOUNDED', locked: ['x'], freedom: ['y'] }] }, tasks: ['T-1'], dependencies: [], acceptanceCriteria: [], declaredChecks: [], evidenceRequirements: [], authorizedEffectClasses: [], repairLatitude: [], stopConditions: [], escalationConditions: [], rollback: [], openQuestions: [], budget: { objectiveLineageId: 'objective-1', objectiveDigest: `sha256:${'a'.repeat(64)}`, legionBlastMapCapMs: 1, sagePlanningCapMs: 1, maxContractVersions: 2 } });
const assertion = { authority: 'sage', assertedBy: 'host', verificationMethod: 'capability-signature', perMessage: true };
const capability = { providerId: 'ci', machineReadable: true, gateable: true, downloadable: true, trustedRetrieval: true, trajectoryBindable: true, sensitivity: 'internal', retention: '30d', deletionOwner: 'ops' };
const requirement = { id: 'acceptance-1', producer: 'ci', durableStore: 'receipt-store', authenticatedPersistence: true, verifier: 'oracle', completionConsumer: 'legion', closePath: true, externalProvider: 'ci' };
const artifact = { acceptanceId: 'acceptance-1', producer: 'ci', verifier: 'oracle', completionConsumer: 'legion', authenticated: true, integratedState: state, observedAt: '2026-08-14T11:59:00.000Z', validUntil: '2026-08-14T13:00:00.000Z', artifactDigest: `sha256:${'b'.repeat(64)}` };

test('S05 positive lifecycle compiles fresh exact-state evidence, valid gate, independent assurance, and seal', () => {
  const registry = new AcceptanceEvidenceRegistry();
  assert.equal(registry.register({ acceptanceId: 'acceptance-1', claimType: 'acceptance-surface', producer: 'ci', durableStore: 'receipt-store', verifier: 'oracle', completionConsumer: 'legion', integratedStateBinding: 'git+integration', validityPolicy: 'one-hour' }).allowed, true);
  assert.equal(verifyExternalProviderCapability(capability).allowed, true);
  const reachability = compileSealReachability({ requirements: [requirement], providerCapabilities: [capability], recoveryPaths: [{ requirementId: 'acceptance-1', authenticated: true, closePath: true }] });
  assert.equal(reachability.allowed, true);
  assert.equal(registry.verify('acceptance-1', artifact, { integratedState: state, latestMaterialChange: '2026-08-14T11:00:00.000Z', now }).allowed, true);
  const fixtures = JSON.parse(readFileSync(new URL('./fixtures/stage5/gate-fixtures.json', import.meta.url), 'utf8'));
  const gate = { id: 'gate-1', inspectedScope: 'src/**', discoveryBreadth: 'full', blockingFilter: 'rule-x', threshold: 'zero', gates: true, authority: 'arcane', failureSemantics: 'fail' };
  const validity = validateGate({ contract: gate, fixtures, execute: (fixture) => ({ status: fixture.expected }) });
  assert.equal(validity.allowed, true);
  assert.equal(executeValidatedGate({ contract: gate, validity, inspected: ['src/a.mjs'] }).allowed, true);
  const packet = buildAssurancePacket({ frozenContract: contract(), artifacts: [artifact], evidenceRegistry: registry, producerAuthority: 'alchemist', reviewerAuthority: 'oracle', integratedState: state });
  assert.equal(packet.allowed, true);
  const root = mkdtempSync(join(tmpdir(), 's05-seal-'));
  try { assert.equal(new ContractSealStore({ root }).seal({ contract: contract(), authorityAssertion: assertion, evidenceReachability: reachability }).created, true); } finally { rmSync(root, { recursive: true, force: true }); }
});

test('S05 rejects substitution, replay, stale evidence, unsound seals, invalid gates, self-certification, and failed recovery', () => {
  const registry = new AcceptanceEvidenceRegistry();
  registry.register({ acceptanceId: 'acceptance-1', claimType: 'acceptance-surface', producer: 'ci', durableStore: 'receipt-store', verifier: 'oracle', completionConsumer: 'legion', integratedStateBinding: 'git+integration', validityPolicy: 'one-hour' });
  assert.equal(registry.verify('acceptance-1', { ...artifact, producer: 'other' }, { integratedState: state, now }).code, 'ARC_BINDING_MISMATCH');
  assert.equal(registry.verify('acceptance-1', { ...artifact, observedAt: '2026-08-14T10:00:00.000Z' }, { integratedState: state, latestMaterialChange: '2026-08-14T11:00:00.000Z', now }).code, 'ARC_EVIDENCE_STALE');
  const replay = new ReplayGuard({ clock: () => now.valueOf() });
  assert.equal(replay.check({ scope: { runId: 'r' }, nonce: 'nonce', sequence: 1, timestamp: now.toISOString() }).allowed, true);
  assert.equal(replay.check({ scope: { runId: 'r' }, nonce: 'nonce', sequence: 2, timestamp: now.toISOString() }).code, 'ARC_REPLAY_NONCE_SEEN');
  const unsound = compileSealReachability({ requirements: [{ ...requirement, selfAttested: true }], providerCapabilities: [capability], recoveryPaths: [] });
  assert.equal(unsound.code, 'ARC_UNSOUND_SEAL');
  assert.equal(compileSealReachability({ requirements: [requirement], providerCapabilities: [capability], recoveryPaths: [] }).code, 'ARC_UNSOUND_SEAL');
  const root = mkdtempSync(join(tmpdir(), 's05-unsound-'));
  try {
    assert.throws(() => new ContractSealStore({ root }).seal({ contract: contract(), authorityAssertion: assertion, evidenceReachability: unsound }), (error) => error.code === 'ARC_UNSOUND_SEAL');
    assert.throws(() => new ContractSealStore({ root }).seal({ contract: { ...contract(), evidenceRequirements: ['closure-grade acceptance proof'] }, authorityAssertion: assertion }), (error) => error.code === 'ARC_UNSOUND_SEAL');
  } finally { rmSync(root, { recursive: true, force: true }); }
  const gate = { id: 'gate-1', inspectedScope: 'src/**', discoveryBreadth: 'full', blockingFilter: 'rule-x', threshold: 'zero', gates: true, authority: 'arcane', failureSemantics: 'fail' };
  const invalid = validateGate({ contract: gate, fixtures: { knownGood: { id: 'good' }, knownBad: { id: 'bad' }, empty: { id: 'empty' }, malformed: { id: 'malformed' } }, execute: () => ({ status: 'PASS' }) });
  assert.equal(invalid.code, 'ARC_GATE_INVALID');
  assert.equal(executeValidatedGate({ contract: gate, validity: invalid, inspected: ['src/a'] }).code, 'ARC_GATE_INVALID');
  const valid = validateGate({ contract: gate, fixtures: JSON.parse(readFileSync(new URL('./fixtures/stage5/gate-fixtures.json', import.meta.url), 'utf8')), execute: (fixture) => ({ status: fixture.expected }) });
  assert.equal(executeValidatedGate({ contract: { ...gate, id: 'gate-2' }, validity: valid, inspected: ['src/a'] }).code, 'ARC_GATE_INVALID');
  assert.equal(executeValidatedGate({ contract: gate, validity: { ...valid }, inspected: ['src/a'] }).code, 'ARC_GATE_INVALID');
  assert.equal(compileSealReachability({ requirements: [requirement], providerCapabilities: [{ ...capability, sensitivity: undefined, retention: undefined, deletionOwner: undefined }], recoveryPaths: [{ requirementId: 'acceptance-1', authenticated: true, closePath: true }] }).code, 'ARC_UNSOUND_SEAL');
  assert.equal(buildAssurancePacket({ frozenContract: contract(), artifacts: [artifact], evidenceRegistry: registry, producerAuthority: 'oracle', reviewerAuthority: 'oracle', integratedState: state }).code, 'ARC_SELF_CERTIFICATION');
  assert.equal(buildAssurancePacket({ frozenContract: contract(), artifacts: [{ ...artifact, producer: 'oracle', verifier: 'oracle' }], evidenceRegistry: registry, producerAuthority: 'alchemist', reviewerAuthority: 'oracle', integratedState: state }).code, 'ARC_BINDING_MISMATCH');
});
