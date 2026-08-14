import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDeliveryGovernanceDispatcher, createDurablePacketAdmissionCapability, createTrustedDeliveryEvidenceCapability, DurablePacketAdmissionStore, runDeliveryGovernance } from '../lib/cli/commands/governance/delivery.mjs';

function hardCut() { return { plan: { mode: 'HARD_CUT', hard_cut: { absence_checks: { imports: [], routes: [], runtime_registrations: [], configuration_keys: [], dependencies: [], tests: [], documentation: [], emitted_protocol_variants: [] } } }, observations: { absence: { imports: [], routes: [], runtime_registrations: [], configuration_keys: [], dependencies: [], tests: [], documentation: [], emitted_protocol_variants: [] } } }; }

test('delivery governance only exposes advisory scheduler output from raw JSON', () => {
  const dispatcher = createDeliveryGovernanceDispatcher();
  const capacity = dispatcher.dispatch({ operation: 'dispatch-capacity', input: { readyTasks: ['a', 'b'], constraints: [{ name: 'lane', capacity: 1 }] } });
  assert.equal(capacity.outcome, 'CAPACITY_ADMITTED');
  assert.deepEqual(capacity.admitted, ['a']);
  assert.equal(dispatcher.dispatch({ operation: 'dispatch-packet', input: { packetDigest: 'sha256:one' } }).code, 'ARC_DIAGNOSTIC_ONLY');
  const cutover = dispatcher.dispatch({ operation: 'migration-cutover', input: hardCut() });
  assert.equal(cutover.code, 'ARC_DIAGNOSTIC_ONLY');
  assert.equal(cutover.consumable, false);
});

test('raw JSON booleans cannot authorize recovery or other consumable control admissions', () => {
  const dispatcher = createDeliveryGovernanceDispatcher();
  const recovery = dispatcher.dispatch({ operation: 'control-recovery', input: { controlId: 'control-1', state: { corrupt: true }, authorization: { controlId: 'control-1', operation: 'RECOVER_CONTROL_STATE', authenticated: true }, repairOutcome: { status: 'PASS', value: { corrupt: false } }, verificationOutcome: { status: 'PASS', value: true } } });
  assert.equal(recovery.code, 'ARC_DIAGNOSTIC_ONLY');
  assert.equal(recovery.consumable, false);
  const retirement = dispatcher.dispatch({ operation: 'control-retirement', input: { record: { control_id: 'control-1', status: 'RETIRED' }, consumerScan: { complete: true, liveConsumers: [] }, obligationDisposition: { complete: true, open: [] }, migrationEvidence: { completed: true }, evalProof: { status: 'PASS', fresh: true } } });
  assert.equal(retirement.code, 'ARC_DIAGNOSTIC_ONLY');
  const phase = dispatcher.dispatch({ operation: 'dispatch-phase', input: { phase: 'activation', requiredProducerProofs: ['proof'], producerProofs: ['proof'] } });
  assert.equal(phase.code, 'ARC_DIAGNOSTIC_ONLY');
});

test('opaque host capabilities & durable packet store enable consumable admissions', () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-packet-store-'));
  try {
  const packetCapability = createDurablePacketAdmissionCapability(new DurablePacketAdmissionStore({ root }));
  const providerCapability = createTrustedDeliveryEvidenceCapability({
    migrationCutoverEvidence: () => hardCut(),
    phaseProofEvidence: () => ({ phase: 'activation', requiredProducerProofs: ['proof'], producerProofs: ['proof'] }),
    controlRecoveryAuthority: () => ({ controlId: 'control-1', state: { corrupt: true }, authorization: { controlId: 'control-1', operation: 'RECOVER_CONTROL_STATE' }, authenticate: () => true, repair: () => ({ corrupt: false }), verify: (state) => state.corrupt === false }),
  });
  const dispatcher = createDeliveryGovernanceDispatcher({
    packetCapability, providerCapability,
  });
  assert.equal(dispatcher.dispatch({ operation: 'migration-cutover', input: {} }).consumable, true);
  assert.equal(dispatcher.dispatch({ operation: 'dispatch-phase', input: {} }).consumable, true);
  assert.equal(dispatcher.dispatch({ operation: 'control-recovery', input: {} }).consumable, true);
  assert.equal(dispatcher.dispatch({ operation: 'dispatch-packet', input: { packetDigest: 'sha256:new' } }).consumable, true);
  const reloaded = createDeliveryGovernanceDispatcher({ packetCapability: createDurablePacketAdmissionCapability(new DurablePacketAdmissionStore({ root })) });
  assert.equal(reloaded.dispatch({ operation: 'dispatch-packet', input: { packetDigest: 'sha256:new' } }).code, 'ARC_PACKET_DIGEST_REPLAY');
  const badProviderCapability = createTrustedDeliveryEvidenceCapability({ migrationCutoverEvidence: () => ({ plan: { mode: 'BOUNDED_COEXISTENCE', bounded_coexistence: {} }, observations: { coexistence: {} } }) });
  const denied = createDeliveryGovernanceDispatcher({ providerCapability: badProviderCapability }).dispatch({ operation: 'migration-cutover', input: {} });
  assert.equal(denied.consumable, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('duck-typed providers, registries & persistence callbacks cannot mint admissions', () => {
  assert.throws(() => createDeliveryGovernanceDispatcher({ providerCapability: { migrationCutoverEvidence() { return hardCut(); } } }), /providerCapability/);
  assert.throws(() => createDeliveryGovernanceDispatcher({ packetCapability: { admit() { return { outcome: 'PACKET_ADMITTED' }; } } }), /packetCapability/);
  assert.throws(() => createDurablePacketAdmissionCapability(Object.create(DurablePacketAdmissionStore.prototype)), /genuine/);
  assert.throws(() => createDurablePacketAdmissionCapability({ root: '/tmp/fake' }), /genuine/);
});

test('handler emits JSON & fails closed for unknown operations', () => {
  let output = '';
  const result = runDeliveryGovernance({ operation: 'unknown', input: {} }, { stdout: { write(value) { output += value; } } });
  assert.equal(result.exitCode, 2);
  assert.equal(JSON.parse(output).code, 'ARC_OPERATION_UNKNOWN');
});
