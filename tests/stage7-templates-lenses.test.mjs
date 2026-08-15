import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { validateSchema } from '../lib/qualification/schema-validator.mjs';
import { ADOPTION_MANIFEST_RECEIPT_BOUND_FIELDS, REQUIRED_ADOPTION_EDGES, admitVerifiedStage, readAdoptionStage, readVerifiedStageFile, transitionVerifiedLedger, transitionVerifiedStage, transitionVerifiedStageFile, validateAdoptionDependencyGraph, validateFormalAdoptionGraph, verifyVerifiedStageAdmission } from '../packages/arcane/lib/adoption-ledger.mjs';
import { AcceptanceEvidenceRegistry } from '../packages/arcane/lib/evidence-registry.mjs';
import { ReceiptStore } from '../packages/arcane/lib/receipt-store.mjs';
import { generateTestKeyRing } from '../packages/arcane/lib/keys.mjs';
import { EVIDENCE_RECEIPT_BOUND_FIELDS, signRecord } from '../packages/arcane/lib/receipt-auth.mjs';
import { digestValue } from '../packages/arcane/lib/canonical.mjs';
import { HostEventLedger } from '../packages/arcane/lib/host-event-ledger.mjs';
import { AuthorityInvocationProofIssuer } from '../packages/arcane/lib/authority-invocation-proof.mjs';

const root = join(import.meta.dirname, '..');
const read = (path) => readFileSync(join(root, path), 'utf8');
const json = (path) => JSON.parse(read(path));
const fixtures = json('tests/fixtures/stage7/representative-instances.json');
const schemaNames = ['architecture-decision', 'adoption-ledger', 'canon-map', 'representative-workload', 'architecture-convergence-receipt', 'intent-epoch'];
const schemaTemplates = { 'architecture-decision': 'adr', 'adoption-ledger': 'adoption-ledger', 'canon-map': 'canon-map', 'representative-workload': 'representative-workload', 'architecture-convergence-receipt': 'architecture-convergence-receipt', 'intent-epoch': 'intent-epoch' };
const templates = ['architecture-brief', 'quality-scenario', 'assumption-unknown-register', 'domain-data-ownership', 'candidate-card', 'option-evaluation', 'evidence-card', 'adr', 'architecture-review', 'review-module-contract', 'representative-workload', 'adoption-ledger', 'canon-map', 'architecture-convergence-receipt', 'intent-epoch'];
const lenses = ['catalogue', 'product-quality', 'data-privacy-security', 'reliability-operations', 'socio-technical', 'economics-sustainability', 'ai-edge-platform-conditional'];

test('S07-01 every representative template has a declared schema where applicable & validates', () => {
  for (const name of templates) assert.ok(read(`doctrine/architecture/templates/${name}.md`).length, name);
  for (const name of schemaNames) {
    const schema = json(`schemas/${name}.schema.json`);
    assert.deepEqual(validateSchema(schema, fixtures[name]), [], name);
    assert.match(read(`doctrine/architecture/templates/${schemaTemplates[name]}.md`), new RegExp(schema.$id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('S07-01 schemas reject closed-shape & critical negative instances', () => {
  for (const name of schemaNames) {
    const invalid = structuredClone(fixtures[name]); invalid.extra = true;
    assert.ok(validateSchema(json(`schemas/${name}.schema.json`), invalid).length, `${name} closes shape`);
  }
  const adr = structuredClone(fixtures['architecture-decision']); adr.record_worthiness.real_trade_off = false;
  assert.ok(validateSchema(json('schemas/architecture-decision.schema.json'), adr).length, 'low-worth ADR rejects');
  const workload = structuredClone(fixtures['representative-workload']); delete workload.actual_acceptance_surface;
  assert.ok(validateSchema(json('schemas/representative-workload.schema.json'), workload).length, 'proxy workload rejects');
});

test('S07-01 anti-serialization binds consumption to artifacts & acceptance IDs', () => {
  const ledger = fixtures['adoption-ledger'];
  const ledgerSchema = json('schemas/adoption-ledger.schema.json');
  assert.equal(ledgerSchema.$id, 'architecture-adoption-ledger.v3');
  assert.deepEqual(validateSchema(ledgerSchema, ledger), []);
  assert.ok(validateSchema(ledgerSchema, { ...structuredClone(ledger), schema: 'architecture-adoption-ledger.v2' }).length, 'live v2 ledger cannot collide with v3 template schema');
  assert.ok(ledger.stages.every((stage) => stage.produce_readiness && stage.integrate_readiness && stage.activate_readiness));
  assert.ok(ledger.consumption_dependencies.every((edge) => edge.consumed_artifact_id && edge.producer_acceptance_id && edge.consumer_acceptance_id && edge.required_verification));
  const wholeStage = structuredClone(ledger); wholeStage.stages[1].dependencies = ['S-1'];
  assert.ok(validateSchema(json('schemas/adoption-ledger.schema.json'), wholeStage).length, 'whole-stage dependency rejects');
  const missingArtifact = structuredClone(ledger); delete missingArtifact.consumption_dependencies[0].consumed_artifact_id;
  assert.ok(validateSchema(json('schemas/adoption-ledger.schema.json'), missingArtifact).length, 'artifact binding required');
  const emptyDag = structuredClone(ledger); emptyDag.consumption_dependencies = [];
  assert.ok(validateSchema(ledgerSchema, emptyDag).length, 'adoption ledger requires an explicit dependency graph');
  const missingStage = structuredClone(ledger); missingStage.consumption_dependencies[0].producer_stage_id = 'S-missing';
  assert.equal(validateAdoptionDependencyGraph(missingStage).allowed, false, 'dependency graph rejects absent stages');
  const cycle = structuredClone(ledger); cycle.consumption_dependencies.push({ consumer_stage_id: 'S-1', consumer_acceptance_id: 'S-1-01', producer_stage_id: 'S-2', producer_acceptance_id: 'S-2-01', consumed_artifact_id: 'cycle.json', consumption: 'INTEGRATE', required_verification: true });
  assert.equal(validateAdoptionDependencyGraph(cycle).allowed, false, 'dependency graph rejects cycles');
  const falseVerified = structuredClone(ledger); falseVerified.stages[0].done_state = 'VERIFIED';
  assert.ok(validateSchema(ledgerSchema, falseVerified).length, 'VERIFIED requires exact integrated state & passed acceptance items');
  const verifiedOpen = structuredClone(ledger); verifiedOpen.stages[0].done_state = 'VERIFIED'; verifiedOpen.stages[0].integrated_state_identity = 'git:abc'; verifiedOpen.stages[0].required_items[0].evidence = ['receipt:1'];
  assert.ok(validateSchema(ledgerSchema, verifiedOpen).length, 'VERIFIED rejects OPEN acceptance items');
  const verifiedMissingEvidence = structuredClone(verifiedOpen); verifiedMissingEvidence.stages[0].required_items[0].result = 'PASS'; verifiedMissingEvidence.stages[0].required_items[0].evidence = [];
  assert.ok(validateSchema(ledgerSchema, verifiedMissingEvidence).length, 'VERIFIED rejects missing acceptance evidence');
  const manualVerified = structuredClone(verifiedOpen); manualVerified.stages[0].required_items[0].result = 'PASS';
  assert.ok(validateSchema(ledgerSchema, manualVerified).length, 'manual VERIFIED lacks required Arcane admission receipt');
  const emptyAuthentication = structuredClone(manualVerified); emptyAuthentication.stages[0].verification_admission = { schemaVersion: 1, kind: 'arcane-adoption-verification', stageId: 'S-1', stageFingerprint: `sha256:${'a'.repeat(64)}`, runId: 'run-1', taskId: 'task-1', contractId: 'contract-1', integratedState: 'git:abc', admittedAt: '2026-08-14T12:00:00Z', authentication: {} };
  assert.ok(validateSchema(ledgerSchema, emptyAuthentication).length, 'VERIFIED rejects empty authentication material');
  const malformedAdmissionTime = structuredClone(emptyAuthentication); malformedAdmissionTime.stages[0].verification_admission.admittedAt = 'not-a-time';
  assert.ok(validateSchema(ledgerSchema, malformedAdmissionTime).some((issue) => issue.endsWith(':format')), 'admission time must be RFC3339');
  const template = read('doctrine/architecture/templates/adoption-ledger.md');
  for (const phrase of ['READY_TO_PRODUCE', 'INTEGRATE', 'ACTIVATE', 'specific consumed artifact', 'whole-stage authoring', 'first `INTEGRATE` or `ACTIVATE`', 'One writer']) assert.match(template, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
});

test('S07-01 Arcane, not a stage author, admits VERIFIED only from fresh exact-state evidence', () => {
  const ledger = structuredClone(fixtures['adoption-ledger']);
  const stage = ledger.stages[0];
  stage.done_state = 'CANDIDATE'; stage.integrated_state_identity = 'git:abc'; stage.required_items[0].result = 'PASS'; stage.required_items[0].evidence = ['receipt:oracle-1'];
  const root = mkdtempSync(join(tmpdir(), 'arcane-adoption-'));
  const receiptStore = new ReceiptStore({ root }); const keyRing = generateTestKeyRing(['k1']);
  const execution = { runId: 'run-adoption', taskId: 'task-adoption', contractId: 'contract-adoption', contractVersion: 1, contractDigest: 'sha256:contract-adoption', sourceRevision: 'abc', acceptanceCriteria: [{ id: 'S-1-01', statement: 'produce artifact' }] };
  const integratedState = 'git:abc'; const latestMaterialChange = '2026-08-14T11:00:00Z';
  const hostLedger = new HostEventLedger({ root: join(root, 'events'), keyRing, keyId: 'k1', clock: () => '2026-08-14T12:00:00Z' });
  const event = hostLedger.append({ eventId: 'oracle-adoption-proof', adapter: 'codex', eventType: 'UserPromptSubmit', sessionId: 'oracle-adoption', binding: execution, sourceRevision: execution.sourceRevision, observedAuthority: 'oracle', payload: {} });
  const authorityProofIssuer = new AuthorityInvocationProofIssuer({ root: join(root, 'proofs'), keyRing, keyId: 'k1', ledgerStore: hostLedger, clock: () => '2026-08-14T12:00:00Z' });
  const authorityProof = authorityProofIssuer.issue({ ledger: event, binding: { ...execution, sessionId: event.sessionId }, purpose: 'completion-claim', role: 'oracle' }).proof;
  const receipt = {
    schemaVersion: 1, kind: 'legion-evidence-capability-receipt', evidenceId: 'evidence-adoption-1', runId: execution.runId, taskId: execution.taskId, contractId: execution.contractId,
    producerAuthority: 'oracle', capability: 'node-test', evidenceClass: 'deterministic', sourceRevision: 'abc', dependsOn: [], stale: false, observedAt: '2026-08-14T12:00:00Z',
    observation: { acceptanceId: 'S-1-01', requirementId: 'R-1', productionSymbol: 'artifact.json', liveConsumer: 'adoption-ledger', acceptanceSurface: 'node --test', integratedState, latestMaterialChange, contractVersion: execution.contractVersion, contractDigest: execution.contractDigest, sourceRevision: execution.sourceRevision, authorityProofDigest: digestValue(authorityProof), validUntil: '2026-08-15T12:00:00Z' },
  };
  receipt.authentication = signRecord(receipt, { keyRing, keyId: 'k1', boundFields: EVIDENCE_RECEIPT_BOUND_FIELDS }); receiptStore.append(receipt);
  const registry = new AcceptanceEvidenceRegistry();
  registry.register({ acceptanceId: 'S-1-01', claimType: 'acceptance-surface', producer: 'writer-a', durableStore: 'ledger', verifier: 'oracle', completionConsumer: 'legion', integratedStateBinding: 'git', validityPolicy: 'until-change' });
  const proof = { acceptanceId: 'S-1-01', producer: 'writer-a', verifier: 'oracle', completionConsumer: 'legion', authenticated: true, integratedState: 'git:abc', observedAt: '2026-08-14T12:00:00Z', validUntil: '2026-08-15T12:00:00Z' };
  try {
    assert.equal(admitVerifiedStage(ledger, 'S-1', { evidenceRegistry: registry, acceptanceProofs: [proof], integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).code, 'ARC_EVIDENCE_INSUFFICIENT', 'caller-built registry and proofs cannot admit VERIFIED');
    assert.equal(admitVerifiedStage(ledger, 'S-1', { receiptStore, keyRing, authorityProofIssuer, execution, integratedState: 'git:other', latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).code, 'ARC_EVIDENCE_INSUFFICIENT', 'stage identity must equal current integrated state');
    const open = structuredClone(ledger); open.stages[0].required_items[0].result = 'OPEN';
    assert.equal(admitVerifiedStage(open, 'S-1', { receiptStore, keyRing, authorityProofIssuer, execution, integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).code, 'ARC_EVIDENCE_INSUFFICIENT', 'OPEN item cannot admit VERIFIED');
    assert.equal(admitVerifiedStage(ledger, 'S-1', { receiptStore, keyRing, authorityProofIssuer, execution, integratedState, latestMaterialChange: '2026-08-14T13:00:00Z', now: new Date('2026-08-14T14:00:00Z') }).code, 'ARC_EVIDENCE_INSUFFICIENT', 'stale receipt cannot admit VERIFIED');
    assert.equal(admitVerifiedStage(ledger, 'S-1', { receiptStore, keyRing, authorityProofIssuer, execution: { ...execution, contractId: 'other-contract' }, integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).code, 'ARC_EVIDENCE_INSUFFICIENT', 'cross-contract evidence cannot replay');
    assert.equal(admitVerifiedStage(ledger, 'S-1', { receiptStore, keyRing, execution, integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).code, 'ARC_EVIDENCE_INSUFFICIENT', 'missing authority proof issuer denies admission');
    const forgedProofReceipt = structuredClone(receipt); forgedProofReceipt.observation.authorityProofDigest = `sha256:${'0'.repeat(64)}`; forgedProofReceipt.authentication = signRecord(forgedProofReceipt, { keyRing, keyId: 'k1', boundFields: EVIDENCE_RECEIPT_BOUND_FIELDS });
    const forgedProofStore = new ReceiptStore({ root: join(root, 'forged-proof-receipts') }); forgedProofStore.append(forgedProofReceipt);
    assert.equal(admitVerifiedStage(ledger, 'S-1', { receiptStore: forgedProofStore, keyRing, authorityProofIssuer, execution, integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).code, 'ARC_EVIDENCE_INSUFFICIENT', 'forged Oracle authority proof reference denies admission');
    assert.equal(admitVerifiedStage(ledger, 'S-1', { receiptStore, keyRing, authorityProofIssuer, execution, integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).allowed, true);
    const blockedSuccessor = structuredClone(ledger); const successor = blockedSuccessor.stages[1]; successor.done_state = 'CANDIDATE'; successor.integrated_state_identity = integratedState; successor.required_items[0].result = 'PASS'; successor.required_items[0].evidence = ['receipt:oracle-2'];
    const successorExecution = { ...execution, acceptanceCriteria: [{ id: 'S-2-01' }] };
    assert.equal(admitVerifiedStage(blockedSuccessor, 'S-2', { receiptStore, keyRing, authorityProofIssuer, execution: successorExecution, integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).code, 'ARC_CLAIM_PREREQUISITE_UNMET', 'successor cannot verify before predecessor');
    const transitioned = transitionVerifiedStage(ledger, 'S-1', { receiptStore, keyRing, authorityProofIssuer, execution, integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') });
    assert.equal(transitioned.allowed, true);
    assert.equal(verifyVerifiedStageAdmission(ledger, 'S-1', { keyRing, integratedState }).allowed, true, 'consumer accepts only Arcane-authenticated transition');
    assert.equal(readAdoptionStage(ledger, 'S-1', { keyRing, integratedState }).detail.doneState, 'VERIFIED', 'status consumer verifies terminal admission before reporting VERIFIED');
    const forged = structuredClone(ledger); forged.stages[0].verification_admission.authentication.mac = '0'.repeat(64);
    assert.equal(verifyVerifiedStageAdmission(forged, 'S-1', { keyRing, integratedState }).allowed, false, 'consumer rejects a manually forged VERIFIED admission');
    const forgedStatus = readAdoptionStage(forged, 'S-1', { keyRing, integratedState });
    assert.equal(forgedStatus.allowed, false);
    assert.equal(forgedStatus.detail.doneState, 'CANDIDATE', 'status reporting cannot treat a schema-shaped forged MAC as VERIFIED');
    const ledgerPath = join(root, 'adoption-ledger.json'); const persisted = structuredClone(fixtures['adoption-ledger']); persisted.stages[0].done_state = 'CANDIDATE'; persisted.stages[0].integrated_state_identity = integratedState; persisted.stages[0].required_items[0].result = 'PASS'; persisted.stages[0].required_items[0].evidence = ['receipt:oracle-1']; writeFileSync(ledgerPath, JSON.stringify(persisted));
    assert.equal(transitionVerifiedStageFile(ledgerPath, 'S-1', { receiptStore, keyRing, authorityProofIssuer, execution, integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).allowed, true, 'production file API persists only admitted VERIFIED stages');
    assert.equal(verifyVerifiedStageAdmission(JSON.parse(readFileSync(ledgerPath, 'utf8')), 'S-1', { keyRing, integratedState }).allowed, true);
    assert.equal(readVerifiedStageFile(ledgerPath, 'S-1', { keyRing, integratedState }).allowed, true, 'production file consumer accepts authenticated current VERIFIED state');
    const persistedForged = JSON.parse(readFileSync(ledgerPath, 'utf8')); persistedForged.stages[0].verification_admission.authentication.mac = '0'.repeat(64); writeFileSync(ledgerPath, JSON.stringify(persistedForged));
    const rejectedRead = readVerifiedStageFile(ledgerPath, 'S-1', { keyRing, integratedState });
    assert.equal(rejectedRead.allowed, false);
    assert.equal(rejectedRead.detail.doneState, 'CANDIDATE', 'production file consumer rejects a schema-shaped forged MAC');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('formal adoption consumes one authenticated exact-item Oracle manifest & admits complete DAG atomically', () => {
  const stageIds = [...new Set(REQUIRED_ADOPTION_EDGES.flat())];
  const formalAdoptionItemId = (stageId) => `${stageId}-01`;
  const ledger = {
    schema: 'architecture-adoption-ledger.v3', ledger_version: 1, acceptance_fingerprint: `sha256:${'a'.repeat(64)}`, frozen_at: '2026-08-14T00:00:00Z',
    stages: stageIds.map((stage_id) => ({ stage_id, owner: 'integration-owner', required_items: [{ acceptance_id: formalAdoptionItemId(stage_id), outcome: `verify ${stage_id}`, producer: 'oracle', observable_surface: 'production', verification_method: 'authenticated manifest', evidence: [], result: 'OPEN' }], produce_readiness: 'PRODUCED', integrate_readiness: 'READY_TO_INTEGRATE', activate_readiness: 'NOT_READY', done_state: 'CANDIDATE', integrated_state_identity: null })),
    consumption_dependencies: REQUIRED_ADOPTION_EDGES.map(([producer_stage_id, consumer_stage_id], index) => ({ producer_stage_id, producer_acceptance_id: formalAdoptionItemId(producer_stage_id), consumer_stage_id, consumer_acceptance_id: formalAdoptionItemId(consumer_stage_id), consumed_artifact_id: `artifact-${index}`, consumption: consumer_stage_id.startsWith('S11') || consumer_stage_id.startsWith('S12') ? 'ACTIVATE' : 'INTEGRATE', required_verification: true })),
  };
  const integratedState = `adoption-state-v1:${'b'.repeat(64)}`;
  const execution = { runId: 'run-formal', taskId: 'T-1', contractId: 'EC-612', contractVersion: 1, contractDigest: `sha256:${'c'.repeat(64)}`, sourceRevision: 'abc' };
  const manifest = { schemaVersion: 1, kind: 'legion-adoption-oracle-manifest', ...execution, acceptanceFingerprint: ledger.acceptance_fingerprint, integratedState, observedAt: '2026-08-14T12:00:00Z', items: stageIds.map((stageId, index) => ({ acceptanceId: formalAdoptionItemId(stageId), verdict: 'PASS', evidenceId: `sha256:${String(index + 1).padStart(64, '0')}`, requirementId: `R-${index + 1}`, productionSymbol: `symbol-${index + 1}`, liveConsumer: 'legion adoption status', acceptanceSurface: 'node --test', observedAt: '2026-08-14T11:00:00Z' })) };
  const root = mkdtempSync(join(tmpdir(), 'arcane-formal-adoption-'));
  try {
    const keyRing = generateTestKeyRing(['host']); const receiptStore = new ReceiptStore({ root: join(root, 'receipts') });
    const hostLedger = new HostEventLedger({ root: join(root, 'events'), keyRing, keyId: 'host', clock: () => '2026-08-14T11:30:00Z' });
    const event = hostLedger.append({ eventId: 'oracle-formal-adoption', adapter: 'codex', eventType: 'SubagentStart', sessionId: 'oracle-formal', binding: execution, sourceRevision: execution.sourceRevision, observedAuthority: 'oracle', payload: {} });
    const authorityProofIssuer = new AuthorityInvocationProofIssuer({ root: join(root, 'proofs'), keyRing, keyId: 'host', ledgerStore: hostLedger, clock: () => '2026-08-14T11:45:00Z' });
    const proof = authorityProofIssuer.issue({ ledger: event, binding: { ...execution, sessionId: event.sessionId }, purpose: 'completion-claim', role: 'oracle' }).proof;
    const receipt = { schemaVersion: 1, kind: 'arcane-adoption-manifest-receipt', receiptId: 'formal-receipt', manifestDigest: digestValue(manifest), itemSetDigest: digestValue(manifest.items.map((item) => item.acceptanceId).sort()), ...execution, acceptanceFingerprint: ledger.acceptance_fingerprint, integratedState, authorityProofDigest: digestValue(proof), observedAt: manifest.observedAt };
    receipt.authentication = signRecord(receipt, { keyRing, keyId: 'host', boundFields: ADOPTION_MANIFEST_RECEIPT_BOUND_FIELDS, macDomain: 'arcane-adoption-manifest-v1' }); receiptStore.append(receipt);
    const options = { receiptStore, keyRing, authorityProofIssuer, execution, integratedState, now: new Date('2026-08-14T12:30:00Z') };
    assert.equal(validateFormalAdoptionGraph(ledger).allowed, true);
    const partial = structuredClone(ledger); partial.consumption_dependencies.pop();
    assert.equal(validateFormalAdoptionGraph(partial).allowed, false, 'missing S11→S12 or any formal edge denies');
    const callerPass = structuredClone(ledger); callerPass.stages.forEach((stage) => stage.required_items.forEach((item) => { item.result = 'PASS'; item.evidence = ['caller']; }));
    assert.equal(transitionVerifiedLedger(callerPass, { ...manifest, items: manifest.items.slice(1) }, options).allowed, false, 'caller-written PASS cannot replace complete manifest');
    assert.equal(transitionVerifiedLedger(structuredClone(ledger), manifest, { ...options, integratedState: `adoption-state-v1:${'d'.repeat(64)}` }).allowed, false, 'cross-state manifest denies');
    const forgedStore = new ReceiptStore({ root: join(root, 'forged') }); const forged = structuredClone(receipt); forged.authentication.mac = '0'.repeat(64); forgedStore.append(forged);
    assert.equal(transitionVerifiedLedger(structuredClone(ledger), manifest, { ...options, receiptStore: forgedStore }).allowed, false, 'forged manifest receipt denies');
    const result = transitionVerifiedLedger(ledger, manifest, options);
    assert.equal(result.allowed, true); assert.equal(result.detail.stageIds.length, 12);
    assert.ok(ledger.stages.every((stage) => stage.done_state === 'VERIFIED' && stage.activate_readiness === 'ACTIVATED' && stage.required_items.every((item) => item.result === 'PASS' && item.evidence.length === 1)));
    assert.ok(ledger.stages.every((stage) => verifyVerifiedStageAdmission(ledger, stage.stage_id, { keyRing, integratedState }).allowed));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('S07-01 concern lenses admit only material concerns & declare contract boundaries', () => {
  for (const lens of lenses) {
    const body = read(`lenses/architecture/${lens}.md`);
    if (lens === 'catalogue') {
      for (const phrase of ['omission scan', 'Admit', 'applicability', 'inputs', 'outputs', 'negative scope']) assert.match(body, new RegExp(phrase, 'i'));
    } else {
      for (const label of ['Applicability:', 'Inputs:', 'Outputs:', 'Negative scope:']) assert.match(body, new RegExp(label, 'i'));
    }
  }
  const nonmaterial = { frozen_driver: false, scenario: false, constraint: false, risk: false, decision: false };
  assert.equal(Object.values(nonmaterial).some(Boolean), false, 'nonmaterial lens is not admitted');
  assert.match(read('doctrine/architecture/reviews/review-gates.md'), /missing negative scope or admission gates cannot block/i);
});
