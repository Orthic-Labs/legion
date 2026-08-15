import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { runCli } from '../lib/cli/run.mjs';
import { adoptionIntegratedState, completionIntegratedStateForRepositories } from '../packages/arcane/lib/completion-state.mjs';
import { loadHostKeyRing } from '../packages/arcane/lib/keys.mjs';
import { ReceiptStore } from '../packages/arcane/lib/receipt-store.mjs';
import { EVIDENCE_RECEIPT_BOUND_FIELDS, signRecord } from '../packages/arcane/lib/receipt-auth.mjs';
import { REQUIRED_ADOPTION_EDGES, transitionVerifiedStage } from '../packages/arcane/lib/adoption-ledger.mjs';
import { digestValue } from '../packages/arcane/lib/canonical.mjs';
import { HostEventLedger } from '../packages/arcane/lib/host-event-ledger.mjs';
import { AuthorityInvocationProofIssuer } from '../packages/arcane/lib/authority-invocation-proof.mjs';
import { SessionBindingStore } from '../packages/arcane/lib/session-binding.mjs';
import { b5Contract, seedStore } from '../packages/arcane/tests/fixtures/runtime-binding-contract.mjs';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/stage7/representative-instances.json', import.meta.url), 'utf8'))['adoption-ledger'];
const stream = () => ({ value: '', write(chunk) { this.value += chunk; } });

function initRepository(cwd) {
  mkdirSync(cwd, { recursive: true });
  execFileSync('git', ['init', '-q'], { cwd });
  execFileSync('git', ['config', 'user.email', 'test@example.invalid'], { cwd });
  execFileSync('git', ['config', 'user.name', 'Legion Test'], { cwd });
  writeFileSync(join(cwd, 'tracked.txt'), 'initial\n');
  execFileSync('git', ['add', 'tracked.txt'], { cwd }); execFileSync('git', ['commit', '-qm', 'initial'], { cwd });
}

function setup() {
  const root = mkdtempSync(join(tmpdir(), 'legion-adoption-cli-')); const cwd = join(root, 'repo-one'); const second = join(root, 'repo-two');
  initRepository(cwd); initRepository(second);
  const keyDir = join(root, 'keys'); mkdirSync(keyDir); writeFileSync(join(keyDir, 'k1.key'), randomBytes(32).toString('hex'));
  return { root, cwd, second, keyDir, ledgerPath: join(root, 'adoption-ledger.json') };
}

function verifiedLedger(repositories, keyDir, storeRoot) {
  const ledger = structuredClone(fixture); const stage = ledger.stages[0]; const integratedState = completionIntegratedStateForRepositories(repositories.map((cwd) => ({ cwd, scope: ['**/*'] })));
  stage.done_state = 'CANDIDATE'; stage.integrated_state_identity = integratedState; stage.required_items[0].result = 'PASS'; stage.required_items[0].evidence = ['receipt:oracle-1'];
  const keyRing = loadHostKeyRing({ dir: keyDir }); const receiptStore = new ReceiptStore({ root: storeRoot });
  const execution = { runId: 'run-adoption', taskId: 'task-adoption', contractId: 'contract-adoption', contractVersion: 1, contractDigest: 'sha256:contract-adoption', sourceRevision: 'abc', acceptanceCriteria: [{ id: 'S-1-01' }] };
  const latestMaterialChange = '2026-08-14T11:00:00Z';
  const hostLedger = new HostEventLedger({ root: join(storeRoot, 'events'), keyRing, keyId: 'k1', clock: () => '2026-08-14T12:00:00Z' });
  const event = hostLedger.append({ eventId: 'oracle-adoption-proof', adapter: 'codex', eventType: 'UserPromptSubmit', sessionId: 'oracle-adoption', binding: execution, sourceRevision: execution.sourceRevision, observedAuthority: 'oracle', payload: {} });
  const authorityProofIssuer = new AuthorityInvocationProofIssuer({ root: join(storeRoot, 'proofs'), keyRing, keyId: 'k1', ledgerStore: hostLedger, clock: () => '2026-08-14T12:00:00Z' });
  const authorityProof = authorityProofIssuer.issue({ ledger: event, binding: { ...execution, sessionId: event.sessionId }, purpose: 'completion-claim', role: 'oracle' }).proof;
  const receipt = { schemaVersion: 1, kind: 'legion-evidence-capability-receipt', evidenceId: 'evidence-adoption-1', runId: execution.runId, taskId: execution.taskId, contractId: execution.contractId, producerAuthority: 'oracle', capability: 'node-test', evidenceClass: 'deterministic', sourceRevision: 'abc', dependsOn: [], stale: false, observedAt: '2026-08-14T12:00:00Z', observation: { acceptanceId: 'S-1-01', requirementId: 'R-1', productionSymbol: 'tracked.txt', liveConsumer: 'legion adoption status', acceptanceSurface: 'node --test', integratedState, latestMaterialChange, contractVersion: execution.contractVersion, contractDigest: execution.contractDigest, sourceRevision: execution.sourceRevision, authorityProofDigest: digestValue(authorityProof), validUntil: '2026-08-15T12:00:00Z' } };
  receipt.authentication = signRecord(receipt, { keyRing, keyId: 'k1', boundFields: EVIDENCE_RECEIPT_BOUND_FIELDS }); receiptStore.append(receipt);
  assert.equal(transitionVerifiedStage(ledger, 'S-1', { receiptStore, keyRing, authorityProofIssuer, execution, integratedState, latestMaterialChange, now: new Date('2026-08-14T14:00:00Z') }).allowed, true);
  return ledger;
}

test('adoption status is a production authenticated consumer & fails closed for forged, untracked, stale & multi-repository VERIFIED JSON', async () => {
  const state = setup();
  try {
    const ledger = verifiedLedger([state.cwd, state.second], state.keyDir, join(state.root, 'receipts')); writeFileSync(state.ledgerPath, JSON.stringify(ledger));
    const stdout = stream(), stderr = stream();
    const args = ['adoption', 'status', '--file', state.ledgerPath, '--stage', 'S-1', '--repository', state.cwd, '--repository', state.second, '--key-dir', state.keyDir];
    const accepted = await runCli(args, { stdout, stderr, env: {}, cwd: state.cwd });
    assert.equal(accepted.exitCode, 0, stderr.value); assert.deepEqual(JSON.parse(stdout.value), { kind: 'legion-adoption-status', stageId: 'S-1', doneState: 'VERIFIED' });
    writeFileSync(join(state.cwd, 'untracked.txt'), 'untracked\n');
    const staleOut = stream(), staleErr = stream();
    const stale = await runCli(args, { stdout: staleOut, stderr: staleErr, env: {}, cwd: state.cwd });
    assert.equal(stale.exitCode, 2); assert.equal(JSON.parse(staleOut.value).doneState, 'CANDIDATE'); assert.equal(JSON.parse(staleOut.value).code, 'ARC_BINDING_MISMATCH');
    unlinkSync(join(state.cwd, 'untracked.txt'));
    writeFileSync(join(state.second, 'tracked.txt'), 'changed in second repository\n');
    const secondOut = stream(), secondErr = stream(); const second = await runCli(args, { stdout: secondOut, stderr: secondErr, env: {}, cwd: state.cwd });
    assert.equal(second.exitCode, 2); assert.equal(JSON.parse(secondOut.value).doneState, 'CANDIDATE'); assert.equal(JSON.parse(secondOut.value).code, 'ARC_BINDING_MISMATCH');
    writeFileSync(join(state.second, 'tracked.txt'), 'initial\n');
    ledger.stages[0].verification_admission.authentication.mac = '0'.repeat(64); writeFileSync(state.ledgerPath, JSON.stringify(ledger));
    const forgedOut = stream(), forgedErr = stream();
    const forged = await runCli(args, { stdout: forgedOut, stderr: forgedErr, env: {}, cwd: state.cwd });
    assert.equal(forged.exitCode, 2); const projected = JSON.parse(forgedOut.value); assert.equal(projected.doneState, 'CANDIDATE'); assert.equal(projected.code, 'ARC_BINDING_MISMATCH'); assert.equal(forgedOut.value.includes('verification_admission'), false);
    ledger.stages[0].verification_admission.authentication = {}; writeFileSync(state.ledgerPath, JSON.stringify(ledger));
    const manualOut = stream(), manualErr = stream();
    const manual = await runCli(args, { stdout: manualOut, stderr: manualErr, env: {}, cwd: state.cwd });
    assert.equal(manual.exitCode, 2); assert.equal(JSON.parse(manualOut.value).doneState, 'CANDIDATE'); assert.equal(JSON.parse(manualOut.value).code, 'ARC_SCHEMA_INVALID');
  } finally { rmSync(state.root, { recursive: true, force: true }); }
});

test('formal adoption identity ignores only derived carrier fields & unrelated root dirt', () => {
  const state = setup();
  try {
    const legion = join(state.cwd, 'legion'); initRepository(legion);
    const legionCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: legion, encoding: 'utf8' }).trim();
    execFileSync('git', ['update-index', '--add', '--cacheinfo', `160000,${legionCommit},legion`], { cwd: state.cwd });
    const ledger = structuredClone(fixture); writeFileSync(state.ledgerPath, JSON.stringify(ledger));
    const skillArchitecturePath = join(state.root, 'SKILL-ARCHITECTURE.md'); writeFileSync(skillArchitecturePath, 'canonical bundles\n');
    const s11EvidencePath = join(state.root, 's11.json'); const s11 = { result: { passed: 103 }, verification: { oracle_admission: 'OPEN' }, contract_lifecycle: { current_admission: 'OPEN' }, integrated_state: { adoption_state: 'CANDIDATE', nested_commit: legionCommit } }; writeFileSync(s11EvidencePath, JSON.stringify(s11));
    const args = { parentRepository: state.cwd, legionRepository: legion, ledgerPath: state.ledgerPath, skillArchitecturePath, s11EvidencePath };
    const baseline = adoptionIntegratedState(args); assert.match(baseline, /^adoption-state-v1:[0-9a-f]{64}$/);
    writeFileSync(join(state.cwd, 'unrelated.txt'), 'dirty carrier\n'); assert.equal(adoptionIntegratedState(args), baseline, 'unrelated root dirt is excluded');
    const carrier = structuredClone(ledger); carrier.stages[0].done_state = 'VERIFIED'; carrier.stages[0].produce_readiness = 'PRODUCED'; carrier.stages[0].integrate_readiness = 'INTEGRATED'; carrier.stages[0].activate_readiness = 'ACTIVATED'; carrier.stages[0].integrated_state_identity = baseline; carrier.stages[0].required_items[0].result = 'PASS'; carrier.stages[0].required_items[0].evidence = ['receipt']; carrier.stages[0].verification_admission = { derived: true }; writeFileSync(state.ledgerPath, JSON.stringify(carrier));
    assert.equal(adoptionIntegratedState(args), baseline, 'derived admission carrier fields are excluded');
    const substantive = structuredClone(carrier); substantive.stages[0].required_items[0].outcome += ' changed'; writeFileSync(state.ledgerPath, JSON.stringify(substantive)); assert.notEqual(adoptionIntegratedState(args), baseline, 'acceptance-definition drift invalidates state');
    writeFileSync(state.ledgerPath, JSON.stringify(carrier)); s11.verification.oracle_admission = 'VERIFIED'; s11.contract_lifecycle.current_admission = 'VERIFIED'; s11.integrated_state.adoption_state = 'VERIFIED'; writeFileSync(s11EvidencePath, JSON.stringify(s11)); assert.equal(adoptionIntegratedState(args), baseline, 'derived S11 admission status is excluded');
    s11.result.passed = 102; writeFileSync(s11EvidencePath, JSON.stringify(s11)); assert.notEqual(adoptionIntegratedState(args), baseline, 'substantive S11 drift invalidates state');
  } finally { rmSync(state.root, { recursive: true, force: true }); }
});

test('production manifest → atomic admission → twelve authenticated status reads', async () => {
  const state = setup(); const sessionId = 'oracle-formal-cli';
  try {
    const legion = join(state.cwd, 'legion'); initRepository(legion); const legionCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: legion, encoding: 'utf8' }).trim();
    execFileSync('git', ['update-index', '--add', '--cacheinfo', `160000,${legionCommit},legion`], { cwd: state.cwd });
    const stageIds = [...new Set(REQUIRED_ADOPTION_EDGES.flat())]; const formalCliItemId = (id) => `${id}-01`;
    const ledger = { schema: 'architecture-adoption-ledger.v3', ledger_version: 1, acceptance_fingerprint: `sha256:${'a'.repeat(64)}`, frozen_at: '2026-08-14T00:00:00Z', stages: stageIds.map((stage_id) => ({ stage_id, owner: 'owner', required_items: [{ acceptance_id: formalCliItemId(stage_id), outcome: stage_id, producer: 'owner', observable_surface: 'surface', verification_method: 'oracle', evidence: [], result: 'OPEN' }], produce_readiness: 'PRODUCED', integrate_readiness: 'READY_TO_INTEGRATE', activate_readiness: 'NOT_READY', done_state: 'CANDIDATE', integrated_state_identity: null })), consumption_dependencies: REQUIRED_ADOPTION_EDGES.map(([producer_stage_id, consumer_stage_id], index) => ({ producer_stage_id, producer_acceptance_id: formalCliItemId(producer_stage_id), consumer_stage_id, consumer_acceptance_id: formalCliItemId(consumer_stage_id), consumed_artifact_id: `artifact-${index}`, consumption: index >= 10 ? 'ACTIVATE' : 'INTEGRATE', required_verification: true })) };
    writeFileSync(state.ledgerPath, JSON.stringify(ledger)); const skillArchitecturePath = join(state.root, 'SKILL.md'); writeFileSync(skillArchitecturePath, 'bundles\n'); const s11EvidencePath = join(state.root, 's11.json'); writeFileSync(s11EvidencePath, JSON.stringify({ result: { passed: 103 }, verification: { oracle_admission: 'OPEN' }, contract_lifecycle: { current_admission: 'OPEN' }, integrated_state: { adoption_state: 'CANDIDATE', nested_commit: legionCommit } }));
    const contract = b5Contract(); contract.contractId = 'EC-612'; contract.sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: state.cwd, encoding: 'utf8' }).trim(); contract.scope.own = ['legion/**']; contract.acceptanceCriteria = [{ id: 'AC-4', statement: 'formal adoption' }];
    const sealed = seedStore(join(state.cwd, '.audit', 'arcane'), contract).record; const runId = 'run-formal-cli'; new SessionBindingStore({ root: join(state.cwd, '.audit', 'arcane', 'session-bindings') }).putBinding(sessionId, { runId, taskId: 'T-1', contractId: contract.contractId, contractVersion: contract.version, contractDigest: sealed.contractDigest });
    const keyRing = loadHostKeyRing({ dir: state.keyDir }); const hostLedger = new HostEventLedger({ root: join(state.cwd, '.audit', 'arcane', 'host-events'), keyRing, keyId: keyRing.activeKeyId() }); const eventTime = new Date(Date.now() - 1000).toISOString();
    hostLedger.append({ eventId: 'oracle-formal-cli-event', adapter: 'codex', eventType: 'SubagentStart', sessionId, binding: { runId, taskId: 'T-1', contractId: contract.contractId, contractVersion: contract.version, contractDigest: sealed.contractDigest }, sourceRevision: contract.sourceRevision, observedAuthority: 'oracle', payload: {} });
    const integratedState = adoptionIntegratedState({ parentRepository: state.cwd, legionRepository: legion, ledgerPath: state.ledgerPath, skillArchitecturePath, s11EvidencePath });
    const manifest = { schemaVersion: 1, kind: 'legion-adoption-oracle-manifest', runId, taskId: 'T-1', contractId: contract.contractId, contractVersion: contract.version, contractDigest: sealed.contractDigest, sourceRevision: contract.sourceRevision, acceptanceFingerprint: ledger.acceptance_fingerprint, integratedState, observedAt: eventTime, items: stageIds.map((stageId, index) => { const path = `source-${index + 1}`; const bytes = `evidence-${index + 1}\n`; writeFileSync(join(state.cwd, path), bytes); const evidence = { kind: 'oracle-adoption-item-evidence', sources: [{ path, digest: `sha256:${createHash('sha256').update(bytes).digest('hex')}` }], checks: ['production CLI fixture'] }; return { acceptanceId: formalCliItemId(stageId), verdict: 'PASS', evidence, evidenceId: digestValue(evidence), requirementId: `R-${index + 1}`, productionSymbol: `symbol-${index + 1}`, liveConsumer: 'legion adoption status', acceptanceSurface: 'node --test', observedAt: eventTime }; }) };
    const manifestPath = join(state.root, 'manifest.json'); writeFileSync(manifestPath, JSON.stringify(manifest)); const common = ['--file', manifestPath, '--ledger', state.ledgerPath, '--session', sessionId, '--key-dir', state.keyDir, '--parent-repository', state.cwd, '--legion-repository', legion, '--skill-architecture', skillArchitecturePath, '--s11-evidence', s11EvidencePath];
    const manifestOut = stream(), manifestErr = stream(); const manifested = await runCli(['adoption', 'manifest', ...common], { stdout: manifestOut, stderr: manifestErr, env: {}, cwd: state.cwd }); assert.equal(manifested.exitCode, 0, manifestErr.value); assert.equal(JSON.parse(manifestOut.value).itemCount, 12);
    const admitOut = stream(), admitErr = stream(); const admitted = await runCli(['adoption', 'admit', ...common], { stdout: admitOut, stderr: admitErr, env: {}, cwd: state.cwd }); assert.equal(admitted.exitCode, 0, admitErr.value); assert.equal(JSON.parse(admitOut.value).stageCount, 12);
    for (const stageId of stageIds) { const out = stream(), err = stream(); const result = await runCli(['adoption', 'status', '--file', state.ledgerPath, '--stage', stageId, '--key-dir', state.keyDir, '--parent-repository', state.cwd, '--legion-repository', legion, '--skill-architecture', skillArchitecturePath, '--s11-evidence', s11EvidencePath], { stdout: out, stderr: err, env: {}, cwd: state.cwd }); assert.equal(result.exitCode, 0, `${stageId}: ${err.value}`); assert.equal(JSON.parse(out.value).doneState, 'VERIFIED'); }
  } finally { rmSync(state.root, { recursive: true, force: true }); }
});
