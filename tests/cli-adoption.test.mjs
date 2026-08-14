import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { runCli } from '../lib/cli/run.mjs';
import { completionIntegratedStateForRepositories } from '../packages/arcane/lib/completion-state.mjs';
import { loadHostKeyRing } from '../packages/arcane/lib/keys.mjs';
import { ReceiptStore } from '../packages/arcane/lib/receipt-store.mjs';
import { EVIDENCE_RECEIPT_BOUND_FIELDS, signRecord } from '../packages/arcane/lib/receipt-auth.mjs';
import { transitionVerifiedStage } from '../packages/arcane/lib/adoption-ledger.mjs';
import { digestValue } from '../packages/arcane/lib/canonical.mjs';
import { HostEventLedger } from '../packages/arcane/lib/host-event-ledger.mjs';
import { AuthorityInvocationProofIssuer } from '../packages/arcane/lib/authority-invocation-proof.mjs';

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
