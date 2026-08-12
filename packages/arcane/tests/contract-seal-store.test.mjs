import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { ContractSealStore } from '../lib/contract-seal-store.mjs';
import { compileAdvisoryProfile } from '../lib/advisory-profile.mjs';

const contract = () => ({ schemaVersion: 1, kind: 'legion-execution-contract', contractId: 'EC-1', version: 1, sourceRevision: 'abcdef0', objective: 'x', currentState: 'x', desiredState: 'x', requirements: [], decisions: [], invariants: [], nonGoals: [], scope: { own: [], read: [], forbidden: [] }, artifacts: { exact: [{ id: 'a', path: 'x', latitude: 'EXACT', content: 'x' }], bounded: [{ id: 'b', path: 'y', latitude: 'BOUNDED', locked: ['x'], freedom: ['y'] }] }, tasks: ['T-1'], dependencies: [], acceptanceCriteria: [], declaredChecks: [], evidenceRequirements: [], authorizedEffectClasses: [], repairLatitude: [], stopConditions: [], escalationConditions: [], rollback: [], openQuestions: [], budget: { objectiveLineageId: 'objective-1', objectiveDigest: `sha256:${'a'.repeat(64)}`, legionBlastMapCapMs: 1, sagePlanningCapMs: 1, maxContractVersions: 2 } });
const assertion = { authority: 'sage', assertedBy: 'host', verificationMethod: 'capability-signature', perMessage: true };
test('B2 seals immutably, returns idempotently, and detects changed desired state', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'seal-')); const store = new ContractSealStore({ root, clock: () => '2026-08-09T12:00:00Z' }); const first = store.seal({ contract: contract(), authorityAssertion: assertion }); const second = store.seal({ contract: contract(), authorityAssertion: { ...assertion, assertedBy: 'other' } });
  assert.equal(first.created, true); assert.equal(second.created, false); assert.equal(store.require(contract()).contractDigest, first.record.contractDigest); const changed = contract(); changed.desiredState = 'changed'; assert.throws(() => store.seal({ contract: changed, authorityAssertion: assertion }), /immutable version/); assert.deepEqual(store.verify('EC-1', 1), { ok: true, code: null, issues: [] });
});

test('advisory profile is canonical before seal persistence', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'seal-profile-'));
  const store = new ContractSealStore({ root, clock: () => '2026-08-09T12:00:00Z' });
  const canonical = contract();
  canonical.advisoryProfile = compileAdvisoryProfile({ bundleId: 'research', profileId: 'audit' });
  assert.equal(store.seal({ contract: canonical, authorityAssertion: assertion }).created, true);
  assert.deepEqual(store.require(canonical).contract.advisoryProfile, canonical.advisoryProfile);

  const forgedRoot = mkdtempSync(path.join(os.tmpdir(), 'seal-profile-forged-'));
  const forged = contract();
  forged.advisoryProfile = { ...canonical.advisoryProfile, mutationAllowed: true };
  assert.throws(() => new ContractSealStore({ root: forgedRoot }).seal({ contract: forged, authorityAssertion: assertion }), (error) => error.code === 'ARC_PROFILE_BINDING_MISMATCH');
  assert.equal(readdirSync(forgedRoot).length, 0);
});

test('B2 32-child barrier creates once, converges, and preserves conflict bytes', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'seal-race-')); const ready = path.join(root, 'ready'); const start = path.join(root, 'start'); const payload = JSON.stringify({ root, contract: contract(), authorityAssertion: assertion });
  const worker = path.join(import.meta.dirname, 'fixtures', 'contract-seal-race-worker.mjs');
  const children = Array.from({ length: 32 }, () => new Promise((resolve, reject) => { const child = spawn(process.execPath, [worker], { env: { ...process.env, ARCANE_SEAL_RACE: payload, ARCANE_SEAL_READY: ready, ARCANE_SEAL_START: start } }); let out = ''; child.stdout.on('data', (data) => { out += data; }); child.on('error', reject); child.on('exit', () => resolve(JSON.parse(out))); }));
  for (let waited = 0; !existsSync(ready) || readdirSync(ready).length !== 32; waited += 10) { if (waited > 5000) throw new Error('race barrier timeout'); await new Promise((resolve) => setTimeout(resolve, 10)); }
  writeFileSync(start, 'go'); const results = await Promise.all(children); assert.equal(results.filter((result) => result.created).length, 1); assert.equal(results.filter((result) => result.created === false).length, 31); const files = readdirSync(root).filter((file) => file.endsWith('.json')); assert.equal(files.length, 1); const sealed = readFileSync(path.join(root, files[0])); const changed = contract(); changed.desiredState = 'changed'; const conflict = await new Promise((resolve) => { const child = spawn(process.execPath, [worker], { env: { ...process.env, ARCANE_SEAL_RACE: JSON.stringify({ root, contract: changed, authorityAssertion: assertion }), ARCANE_SEAL_READY: ready, ARCANE_SEAL_START: start } }); let out = ''; child.stdout.on('data', (data) => { out += data; }); child.on('exit', () => resolve(JSON.parse(out))); }); assert.equal(conflict.error, 'ARC_CONTRACT_VERSION_MISMATCH'); assert.deepEqual(readFileSync(path.join(root, files[0])), sealed);
});
