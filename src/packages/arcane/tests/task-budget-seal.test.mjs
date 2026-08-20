import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { TaskBudgetSealStore } from '../lib/task-budget-seal-store.mjs';
import { digestValue } from '../lib/canonical.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
test('Legion or Sage task budget seals exact contract, task & scope bindings immutably', () => {
  const contract = { contractId: 'EC-1', version: 1 }; const task = { taskId: 'T-1', ownScope: ['x'], title: 'x' }; task.budgetSeal = { contractId: 'EC-1', contractVersion: 1, contractDigest: digestValue(contract), taskDigest: digestValue({ taskId: 'T-1', ownScope: ['x'], title: 'x' }), scopeDigest: digestValue(['x']), activeTimeCapMs: 10, progressDeadlineMs: 5, evidenceReferences: ['B-1'] };
  const ring = generateTestKeyRing(); const root = mkdtempSync(path.join(os.tmpdir(), 'task-budget-')); const store = new TaskBudgetSealStore({ root, keyRing: ring, clock: () => '2026-08-12T00:00:00Z' }); const assertion = { authority: 'legion', assertedBy: 'host', verificationMethod: 'capability-signature', perMessage: true };
  const sealed = store.seal({ contract, task, authorityAssertion: assertion }); assert.equal(sealed.taskId, 'T-1'); assert.equal(sealed.sealedBy.authority, 'legion'); assert.throws(() => store.seal({ contract, task, authorityAssertion: { ...assertion, authority: 'alchemist' } }), /only Legion or Sage/); const file = path.join(root, readdirSync(root)[0]); const forged = JSON.parse(readFileSync(file)); forged.activeTimeCapMs = 99; writeFileSync(file, JSON.stringify(forged)); assert.throws(() => store.require('EC-1', 'T-1', contract.version), /MAC/); task.ownScope = ['changed']; assert.throws(() => store.seal({ contract, task, authorityAssertion: assertion }), /binding mismatch/);
});
