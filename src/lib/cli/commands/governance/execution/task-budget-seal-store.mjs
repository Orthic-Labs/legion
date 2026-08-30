import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs';
import { ArcaneError } from '../../../../contracts/arcane/errors.mjs';
import { canonicalJson, digestValue } from '../../../../contracts/arcane/canonical.mjs';
import { RuntimeSchemaSet } from '../../../../contracts/arcane/runtime-schema.mjs';
import { stateFile } from '../../../../contracts/arcane/state-paths.mjs';
import { signRecord, verifyRecord } from '../../../../guard/compat/audit/receipt-auth.mjs';
const schema = new RuntimeSchemaSet();
export const TASK_BUDGET_SEAL_BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'contractId', 'contractVersion', 'contractDigest', 'taskId', 'taskDigest', 'scopeDigest', 'activeTimeCapMs', 'progressDeadlineMs', 'evidenceReferences', 'sealedBy', 'sealedAt']);
const fail = (code, message, detail = {}) => { throw new ArcaneError(code, message, detail); };
export class TaskBudgetSealStore {
  #root; #clock; #keyRing; #keyId;
  constructor({ root, keyRing, keyId = keyRing?.activeKeyId(), clock = () => new Date().toISOString() } = {}) { this.#root = root; this.#clock = clock; this.#keyRing = keyRing; this.#keyId = keyId; }
  #path(contractId, taskId, contractVersion) { return stateFile(this.#root, 'arcane.task-budget-seal.v1', [contractId, taskId, String(contractVersion)]); }
  #read(path) { try { const value = JSON.parse(readFileSync(path, 'utf8')); if (schema.validate('arcane-task-budget-seal-v1', value).length) fail('ARC_STORE_CORRUPT', 'invalid task budget seal'); return value; } catch (error) { if (error instanceof ArcaneError) throw error; fail('ARC_STORE_CORRUPT', 'unreadable task budget seal'); } }
  seal({ contract, task, authorityAssertion }) {
    if (!authorityAssertion || !['legion', 'sage'].includes(authorityAssertion.authority) || authorityAssertion.verificationMethod !== 'capability-signature' || authorityAssertion.perMessage !== true || !authorityAssertion.assertedBy) fail('ARC_SCHEMA_INVALID', 'only Legion or Sage may seal a task budget');
    const budget = task.budgetSeal; if (!budget || budget.contractId !== contract.contractId || budget.contractVersion !== contract.version || budget.contractDigest !== digestValue(contract)) fail('ARC_BINDING_MISMATCH', 'task budget contract binding mismatch');
    const { budgetSeal: _budgetSeal, ...unsignedTask } = task;
    if (budget.taskDigest !== digestValue(unsignedTask) || budget.scopeDigest !== digestValue(task.ownScope)) fail('ARC_BINDING_MISMATCH', 'task budget task or scope binding mismatch');
    const record = { schemaVersion: 1, kind: 'arcane-task-budget-seal', ...budget, taskId: task.taskId, sealedBy: { authority: authorityAssertion.authority, assertedBy: authorityAssertion.assertedBy, verificationMethod: 'capability-signature', perMessage: true }, sealedAt: this.#clock() };
    record.authentication = signRecord(record, { keyRing: this.#keyRing, keyId: this.#keyId, boundFields: TASK_BUDGET_SEAL_BOUND_FIELDS, macDomain: 'arcane-task-budget-seal-v1' });
    if (schema.validate('arcane-task-budget-seal-v1', record).length) fail('ARC_SCHEMA_INVALID', 'invalid task budget seal');
    const path = this.#path(record.contractId, record.taskId, record.contractVersion); mkdirSync(this.#root, { recursive: true });
    try { const fd = openSync(path, 'wx', 0o600); const bytes = Buffer.from(`${canonicalJson(record)}\n`); for (let offset = 0; offset < bytes.length;) offset += writeSync(fd, bytes, offset); fsyncSync(fd); closeSync(fd); return record; } catch (error) { if (error.code !== 'EEXIST') fail('ARC_STORE_CORRUPT', 'cannot persist task budget seal'); const existing = this.#read(path); if (digestValue(existing) !== digestValue(record)) fail('ARC_CONTRACT_VERSION_MISMATCH', 'immutable task budget seal conflicts'); return existing; }
  }
  require(contractId, taskId, contractVersion) { const record = this.#read(this.#path(contractId, taskId, contractVersion)); const checked = verifyRecord(record, record.authentication, { keyRing: this.#keyRing, boundFields: TASK_BUDGET_SEAL_BOUND_FIELDS, macDomain: 'arcane-task-budget-seal-v1' }); if (!checked.allowed) fail(checked.code, checked.message, checked.detail); return record; }
}
