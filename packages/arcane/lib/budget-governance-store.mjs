import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { ArcaneError } from './errors.mjs';
import { canonicalJson, digestValue } from './canonical.mjs';
import { signRecord, verifyRecord } from './receipt-auth.mjs';
import { RuntimeSchemaSet } from './runtime-schema.mjs';
import { stateFile } from './state-paths.mjs';

const schema = new RuntimeSchemaSet();
export const BUDGET_BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'contractId', 'version', 'contractDigest', 'objectiveLineageId', 'objectiveDigest', 'legionBlastMapCapMs', 'sagePlanningCapMs', 'maxContractVersions', 'resumeEvidence']);
export const BUDGET_RESUME_BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'objectiveDigest', 'priorLineageId', 'newLineageId', 'userTurnDigest', 'sessionId', 'observedAt']);
export const EXTERNAL_WAIT_BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'runId', 'contractId', 'taskId', 'startedAtMs', 'endedAtMs', 'durationMs', 'evidenceRef', 'nonce']);
export const BUDGET_EVENT_BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'runId', 'contractId', 'version', 'taskId', 'sequence', 'predecessorDigest', 'atMs', 'event']);
export const BUDGET_RUN_BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'runId', 'contractId', 'version', 'taskId', 'activeTimeCapMs', 'progressDeadlineMs', 'startedAtMs', 'lastObservedAtMs', 'lastProgressAtMs', 'excludedWaitMs', 'retries', 'waitNonces', 'stopped', 'ledgerCount', 'ledgerDigest']);
const fail = (code, message, detail = {}) => { throw new ArcaneError(code, message, detail); };
const nowMs = () => Number(process.hrtime.bigint() / 1000000n);
const readdirSafe = (dir) => { try { return readdirSync(dir); } catch { return []; } };

export class BudgetGovernanceStore {
  #root; #keyRing; #monotonic;
  constructor({ root, keyRing, monotonicNow = nowMs } = {}) { this.#root = root; this.#keyRing = keyRing; this.#monotonic = monotonicNow; }
  #path(contractId, version) { return stateFile(this.#root, 'arcane.budget-governance.v1', [contractId, version]); }
  #runPath(runId) { return stateFile(join(this.#root, 'runs'), 'arcane.budget-run.v1', [runId]); }
  #eventDir(runId) { return join(this.#root, 'events', digestValue(runId).slice(7)); }
  #events(run) { const dir = this.#eventDir(run.runId); if (!readdirSafe(dir).length) return []; const entries = readdirSafe(dir).sort().map((file) => JSON.parse(readFileSync(join(dir, file), 'utf8'))); let predecessorDigest = null; entries.forEach((entry, index) => { const checked = verifyRecord(entry, entry.authentication, { keyRing: this.#keyRing, boundFields: BUDGET_EVENT_BOUND_FIELDS, expectedBinding: { runId: run.runId, contractId: run.contractId, taskId: run.taskId }, macDomain: 'arcane-budget-event-v1' }); if (!checked.allowed || entry.version !== run.version || entry.sequence !== index + 1 || entry.predecessorDigest !== predecessorDigest) fail('ARC_STORE_CORRUPT', 'invalid budget event chain'); predecessorDigest = digestValue(entry); }); return entries; }
  #append(run, event) { const events = this.#events(run); const record = { schemaVersion: 1, kind: 'arcane-budget-event', runId: run.runId, contractId: run.contractId, version: run.version, taskId: run.taskId, sequence: events.length + 1, predecessorDigest: events.length ? digestValue(events.at(-1)) : null, atMs: run.lastObservedAtMs, event }; record.authentication = signRecord(record, { keyRing: this.#keyRing, keyId: this.#keyRing.activeKeyId(), boundFields: BUDGET_EVENT_BOUND_FIELDS, macDomain: 'arcane-budget-event-v1' }); const dir = this.#eventDir(run.runId); mkdirSync(dir, { recursive: true }); const fd = openSync(join(dir, `${String(record.sequence).padStart(12, '0')}.json`), 'wx', 0o600); const bytes = Buffer.from(`${canonicalJson(record)}\n`); for (let offset = 0; offset < bytes.length;) offset += writeSync(fd, bytes, offset); fsyncSync(fd); closeSync(fd); run.ledgerDigest = digestValue(record); run.ledgerCount = record.sequence; }
  #persist(run) { const dir = join(this.#root, 'runs'); mkdirSync(dir, { recursive: true }); const path = this.#runPath(run.runId), tmp = `${path}.${process.pid}.tmp`; const unsigned = { schemaVersion: 1, kind: 'arcane-budget-run', ...run, retries: [...run.retries], waitNonces: [...run.waitNonces] }; const record = { ...unsigned, authentication: signRecord(unsigned, { keyRing: this.#keyRing, keyId: this.#keyRing.activeKeyId(), boundFields: BUDGET_RUN_BOUND_FIELDS, macDomain: 'arcane-budget-run-v1' }) }; const fd = openSync(tmp, 'w', 0o600); const bytes = Buffer.from(`${canonicalJson(record)}\n`); for (let offset = 0; offset < bytes.length;) offset += writeSync(fd, bytes, offset); fsyncSync(fd); closeSync(fd); renameSync(tmp, path); }
  #loadRun(runId) { const path = this.#runPath(runId); if (!existsSync(path)) return null; let saved; try { saved = JSON.parse(readFileSync(path, 'utf8')); } catch { fail('ARC_STORE_CORRUPT', 'budget run snapshot is unreadable'); } const checked = verifyRecord(saved, saved.authentication, { keyRing: this.#keyRing, boundFields: BUDGET_RUN_BOUND_FIELDS, expectedBinding: { runId }, macDomain: 'arcane-budget-run-v1' }); if (!checked.allowed) fail(checked.code, 'budget run snapshot authentication failed', checked.detail); const run = { ...saved, retries: new Set(saved.retries), waitNonces: new Set(saved.waitNonces) }; delete run.authentication; const events = this.#events(run); if (saved.ledgerCount !== events.length || (events.length ? saved.ledgerDigest !== digestValue(events.at(-1)) : saved.ledgerDigest !== null)) fail('ARC_STORE_CORRUPT', 'budget event ledger truncated'); return run; }
  #read(path) { try { const value = JSON.parse(readFileSync(path, 'utf8')); if (schema.validate('arcane-budget-governance-v1', value).length) fail('ARC_STORE_CORRUPT', 'invalid stored budget'); return value; } catch (error) { if (error instanceof ArcaneError) throw error; fail('ARC_STORE_CORRUPT', 'unreadable stored budget'); } }
  seal(budget) {
    if (schema.validate('arcane-budget-governance-v1', budget).length) fail('ARC_SCHEMA_INVALID', 'invalid budget binding');
    const authenticated = verifyRecord(budget, budget.authentication, { keyRing: this.#keyRing, boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
    if (!authenticated.allowed) fail(authenticated.code, authenticated.message, authenticated.detail);
    mkdirSync(this.#root, { recursive: true });
    const allBudgets = readdirSync(this.#root).filter((file) => file.endsWith('.json')).map((file) => this.#read(join(this.#root, file)));
    const existingVersions = allBudgets.filter((entry) => entry.objectiveLineageId === budget.objectiveLineageId);
    const priorObjective = allBudgets.filter((entry) => entry.objectiveDigest === budget.objectiveDigest && entry.objectiveLineageId !== budget.objectiveLineageId).at(-1);
    if (priorObjective) { const resume = budget.resumeEvidence; const checked = resume && verifyRecord(resume, resume.authentication, { keyRing: this.#keyRing, boundFields: BUDGET_RESUME_BOUND_FIELDS, macDomain: 'arcane-budget-resume-v1' }); if (!checked?.allowed || resume.objectiveDigest !== budget.objectiveDigest || resume.priorLineageId !== priorObjective.objectiveLineageId || resume.newLineageId !== budget.objectiveLineageId) fail('ARC_AUTHORITY_NOT_ASSERTED', 'new objective lineage requires authenticated explicit user resume evidence'); }
    const path = this.#path(budget.contractId, budget.version);
    if (existingVersions.length >= 2 && !existingVersions.some((entry) => entry.contractId === budget.contractId && entry.version === budget.version)) fail('ARC_CONTRACT_VERSION_MISMATCH', 'objective lineage exceeds two contract versions', { objectiveLineageId: budget.objectiveLineageId });
    try { const fd = openSync(path, 'wx', 0o600); const bytes = Buffer.from(`${canonicalJson(budget)}\n`); for (let offset = 0; offset < bytes.length;) offset += writeSync(fd, bytes, offset); fsyncSync(fd); closeSync(fd); } catch (error) { if (error.code !== 'EEXIST') fail('ARC_STORE_CORRUPT', 'cannot persist budget'); const existing = this.#read(path); if (digestValue(existing) !== digestValue(budget)) fail('ARC_CONTRACT_VERSION_MISMATCH', 'immutable budget conflicts'); return existing; }
    return budget;
  }
  require(contractId, version) { return this.#read(this.#path(contractId, version)); }
  begin({ contractId, version, taskId, activeTimeCapMs, progressDeadlineMs, runId = digestValue({ contractId, version, taskId }) }) { const saved = this.#loadRun(runId); if (saved) { if (saved.contractId !== contractId || saved.version !== version || saved.taskId !== taskId || saved.activeTimeCapMs !== activeTimeCapMs || saved.progressDeadlineMs !== progressDeadlineMs) fail('ARC_BINDING_MISMATCH', 'budget run binding or ceiling differs'); return saved; } const startedAtMs = this.#monotonic(); const run = { runId, contractId, version, taskId, activeTimeCapMs, progressDeadlineMs, startedAtMs, lastObservedAtMs: startedAtMs, lastProgressAtMs: startedAtMs, excludedWaitMs: 0, retries: new Set(), waitNonces: new Set(), stopped: null, ledgerCount: 0, ledgerDigest: null }; this.#persist(run); return run; }
  observe(run, { progress = false, externalWait = null, retry = null } = {}) {
    if (run.stopped) return run.stopped;
    const at = this.#monotonic();
    if (at < run.lastObservedAtMs) { run.stopped = { kind: 'BUDGET_STOP', code: 'MONOTONIC_REGRESSION', atMs: at }; this.#append(run, run.stopped); this.#persist(run); return run.stopped; }
    run.lastObservedAtMs = at;
    if (externalWait) { const checked = verifyRecord(externalWait, externalWait.authentication, { keyRing: this.#keyRing, boundFields: EXTERNAL_WAIT_BOUND_FIELDS, expectedBinding: { runId: run.runId, contractId: run.contractId, taskId: run.taskId }, macDomain: 'arcane-external-wait-v1' }); if (!checked.allowed || !Number.isInteger(externalWait.durationMs) || externalWait.durationMs < 0 || externalWait.endedAtMs - externalWait.startedAtMs !== externalWait.durationMs || !externalWait.evidenceRef || run.waitNonces.has(externalWait.nonce)) { run.stopped = { kind: 'BUDGET_STOP', code: 'INVALID_WAIT', atMs: at }; this.#append(run, run.stopped); this.#persist(run); return run.stopped; } run.waitNonces.add(externalWait.nonce); run.excludedWaitMs += externalWait.durationMs; }
    if (progress) run.lastProgressAtMs = at;
    const retryFingerprint = retry ? digestValue({ taskId: run.taskId, method: retry.method, inputState: retry.inputState, error: retry.error }) : null;
    if (retryFingerprint) { if (run.retries.has(retryFingerprint)) { run.stopped = { kind: 'BUDGET_STOP', code: 'IDENTICAL_RETRY', atMs: at }; this.#append(run, run.stopped); this.#persist(run); return run.stopped; } run.retries.add(retryFingerprint); }
    const activeMs = at - run.startedAtMs - run.excludedWaitMs;
    if (activeMs > run.activeTimeCapMs) run.stopped = { kind: 'BUDGET_STOP', code: 'ACTIVE_CAP', atMs: at, activeMs };
    else if (at - run.lastProgressAtMs > run.progressDeadlineMs) run.stopped = { kind: 'BUDGET_STOP', code: 'PROGRESS_DEADLINE', atMs: at };
    const result = run.stopped ?? { kind: 'BUDGET_OK', activeMs }; this.#append(run, result); this.#persist(run); return result;
  }
  inspect({ contractId, version, taskId, runId = digestValue({ contractId, version, taskId }) }) { const run = this.#loadRun(runId); if (!run || run.contractId !== contractId || run.version !== version || run.taskId !== taskId) fail('ARC_BINDING_MISMATCH', 'budget run is unavailable or bound elsewhere'); return Object.freeze({ allowed: run.stopped === null, code: run.stopped?.code ?? null, stopped: run.stopped, events: Object.freeze(this.#events(run).map((event) => Object.freeze({ ...event }))) }); }
}
