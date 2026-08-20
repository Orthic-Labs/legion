// EC-5 item 3 — `legion run open|close`: the missing writer H-11 named.
//
// A sealed executable contract needs runtime binding. `open` records
// "run R executes contract C for session S" as machine state & binds current session (self-healing via
// `ensureBinding` if SessionStart never fired) to a contract/task; `close`
// clears the contract/task but keeps the runId — the session reverts to
// ambient, the run continues, it is simply no longer authorized against a
// specific contract.
//
// Session id resolution (verified, not assumed — see the escalation this
// closes): `--session <id>` first (deterministic channel for tests and
// callers that already know their session id), then environment fallback.
// `CLAUDE_CODE_SESSION_ID` is the ONLY name confirmed against a live process
// environment (this machine, Claude Code Desktop/Agent SDK session,
// 2026-08-09 — `CLAUDE_SESSION_ID` and `CODEX_SESSION_ID` were both unset in
// that same environment). The other two names are kept as fallbacks, not
// removed: they are predecessor-hook implementation detail
// (`process.env.CODEX_SESSION_ID ?? process.env.CLAUDE_SESSION_ID`) and
// Codex's live environment has never actually been observed by this
// codebase, so dropping them would trade one unverified assumption for
// another. If none resolve, this fails closed with `ARC_SESSION_UNKNOWN` —
// never a guessed session.

import { parseArgs } from 'node:util';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';

import { EXIT, LegionError } from '../../errors.mjs';
import { isId } from '../../../packages/arcane/lib/ids.mjs';
import { SessionBindingStore } from '../../../packages/arcane/lib/session-binding.mjs';
import { ContractSealStore } from '../../../packages/arcane/lib/contract-seal-store.mjs';
import { ContractLifecycle } from '../../../packages/arcane/lib/contract-lifecycle.mjs';
import { loadHostKeyRing } from '../../../packages/arcane/lib/keys.mjs';
import { ReceiptStore } from '../../../packages/arcane/lib/receipt-store.mjs';
import { evaluateCompletion } from '../../../packages/arcane/lib/completion-gate.mjs';
import { loadPolicy, PolicyEngine } from '../../../packages/arcane/lib/policy.mjs';
import { authoritiesAbsent, finalizeClose, openDelivery, prepareClose, validateDeliveryAuthority, validateDeliveryReuse } from '../../../packages/arcane/lib/delivery-guard.mjs';
import { BudgetGovernanceStore } from '../../../packages/arcane/lib/budget-governance-store.mjs';
import { TaskBudgetSealStore } from '../../../packages/arcane/lib/task-budget-seal-store.mjs';
import { completionIntegratedStateForRepositories, latestScopedMaterialChange } from '../../../packages/arcane/lib/completion-state.mjs';
import { HostEventLedger } from '../../../packages/arcane/lib/host-event-ledger.mjs';
import { AuthorityInvocationProofIssuer } from '../../../packages/arcane/lib/authority-invocation-proof.mjs';

/** Workspace-relative, matching lib/session-binding.mjs's own contract
 * (`<workspace>/.audit/arcane/session-bindings/`) — bindings are per-checkout
 * + session, unlike host-identity keys. */
function bindingRoot(cwd) {
  return join(cwd, '.audit', 'arcane', 'session-bindings');
}

function receiptRoot(cwd) {
  return join(cwd, '.audit', 'arcane', 'receipts');
}
function completionRepositories(cwd, delivery, scope) {
  const roots = delivery?.repositories?.map((repo) => repo.root).filter(Boolean);
  return (roots?.length ? roots : [cwd]).map((root) => ({ cwd: root, scope }));
}
function latestCompletionChange(receiptStore, runId, repositories) {
  return repositories.map(({ cwd, scope }) => latestScopedMaterialChange(receiptStore, runId, scope, cwd)).filter(Boolean).sort().at(-1) ?? null;
}
function budgetRoot(cwd) { return join(cwd, '.audit', 'arcane', 'budget-governance'); }
function taskBudgetRoot(cwd) { return join(cwd, '.audit', 'arcane', 'task-budget-seals'); }
function requireExactTaskBudget({ cwd, env, contract, version, task, digest }) {
  if (!task) throw new LegionError('ARC_BINDING_MISMATCH: contracted run requires a task budget', { code: 'ARC_BINDING_MISMATCH', exitCode: EXIT.INCOMPLETE });
  if (!env.ARCANE_KEY_DIR) throw new LegionError('ARC_AUTH_KEY_UNAVAILABLE: run budget verification requires ARCANE_KEY_DIR', { code: 'ARC_AUTH_KEY_UNAVAILABLE', exitCode: EXIT.INCOMPLETE });
  try {
    const keyRing = loadHostKeyRing({ dir: env.ARCANE_KEY_DIR });
    const budget = new BudgetGovernanceStore({ root: budgetRoot(cwd), keyRing }).require(contract, version);
    const taskSeal = new TaskBudgetSealStore({ root: taskBudgetRoot(cwd), keyRing }).require(contract, task, version);
    if (budget.contractDigest !== digest || taskSeal.contractVersion !== version || taskSeal.contractDigest !== digest || taskSeal.contractId !== contract) throw new LegionError('ARC_BINDING_MISMATCH: budget does not exactly bind this contract', { code: 'ARC_BINDING_MISMATCH', exitCode: EXIT.INCOMPLETE });
    return { budget, taskSeal, store: new BudgetGovernanceStore({ root: budgetRoot(cwd), keyRing }) };
  } catch (error) {
    if (error instanceof LegionError) throw error;
    throw new LegionError(`${error.code ?? 'ARC_STORE_CORRUPT'}: exact budget evidence unavailable`, { code: error.code ?? 'ARC_STORE_CORRUPT', exitCode: EXIT.INCOMPLETE });
  }
}
function requireGreenBudget(store, { contract, version, task, runId }) {
  if (typeof store.inspect !== 'function') return;
  const status = store.inspect({ contractId: contract, version, taskId: task, runId });
  if (status?.allowed === false || status?.stopped) throw new LegionError(`run blocked by budget stop: ${status?.code ?? status?.stopped?.code ?? 'BUDGET_STOP'}`, { code: status?.code ?? status?.stopped?.code ?? 'BUDGET_STOP', exitCode: EXIT.INCOMPLETE });
}
function beginBudget(store, taskSeal, { contract, version, task, runId }) {
  try {
    return store.begin({ contractId: contract, version, taskId: task, runId, activeTimeCapMs: taskSeal.activeTimeCapMs, progressDeadlineMs: taskSeal.progressDeadlineMs });
  } catch (error) {
    throw new LegionError(`${error.code ?? 'ARC_STORE_CORRUPT'}: budget run cannot open`, { code: error.code ?? 'ARC_STORE_CORRUPT', exitCode: EXIT.INCOMPLETE });
  }
}

function manifestPath(cwd, owner) { return join(cwd, '.audit', 'arcane', 'delivery', 'manifests', `${createHash('sha256').update(`${owner.sessionId}\0${owner.runId}\0${owner.taskId}`).digest('hex')}.json`); }
function manifestRepos(delivery) { return delivery.repositories.map((repo) => { const { reused, ...value } = repo; return value; }).sort((a, b) => a.commonDir.localeCompare(b.commonDir)); }
function manifestDigest(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
function bindManifest(cwd, owner, delivery) {
  const path = manifestPath(cwd, owner); mkdirSync(join(cwd, '.audit', 'arcane', 'delivery', 'manifests'), { recursive: true });
  const expected = { owner, repositories: manifestRepos(delivery) };
  if (existsSync(path)) {
    const existing = JSON.parse(readFileSync(path, 'utf8'));
    if (JSON.stringify({ owner: existing.owner, repositories: existing.repositories }) !== JSON.stringify(expected)) throw Object.assign(new Error('delivery manifest owner or repositories differ'), { code: 'ARC_INTEGRATION_OWNER_CONFLICT' });
    delivery.manifest = { token: existing.token, digest: manifestDigest(existing) }; return delivery;
  }
  const record = { ...expected, token: randomBytes(32).toString('hex') };
  writeFileSync(path, JSON.stringify(record), { encoding: 'utf8', flag: 'wx' }); delivery.manifest = { token: record.token, digest: manifestDigest(record) }; return delivery;
}
function validateManifest(cwd, owner, delivery, { recovery = false } = {}) {
  const path = manifestPath(cwd, owner);
  if (!existsSync(path)) { if (recovery && authoritiesAbsent(delivery)) return delivery; throw Object.assign(new Error('delivery manifest is missing while authority remains'), { code: 'ARC_DELIVERY_METADATA_MISSING' }); }
  const record = JSON.parse(readFileSync(path, 'utf8'));
  if (JSON.stringify({ owner: record.owner, repositories: record.repositories }) !== JSON.stringify({ owner, repositories: manifestRepos(delivery) }) || record.token !== delivery.manifest?.token || manifestDigest(record) !== delivery.manifest?.digest) throw Object.assign(new Error('delivery manifest differs from routing binding'), { code: 'ARC_DELIVERY_METADATA_MISMATCH' });
  return delivery;
}
function removeManifest(cwd, owner, delivery, { recovery = false } = {}) { validateManifest(cwd, owner, delivery, { recovery }); const path = manifestPath(cwd, owner); if (existsSync(path)) unlinkSync(path); }

export function resolveRunSessionId(explicitSession, env) {
  if (typeof explicitSession === 'string' && explicitSession.length > 0) return explicitSession;
  return env.CODEX_THREAD_ID || env.CLAUDE_CODE_SESSION_ID || env.CLAUDE_SESSION_ID || env.CODEX_SESSION_ID || null;
}

function sessionUnknownError() {
  return new LegionError(
    'ARC_SESSION_UNKNOWN: no session id available (checked --session, then CODEX_THREAD_ID, CLAUDE_CODE_SESSION_ID, CLAUDE_SESSION_ID, CODEX_SESSION_ID) — never guessed',
    { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.USAGE },
  );
}

export async function runRun(argv, { stdout, stderr, env, cwd, receiptStoreFactory = ({ root }) => new ReceiptStore({ root }) }) {
  const [sub, ...rest] = argv;
  if (sub === 'open') return runOpen(rest, { stdout, env, cwd });
  if (sub === 'close') return runClose(rest, { stdout, env, cwd, receiptStoreFactory });
  if (sub === 'suspend' || sub === 'supersede' || sub === 'repair') return runLifecycle(sub, rest, { stdout, env, cwd });
  throw new LegionError(`run requires a subcommand: open|close|suspend|supersede|repair (got ${sub ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
}

function lifecycleError(error) {
  if (error instanceof LegionError) throw error;
  const code = error?.code ?? 'ARC_DELIVERY_FAILED';
  throw new LegionError(`${code}: ${error.message}`, { code, exitCode: code.startsWith('ARC_AUTH') || code.startsWith('ARC_REPLAY') || code === 'ARC_BINDING_MISMATCH' ? EXIT.INTEGRITY : EXIT.INCOMPLETE });
}
function runLifecycle(action, argv, { stdout, env, cwd }) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, allowPositionals: false, strict: true, options: {
      session: { type: 'string' }, transaction: { type: 'string' }, contract: { type: 'string' }, version: { type: 'string' }, task: { type: 'string' },
    } });
  } catch (error) { throw new LegionError(error.message, { code: 'USAGE', exitCode: EXIT.USAGE }); }
  const sessionId = resolveRunSessionId(parsed.values.session ?? null, env);
  if (!sessionId) throw sessionUnknownError();
  try {
    const keyDir = env.ARCANE_KEY_DIR;
    if (!keyDir) throw Object.assign(new Error('ARCANE_KEY_DIR is required for authenticated lifecycle transition'), { code: 'ARC_AUTH_KEY_UNAVAILABLE' });
    const keyRing = loadHostKeyRing({ dir: keyDir });
    const lifecycle = new ContractLifecycle({
      root: join(cwd, '.audit', 'arcane', 'contract-transitions'),
      bindingStore: new SessionBindingStore({ root: bindingRoot(cwd) }),
      sealStore: new ContractSealStore({ root: join(cwd, '.audit', 'arcane', 'contract-seals') }),
      keyRing, keyId: env.ARCANE_KEY_ID ?? keyRing.activeKeyId(),
    });
    let receipt;
    if (action === 'repair') receipt = lifecycle.repair({ sessionId });
    else {
      const transactionId = parsed.values.transaction;
      if (!transactionId) throw new LegionError(`run ${action} requires --transaction <id>`, { code: 'USAGE', exitCode: EXIT.USAGE });
      let target = null;
      if (action === 'supersede') {
        const contractId = parsed.values.contract, version = Number(parsed.values.version);
        if (!contractId || !Number.isInteger(version) || version < 1) throw new LegionError('run supersede requires --contract <EC-#> --version <positive integer>', { code: 'USAGE', exitCode: EXIT.USAGE });
        const seal = new ContractSealStore({ root: join(cwd, '.audit', 'arcane', 'contract-seals') }).get(contractId, version);
        let head; try { head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim(); } catch { throw new LegionError('run supersede cannot verify current source revision', { code: 'ARC_SOURCE_UNAVAILABLE', exitCode: EXIT.INCOMPLETE }); }
        if (!seal || seal.sourceRevision !== head) throw new LegionError('ARC_CONTRACT_SOURCE_STALE: supersede target seal differs from current HEAD', { code: 'ARC_CONTRACT_SOURCE_STALE', exitCode: EXIT.INCOMPLETE });
        target = { contractId, version, taskId: parsed.values.task ?? null };
      }
      receipt = lifecycle.transition({ action, sessionId, transactionId, target });
    }
    stdout.write(`${JSON.stringify({ kind: 'legion-contract-transition', receipt })}\n`);
    return { exitCode: EXIT.PASS };
  } catch (error) { lifecycleError(error); }
}

function runOpen(argv, { stdout, env, cwd }) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: false,
      strict: true,
      options: {
        contract: { type: 'string' },
        version: { type: 'string' },
        task: { type: 'string' },
        session: { type: 'string' },
        adapter: { type: 'string' },
        repo: { type: 'string', multiple: true },
        'read-only': { type: 'boolean' },
      },
    });
  } catch (err) {
    throw new LegionError(err.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const { contract = null, task = null, session = null, version = null, repo = [], adapter = 'claude-code', 'read-only': readOnly = false } = parsed.values;
  if (!contract || !isId('executionContract', contract)) {
    throw new LegionError(`run open requires --contract <EC-#> (got ${contract ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  if (!/^\d+$/.test(version || '') || Number(version) < 1) throw new LegionError('run open requires --version <positive integer>', { code: 'USAGE', exitCode: EXIT.USAGE });
  if (task !== null && !isId('executionTask', task)) {
    throw new LegionError(`run open --task must match T-#(.#)* (got ${task})`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const sessionId = resolveRunSessionId(session, env);
  if (!sessionId) throw sessionUnknownError();

  const seal = new ContractSealStore({ root: join(cwd, '.audit', 'arcane', 'contract-seals') }).get(contract, Number(version));
  if (!seal) throw new LegionError('run open requires an exact sealed contract version', { code: 'ARC_NO_CONTRACT', exitCode: EXIT.USAGE });
  let head = null;
  try { head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim(); } catch { throw new LegionError('run open cannot verify current source revision', { code: 'ARC_SOURCE_UNAVAILABLE', exitCode: EXIT.INCOMPLETE }); }
  if (seal.sourceRevision !== head) throw new LegionError('ARC_CONTRACT_SOURCE_STALE: sealed contract sourceRevision differs from current HEAD', { code: 'ARC_CONTRACT_SOURCE_STALE', exitCode: EXIT.INCOMPLETE });
  if (!['claude-code', 'codex'].includes(adapter)) throw new LegionError(`run open unknown adapter '${adapter}'`, { code: 'USAGE', exitCode: EXIT.USAGE });
  if (adapter === 'codex') {
    if (!env.ARCANE_KEY_DIR) throw new LegionError('ARC_AUTH_KEY_UNAVAILABLE: Codex run open requires ARCANE_KEY_DIR', { code: 'ARC_AUTH_KEY_UNAVAILABLE', exitCode: EXIT.INTERNAL_ERROR });
    let keyRing;
    try { keyRing = loadHostKeyRing({ dir: env.ARCANE_KEY_DIR }); } catch { throw new LegionError('ARC_AUTH_KEY_UNAVAILABLE: Codex run open host key unavailable', { code: 'ARC_AUTH_KEY_UNAVAILABLE', exitCode: EXIT.INTERNAL_ERROR }); }
    const ledger = new HostEventLedger({ root: join(cwd, '.audit', 'arcane', 'host-events'), keyRing, keyId: keyRing.activeKeyId() });
    const continuity = ledger.verify();
    const current = continuity.allowed
      ? ledger.records().filter((event) => event.adapter === adapter && event.sessionId === sessionId && ['SessionStart', 'SubagentStart'].includes(event.eventType) && ['legion', 'sage'].includes(event.observedAuthority)).at(-1)
      : null;
    if (!current) throw new LegionError('ARC_AUTHORITY_NOT_ASSERTED: current observed Codex Legion or Sage host event required', { code: 'ARC_AUTHORITY_NOT_ASSERTED', exitCode: EXIT.INTERNAL_ERROR });
  }
  const exactBudget = requireExactTaskBudget({ cwd, env, contract, version: seal.version, task, digest: seal.contractDigest });
  // Source preflight is intentionally before even ambient binding creation.
  const store = new SessionBindingStore({ root: bindingRoot(cwd) });
  const ensured = store.ensureBinding(sessionId);
  if (!ensured) {
    throw new LegionError('run open: session binding store is unavailable', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
  }
  if (ensured.delivery && (ensured.taskId !== task || ensured.contractId !== contract || ensured.contractVersion !== seal.version || ensured.contractDigest !== seal.contractDigest)) {
    throw new LegionError('ARC_INTEGRATION_OWNER_CONFLICT: active delivery belongs to another contract/task', { code: 'ARC_INTEGRATION_OWNER_CONFLICT', exitCode: EXIT.INCOMPLETE });
  }
  beginBudget(exactBudget.store, exactBudget.taskSeal, { contract, version: seal.version, task, runId: ensured.runId });
  let delivery;
  const owner = { sessionId, runId: ensured.runId, taskId: task };
  try { delivery = ensured.delivery ? validateDeliveryReuse({ delivery: ensured.delivery, repositories: repo, readOnly, owner, cwd }) : openDelivery({ repositories: repo, readOnly, owner, cwd }); delivery = bindManifest(cwd, owner, delivery); }
  catch (error) { throw new LegionError(error.message, { code: error.code ?? 'ARC_DELIVERY_FAILED', exitCode: EXIT.INCOMPLETE }); }
  const upgraded = store.putBinding(sessionId, { runId: ensured.runId, taskId: task, contractId: contract, contractVersion: seal.version, contractDigest: seal.contractDigest, delivery });
  if (!upgraded) {
    try { finalizeClose(delivery, { owner }); } catch {}
    throw new LegionError('run open: failed to persist the contract/task binding', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
  }

  stdout.write(`${JSON.stringify({ kind: 'legion-run-binding', sessionId, ...upgraded })}\n`);
  return { exitCode: EXIT.PASS };
}

function runClose(argv, { stdout, env, cwd, receiptStoreFactory }) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, allowPositionals: false, strict: true, options: { session: { type: 'string' }, disposition: { type: 'string' } } });
  } catch (err) {
    throw new LegionError(err.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const sessionId = resolveRunSessionId(parsed.values.session ?? null, env);
  if (!sessionId) throw sessionUnknownError();

  const store = new SessionBindingStore({ root: bindingRoot(cwd) });
  // close never mints — only an ALREADY-bound session has anything to clear.
  const existing = store.getBinding(sessionId);
  if (!existing) {
    throw new LegionError('run close: no binding exists for this session — nothing to close', { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  if (existing.lifecycle?.state === 'suspended') {
    throw new LegionError('run close: suspended binding requires lifecycle repair or supersede before release', { code: 'ARC_BINDING_MISMATCH', exitCode: EXIT.INCOMPLETE });
  }
  const disposition = parsed.values.disposition ?? 'complete';
  if (!['complete', 'archive'].includes(disposition)) throw new LegionError('run close --disposition must be complete or archive', { code: 'USAGE', exitCode: EXIT.USAGE });
  if (existing.contractId && !existing.delivery) {
    throw new LegionError('ARC_DELIVERY_METADATA_MISSING: contracted binding lacks delivery metadata', { code: 'ARC_DELIVERY_METADATA_MISSING', exitCode: EXIT.INCOMPLETE });
  }

  const receiptStore = receiptStoreFactory({ root: receiptRoot(cwd) });
  const exactBudget = existing.contractId ? requireExactTaskBudget({ cwd, env, contract: existing.contractId, version: existing.contractVersion, task: existing.taskId, digest: existing.contractDigest }) : null;
  if (exactBudget) requireGreenBudget(exactBudget.store, { contract: existing.contractId, version: existing.contractVersion, task: existing.taskId, runId: existing.runId });
  const priorReceipts = receiptStore.list({ runId: existing.runId });
  const touchedPaths = [...new Set(priorReceipts.flatMap((record) => Array.isArray(record.targets) ? record.targets : []))];
  const seal = existing.contractId ? new ContractSealStore({ root: join(cwd, '.audit', 'arcane', 'contract-seals') }).get(existing.contractId, existing.contractVersion) : null;
  const completion = disposition === 'complete'
    ? (() => { const keyRing = env.ARCANE_KEY_DIR ? loadHostKeyRing({ dir: env.ARCANE_KEY_DIR }) : null; const ledger = keyRing ? new HostEventLedger({ root: join(cwd, '.audit', 'arcane', 'host-events'), keyRing, keyId: keyRing.activeKeyId() }) : null; const authorityProofIssuer = keyRing && ledger ? new AuthorityInvocationProofIssuer({ root: join(cwd, '.audit', 'arcane', 'authority-invocations'), keyRing, keyId: keyRing.activeKeyId(), ledgerStore: ledger }) : null; return evaluateCompletion({ runId: existing.runId, taskId: existing.taskId, claimedLevel: 'signoff', touchedPaths, contractId: existing.contractId, contractVersion: existing.contractVersion, contractDigest: existing.contractDigest, sourceRevision: seal?.sourceRevision ?? null }, { policy: new PolicyEngine(loadPolicy()), receiptStore, budgetStore: exactBudget?.store ?? null, keyRing, authorityProofIssuer, execution: seal ? { runId: existing.runId, taskId: existing.taskId, contractId: existing.contractId, contractVersion: existing.contractVersion, contractDigest: existing.contractDigest, sourceRevision: seal.sourceRevision, acceptanceCriteria: seal.contract.acceptanceCriteria } : null, requireAcceptanceEvidence: true, integratedState: seal ? completionIntegratedStateForRepositories(completionRepositories(cwd, existing.delivery, seal.contract.scope.own)) : null, latestMaterialChange: seal ? latestCompletionChange(receiptStore, existing.runId, completionRepositories(cwd, existing.delivery, seal.contract.scope.own)) : null }); })()
    : { allowed: true, code: 'ARC_ARCHIVE', enforcementHealth: 'not-applicable' };
  const expectedDelivery = (existing.delivery?.repositories ?? []).map((repo) => ({ repository: repo.root, baselineTree: repo.snapshotTree, leaseToken: repo.leaseToken ?? null }));
  const recovered = priorReceipts.find((receipt) => receipt.kind === 'legion-run-close-receipt'
    && receipt.sessionId === sessionId && receipt.runId === existing.runId && receipt.contractId === existing.contractId
    && receipt.contractVersion === existing.contractVersion && receipt.contractDigest === existing.contractDigest
    && receipt.deliveryDisposition === disposition && JSON.stringify(receipt.deliveryEvidence ?? []) === JSON.stringify(expectedDelivery));
  // A terminal receipt can recover a crash after its own persistence, but it
  // never freezes a completion decision. Revalidate current state/evidence
  // before releasing any still-live delivery authority.
  if (!completion.allowed) throw new LegionError(`run close blocked by completion gate: ${completion.code}`, { code: completion.code ?? 'ARC_COMPLETION_BLOCKED', exitCode: EXIT.INCOMPLETE });
  if (recovered) {
    try { if (existing.delivery) { const owner = { sessionId, runId: existing.runId, taskId: existing.taskId }; finalizeClose(validateDeliveryAuthority(validateManifest(cwd, owner, existing.delivery, { recovery: true }), { recovery: true, owner }), { recovery: true, owner }); removeManifest(cwd, owner, existing.delivery, { recovery: true }); } } catch (error) { throw new LegionError(error.message, { code: error.code ?? 'ARC_DELIVERY_FAILED', exitCode: EXIT.INCOMPLETE }); }
    const cleared = store.putBinding(sessionId, { runId: existing.runId, taskId: null, contractId: null, contractVersion: null, contractDigest: null, delivery: null, lifecycle: null });
    if (!cleared) throw new LegionError('run close: failed to persist the cleared binding', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
    stdout.write(`${JSON.stringify({ kind: 'legion-run-binding', sessionId, ...cleared, closeReceipt: recovered })}\n`);
    return { exitCode: EXIT.PASS };
  }
  if (priorReceipts.some((receipt) => receipt.kind === 'legion-run-close-receipt' && receipt.sessionId === sessionId && receipt.runId === existing.runId
    && receipt.contractId === existing.contractId && receipt.contractVersion === existing.contractVersion && receipt.contractDigest === existing.contractDigest
    && receipt.deliveryDisposition === disposition)) {
    throw new LegionError('run close: terminal receipt does not authenticate this binding', { code: 'ARC_DELIVERY_RECOVERY_MISMATCH', exitCode: EXIT.INCOMPLETE });
  }
  let deliveryReceipts = [];
  const closeOwner = { sessionId, runId: existing.runId, taskId: existing.taskId };
  try { if (existing.delivery) deliveryReceipts = prepareClose(validateDeliveryAuthority(validateManifest(cwd, closeOwner, existing.delivery), { owner: closeOwner }), disposition, { owner: closeOwner }); }
  catch (error) { throw new LegionError(error.message, { code: error.code ?? 'ARC_DELIVERY_FAILED', exitCode: EXIT.INCOMPLETE }); }
  const closeReceipt = {
    schemaVersion: 1,
    kind: 'legion-run-close-receipt',
    runId: existing.runId,
    taskId: existing.taskId,
    contractId: existing.contractId,
    contractVersion: existing.contractVersion,
    contractDigest: existing.contractDigest,
    sessionId,
    finalClaimState: 'passed',
    completionCode: completion.code,
    enforcementHealth: completion.enforcementHealth,
    deliveryDisposition: disposition,
    deliveryEvidence: expectedDelivery,
    closedAt: new Date().toISOString(),
  };
  try { for (const receipt of deliveryReceipts) {
    const deliveryRecord = { schemaVersion: 1, kind: 'arcane-delivery-receipt', sessionId, runId: existing.runId, taskId: existing.taskId, contractId: existing.contractId, contractVersion: existing.contractVersion, contractDigest: existing.contractDigest, ...receipt };
    const transactionKeys = ['sessionId', 'runId', 'taskId', 'contractId', 'contractVersion', 'contractDigest', 'disposition', 'repository', 'baselineTree', 'closeTree', 'leaseToken', 'state', 'reachable', 'parentPinned'];
    if (!priorReceipts.some((prior) => prior.kind === deliveryRecord.kind && transactionKeys.every((key) => JSON.stringify(prior[key]) === JSON.stringify(deliveryRecord[key])) && JSON.stringify(prior.patch) === JSON.stringify(deliveryRecord.patch))) receiptStore.append({ ...deliveryRecord, closedAt: new Date().toISOString() });
  }
  const storedReceipt = receiptStore.append(closeReceipt);
  try { if (existing.delivery) { finalizeClose(existing.delivery, { owner: closeOwner }); removeManifest(cwd, closeOwner, existing.delivery); } } catch (error) { throw new LegionError(error.message, { code: error.code ?? 'ARC_DELIVERY_FAILED', exitCode: EXIT.INCOMPLETE }); }
  const cleared = store.putBinding(sessionId, { runId: existing.runId, taskId: null, contractId: null, contractVersion: null, contractDigest: null, delivery: null, lifecycle: null });
  if (!cleared) throw new LegionError('run close: failed to persist the cleared binding', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
  stdout.write(`${JSON.stringify({ kind: 'legion-run-binding', sessionId, ...cleared, closeReceipt: { ...closeReceipt, ...storedReceipt } })}\n`);
  return { exitCode: EXIT.PASS };
  } catch (error) {
    if (error instanceof LegionError) throw error;
    throw new LegionError(`run close: receipt persistence failed: ${error.message}`, { code: 'ARC_DELIVERY_RECEIPT_FAILED', exitCode: EXIT.INCOMPLETE });
  }
}
