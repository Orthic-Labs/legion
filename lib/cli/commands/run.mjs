// EC-5 item 3 — `legion run open|close`: the missing writer H-11 named.
//
// A Sage contract is a prose artifact; before this command, nothing recorded
// "run R executes contract C for session S" as machine state (H-11,
// IMPLEMENTATION-PLAN.md). `open` binds the CURRENT session (self-healing via
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
// removed: they are `forge/hooks/generic/hook.js`'s own precedent
// (`process.env.CODEX_SESSION_ID ?? process.env.CLAUDE_SESSION_ID`) and
// Codex's live environment has never actually been observed by this
// codebase, so dropping them would trade one unverified assumption for
// another. If none resolve, this fails closed with `ARC_SESSION_UNKNOWN` —
// never a guessed session.

import { parseArgs } from 'node:util';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';

import { EXIT, LegionError } from '../../errors.mjs';
import { isId } from '../../../packages/arcane/lib/ids.mjs';
import { SessionBindingStore } from '../../../packages/arcane/lib/session-binding.mjs';
import { ContractSealStore } from '../../../packages/arcane/lib/contract-seal-store.mjs';
import { ReceiptStore } from '../../../packages/arcane/lib/receipt-store.mjs';
import { evaluateCompletion } from '../../../packages/arcane/lib/completion-gate.mjs';
import { loadPolicy, PolicyEngine } from '../../../packages/arcane/lib/policy.mjs';
import { authoritiesAbsent, finalizeClose, openDelivery, prepareClose, validateDeliveryAuthority, validateDeliveryReuse } from '../../../packages/arcane/lib/delivery-guard.mjs';

/** Workspace-relative, matching lib/session-binding.mjs's own contract
 * (`<workspace>/.audit/arcane/session-bindings/`) — bindings are per-checkout
 * + session, unlike host-identity keys. */
function bindingRoot(cwd) {
  return join(cwd, '.audit', 'arcane', 'session-bindings');
}

function receiptRoot(cwd) {
  return join(cwd, '.audit', 'arcane', 'receipts');
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
  throw new LegionError(`run requires a subcommand: open|close (got ${sub ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
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
        repo: { type: 'string', multiple: true },
        'read-only': { type: 'boolean' },
      },
    });
  } catch (err) {
    throw new LegionError(err.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const { contract = null, task = null, session = null, version = null, repo = [], 'read-only': readOnly = false } = parsed.values;
  if (!contract || !isId('executionContract', contract)) {
    throw new LegionError(`run open requires --contract <EC-#> (got ${contract ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  if (!/^\d+$/.test(version || '') || Number(version) < 1) throw new LegionError('run open requires --version <positive integer>', { code: 'USAGE', exitCode: EXIT.USAGE });
  if (task !== null && !isId('executionTask', task)) {
    throw new LegionError(`run open --task must match T-#(.#)* (got ${task})`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const sessionId = resolveRunSessionId(session, env);
  if (!sessionId) throw sessionUnknownError();

  const store = new SessionBindingStore({ root: bindingRoot(cwd) });
  // Self-heal: mint the ambient binding here if SessionStart never fired for
  // this session (e.g. the CLI is invoked outside a hook-observed session).
  const ensured = store.ensureBinding(sessionId);
  if (!ensured) {
    throw new LegionError('run open: session binding store is unavailable', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
  }
  const seal = new ContractSealStore({ root: join(cwd, '.audit', 'arcane', 'contract-seals') }).get(contract, Number(version));
  if (!seal) throw new LegionError('run open requires an exact sealed contract version', { code: 'ARC_NO_CONTRACT', exitCode: EXIT.USAGE });
  if (ensured.delivery && (ensured.taskId !== task || ensured.contractId !== contract || ensured.contractVersion !== seal.version || ensured.contractDigest !== seal.contractDigest)) {
    throw new LegionError('ARC_INTEGRATION_OWNER_CONFLICT: active delivery belongs to another contract/task', { code: 'ARC_INTEGRATION_OWNER_CONFLICT', exitCode: EXIT.INCOMPLETE });
  }
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
  const disposition = parsed.values.disposition ?? 'complete';
  if (!['complete', 'archive'].includes(disposition)) throw new LegionError('run close --disposition must be complete or archive', { code: 'USAGE', exitCode: EXIT.USAGE });
  if (existing.contractId && !existing.delivery) {
    throw new LegionError('ARC_DELIVERY_METADATA_MISSING: contracted binding lacks delivery metadata', { code: 'ARC_DELIVERY_METADATA_MISSING', exitCode: EXIT.INCOMPLETE });
  }

  const receiptStore = receiptStoreFactory({ root: receiptRoot(cwd) });
  const priorReceipts = receiptStore.list({ runId: existing.runId });
  const touchedPaths = [...new Set(priorReceipts.flatMap((record) => Array.isArray(record.targets) ? record.targets : []))];
  const completion = disposition === 'complete'
    ? evaluateCompletion({ runId: existing.runId, taskId: existing.taskId, claimedLevel: 'signoff', touchedPaths }, { policy: new PolicyEngine(loadPolicy()), receiptStore })
    : { allowed: true, code: 'ARC_ARCHIVE', enforcementHealth: 'not-applicable' };
  const expectedDelivery = (existing.delivery?.repositories ?? []).map((repo) => ({ repository: repo.root, baselineTree: repo.snapshotTree, leaseToken: repo.leaseToken ?? null }));
  const recovered = priorReceipts.find((receipt) => receipt.kind === 'legion-run-close-receipt'
    && receipt.sessionId === sessionId && receipt.runId === existing.runId && receipt.contractId === existing.contractId
    && receipt.contractVersion === existing.contractVersion && receipt.contractDigest === existing.contractDigest
    && receipt.deliveryDisposition === disposition && JSON.stringify(receipt.deliveryEvidence ?? []) === JSON.stringify(expectedDelivery));
  if (recovered) {
    try { if (existing.delivery) { const owner = { sessionId, runId: existing.runId, taskId: existing.taskId }; finalizeClose(validateDeliveryAuthority(validateManifest(cwd, owner, existing.delivery, { recovery: true }), { recovery: true, owner }), { recovery: true, owner }); removeManifest(cwd, owner, existing.delivery, { recovery: true }); } } catch (error) { throw new LegionError(error.message, { code: error.code ?? 'ARC_DELIVERY_FAILED', exitCode: EXIT.INCOMPLETE }); }
    const cleared = store.putBinding(sessionId, { runId: existing.runId, taskId: null, contractId: null, contractVersion: null, contractDigest: null, delivery: null });
    if (!cleared) throw new LegionError('run close: failed to persist the cleared binding', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
    stdout.write(`${JSON.stringify({ kind: 'legion-run-binding', sessionId, ...cleared, closeReceipt: recovered })}\n`);
    return { exitCode: EXIT.PASS };
  }
  if (priorReceipts.some((receipt) => receipt.kind === 'legion-run-close-receipt' && receipt.sessionId === sessionId && receipt.runId === existing.runId
    && receipt.contractId === existing.contractId && receipt.contractVersion === existing.contractVersion && receipt.contractDigest === existing.contractDigest
    && receipt.deliveryDisposition === disposition)) {
    throw new LegionError('run close: terminal receipt does not authenticate this binding', { code: 'ARC_DELIVERY_RECOVERY_MISMATCH', exitCode: EXIT.INCOMPLETE });
  }
  if (!completion.allowed) throw new LegionError(`run close blocked by completion gate: ${completion.code}`, { code: completion.code ?? 'ARC_COMPLETION_BLOCKED', exitCode: EXIT.INCOMPLETE });
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
  const cleared = store.putBinding(sessionId, { runId: existing.runId, taskId: null, contractId: null, contractVersion: null, contractDigest: null, delivery: null });
  if (!cleared) throw new LegionError('run close: failed to persist the cleared binding', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
  stdout.write(`${JSON.stringify({ kind: 'legion-run-binding', sessionId, ...cleared, closeReceipt: { ...closeReceipt, ...storedReceipt } })}\n`);
  return { exitCode: EXIT.PASS };
  } catch (error) {
    if (error instanceof LegionError) throw error;
    throw new LegionError(`run close: receipt persistence failed: ${error.message}`, { code: 'ARC_DELIVERY_RECEIPT_FAILED', exitCode: EXIT.INCOMPLETE });
  }
}
