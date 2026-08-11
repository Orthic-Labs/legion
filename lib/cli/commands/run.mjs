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

import { EXIT, LegionError } from '../../errors.mjs';
import { isId } from '../../../packages/arcane/lib/ids.mjs';
import { SessionBindingStore } from '../../../packages/arcane/lib/session-binding.mjs';
import { ContractSealStore } from '../../../packages/arcane/lib/contract-seal-store.mjs';
import { ReceiptStore } from '../../../packages/arcane/lib/receipt-store.mjs';
import { evaluateCompletion } from '../../../packages/arcane/lib/completion-gate.mjs';
import { loadPolicy, PolicyEngine } from '../../../packages/arcane/lib/policy.mjs';

/** Workspace-relative, matching lib/session-binding.mjs's own contract
 * (`<workspace>/.audit/arcane/session-bindings/`) — bindings are per-checkout
 * + session, unlike host-identity keys. */
function bindingRoot(cwd) {
  return join(cwd, '.audit', 'arcane', 'session-bindings');
}

function receiptRoot(cwd) {
  return join(cwd, '.audit', 'arcane', 'receipts');
}

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

export async function runRun(argv, { stdout, stderr, env, cwd }) {
  const [sub, ...rest] = argv;
  if (sub === 'open') return runOpen(rest, { stdout, env, cwd });
  if (sub === 'close') return runClose(rest, { stdout, env, cwd });
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
      },
    });
  } catch (err) {
    throw new LegionError(err.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const { contract = null, task = null, session = null, version = null } = parsed.values;
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
  const upgraded = store.putBinding(sessionId, { runId: ensured.runId, taskId: task, contractId: contract, contractVersion: seal.version, contractDigest: seal.contractDigest });
  if (!upgraded) {
    throw new LegionError('run open: failed to persist the contract/task binding', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
  }

  stdout.write(`${JSON.stringify({ kind: 'legion-run-binding', sessionId, ...upgraded })}\n`);
  return { exitCode: EXIT.PASS };
}

function runClose(argv, { stdout, env, cwd }) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, allowPositionals: false, strict: true, options: { session: { type: 'string' } } });
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

  const receiptStore = new ReceiptStore({ root: receiptRoot(cwd) });
  const priorReceipts = receiptStore.list({ runId: existing.runId });
  const touchedPaths = [...new Set(priorReceipts.flatMap((record) => Array.isArray(record.targets) ? record.targets : []))];
  const completion = evaluateCompletion(
    { runId: existing.runId, taskId: existing.taskId, claimedLevel: 'signoff', touchedPaths },
    { policy: new PolicyEngine(loadPolicy()), receiptStore },
  );
  const closeReceipt = {
    schemaVersion: 1,
    kind: 'legion-run-close-receipt',
    runId: existing.runId,
    taskId: existing.taskId,
    contractId: existing.contractId,
    contractVersion: existing.contractVersion,
    contractDigest: existing.contractDigest,
    finalClaimState: completion.allowed ? 'passed' : 'blocked',
    completionCode: completion.code,
    enforcementHealth: completion.enforcementHealth,
    closedAt: new Date().toISOString(),
  };
  const cleared = store.putBinding(sessionId, { runId: existing.runId, taskId: null, contractId: null, contractVersion: null, contractDigest: null });
  if (!cleared) {
    throw new LegionError('run close: failed to persist the cleared binding', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
  }
  const storedReceipt = receiptStore.append(closeReceipt);
  stdout.write(`${JSON.stringify({ kind: 'legion-run-binding', sessionId, ...cleared, closeReceipt: { ...closeReceipt, ...storedReceipt } })}\n`);
  return { exitCode: EXIT.PASS };
}
