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

/** Workspace-relative, matching lib/session-binding.mjs's own contract
 * (`<workspace>/.audit/arcane/session-bindings/`) — bindings are per-checkout
 * + session, unlike host-identity keys. */
function bindingRoot(cwd) {
  return join(cwd, '.audit', 'arcane', 'session-bindings');
}

function resolveSessionId(explicitSession, env) {
  if (typeof explicitSession === 'string' && explicitSession.length > 0) return explicitSession;
  return env.CLAUDE_CODE_SESSION_ID || env.CLAUDE_SESSION_ID || env.CODEX_SESSION_ID || null;
}

function sessionUnknownError() {
  return new LegionError(
    'ARC_SESSION_UNKNOWN: no session id available (checked --session, then CLAUDE_CODE_SESSION_ID, CLAUDE_SESSION_ID, CODEX_SESSION_ID) — never guessed',
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
        task: { type: 'string' },
        session: { type: 'string' },
      },
    });
  } catch (err) {
    throw new LegionError(err.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const { contract = null, task = null, session = null } = parsed.values;
  if (!contract || !isId('executionContract', contract)) {
    throw new LegionError(`run open requires --contract <EC-#> (got ${contract ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  if (task !== null && !isId('executionTask', task)) {
    throw new LegionError(`run open --task must match T-#(.#)* (got ${task})`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const sessionId = resolveSessionId(session, env);
  if (!sessionId) throw sessionUnknownError();

  const store = new SessionBindingStore({ root: bindingRoot(cwd) });
  // Self-heal: mint the ambient binding here if SessionStart never fired for
  // this session (e.g. the CLI is invoked outside a hook-observed session).
  const ensured = store.ensureBinding(sessionId);
  if (!ensured) {
    throw new LegionError('run open: session binding store is unavailable', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
  }
  const upgraded = store.putBinding(sessionId, { runId: ensured.runId, taskId: task, contractId: contract });
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

  const sessionId = resolveSessionId(parsed.values.session ?? null, env);
  if (!sessionId) throw sessionUnknownError();

  const store = new SessionBindingStore({ root: bindingRoot(cwd) });
  // close never mints — only an ALREADY-bound session has anything to clear.
  const existing = store.getBinding(sessionId);
  if (!existing) {
    throw new LegionError('run close: no binding exists for this session — nothing to close', { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const cleared = store.putBinding(sessionId, { runId: existing.runId, taskId: null, contractId: null });
  if (!cleared) {
    throw new LegionError('run close: failed to persist the cleared binding', { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.INTERNAL_ERROR });
  }

  stdout.write(`${JSON.stringify({ kind: 'legion-run-binding', sessionId, ...cleared })}\n`);
  return { exitCode: EXIT.PASS };
}
