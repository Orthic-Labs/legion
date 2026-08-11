// `legion contract seal` — the authenticated Sage contract-seal producer.
//
// Why this exists: `ContractSealStore.seal()` has always been callable, but no
// production code path ever called it — only test fixtures did. So a locked
// domain (`tools/rhook/**`, `packages/arcane/**`, `qualification/**`) could be
// refused by the pre-effect gate for having no sealed contract, while there was
// no supported way to PRODUCE one. That is a dead end, not enforcement: the only
// route through was to edit the enforcement plane itself, which is exactly the
// bypass the locked domains exist to prevent.
//
// The authority rule this command must not break (lib/authority.mjs, S02):
// authority is asserted by the kernel per turn, never claimed by the caller.
// So this command does NOT take an `--authority sage` flag. It names an already
// OBSERVED agent identity (`--agent`), and `AuthorityBindingStore.assertForTurn`
// decides what authority that identity carries — a binding the SubagentStart
// hook wrote when the agent started. If the observed authority is not `sage`,
// the seal is refused. A caller cannot promote itself by passing a different
// string, because no such string is read.
//
// The host key is required (not optional): `assertForTurn` throws
// ARC_AUTH_KEY_UNAVAILABLE without one, so a host that cannot authenticate
// cannot mint seals. Fail closed, never a degraded stamp.

import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { EXIT, LegionError } from '../../errors.mjs';
import { ArcaneError } from '../../../packages/arcane/lib/errors.mjs';
import { ContractSealStore } from '../../../packages/arcane/lib/contract-seal-store.mjs';
import { AuthorityBindingStore } from '../../../packages/arcane/lib/authority-binding-store.mjs';
import { AuthorityLedger } from '../../../packages/arcane/lib/authority.mjs';
import { loadHostKeyRing } from '../../../packages/arcane/lib/keys.mjs';

const stateDir = (cwd, ...parts) => join(cwd, '.audit', 'arcane', ...parts);

function resolveSessionId(explicitSession, env) {
  if (typeof explicitSession === 'string' && explicitSession.length > 0) return explicitSession;
  return env.CODEX_THREAD_ID || env.CLAUDE_CODE_SESSION_ID || env.CLAUDE_SESSION_ID || env.CODEX_SESSION_ID || null;
}

export async function runContract(argv, { stdout, stderr, env, cwd }) {
  const [sub, ...rest] = argv;
  if (sub === 'seal') return contractSeal(rest, { stdout, env, cwd });
  throw new LegionError(`contract requires a subcommand: seal (got ${sub ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
}

function contractSeal(argv, { stdout, env, cwd }) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: false,
      strict: true,
      options: {
        file: { type: 'string' },
        agent: { type: 'string' },
        session: { type: 'string' },
        adapter: { type: 'string' },
        'key-dir': { type: 'string' },
      },
    });
  } catch (err) {
    throw new LegionError(err.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const { file = null, agent = null, session = null, adapter = 'claude-code', 'key-dir': keyDirFlag = null } = parsed.values;
  if (!file) throw new LegionError('contract seal requires --file <executable-contract.json>', { code: 'USAGE', exitCode: EXIT.USAGE });
  // --agent stays supported, but is no longer required. Only agentIdDigest is
  // ever persisted, and the lookup path hashes the raw id, so no agent can
  // discover its own agentId to pass here — which made this command, and with
  // it every locked domain, unrunnable by anyone. Omitting --agent resolves the
  // most recent Sage binding for THIS session instead. That is not a weaker
  // gate: the binding still has to have been written by a real SubagentStart,
  // the host key is still mandatory, and authority still comes from the
  // observed record, never from the caller.

  const sessionId = resolveSessionId(session, env);
  if (!sessionId) {
    throw new LegionError(
      'ARC_SESSION_UNKNOWN: no session id available (checked --session, then CODEX_THREAD_ID, CLAUDE_CODE_SESSION_ID, CLAUDE_SESSION_ID, CODEX_SESSION_ID) — never guessed',
      { code: 'ARC_SESSION_UNKNOWN', exitCode: EXIT.USAGE },
    );
  }

  let contract;
  try {
    contract = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new LegionError(`contract seal cannot read --file ${file}: ${err.message}`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  // The host key is mandatory. Without it assertForTurn throws
  // ARC_AUTH_KEY_UNAVAILABLE and no seal is minted — a host that cannot
  // authenticate must not be able to authorize a locked domain.
  const keyDir = keyDirFlag ?? env.ARCANE_KEY_DIR ?? join(homedir(), '.claude', 'arcane-keys');
  let keyRing;
  try {
    keyRing = loadHostKeyRing({ dir: keyDir });
  } catch {
    throw new LegionError(
      `ARC_AUTH_KEY_UNAVAILABLE: no host key in ${keyDir} — a seal cannot be minted without one`,
      { code: 'ARC_AUTH_KEY_UNAVAILABLE', exitCode: EXIT.INTERNAL_ERROR },
    );
  }

  const bindings = new AuthorityBindingStore({ root: stateDir(cwd, 'authority-bindings') });
  const observed = agent
    ? bindings.get({ adapter, sessionId, agentId: agent })
    : bindings.findLatest({ adapter, sessionId, authority: 'sage' });
  if (!observed) {
    throw new LegionError(
      agent
        ? `ARC_AUTHORITY_NOT_ASSERTED: no observed authority binding for agent '${agent}' in this session — the host must observe the agent (SubagentStart) before it can seal`
        : 'ARC_AUTHORITY_NOT_ASSERTED: no observed Sage binding in this session — a Sage agent must have started (SubagentStart) before a contract can be sealed',
      { code: 'ARC_AUTHORITY_NOT_ASSERTED', exitCode: EXIT.INTERNAL_ERROR },
    );
  }
  if (observed.authority !== 'sage') {
    throw new LegionError(
      `ARC_AUTHORITY_NOT_ASSERTED: agent '${agent}' is observed as authority '${observed.authority}'; only Sage may seal an execution contract`,
      { code: 'ARC_AUTHORITY_NOT_ASSERTED', exitCode: EXIT.INTERNAL_ERROR },
    );
  }

  let assertion;
  let record;
  try {
    assertion = bindings.assertForTurn({
      adapter,
      sessionId,
      agentId: agent,
      record: agent ? null : observed,
      turnId: `seal:${contract?.contractId ?? 'unknown'}:${contract?.version ?? 'unknown'}`,
      authorityLedger: new AuthorityLedger(),
      keyId: keyRing.activeKeyId(),
    });
    record = new ContractSealStore({ root: stateDir(cwd, 'contract-seals') }).seal({ contract, authorityAssertion: assertion });
  } catch (err) {
    if (err instanceof ArcaneError) {
      throw new LegionError(`${err.code}: ${err.message}`, { code: err.code, exitCode: EXIT.INTERNAL_ERROR });
    }
    throw err;
  }

  stdout.write(`${JSON.stringify({
    kind: 'legion-contract-seal',
    contractId: record.record.contractId,
    version: record.record.version,
    contractDigest: record.record.contractDigest,
    sourceRevision: record.record.sourceRevision,
    sealedBy: record.record.sealedBy,
    created: record.created,
  })}\n`);
  return { exitCode: EXIT.PASS };
}
