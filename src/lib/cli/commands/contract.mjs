// `legion contract seal` — the authenticated contract-seal producer.
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
// hook wrote when the agent started. If the observed authority is neither
// `legion` nor `sage`, the seal is refused. A caller cannot promote itself by
// passing a different string, because no such string is read. Legion seals
// settled executable contracts; Sage seals contracts whose settled meaning
// includes an actual Sage adjudication.
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
import { compileSealReachability } from '../../../packages/arcane/lib/seal-reachability.mjs';
import { AMENDED_BUDGET_BOUND_FIELDS, BUDGET_AMENDMENT_BOUND_FIELDS, BUDGET_BOUND_FIELDS, BudgetGovernanceStore } from '../../../packages/arcane/lib/budget-governance-store.mjs';
import { TaskBudgetSealStore } from '../../../packages/arcane/lib/task-budget-seal-store.mjs';
import { HostEventLedger } from '../../../packages/arcane/lib/host-event-ledger.mjs';
import { AuthorityInvocationProofIssuer } from '../../../packages/arcane/lib/authority-invocation-proof.mjs';
import { digestValue } from '../../../packages/arcane/lib/canonical.mjs';
import { signRecord } from '../../../packages/arcane/lib/receipt-auth.mjs';

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
        reachability: { type: 'string' },
        'task-budgets': { type: 'string' },
      },
    });
  } catch (err) {
    throw new LegionError(err.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }

  const { file = null, agent = null, session = null, adapter = 'claude-code', 'key-dir': keyDirFlag = null, reachability: reachabilityPath = null, 'task-budgets': taskBudgetsPath = null } = parsed.values;
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

  let evidenceReachability = null;
  if (contract.evidenceRequirements?.length) {
    if (!reachabilityPath) throw new LegionError('ARC_UNSOUND_SEAL: contract seal requires --reachability <evidence-lifecycle.json>', { code: 'ARC_UNSOUND_SEAL', exitCode: EXIT.USAGE });
    let lifecycle;
    try { lifecycle = JSON.parse(readFileSync(reachabilityPath, 'utf8')); }
    catch (err) { throw new LegionError(`contract seal cannot read --reachability ${reachabilityPath}: ${err.message}`, { code: 'USAGE', exitCode: EXIT.USAGE }); }
    const covered = lifecycle.requirements?.map((entry) => entry.contractRequirement) ?? [];
    const expected = [...contract.evidenceRequirements].sort();
    if (covered.length !== new Set(covered).size || JSON.stringify([...covered].sort()) !== JSON.stringify(expected)) throw new LegionError('ARC_UNSOUND_SEAL: evidence lifecycle must exactly cover contract evidence requirements', { code: 'ARC_UNSOUND_SEAL', exitCode: EXIT.USAGE });
    evidenceReachability = compileSealReachability(lifecycle);
    if (!evidenceReachability.allowed) throw new LegionError(`${evidenceReachability.code}: ${evidenceReachability.message}`, { code: evidenceReachability.code, exitCode: EXIT.USAGE });
  }
  let taskBudgets = null;
  if (taskBudgetsPath) {
    try { taskBudgets = JSON.parse(readFileSync(taskBudgetsPath, 'utf8')); }
    catch (err) { throw new LegionError(`contract seal cannot read --task-budgets ${taskBudgetsPath}: ${err.message}`, { code: 'USAGE', exitCode: EXIT.USAGE }); }
    const taskIds = taskBudgets?.tasks?.map((entry) => entry.taskId) ?? [];
    if (taskIds.length !== new Set(taskIds).size || JSON.stringify([...taskIds].sort()) !== JSON.stringify([...contract.tasks].sort())) throw new LegionError('ARC_BINDING_MISMATCH: task budget companion must exactly cover contract tasks', { code: 'ARC_BINDING_MISMATCH', exitCode: EXIT.USAGE });
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
    : bindings.findLatest({ adapter, sessionId, authority: 'sage' }) ?? bindings.findLatest({ adapter, sessionId, authority: 'legion' });
  if (!observed) {
    throw new LegionError(
      agent
        ? `ARC_AUTHORITY_NOT_ASSERTED: no observed authority binding for agent '${agent}' in this session — the host must observe the agent (SubagentStart) before it can seal`
        : 'ARC_AUTHORITY_NOT_ASSERTED: no observed Sage or Legion binding in this session — a Sage agent or the Legion orchestrator must have started before a contract can be sealed',
      { code: 'ARC_AUTHORITY_NOT_ASSERTED', exitCode: EXIT.INTERNAL_ERROR },
    );
  }
  if (!['legion', 'sage'].includes(observed.authority)) {
    throw new LegionError(
      `ARC_AUTHORITY_NOT_ASSERTED: agent '${agent}' is observed as authority '${observed.authority}'; only Legion or Sage may seal an execution contract`,
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
    record = new ContractSealStore({ root: stateDir(cwd, 'contract-seals') }).seal({ contract, authorityAssertion: assertion, evidenceReachability });
    if (taskBudgets) {
      const contractDigest = digestValue(contract);
      const budget = { schemaVersion: 1, kind: 'arcane-budget-governance', contractId: contract.contractId, version: contract.version, contractDigest, objectiveLineageId: contract.budget.objectiveLineageId, objectiveDigest: contract.budget.objectiveDigest, legionBlastMapCapMs: contract.budget.legionBlastMapCapMs, sagePlanningCapMs: contract.budget.sagePlanningCapMs, maxContractVersions: contract.budget.maxContractVersions, resumeEvidence: null };
      const hostEventLedger = new HostEventLedger({ root: stateDir(cwd, 'host-events'), keyRing, keyId: keyRing.activeKeyId() });
      const proofIssuer = new AuthorityInvocationProofIssuer({ root: stateDir(cwd, 'authority-invocations'), keyRing, keyId: keyRing.activeKeyId(), ledgerStore: hostEventLedger });
      const budgetStore = new BudgetGovernanceStore({ root: stateDir(cwd, 'budget-governance'), keyRing, proofIssuer, hostEventLedger });
      let prior = null;
      if (contract.version > 1) {
        try { prior = budgetStore.require(contract.contractId, contract.version - 1); }
        catch (error) { if (error?.code !== 'ARC_STORE_CORRUPT') throw error; }
      }
      if (prior) {
        const event = hostEventLedger.records().at(-1);
        if (!event || event.sessionId !== sessionId || !['legion', 'sage'].includes(event.observedAuthority)) throw new LegionError('ARC_AUTHORITY_NOT_ASSERTED: current Legion or Sage host event required for contract amendment', { code: 'ARC_AUTHORITY_NOT_ASSERTED', exitCode: EXIT.INTERNAL_ERROR });
        const proof = proofIssuer.issue({ ledger: event, binding: { runId: event.runId ?? `seal:${contract.contractId}`, taskId: contract.tasks[0], contractId: prior.contractId, contractVersion: prior.version, contractDigest: prior.contractDigest }, purpose: 'budget-amendment', role: 'sage' }).proof;
        budget.amendmentEvidence = { schemaVersion: 1, kind: 'arcane-budget-amendment', priorContractDigest: prior.contractDigest, newContractDigest: contractDigest, priorLegionBlastMapCapMs: prior.legionBlastMapCapMs, newLegionBlastMapCapMs: budget.legionBlastMapCapMs, priorSagePlanningCapMs: prior.sagePlanningCapMs, newSagePlanningCapMs: budget.sagePlanningCapMs, scopeExpanded: false, invocationProofDigest: digestValue(proof), observedAt: new Date().toISOString() };
        budget.amendmentEvidence.authentication = signRecord(budget.amendmentEvidence, { keyRing, keyId: keyRing.activeKeyId(), boundFields: BUDGET_AMENDMENT_BOUND_FIELDS, macDomain: 'arcane-budget-amendment-v1' });
        budget.userScopeExpansionEvidence = null;
      }
      budget.authentication = signRecord(budget, { keyRing, keyId: keyRing.activeKeyId(), boundFields: prior ? AMENDED_BUDGET_BOUND_FIELDS : BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
      budgetStore.seal(budget);
      const store = new TaskBudgetSealStore({ root: stateDir(cwd, 'task-budget-seals'), keyRing });
      for (const spec of taskBudgets.tasks) {
        if (!Array.isArray(spec.ownScope) || !spec.ownScope.length || !Number.isInteger(spec.activeTimeCapMs) || !Number.isInteger(spec.progressDeadlineMs) || !Array.isArray(spec.evidenceReferences) || !spec.evidenceReferences.length) throw new LegionError('ARC_SCHEMA_INVALID: task budget requires ownScope, positive ceilings, & evidence references', { code: 'ARC_SCHEMA_INVALID', exitCode: EXIT.USAGE });
        const task = { taskId: spec.taskId, ownScope: spec.ownScope };
        task.budgetSeal = { contractId: contract.contractId, contractVersion: contract.version, contractDigest, taskDigest: digestValue(task), scopeDigest: digestValue(task.ownScope), activeTimeCapMs: spec.activeTimeCapMs, progressDeadlineMs: spec.progressDeadlineMs, evidenceReferences: spec.evidenceReferences };
        store.seal({ contract, task, authorityAssertion: assertion });
      }
    }
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
    taskBudgetsSealed: taskBudgets?.tasks?.length ?? 0,
  })}\n`);
  return { exitCode: EXIT.PASS };
}
