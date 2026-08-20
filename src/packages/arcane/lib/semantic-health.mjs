import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { normalizeClaudeCodeEvent } from '../host/claude-code-adapter.mjs';
import { mapCodexPreEffect, normalizeCodexEvent } from '../host/codex-adapter.mjs';
import { createHostRuntime } from '../host/host-runtime.mjs';
import { preEffectDiscipline } from './discipline-controls.mjs';
import { HostEventLedger } from './host-event-ledger.mjs';
import { AuthorityInvocationProofIssuer } from './authority-invocation-proof.mjs';
import { generateTestKeyRing } from './keys.mjs';
import { AMENDED_BUDGET_BOUND_FIELDS, BudgetGovernanceStore, BUDGET_AMENDMENT_BOUND_FIELDS, BUDGET_BOUND_FIELDS, BUDGET_SCOPE_EXPANSION_BOUND_FIELDS } from './budget-governance-store.mjs';
import { TaskBudgetSealStore } from './task-budget-seal-store.mjs';
import { signRecord } from './receipt-auth.mjs';
import { digestValue } from './canonical.mjs';
import { evaluateStopShape } from '../../../../hooks/stop-shape.mjs';

const SELF = fileURLToPath(import.meta.url);
const PROBES = Object.freeze([
  'generated-input-rejection',
  'ambient-availability-bypass',
  'locked-unavailable-denial',
  'uncertified-stop-exit',
  'two-denial-release',
  'recovery-preservation',
  'adapter-parity',
  'budget_store_integrity',
  'budget_binding_exactness',
  'budget_monotonicity',
  'budget_stop_enforcement',
  'budget_role_cap_enforcement',
  'budget_amendment_authority',
]);

function fail(message) { throw new Error(message); }

function fixture(name, callback) {
  const root = mkdtempSync(join(tmpdir(), `arcane-semantic-${name}-`));
  try { return callback(root); } finally { rmSync(root, { recursive: true, force: true }); }
}

function keyDir(root) {
  const path = join(root, 'keys');
  mkdirSync(path, { recursive: true });
  writeFileSync(join(path, 'k1.key'), 'a'.repeat(64));
  return path;
}

function adapter() {
  return { name: 'codex', normalize: normalizeCodexEvent, mapPreEffect: mapCodexPreEffect };
}

function signedBudget(ring, contractId = 'EC-604') {
  const budget = { schemaVersion: 1, kind: 'arcane-budget-governance', contractId, version: 1, contractDigest: digestValue({ contractId, version: 1 }), objectiveLineageId: 'budget-semantic', objectiveDigest: digestValue('budget semantic'), legionBlastMapCapMs: 100, sagePlanningCapMs: 100, maxContractVersions: 2, resumeEvidence: null, amendmentEvidence: null, userScopeExpansionEvidence: null };
  budget.authentication = signRecord(budget, { keyRing: ring, keyId: ring.activeKeyId(), boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
  return budget;
}

const probe = {
  'generated-input-rejection'() {
    const result = preEffectDiscipline(
      { tool_input: { patch: '*** Begin Patch\n*** Update File: docs/generated-lock.json\n*** End Patch' } },
      { workspace: process.cwd(), checkCommit: false },
    );
    if (result?.code !== 'ARC_EFFECT_CLASS_UNAUTHORIZED') fail('generated input was not denied');
  },
  'ambient-availability-bypass'() {
    fixture('ambient-availability-bypass', (workspace) => {
      const runtime = createHostRuntime({ adapter: adapter(), workspace, keyDir: join(workspace, 'missing-keys') });
      const result = runtime.handle({ hook_event_name: 'PreToolUse', cwd: workspace, session_id: 'semantic', tool_name: 'Write', tool_input: { file_path: 'src/a.mjs' }, tool_use_id: 'semantic-ambient-bypass' });
      if (!result.allowed || result.code !== 'ARC_AUTH_KEY_UNAVAILABLE' || result.enforcementHealth !== 'degraded' || result.stdout !== null) fail(`ambient availability bypass was ${result.code}`);
    });
  },
  'locked-unavailable-denial'() {
    fixture('locked-unavailable-denial', (workspace) => {
      const runtime = createHostRuntime({ adapter: adapter(), workspace, keyDir: join(workspace, 'missing-keys') });
      const result = runtime.handle({ hook_event_name: 'PreToolUse', cwd: workspace, session_id: 'semantic', tool_name: 'Write', tool_input: { file_path: 'tools/rhook/src/main.rs' }, tool_use_id: 'semantic-locked-denial' });
      if (result.allowed || result.code !== 'ARC_AUTH_KEY_UNAVAILABLE') fail(`locked unavailable denial was ${result.code}`);
    });
  },
  'uncertified-stop-exit'() {
    fixture('uncertified-stop', (workspace) => {
      const runtime = createHostRuntime({ adapter: adapter(), workspace, keyDir: keyDir(workspace) });
      const result = runtime.handle({ hook_event_name: 'Stop', cwd: workspace, session_id: 'semantic-stop' });
      if (!result.allowed || result.stdout !== null) fail(`uncertified Stop did not exit: ${result.code}`);
    });
  },
  'two-denial-release'() {
    const result = evaluateStopShape('Implementation is ready. Say go and I execute.', { intent: 'EXECUTE', authorized: true, pushes: 2 });
    if (result.block || result.reason !== 'stop-circuit-open') fail('two-denial circuit did not release Stop');
  },
  'recovery-preservation'() {
    fixture('recovery', (root) => {
      const keys = generateTestKeyRing(['k1']);
      const ledger = new HostEventLedger({ root: join(root, 'events'), keyRing: keys, keyId: 'k1' });
      ledger.append({ eventId: 'semantic-event', adapter: 'codex', eventType: 'SessionStart', sessionId: 'semantic-session', binding: { runId: 'run-semantic', taskId: 'T-7', contractId: 'EC-603', contractVersion: 7, contractDigest: 'sha256:' + 'a'.repeat(64) }, sourceRevision: '7f4adfeeb8dec603c9e60ea820a7f21052eef102', observedAuthority: 'alchemist', payload: { fixture: true } });
      const recovered = new HostEventLedger({ root: join(root, 'events'), keyRing: keys, keyId: 'k1' }).verify();
      if (!recovered.allowed || !existsSync(join(root, 'events', '0000000000000001.json'))) fail('recovery did not preserve authenticated ledger state');
    });
  },
  'adapter-parity'() {
    const payload = { hook_event_name: 'PostToolUseFailure', session_id: 'semantic-session', cwd: process.cwd(), tool_name: 'Write', tool_input: { file_path: 'src/a.mjs' }, tool_response: { error: 'fixture' }, tool_use_id: 'semantic-parity' };
    const codex = normalizeCodexEvent(payload);
    const claude = normalizeClaudeCodeEvent(payload);
    if (codex.eventType !== 'post-effect-failure' || claude.eventType !== 'post-effect-failure' || codex.result?.outcome !== 'failure' || claude.result?.outcome !== 'failure') fail('adapters diverged on failed post-effect behavior');
  },
  'budget_store_integrity'() {
    fixture('budget-store', (root) => {
      const ring = generateTestKeyRing(['k1']);
      const store = new BudgetGovernanceStore({ root, keyRing: ring });
      store.seal(signedBudget(ring));
      if (store.require('EC-604', 1).contractId !== 'EC-604') fail('budget store did not return sealed binding');
      const file = readdirSync(root).find((name) => name.endsWith('.json')); const changed = JSON.parse(readFileSync(join(root, file), 'utf8')); changed.sagePlanningCapMs += 1; writeFileSync(join(root, file), JSON.stringify(changed));
      try { store.require('EC-604', 1); fail('tampered stored budget passed authentication'); } catch (error) { if (error.code !== 'ARC_STORE_CORRUPT') throw error; }
    });
  },
  'budget_binding_exactness'() {
    fixture('budget-binding', (root) => {
      const ring = generateTestKeyRing(['k1']);
      const contract = { contractId: 'EC-604', version: 1 };
      const task = { taskId: 'T-2', ownScope: ['owned.mjs'], title: 'budget health' };
      task.budgetSeal = { contractId: contract.contractId, contractVersion: contract.version, contractDigest: digestValue(contract), taskDigest: digestValue({ taskId: task.taskId, ownScope: task.ownScope, title: task.title }), scopeDigest: digestValue(task.ownScope), activeTimeCapMs: 10, progressDeadlineMs: 5, evidenceReferences: ['AC-6'] };
      const seals = new TaskBudgetSealStore({ root, keyRing: ring });
      seals.seal({ contract, task, authorityAssertion: { authority: 'sage', assertedBy: 'semantic-health', verificationMethod: 'capability-signature', perMessage: true } });
      if (seals.require('EC-604', 'T-2', 1).scopeDigest !== digestValue(task.ownScope)) fail('task budget binding differs');
    });
  },
  'budget_monotonicity'() {
    fixture('budget-monotonicity', (root) => {
      const ring = generateTestKeyRing(['k1']); let tick = 10;
      const store = new BudgetGovernanceStore({ root, keyRing: ring, monotonicNow: () => tick });
      store.seal(signedBudget(ring)); const run = store.begin({ contractId: 'EC-604', version: 1, taskId: 'T-2', runId: 'semantic-monotonic', activeTimeCapMs: 10, progressDeadlineMs: 10 });
      tick = 9; if (store.observe(run).code !== 'MONOTONIC_REGRESSION') fail('monotonic regression was not terminal');
    });
  },
  'budget_stop_enforcement'() {
    fixture('budget-stop', (root) => {
      const ring = generateTestKeyRing(['k1']); let tick = 0;
      const store = new BudgetGovernanceStore({ root, keyRing: ring, monotonicNow: () => tick });
      store.seal(signedBudget(ring)); const run = store.begin({ contractId: 'EC-604', version: 1, taskId: 'T-2', runId: 'semantic-stop', activeTimeCapMs: 1, progressDeadlineMs: 10 });
      tick = 2; if (store.observe(run).code !== 'ACTIVE_CAP' || store.observe(run).kind !== 'BUDGET_STOP') fail('budget stop did not remain terminal');
    });
  },
  'budget_role_cap_enforcement'() {
    fixture('budget-role-cap', (root) => {
      const ring = generateTestKeyRing(['k1']); const store = new BudgetGovernanceStore({ root, keyRing: ring });
      store.seal(signedBudget(ring));
      try { store.begin({ contractId: 'EC-604', version: 1, taskId: 'T-1', authorityRole: 'sage', activeTimeCapMs: 101, progressDeadlineMs: 10 }); fail('Sage role cap was not enforced'); }
      catch (error) { if (error.code !== 'ARC_BINDING_MISMATCH') throw error; }
    });
  },
  'budget_amendment_authority'() {
    fixture('budget-amendment', (root) => {
      const ring = generateTestKeyRing(['k1']); const first = signedBudget(ring); const binding = { runId: 'semantic-budget-run', taskId: 'T-1', contractId: first.contractId, contractVersion: 1, contractDigest: first.contractDigest }; const ledger = new HostEventLedger({ root: join(root, 'host-events'), keyRing: ring, keyId: 'k1', clock: () => '2026-08-12T00:00:00.000Z' }); const sageEvent = ledger.append({ eventId: 'semantic-sage-amendment', adapter: 'codex', eventType: 'SubagentStart', sessionId: 'semantic-sage', binding, observedAuthority: 'sage', payload: { purpose: 'budget amendment' } }); const issuer = new AuthorityInvocationProofIssuer({ root: join(root, 'authority-proofs'), keyRing: ring, keyId: 'k1', ledgerStore: ledger, clock: () => '2026-08-12T00:00:00.000Z' });
      const proof = issuer.issue({ ledger: sageEvent, binding: { ...binding, sessionId: 'semantic-sage' }, purpose: 'budget-amendment', role: 'sage' }).proof;
      const userEvent = ledger.append({ eventId: 'semantic-user-expansion', adapter: 'codex', eventType: 'UserPromptSubmit', sessionId: 'semantic-user', binding, observedAuthority: null, payload: { prompt: 'expand scope' } }); const store = new BudgetGovernanceStore({ root, keyRing: ring, proofIssuer: issuer, hostEventLedger: ledger }); store.seal(first);
      const second = { ...signedBudget(ring), version: 2, contractDigest: digestValue({ contractId: 'EC-604', version: 2 }), legionBlastMapCapMs: 101 };
      second.amendmentEvidence = { schemaVersion: 1, kind: 'arcane-budget-amendment', priorContractDigest: first.contractDigest, newContractDigest: second.contractDigest, priorLegionBlastMapCapMs: 100, newLegionBlastMapCapMs: 101, priorSagePlanningCapMs: 100, newSagePlanningCapMs: 100, scopeExpanded: true, invocationProofDigest: digestValue(proof), observedAt: '2026-08-12T00:00:00.000Z' };
      second.amendmentEvidence.authentication = signRecord(second.amendmentEvidence, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_AMENDMENT_BOUND_FIELDS, macDomain: 'arcane-budget-amendment-v1' });
      second.authentication = signRecord(second, { keyRing: ring, keyId: 'k1', boundFields: AMENDED_BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
      try { store.seal(second); fail('scope expansion lacked user evidence'); } catch (error) { if (error.code !== 'ARC_AUTHORITY_NOT_ASSERTED') throw error; }
      second.userScopeExpansionEvidence = { schemaVersion: 1, kind: 'arcane-budget-scope-expansion-evidence', priorContractDigest: first.contractDigest, newContractDigest: second.contractDigest, userTurnDigest: userEvent.payloadDigest, hostEventDigest: digestValue(userEvent), sessionId: userEvent.sessionId, observedAt: '2026-08-12T00:00:00.000Z' };
      second.userScopeExpansionEvidence.authentication = signRecord(second.userScopeExpansionEvidence, { keyRing: ring, keyId: 'k1', boundFields: BUDGET_SCOPE_EXPANSION_BOUND_FIELDS, macDomain: 'arcane-budget-scope-expansion-v1' });
      second.authentication = signRecord(second, { keyRing: ring, keyId: 'k1', boundFields: AMENDED_BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
      if (store.seal(second).version !== 2) fail('authenticated amendment did not seal');
    });
  },
};

function injected(name, env) {
  return new Set(String(env.ARCANE_SEMANTIC_HEALTH_INJECT_FAILURE ?? '').split(',').map((value) => value.trim())).has(name);
}

export function runProbe(name, { env = process.env } = {}) {
  const startedAt = new Date().toISOString();
  try {
    if (!PROBES.includes(name)) fail(`unknown semantic probe: ${name}`);
    probe[name]();
    if (injected(name, env)) fail('injected semantic failure fixture');
    return { id: name, ok: true, startedAt, finishedAt: new Date().toISOString(), error: null };
  } catch (error) {
    return { id: name, ok: false, startedAt, finishedAt: new Date().toISOString(), error: String(error?.message ?? error).slice(0, 300) };
  }
}

export function runSemanticHealth({ cwd = process.cwd(), env = process.env, spawn = spawnSync } = {}) {
  const probes = PROBES.map((id) => {
    const child = spawn(process.execPath, [SELF, '--probe', id, '--json'], { cwd, env: { ...process.env, ...env }, encoding: 'utf8', windowsHide: true });
    try {
      const value = JSON.parse(child.stdout);
      return value?.id === id ? value : { id, ok: false, error: 'semantic probe returned malformed output' };
    } catch {
      return { id, ok: false, error: (child.stderr || child.stdout || child.error?.message || 'semantic probe did not return JSON').trim().slice(0, 300) };
    }
  });
  return { schemaVersion: 1, kind: 'arcane-semantic-health', healthy: probes.every((item) => item.ok), probes };
}

function main() {
  const index = process.argv.indexOf('--probe');
  if (index >= 0) {
    const result = runProbe(process.argv[index + 1]);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = result.ok ? 0 : 1;
    return;
  }
  const result = runSemanticHealth();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.healthy ? 0 : 1;
}

if (process.argv[1] && SELF === process.argv[1]) main();
