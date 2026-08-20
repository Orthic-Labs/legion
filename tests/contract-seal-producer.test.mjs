// The authenticated Sage contract-seal producer (`legion contract seal`).
//
// Before this command existed, `ContractSealStore.seal()` was called only by
// test fixtures, so a locked domain could be refused for having no sealed
// contract while there was no supported way to produce one. These tests pin
// both halves of the fix: a Sage-observed agent CAN mint a seal, and nobody
// else can — including a caller who tries to name its own authority.

import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { runContract } from '../src/lib/cli/commands/contract.mjs';
import { AuthorityBindingStore } from '../src/packages/arcane/lib/authority-binding-store.mjs';
import { BUDGET_BOUND_FIELDS, BudgetGovernanceStore } from '../src/packages/arcane/lib/budget-governance-store.mjs';
import { digestValue } from '../src/packages/arcane/lib/canonical.mjs';
import { loadHostKeyRing } from '../src/packages/arcane/lib/keys.mjs';
import { signRecord } from '../src/packages/arcane/lib/receipt-auth.mjs';
import { TaskBudgetSealStore } from '../src/packages/arcane/lib/task-budget-seal-store.mjs';
import { HostEventLedger } from '../src/packages/arcane/lib/host-event-ledger.mjs';
import { b5Contract } from '../src/packages/arcane/tests/fixtures/runtime-binding-contract.mjs';

const SESSION = 'session-seal';
const ADAPTER = 'claude-code';

function scenario({ agentType = 'sage' } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'legion-seal-'));
  const keyDir = join(root, 'keys');
  mkdirSync(keyDir, { recursive: true });
  writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));

  // The host observes the agent, exactly as the SubagentStart hook would.
  new AuthorityBindingStore({ root: join(root, '.audit', 'arcane', 'authority-bindings') })
    .observe({ adapter: ADAPTER, sessionId: SESSION, agentId: 'agent-1', agentType, eventId: 'hev_test' });

  const contractPath = join(root, 'contract.json');
  writeFileSync(contractPath, JSON.stringify(b5Contract('EC-9')));

  const out = [];
  return {
    root,
    contractPath,
    ctx: {
      stdout: { write: (chunk) => out.push(chunk) },
      stderr: { write: () => {} },
      env: { ARCANE_KEY_DIR: keyDir },
      cwd: root,
    },
    out,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

test('a Sage-observed agent mints a contract seal', async () => {
  const s = scenario();
  try {
    const result = await runContract(
      ['seal', '--file', s.contractPath, '--agent', 'agent-1', '--session', SESSION],
      s.ctx,
    );
    assert.equal(result.exitCode, 0);
    const payload = JSON.parse(s.out.join(''));
    assert.equal(payload.kind, 'legion-contract-seal');
    assert.equal(payload.contractId, 'EC-9');
    assert.equal(payload.created, true);
    assert.equal(payload.sealedBy.authority, 'sage');
    assert.equal(payload.sealedBy.perMessage, true);
  } finally { s.cleanup(); }
});

test('nonempty evidence requirements seal only through exact reachable lifecycle input', async () => {
  const s = scenario();
  try {
    const contract = b5Contract('EC-10');
    contract.evidenceRequirements = ['independent acceptance proof'];
    writeFileSync(s.contractPath, JSON.stringify(contract));
    await assert.rejects(runContract(['seal', '--file', s.contractPath, '--agent', 'agent-1', '--session', SESSION], s.ctx), /ARC_UNSOUND_SEAL/);
    const reachability = join(s.root, 'reachability.json');
    writeFileSync(reachability, JSON.stringify({ requirements: [{ id: 'E-1', contractRequirement: 'independent acceptance proof', producer: 'oracle', durableStore: true, authenticatedPersistence: true, verifier: 'arcane', completionConsumer: 'legion', closePath: true }], recoveryPaths: [{ requirementId: 'E-1', authenticated: true, closePath: true }] }));
    const result = await runContract(['seal', '--file', s.contractPath, '--reachability', reachability, '--agent', 'agent-1', '--session', SESSION], s.ctx);
    assert.equal(result.exitCode, 0);
  } finally { s.cleanup(); }
});

test('Sage seal command creates exact contract & task budget bindings', async () => {
  const s = scenario();
  try {
    const contract = b5Contract('EC-11'); contract.budget = { objectiveLineageId: 'EC-11-lineage', objectiveDigest: digestValue('EC-11'), legionBlastMapCapMs: 900000, sagePlanningCapMs: 900000, maxContractVersions: 2 }; writeFileSync(s.contractPath, JSON.stringify(contract));
    const budgets = join(s.root, 'task-budgets.json');
    writeFileSync(budgets, JSON.stringify({ tasks: [{ taskId: 'T-1', ownScope: ['x'], activeTimeCapMs: 900000, progressDeadlineMs: 600000, evidenceReferences: ['AC-1'] }] }));
    await runContract(['seal', '--file', s.contractPath, '--task-budgets', budgets, '--agent', 'agent-1', '--session', SESSION], s.ctx);
    const keys = loadHostKeyRing({ dir: s.ctx.env.ARCANE_KEY_DIR });
    assert.equal(new BudgetGovernanceStore({ root: join(s.root, '.audit', 'arcane', 'budget-governance'), keyRing: keys }).require('EC-11', 1).contractDigest, digestValue(contract));
    assert.equal(new TaskBudgetSealStore({ root: join(s.root, '.audit', 'arcane', 'task-budget-seals'), keyRing: keys }).require('EC-11', 'T-1', 1).activeTimeCapMs, 900000);
  } finally { s.cleanup(); }
});

test('Sage seal command authenticates one bounded v1 → v2 budget amendment', async () => {
  const s = scenario();
  try {
    const budgets = join(s.root, 'task-budgets.json');
    writeFileSync(budgets, JSON.stringify({ tasks: [{ taskId: 'T-1', ownScope: ['x'], activeTimeCapMs: 900000, progressDeadlineMs: 600000, evidenceReferences: ['AC-1'] }] }));
    const first = b5Contract('EC-12'); first.budget = { objectiveLineageId: 'EC-12-lineage', objectiveDigest: digestValue('EC-12'), legionBlastMapCapMs: 900000, sagePlanningCapMs: 900000, maxContractVersions: 2 }; writeFileSync(s.contractPath, JSON.stringify(first));
    await runContract(['seal', '--file', s.contractPath, '--task-budgets', budgets, '--agent', 'agent-1', '--session', SESSION], s.ctx);
    const keys = loadHostKeyRing({ dir: s.ctx.env.ARCANE_KEY_DIR });
    new HostEventLedger({ root: join(s.root, '.audit', 'arcane', 'host-events'), keyRing: keys, keyId: keys.activeKeyId() }).append({ eventId: 'sage-v2-amendment', adapter: ADAPTER, eventType: 'SubagentStart', sessionId: SESSION, binding: { runId: 'run-v1', taskId: 'T-1', contractId: first.contractId, contractVersion: 1, contractDigest: digestValue(first) }, sourceRevision: first.sourceRevision, observedAuthority: 'sage', payload: {} });
    const second = structuredClone(first); second.version = 2; writeFileSync(s.contractPath, JSON.stringify(second)); s.out.length = 0;
    const result = await runContract(['seal', '--file', s.contractPath, '--task-budgets', budgets, '--agent', 'agent-1', '--session', SESSION], s.ctx);
    assert.equal(result.exitCode, 0);
    const stored = new BudgetGovernanceStore({ root: join(s.root, '.audit', 'arcane', 'budget-governance'), keyRing: keys }).require('EC-12', 2);
    assert.equal(stored.amendmentEvidence.priorContractDigest, digestValue(first));
    assert.equal(stored.amendmentEvidence.newContractDigest, digestValue(second));
    assert.equal(stored.amendmentEvidence.scopeExpanded, false);
  } finally { s.cleanup(); }
});

test('a non-sealer authority cannot mint a contract seal', async () => {
  const s = scenario({ agentType: 'alchemist' });
  try {
    await assert.rejects(
      runContract(['seal', '--file', s.contractPath, '--agent', 'agent-1', '--session', SESSION], s.ctx),
      /only Legion or Sage may seal/,
    );
  } finally { s.cleanup(); }
});

test('an unobserved agent cannot mint a contract seal', async () => {
  const s = scenario();
  try {
    await assert.rejects(
      runContract(['seal', '--file', s.contractPath, '--agent', 'ghost-agent', '--session', SESSION], s.ctx),
      /ARC_AUTHORITY_NOT_ASSERTED/,
    );
  } finally { s.cleanup(); }
});

test('authority cannot be claimed on the command line', async () => {
  const s = scenario({ agentType: 'alchemist' });
  try {
    // There is no --authority flag by design; passing one is a usage error,
    // never a promotion.
    await assert.rejects(
      runContract(['seal', '--file', s.contractPath, '--agent', 'agent-1', '--session', SESSION, '--authority', 'sage'], s.ctx),
      /Unknown option/,
    );
  } finally { s.cleanup(); }
});

test('sealing is idempotent for an identical contract version', async () => {
  const s = scenario();
  try {
    await runContract(['seal', '--file', s.contractPath, '--agent', 'agent-1', '--session', SESSION], s.ctx);
    s.out.length = 0;
    await runContract(['seal', '--file', s.contractPath, '--agent', 'agent-1', '--session', SESSION], s.ctx);
    assert.equal(JSON.parse(s.out.join('')).created, false);
  } finally { s.cleanup(); }
});

// The dead end, end to end: seal -> run open -> the pre-effect gate now
// AUTHORIZES a locked-domain write that was previously refused ARC_NO_CONTRACT
// with no supported way to fix it.
test('sealed contract + run open lets the gate authorize a locked-domain write', async () => {
  const { execFileSync } = await import('node:child_process');
  const { createHostRuntime } = await import('../src/packages/arcane/host/host-runtime.mjs');
  const { claudeCodeHostAdapter } = await import('../src/packages/arcane/host/claude-code-adapter.mjs');
  const { runRun } = await import('../src/lib/cli/commands/run.mjs');

  const s = scenario();
  const target = 'tools/rhook/src/main.rs'; // a locked domain in the real policy
  try {
    for (const args of [['init', '-q'], ['config', 'user.email', 't@e.com'], ['config', 'user.name', 't'], ['commit', '-qm', 'init', '--allow-empty']]) {
      execFileSync('git', args, { cwd: s.root });
    }
    const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: s.root, encoding: 'utf8' }).trim();

    const contract = b5Contract('EC-9');
    contract.sourceRevision = revision;
    contract.scope.own = ['tools/rhook/**'];
    contract.artifacts.exact[0].path = target;
    contract.authorizedEffectClasses = ['FILE_WRITE'];
    writeFileSync(s.contractPath, JSON.stringify(contract));

    await runContract(['seal', '--file', s.contractPath, '--agent', 'agent-1', '--session', SESSION], s.ctx);
    const keyRing = loadHostKeyRing({ dir: s.ctx.env.ARCANE_KEY_DIR });
    const contractDigest = digestValue(contract);
    const budget = {
      schemaVersion: 1,
      kind: 'arcane-budget-governance',
      contractId: contract.contractId,
      version: contract.version,
      contractDigest,
      objectiveLineageId: 'contract-seal-e2e',
      objectiveDigest: digestValue('contract-seal-e2e'),
      legionBlastMapCapMs: 900000,
      sagePlanningCapMs: 900000,
      maxContractVersions: 2,
      resumeEvidence: null,
    };
    budget.authentication = signRecord(budget, {
      keyRing,
      keyId: keyRing.activeKeyId(),
      boundFields: BUDGET_BOUND_FIELDS,
      macDomain: 'arcane-budget-governance-v1',
    });
    new BudgetGovernanceStore({ root: join(s.root, '.audit', 'arcane', 'budget-governance'), keyRing }).seal(budget);
    const task = { taskId: 'T-1', ownScope: ['tools/rhook/**'] };
    task.budgetSeal = {
      contractId: contract.contractId,
      contractVersion: contract.version,
      contractDigest,
      taskDigest: digestValue(task),
      scopeDigest: digestValue(task.ownScope),
      activeTimeCapMs: 900000,
      progressDeadlineMs: 900000,
      evidenceReferences: ['fixture:contract-seal-e2e'],
    };
    new TaskBudgetSealStore({ root: join(s.root, '.audit', 'arcane', 'task-budget-seals'), keyRing }).seal({
      contract,
      task,
      authorityAssertion: { authority: 'sage', assertedBy: 'agent-1', verificationMethod: 'capability-signature', perMessage: true },
    });
    await runRun(['open', '--contract', 'EC-9', '--version', '1', '--task', 'T-1', '--session', SESSION], s.ctx);

    const runtime = createHostRuntime({ adapter: claudeCodeHostAdapter, workspace: s.root, keyDir: join(s.root, 'keys') });
    const result = runtime.handle({
      hook_event_name: 'PreToolUse', cwd: s.root, session_id: SESSION,
      agent_id: 'agent-1', agent_type: 'sage',
      tool_name: 'Write', tool_input: { file_path: target }, tool_use_id: 'tu-sealed',
    });
    assert.notEqual(result.code, 'ARC_NO_CONTRACT');
    assert.equal(result.allowed, true, `denied: ${result.code}`);
    assert.ok(result.capabilityId, 'a capability was minted for the authorized effect');
  } finally { s.cleanup(); }
});
