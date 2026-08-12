import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { EXIT, exitCodeForReport } from '../lib/errors.mjs';
import { LEGION_VERSION } from '../lib/version.mjs';
import { runCli as runCliRaw } from '../lib/cli/run.mjs';
import { runRun as runRunRaw } from '../lib/cli/commands/run.mjs';
import { b5Contract, seedStore } from '../packages/arcane/tests/fixtures/runtime-binding-contract.mjs';
import { ReceiptStore } from '../packages/arcane/lib/receipt-store.mjs';
import { SessionBindingStore } from '../packages/arcane/lib/session-binding.mjs';
import { loadHostKeyRing } from '../packages/arcane/lib/keys.mjs';
import { digestValue } from '../packages/arcane/lib/canonical.mjs';
import { signRecord } from '../packages/arcane/lib/receipt-auth.mjs';
import { BudgetGovernanceStore, BUDGET_BOUND_FIELDS } from '../packages/arcane/lib/budget-governance-store.mjs';
import { TaskBudgetSealStore } from '../packages/arcane/lib/task-budget-seal-store.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const BIN = fileURLToPath(new URL('../bin/legion.mjs', import.meta.url));
const testKeyDir = (cwd) => join(cwd, '.audit', 'arcane', 'test-keys');
const withTestKeys = (options) => ({ ...options, env: { ARCANE_KEY_DIR: testKeyDir(options.cwd), ...options.env } });
const runCli = (args, options) => runCliRaw(args, withTestKeys(options));
const runRun = (args, options) => runRunRaw(args, withTestKeys(options));

function capture(args) {
  const result = spawnSync(process.execPath, [BIN, ...args], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return { exitCode: result.status, stdout: result.stdout, stderr: result.stderr };
}

test('--help prints usage and exits 0', () => {
  const { exitCode, stdout } = capture(['--help']);
  assert.equal(exitCode, EXIT.PASS);
  assert.match(stdout, /legion <command>/);
  assert.match(stdout, /Commands:/);
});

test('--version prints the canonical version', () => {
  const { exitCode, stdout } = capture(['--version']);
  assert.equal(exitCode, EXIT.PASS);
  assert.equal(stdout.trim(), LEGION_VERSION);
});

test('no subcommand prints usage and exits 4', () => {
  const { exitCode, stdout } = capture([]);
  assert.equal(exitCode, EXIT.USAGE);
  assert.match(stdout, /legion <command>/);
});

test('unknown subcommand exits 4', () => {
  const { exitCode, stderr } = capture(['frobnicate']);
  assert.equal(exitCode, EXIT.USAGE);
  assert.match(stderr, /unknown command/);
});

test('providers --json emits machine JSON on stdout', () => {
  const { exitCode, stdout } = capture(['providers', '--json']);
  assert.equal(exitCode, EXIT.PASS);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.kind, 'legion-providers');
  assert.ok(Array.isArray(parsed.providers));
  assert.ok(parsed.providers.some((provider) => provider.id === 'framework.major-suite'));
});

test('languages --json emits the coverage family surface', () => {
  const { exitCode, stdout } = capture(['languages', '--json']);
  assert.equal(exitCode, EXIT.PASS);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.kind, 'legion-languages');
  assert.ok(Array.isArray(parsed.languages));
});

test('plan --json seals a plan for the checkout root', () => {
  const { exitCode, stdout } = capture(['plan', root, '--json']);
  assert.equal(exitCode, EXIT.PASS);
  const plan = JSON.parse(stdout);
  assert.equal(plan.kind, 'audit-provider-plan');
  assert.ok(plan.seal.digest, 'plan is sealed');
});

test('report --format json renders a report', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-report-'));
  const reportPath = join(dir, 'report.json');
  writeFileSync(reportPath, JSON.stringify({
    kind: 'repository-audit-report', audit_status: 'pass', findings: [], coverage_gaps: [],
  }));
  try {
    const { exitCode, stdout } = capture(['report', reportPath, '--format', 'json']);
    assert.equal(exitCode, EXIT.PASS);
    assert.equal(JSON.parse(stdout).kind, 'repository-audit-report');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verify resolves a run directory to its facts artifact', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-verify-run-'));
  writeFileSync(join(dir, 'facts.json'), '{}');
  writeFileSync(join(dir, 'plan.json'), '{}');
  try {
    const { stderr } = capture(['verify', dir]);
    assert.doesNotMatch(stderr, /EISDIR|facts artifact missing/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verify preserves direct facts-file support', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-verify-file-'));
  const facts = join(dir, 'facts.json');
  writeFileSync(facts, '{}');
  try {
    const { stderr } = capture(['verify', facts]);
    assert.doesNotMatch(stderr, /EISDIR|facts artifact missing|plan artifact missing/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verify reports a typed missing-facts error for an invalid run directory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-verify-missing-'));
  try {
    const { exitCode, stderr } = capture(['verify', dir]);
    assert.equal(exitCode, EXIT.USAGE);
    assert.match(stderr, /verify facts artifact missing:/);
    assert.doesNotMatch(stderr, /EISDIR/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verify reports a typed missing-plan error for an incomplete run directory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-verify-plan-'));
  writeFileSync(join(dir, 'facts.json'), '{}');
  try {
    const { exitCode, stderr } = capture(['verify', dir]);
    assert.equal(exitCode, EXIT.USAGE);
    assert.match(stderr, /verify plan artifact missing:/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('exit taxonomy maps report states to codes', () => {
  assert.equal(exitCodeForReport({ audit_status: 'pass' }), 0);
  assert.equal(exitCodeForReport({ audit_status: 'fail' }), 1);
  assert.equal(exitCodeForReport({ audit_status: 'incomplete' }), 2);
  assert.equal(exitCodeForReport({ integrity: { valid: false } }), 5);
});

test('runCli returns structured results with injected streams', async () => {
  const stdout = { write() {} };
  const stderr = { write() {} };
  const result = await runCli(['--version'], { stdout, stderr, env: process.env, cwd: root });
  assert.equal(result.exitCode, EXIT.PASS);
});

test('rules compile previews and atomically writes a policy', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-rules-'));
  try {
    const source = join(root, 'packages', 'arcane', 'policy', 'arcane-policy-v1.rules');
    const base = join(root, 'packages', 'arcane', 'policy', 'arcane-policy-v1.json');
    const preview = capture(['rules', 'compile', source, '--base', base]);
    assert.equal(preview.exitCode, EXIT.PASS, preview.stderr);
    assert.deepEqual(JSON.parse(preview.stdout).effectRules, JSON.parse(readFileSync(base, 'utf8')).effectRules);
    const output = join(dir, 'compiled.json');
    const written = capture(['rules', 'compile', source, '--base', base, '--out', output]);
    assert.equal(written.exitCode, EXIT.PASS, written.stderr);
    assert.equal(JSON.parse(written.stdout).output, output);
    assert.deepEqual(JSON.parse(readFileSync(output, 'utf8')).effectRules, JSON.parse(readFileSync(base, 'utf8')).effectRules);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ────────────────────────────────────────────────────── EC-5 item 3: `run open|close`
//
// Every test here supplies its OWN `env` object (never `process.env`) so the
// session-id resolution path is fully deterministic regardless of what
// happens to be set in whatever environment actually runs this suite, and
// its own temp `cwd` so `.audit/arcane/session-bindings/` never collides
// across tests or leaks into the real checkout.

function captureStream() {
  const stream = { buf: '', write(chunk) { stream.buf += chunk; } };
  return stream;
}

function failingReceiptStoreFactory(kind) {
  let failed = false;
  return ({ root }) => {
    const store = new ReceiptStore({ root });
    return {
      list: (...args) => store.list(...args),
      append(record) {
        if (!failed && record.kind === kind) { failed = true; throw new Error(`${kind} append failed`); }
        return store.append(record);
      },
    };
  };
}

function runDir() {
  const dir = mkdtempSync(join(tmpdir(), 'legion-run-cli-'));
  spawnSync('git', ['init', '--initial-branch=main'], { cwd: dir });
  spawnSync('git', ['config', 'user.email', 'test@example.test'], { cwd: dir });
  spawnSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
  writeFileSync(join(dir, 'tracked.txt'), 'base\n');
  spawnSync('git', ['add', '.'], { cwd: dir });
  spawnSync('git', ['commit', '-m', 'base'], { cwd: dir });
  mkdirSync(testKeyDir(dir), { recursive: true });
  writeFileSync(join(testKeyDir(dir), 'k1.key'), '11'.repeat(32));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function seedCurrent(dir, contract = b5Contract()) {
  const sourceRevision = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).stdout.trim();
  assert.match(sourceRevision, /^[0-9a-f]{40}$/);
  contract.sourceRevision = sourceRevision;
  const seeded = seedStore(join(dir, '.audit', 'arcane'), contract);
  const keyRing = loadHostKeyRing({ dir: testKeyDir(dir) });
  const budget = {
    schemaVersion: 1,
    kind: 'arcane-budget-governance',
    contractId: contract.contractId,
    version: contract.version,
    contractDigest: seeded.record.contractDigest,
    objectiveLineageId: 'cli-fixture-lineage',
    objectiveDigest: digestValue('cli-fixture-objective'),
    legionBlastMapCapMs: 900000,
    sagePlanningCapMs: 900000,
    maxContractVersions: 2,
    resumeEvidence: null,
  };
  budget.authentication = signRecord(budget, { keyRing, keyId: 'k1', boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
  new BudgetGovernanceStore({ root: join(dir, '.audit', 'arcane', 'budget-governance'), keyRing }).seal(budget);
  const taskStore = new TaskBudgetSealStore({ root: join(dir, '.audit', 'arcane', 'task-budget-seals'), keyRing, keyId: 'k1', clock: () => '2026-08-12T00:00:00.000Z' });
  for (const taskId of ['T-1', 'T-2']) {
    const task = { taskId, ownScope: ['**'] };
    task.budgetSeal = { contractId: contract.contractId, contractVersion: contract.version, contractDigest: seeded.record.contractDigest, taskDigest: digestValue(task), scopeDigest: digestValue(task.ownScope), activeTimeCapMs: 900000, progressDeadlineMs: 900000, evidenceReferences: ['fixture:cli-budget'] };
    taskStore.seal({ contract, task, authorityAssertion: { authority: 'sage', assertedBy: 'test-fixture', verificationMethod: 'capability-signature', perMessage: true } });
  }
  return seeded;
}

function deliveryManifestPath(dir, sessionId, binding) {
  const token = createHash('sha256').update(`${sessionId}\0${binding.runId}\0${binding.taskId}`).digest('hex');
  return join(dir, '.audit', 'arcane', 'delivery', 'manifests', `${token}.json`);
}

function appendMatchingArchiveCloseReceipt(dir, sessionId, binding) {
  new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') }).append({
    schemaVersion: 1, kind: 'legion-run-close-receipt', sessionId, runId: binding.runId, taskId: binding.taskId,
    contractId: binding.contractId, contractVersion: binding.contractVersion, contractDigest: binding.contractDigest,
    finalClaimState: 'passed', completionCode: 'ARC_ARCHIVE', enforcementHealth: 'not-applicable', deliveryDisposition: 'archive',
    deliveryEvidence: binding.delivery.repositories.map((repo) => ({ repository: repo.root, baselineTree: repo.snapshotTree, leaseToken: repo.leaseToken ?? null })),
  });
}

test('run open mints a fresh binding and stamps contract/task', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir);
    const stdout = captureStream();
    const stderr = captureStream();
    const result = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-open-1'],
      { stdout, stderr, env: {}, cwd: dir },
    );
    assert.equal(result.exitCode, EXIT.PASS, stderr.buf);
    const parsed = JSON.parse(stdout.buf.trim());
    assert.equal(parsed.kind, 'legion-run-binding');
    assert.equal(parsed.sessionId, 'sess-open-1');
    assert.match(parsed.runId, /^run_[0-9A-HJKMNP-TV-Z]{26}$/);
    assert.equal(parsed.taskId, 'T-1');
    assert.equal(parsed.contractId, 'EC-5');
    assert.equal(parsed.contractVersion, 1);
    assert.match(parsed.contractDigest, /^sha256:[0-9a-f]{64}$/);
  } finally {
    cleanup();
  }
});

test('run open is idempotent on runId — a repeat open for the same session upgrades contract/task but keeps runId', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir);
    seedCurrent(dir, b5Contract('EC-6'));
    const firstOut = captureStream();
    const first = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-repeat'],
      { stdout: firstOut, stderr: captureStream(), env: {}, cwd: dir },
    );
    assert.equal(first.exitCode, EXIT.PASS);
    const firstBinding = JSON.parse(firstOut.buf.trim());
    writeFileSync(join(dir, 'after-open.txt'), 'must remain task output\n');

    const secondOut = captureStream();
    const second = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-repeat'],
      { stdout: secondOut, stderr: captureStream(), env: {}, cwd: dir },
    );
    assert.equal(second.exitCode, EXIT.PASS);
    const secondBinding = JSON.parse(secondOut.buf.trim());

    assert.equal(secondBinding.runId, firstBinding.runId, 'repeat open never mints a second runId');
    assert.equal(secondBinding.contractId, 'EC-5', 'exact repeat remains on original contract');
    assert.equal(secondBinding.taskId, 'T-1');
    assert.equal(firstBinding.contractVersion, 1);
    assert.match(firstBinding.contractDigest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(secondBinding.contractVersion, 1);
    assert.equal(secondBinding.contractDigest, firstBinding.contractDigest);
    assert.equal(secondBinding.delivery.repositories[0].snapshotTree, firstBinding.delivery.repositories[0].snapshotTree, 'same-owner reopen retains original baseline');
  } finally {
    cleanup();
  }
});

test('run open rejects active delivery contract/task change without replacing its lease or binding', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); seedCurrent(dir, b5Contract('EC-6'));
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-active'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    const stderr = captureStream();
    const result = await runCli(['run', 'open', '--contract', 'EC-6', '--version', '1', '--task', 'T-2', '--session', 'sess-active'], { stdout: captureStream(), stderr, env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.match(stderr.buf, /ARC_INTEGRATION_OWNER_CONFLICT/);
    assert.equal(JSON.parse(readFileSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json'), 'utf8')).taskId, 'T-1');
    const binding = new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') }).getBinding('sess-active');
    assert.equal(binding.contractId, 'EC-5'); assert.equal(binding.taskId, 'T-1');
  } finally { cleanup(); }
});

test('run open rejects active delivery repository or mode changes without new lease', async () => {
  const a = runDir(), b = runDir();
  try {
    seedCurrent(a.dir);
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-repos', '--repo', a.dir], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: a.dir });
    const other = await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-repos', '--repo', b.dir], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: a.dir });
    const mode = await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-repos', '--repo', a.dir, '--read-only'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: a.dir });
    assert.equal(other.exitCode, EXIT.INCOMPLETE); assert.equal(mode.exitCode, EXIT.INCOMPLETE);
    assert.equal(existsSync(join(a.dir, '.audit', 'arcane', 'delivery', 'lease.json')), true); assert.equal(existsSync(join(b.dir, '.audit', 'arcane', 'delivery', 'lease.json')), false);
  } finally { a.cleanup(); b.cleanup(); }
});

test('run close retains its binding when completion evidence blocks', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir);
    const openOut = captureStream();
    await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-close-1'],
      { stdout: openOut, stderr: captureStream(), env: {}, cwd: dir },
    );
    const opened = JSON.parse(openOut.buf.trim());

    const closeOut = captureStream();
    const closeResult = await runCli(
      ['run', 'close', '--session', 'sess-close-1'],
      { stdout: closeOut, stderr: captureStream(), env: {}, cwd: dir },
    );
    assert.equal(closeResult.exitCode, EXIT.INCOMPLETE);
    assert.equal(closeOut.buf, '');
    const receipts = new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') }).list({ runId: opened.runId });
    assert.equal(receipts.length, 0);
  } finally {
    cleanup();
  }
});

test('run close archive succeeds without signoff & clears delivery lease', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir);
    const openOut = captureStream();
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-archive'], { stdout: openOut, stderr: captureStream(), env: {}, cwd: dir });
    const opened = JSON.parse(openOut.buf);
    writeFileSync(join(dir, 'tracked.txt'), 'changed\n');
    const closeOut = captureStream();
    const result = await runCli(['run', 'close', '--session', 'sess-archive', '--disposition', 'archive'], { stdout: closeOut, stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.PASS);
    assert.equal(JSON.parse(closeOut.buf).closeReceipt.deliveryDisposition, 'archive');
    assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), false);
    const manifest = createHash('sha256').update(`sess-archive\0${opened.runId}\0T-1`).digest('hex');
    assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'manifests', `${manifest}.json`)), false);
  } finally { cleanup(); }
});

test('delivery receipt append failure retains authority, binding, & manifest', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); const openedOut = captureStream();
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-delivery-append'], { stdout: openedOut, stderr: captureStream(), env: {}, cwd: dir }); const opened = JSON.parse(openedOut.buf);
    writeFileSync(join(dir, 'tracked.txt'), 'changed\n'); const out = captureStream();
    await assert.rejects(() => runRun(['close', '--session', 'sess-delivery-append', '--disposition', 'archive'], { stdout: out, stderr: captureStream(), env: {}, cwd: dir, receiptStoreFactory: failingReceiptStoreFactory('arcane-delivery-receipt') }), { code: 'ARC_DELIVERY_RECEIPT_FAILED' });
    assert.equal(out.buf, ''); assert.equal(new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') }).list({ runId: opened.runId }).length, 0); assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), true); assert.equal(new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') }).getBinding('sess-delivery-append').contractId, 'EC-5');
  } finally { cleanup(); }
});

test('terminal receipt append retry dedupes delivery evidence before release', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); const openedOut = captureStream();
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-terminal-append'], { stdout: openedOut, stderr: captureStream(), env: {}, cwd: dir }); const opened = JSON.parse(openedOut.buf);
    writeFileSync(join(dir, 'tracked.txt'), 'changed\n'); const failedOut = captureStream();
    await assert.rejects(() => runRun(['close', '--session', 'sess-terminal-append', '--disposition', 'archive'], { stdout: failedOut, stderr: captureStream(), env: {}, cwd: dir, receiptStoreFactory: failingReceiptStoreFactory('legion-run-close-receipt') }), { code: 'ARC_DELIVERY_RECEIPT_FAILED' });
    const store = new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') }); assert.equal(failedOut.buf, ''); assert.equal(store.list({ runId: opened.runId }).filter((record) => record.kind === 'arcane-delivery-receipt').length, 1); assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), true);
    const retry = captureStream(); const result = await runRun(['close', '--session', 'sess-terminal-append', '--disposition', 'archive'], { stdout: retry, stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.PASS); assert.equal(store.list({ runId: opened.runId }).filter((record) => record.kind === 'arcane-delivery-receipt').length, 1); assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), false); assert.equal(new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') }).getBinding('sess-terminal-append').contractId, null);
  } finally { cleanup(); }
});

test('archive close excludes unignored Arcane control state from task snapshot', async () => {
  const { dir, cleanup } = runDir();
  try {
    spawnSync('git', ['rm', '.gitignore'], { cwd: dir }); spawnSync('git', ['commit', '-m', 'unignore audit'], { cwd: dir });
    seedCurrent(dir); const beforeIndex = readFileSync(join(dir, '.git', 'index')); const beforeStatus = spawnSync('git', ['status', '--porcelain=v1'], { cwd: dir, encoding: 'utf8' }).stdout;
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-control-clean'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    const result = await runCli(['run', 'close', '--session', 'sess-control-clean', '--disposition', 'archive'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.PASS);
    const delivery = new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') }).list().find((receipt) => receipt.kind === 'arcane-delivery-receipt');
    assert.equal(delivery.state, 'clean'); assert.equal(delivery.patch, null); assert.deepEqual(readFileSync(join(dir, '.git', 'index')), beforeIndex); assert.equal(spawnSync('git', ['status', '--porcelain=v1'], { cwd: dir, encoding: 'utf8' }).stdout, beforeStatus);
  } finally { cleanup(); }
});

test('unrelated synthetic same-run receipt cannot recover but normal archive close proceeds', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir);
    const openOut = captureStream();
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-recovery'], { stdout: openOut, stderr: captureStream(), env: {}, cwd: dir });
    const opened = JSON.parse(openOut.buf);
    const receipts = new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') });
    receipts.append({ kind: 'legion-run-close-receipt', runId: opened.runId, deliveryDisposition: 'archive', finalClaimState: 'passed' });
    const result = await runCli(['run', 'close', '--session', 'sess-recovery', '--disposition', 'archive'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.PASS);
    assert.equal(receipts.list({ runId: opened.runId }).filter((receipt) => receipt.kind === 'legion-run-close-receipt').length, 2);
    assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), false);
    const binding = JSON.parse(readFileSync(join(dir, '.audit', 'arcane', 'session-bindings', `${createHash('sha256').update('sess-recovery').digest('hex')}.json`), 'utf8'));
    assert.equal(binding.contractId, null);
  } finally { cleanup(); }
});

test('contracted binding without delivery metadata fails closed without receipt or clear', async () => {
  const { dir, cleanup } = runDir();
  try {
    const sealed = seedCurrent(dir);
    const bindings = new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') });
    bindings.putBinding('sess-no-delivery', { runId: 'run_no_delivery', taskId: 'T-1', contractId: 'EC-5', contractVersion: 1, contractDigest: sealed.record.contractDigest });
    const stderr = captureStream();
    const result = await runCli(['run', 'close', '--session', 'sess-no-delivery'], { stdout: captureStream(), stderr, env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.match(stderr.buf, /ARC_DELIVERY_METADATA_MISSING/);
    assert.equal(new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') }).list({ runId: 'run_no_delivery' }).length, 0);
    assert.equal(bindings.getBinding('sess-no-delivery').contractId, 'EC-5');
  } finally { cleanup(); }
});

test('archived budgeted run cannot authenticate a second delivery with its stale terminal receipt', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir);
    const first = captureStream();
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-sequential'], { stdout: first, stderr: captureStream(), env: {}, cwd: dir });
    const runId = JSON.parse(first.buf).runId;
    assert.equal((await runCli(['run', 'close', '--session', 'sess-sequential', '--disposition', 'archive'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir })).exitCode, EXIT.PASS);
    const secondOpenError = captureStream();
    assert.equal((await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-sequential'], { stdout: captureStream(), stderr: secondOpenError, env: {}, cwd: dir })).exitCode, EXIT.PASS, secondOpenError.buf);
    const secondCloseError = captureStream();
    assert.equal((await runCli(['run', 'close', '--session', 'sess-sequential', '--disposition', 'archive'], { stdout: captureStream(), stderr: secondCloseError, env: {}, cwd: dir })).exitCode, EXIT.INCOMPLETE);
    assert.match(secondCloseError.buf, /terminal receipt does not authenticate this binding/);
    assert.equal(new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') }).getBinding('sess-sequential').runId, runId);
    const receipts = new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') }).list({ runId });
    assert.equal(receipts.filter((receipt) => receipt.kind === 'legion-run-close-receipt').length, 1);
    const deliveries = receipts.filter((receipt) => receipt.kind === 'arcane-delivery-receipt');
    assert.equal(deliveries.length, 1); assert.deepEqual(new Set(deliveries.map((receipt) => receipt.contractId)), new Set(['EC-5']));
  } finally { cleanup(); }
});

test('forged current-binding delivery receipt mismatch blocks archive close', async () => {
  const { dir, cleanup } = runDir();
  try {
    const sealed = seedCurrent(dir); const openedOut = captureStream();
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-forged'], { stdout: openedOut, stderr: captureStream(), env: {}, cwd: dir });
    const opened = JSON.parse(openedOut.buf); const delivery = opened.delivery.repositories[0];
    new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') }).append({ kind: 'legion-run-close-receipt', sessionId: 'sess-forged', runId: opened.runId, contractId: 'EC-5', contractVersion: 1, contractDigest: sealed.record.contractDigest, deliveryDisposition: 'archive', deliveryEvidence: [{ repository: delivery.root, baselineTree: 'forged', leaseToken: delivery.leaseToken }] });
    const result = await runCli(['run', 'close', '--session', 'sess-forged', '--disposition', 'archive'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), true);
    assert.equal(new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') }).getBinding('sess-forged').contractId, 'EC-5');
  } finally { cleanup(); }
});

test('matching close receipt recovers only after authority & manifest have both released', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); const out = captureStream(); const sessionId = 'sess-manifest-recover';
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', sessionId], { stdout: out, stderr: captureStream(), env: {}, cwd: dir });
    const opened = JSON.parse(out.buf); appendMatchingArchiveCloseReceipt(dir, sessionId, opened);
    unlinkSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')); unlinkSync(deliveryManifestPath(dir, sessionId, opened));
    const result = await runCli(['run', 'close', '--session', sessionId, '--disposition', 'archive'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.PASS);
    assert.equal(new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') }).getBinding(sessionId).contractId, null);
  } finally { cleanup(); }
});

test('missing manifest with remaining authority blocks recovery & retains binding', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); const out = captureStream(); const sessionId = 'sess-manifest-missing';
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', sessionId], { stdout: out, stderr: captureStream(), env: {}, cwd: dir });
    const opened = JSON.parse(out.buf); appendMatchingArchiveCloseReceipt(dir, sessionId, opened); unlinkSync(deliveryManifestPath(dir, sessionId, opened));
    const stderr = captureStream(); const result = await runCli(['run', 'close', '--session', sessionId, '--disposition', 'archive'], { stdout: captureStream(), stderr, env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.match(stderr.buf, /manifest is missing/);
    assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), true);
    assert.equal(new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') }).getBinding(sessionId).contractId, 'EC-5');
  } finally { cleanup(); }
});

test('present mismatched manifest blocks recovery & retains binding', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); const out = captureStream(); const sessionId = 'sess-manifest-forged';
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', sessionId], { stdout: out, stderr: captureStream(), env: {}, cwd: dir });
    const opened = JSON.parse(out.buf); appendMatchingArchiveCloseReceipt(dir, sessionId, opened);
    const path = deliveryManifestPath(dir, sessionId, opened); const forged = JSON.parse(readFileSync(path, 'utf8')); forged.token = 'forged'; writeFileSync(path, JSON.stringify(forged));
    const stderr = captureStream(); const result = await runCli(['run', 'close', '--session', sessionId, '--disposition', 'archive'], { stdout: captureStream(), stderr, env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.match(stderr.buf, /manifest differs/);
    assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), true);
    assert.equal(new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') }).getBinding(sessionId).contractId, 'EC-5');
  } finally { cleanup(); }
});

test('tampered write delivery binding cannot mint clean close', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-tamper-write'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    const path = join(dir, '.audit', 'arcane', 'session-bindings', `${createHash('sha256').update('sess-tamper-write').digest('hex')}.json`); const binding = JSON.parse(readFileSync(path, 'utf8')); binding.delivery.repositories[0].snapshotTree = '0'.repeat(40); writeFileSync(path, JSON.stringify(binding));
    const result = await runCli(['run', 'close', '--session', 'sess-tamper-write', '--disposition', 'archive'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), true);
  } finally { cleanup(); }
});

test('dropped repository array cannot bypass workspace delivery manifest', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-drop'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    const path = join(dir, '.audit', 'arcane', 'session-bindings', `${createHash('sha256').update('sess-drop').digest('hex')}.json`); const binding = JSON.parse(readFileSync(path, 'utf8')); binding.delivery.repositories = []; writeFileSync(path, JSON.stringify(binding));
    const result = await runCli(['run', 'close', '--session', 'sess-drop', '--disposition', 'archive'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), true);
  } finally { cleanup(); }
});

test('copied delivery binding under another session cannot use manifest authority', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-source'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    const source = join(dir, '.audit', 'arcane', 'session-bindings', `${createHash('sha256').update('sess-source').digest('hex')}.json`); const copy = join(dir, '.audit', 'arcane', 'session-bindings', `${createHash('sha256').update('sess-copy').digest('hex')}.json`); writeFileSync(copy, readFileSync(source));
    const result = await runCli(['run', 'close', '--session', 'sess-copy', '--disposition', 'archive'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json')), true);
  } finally { cleanup(); }
});

test('forged current-session manifest cannot steal another owner delivery authority', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); const sourceSession = 'sess-owner-one', copiedSession = 'sess-owner-two';
    await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', sourceSession], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    const bindings = new SessionBindingStore({ root: join(dir, '.audit', 'arcane', 'session-bindings') }); const copied = bindings.getBinding(sourceSession);
    const owner = { sessionId: copiedSession, runId: copied.runId, taskId: copied.taskId };
    const repositories = copied.delivery.repositories.map(({ reused, ...repo }) => repo).sort((a, b) => a.commonDir.localeCompare(b.commonDir));
    const manifest = { owner, repositories, token: 'forged-owner-two-manifest' };
    copied.delivery.manifest = { token: manifest.token, digest: createHash('sha256').update(JSON.stringify(manifest)).digest('hex') };
    bindings.putBinding(copiedSession, copied); writeFileSync(deliveryManifestPath(dir, copiedSession, copied), JSON.stringify(manifest));
    const stderr = captureStream(); const result = await runCli(['run', 'close', '--session', copiedSession, '--disposition', 'archive'], { stdout: captureStream(), stderr, env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.match(stderr.buf, /authority owner differs/);
    assert.equal(JSON.parse(readFileSync(join(dir, '.audit', 'arcane', 'delivery', 'lease.json'), 'utf8')).sessionId, sourceSession);
    assert.equal(bindings.getBinding(copiedSession).contractId, 'EC-5');
  } finally { cleanup(); }
});

test('tampered read-only delivery binding blocks & retains acquisition', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir); const out = captureStream(); await runCli(['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', 'sess-tamper-read', '--read-only'], { stdout: out, stderr: captureStream(), env: {}, cwd: dir });
    const opened = JSON.parse(out.buf); const key = opened.delivery.repositories[0].acquisitionKey; const path = join(dir, '.audit', 'arcane', 'session-bindings', `${createHash('sha256').update('sess-tamper-read').digest('hex')}.json`); const binding = JSON.parse(readFileSync(path, 'utf8')); binding.delivery.repositories[0].snapshotTree = '0'.repeat(40); writeFileSync(path, JSON.stringify(binding));
    const result = await runCli(['run', 'close', '--session', 'sess-tamper-read', '--disposition', 'archive'], { stdout: captureStream(), stderr: captureStream(), env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.INCOMPLETE); assert.equal(existsSync(join(dir, '.audit', 'arcane', 'delivery', 'acquisitions', `${key}.json`)), true);
  } finally { cleanup(); }
});

test('run close with no prior binding fails USAGE, never mints one', async () => {
  const { dir, cleanup } = runDir();
  try {
    const stderr = captureStream();
    const result = await runCli(
      ['run', 'close', '--session', 'sess-never-opened'],
      { stdout: captureStream(), stderr, env: {}, cwd: dir },
    );
    assert.equal(result.exitCode, EXIT.USAGE);
    assert.match(stderr.buf, /no binding exists for this session/);
  } finally {
    cleanup();
  }
});

test('run open rejects a malformed --contract id as USAGE', async () => {
  const { dir, cleanup } = runDir();
  try {
    const stderr = captureStream();
    const result = await runCli(
      ['run', 'open', '--contract', 'not-an-ec-id', '--session', 'sess-bad-contract'],
      { stdout: captureStream(), stderr, env: {}, cwd: dir },
    );
    assert.equal(result.exitCode, EXIT.USAGE);
    assert.match(stderr.buf, /--contract/);
  } finally {
    cleanup();
  }
});

test('run open rejects a malformed --task id as USAGE', async () => {
  const { dir, cleanup } = runDir();
  try {
    const stderr = captureStream();
    const result = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'not-a-task-id'],
      { stdout: captureStream(), stderr, env: {}, cwd: dir },
    );
    assert.equal(result.exitCode, EXIT.USAGE);
    assert.match(stderr.buf, /--task/);
    assert.doesNotMatch(stderr.buf, /ARC_SESSION_UNKNOWN/);
  } finally {
    cleanup();
  }
});

test('run open with no --session and no session env var anywhere fails ARC_SESSION_UNKNOWN, never guesses', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir);
    const stderr = captureStream();
    const result = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1'],
      { stdout: captureStream(), stderr, env: {}, cwd: dir }, // env deliberately empty
    );
    assert.equal(result.exitCode, EXIT.USAGE);
    assert.match(stderr.buf, /ARC_SESSION_UNKNOWN/);
  } finally {
    cleanup();
  }
});

test('run open resolves the session id from CLAUDE_CODE_SESSION_ID when --session is not given (the verified real name)', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir);
    const stdout = captureStream();
    const result = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1'],
      { stdout, stderr: captureStream(), env: { CLAUDE_CODE_SESSION_ID: 'env-sess-1' }, cwd: dir },
    );
    assert.equal(result.exitCode, EXIT.PASS);
    assert.equal(JSON.parse(stdout.buf.trim()).sessionId, 'env-sess-1');
  } finally {
    cleanup();
  }
});

test('run open falls back to CLAUDE_SESSION_ID then CODEX_SESSION_ID when CLAUDE_CODE_SESSION_ID is absent', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedCurrent(dir);
    const stdoutA = captureStream();
    const a = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1', '--session', ''], // empty string is not a real override
      { stdout: stdoutA, stderr: captureStream(), env: { CLAUDE_SESSION_ID: 'env-sess-claude' }, cwd: dir },
    );
    assert.equal(a.exitCode, EXIT.PASS);
    assert.equal(JSON.parse(stdoutA.buf.trim()).sessionId, 'env-sess-claude');

    const { dir: dir2, cleanup: cleanup2 } = runDir();
    try {
      seedCurrent(dir2);
      const stdoutB = captureStream();
      const b = await runCli(
        ['run', 'open', '--contract', 'EC-5', '--version', '1', '--task', 'T-1'],
        { stdout: stdoutB, stderr: captureStream(), env: { CODEX_SESSION_ID: 'env-sess-codex' }, cwd: dir2 },
      );
      assert.equal(b.exitCode, EXIT.PASS);
      assert.equal(JSON.parse(stdoutB.buf.trim()).sessionId, 'env-sess-codex');
    } finally {
      cleanup2();
    }
  } finally {
    cleanup();
  }
});

test('run with an unknown subcommand fails USAGE', async () => {
  const { dir, cleanup } = runDir();
  try {
    const stderr = captureStream();
    const result = await runCli(['run', 'frobnicate'], { stdout: captureStream(), stderr, env: {}, cwd: dir });
    assert.equal(result.exitCode, EXIT.USAGE);
    assert.match(stderr.buf, /run requires a subcommand/);
  } finally {
    cleanup();
  }
});
