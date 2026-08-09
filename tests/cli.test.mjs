import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { EXIT, exitCodeForReport } from '../lib/errors.mjs';
import { LEGION_VERSION } from '../lib/version.mjs';
import { runCli } from '../lib/cli/run.mjs';
import { b5Contract, EC5_DIGEST, EC6_DIGEST, seedStore } from '../packages/arcane/tests/fixtures/runtime-binding-contract.mjs';
import { ReceiptStore } from '../packages/arcane/lib/receipt-store.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const BIN = fileURLToPath(new URL('../bin/legion.mjs', import.meta.url));

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

function runDir() {
  const dir = mkdtempSync(join(tmpdir(), 'legion-run-cli-'));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('run open mints a fresh binding and stamps contract/task', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedStore(join(dir, '.audit', 'arcane'));
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
    assert.equal(parsed.contractDigest, EC5_DIGEST);
  } finally {
    cleanup();
  }
});

test('run open is idempotent on runId — a repeat open for the same session upgrades contract/task but keeps runId', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedStore(join(dir, '.audit', 'arcane'));
    seedStore(join(dir, '.audit', 'arcane'), b5Contract('EC-6'));
    const firstOut = captureStream();
    const first = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--session', 'sess-repeat'],
      { stdout: firstOut, stderr: captureStream(), env: {}, cwd: dir },
    );
    assert.equal(first.exitCode, EXIT.PASS);
    const firstBinding = JSON.parse(firstOut.buf.trim());

    const secondOut = captureStream();
    const second = await runCli(
      ['run', 'open', '--contract', 'EC-6', '--version', '1', '--task', 'T-2', '--session', 'sess-repeat'],
      { stdout: secondOut, stderr: captureStream(), env: {}, cwd: dir },
    );
    assert.equal(second.exitCode, EXIT.PASS);
    const secondBinding = JSON.parse(secondOut.buf.trim());

    assert.equal(secondBinding.runId, firstBinding.runId, 'repeat open never mints a second runId');
    assert.equal(secondBinding.contractId, 'EC-6', 'contract/task upgrade applied');
    assert.equal(secondBinding.taskId, 'T-2');
    assert.equal(firstBinding.contractVersion, 1);
    assert.equal(firstBinding.contractDigest, EC5_DIGEST);
    assert.equal(secondBinding.contractVersion, 1);
    assert.equal(secondBinding.contractDigest, EC6_DIGEST);
  } finally {
    cleanup();
  }
});

test('run close clears contractId/taskId but keeps runId (reverts to ambient, run continues)', async () => {
  const { dir, cleanup } = runDir();
  try {
    seedStore(join(dir, '.audit', 'arcane'));
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
    assert.equal(closeResult.exitCode, EXIT.PASS);
    const closed = JSON.parse(closeOut.buf.trim());
    assert.equal(closed.runId, opened.runId, 'close keeps the runId — the run continues');
    assert.equal(closed.taskId, null);
    assert.equal(closed.contractId, null);
    assert.equal(closed.contractVersion, null);
    assert.equal(closed.contractDigest, null);
    assert.equal(closed.closeReceipt.kind, 'legion-run-close-receipt');
    assert.equal(closed.closeReceipt.runId, opened.runId);
    assert.equal(closed.closeReceipt.contractId, 'EC-5');
    assert.equal(closed.closeReceipt.finalClaimState, 'blocked');
    assert.equal(closed.closeReceipt.completionCode, 'ARC_EVIDENCE_INSUFFICIENT');
    const receipts = new ReceiptStore({ root: join(dir, '.audit', 'arcane', 'receipts') }).list({ runId: opened.runId });
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].kind, 'legion-run-close-receipt');
  } finally {
    cleanup();
  }
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
    seedStore(join(dir, '.audit', 'arcane'));
    const stderr = captureStream();
    const result = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1'],
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
    seedStore(join(dir, '.audit', 'arcane'));
    const stdout = captureStream();
    const result = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1'],
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
    seedStore(join(dir, '.audit', 'arcane'));
    const stdoutA = captureStream();
    const a = await runCli(
      ['run', 'open', '--contract', 'EC-5', '--version', '1', '--session', ''], // empty string is not a real override
      { stdout: stdoutA, stderr: captureStream(), env: { CLAUDE_SESSION_ID: 'env-sess-claude' }, cwd: dir },
    );
    assert.equal(a.exitCode, EXIT.PASS);
    assert.equal(JSON.parse(stdoutA.buf.trim()).sessionId, 'env-sess-claude');

    const { dir: dir2, cleanup: cleanup2 } = runDir();
    try {
      seedStore(join(dir2, '.audit', 'arcane'));
      const stdoutB = captureStream();
      const b = await runCli(
        ['run', 'open', '--contract', 'EC-5', '--version', '1'],
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
