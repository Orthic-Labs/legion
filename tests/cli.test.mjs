import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { EXIT, exitCodeForReport } from '../lib/errors.mjs';
import { LEGION_VERSION } from '../lib/version.mjs';
import { runCli } from '../lib/cli/run.mjs';

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
