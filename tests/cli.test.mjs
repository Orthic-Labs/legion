import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { EXIT, exitCodeForReport } from '../lib/errors.mjs';
import { NEMESIS_VERSION } from '../lib/version.mjs';
import { runCli } from '../lib/cli/run.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const BIN = new URL('../bin/nemesis.mjs', import.meta.url).pathname;

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
  assert.match(stdout, /nemesis <command>/);
  assert.match(stdout, /Commands:/);
});

test('--version prints the canonical version', () => {
  const { exitCode, stdout } = capture(['--version']);
  assert.equal(exitCode, EXIT.PASS);
  assert.equal(stdout.trim(), NEMESIS_VERSION);
});

test('no subcommand prints usage and exits 4', () => {
  const { exitCode, stdout } = capture([]);
  assert.equal(exitCode, EXIT.USAGE);
  assert.match(stdout, /nemesis <command>/);
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
  assert.equal(parsed.kind, 'nemesis-providers');
  assert.ok(Array.isArray(parsed.providers));
  assert.ok(parsed.providers.some((provider) => provider.id === 'framework.major-suite'));
});

test('languages --json emits the coverage family surface', () => {
  const { exitCode, stdout } = capture(['languages', '--json']);
  assert.equal(exitCode, EXIT.PASS);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.kind, 'nemesis-languages');
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
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-report-'));
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
