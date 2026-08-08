import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const BIN = fileURLToPath(new URL('../bin/nemesis.mjs', import.meta.url));
const root = fileURLToPath(new URL('..', import.meta.url));

function doctor(args = [], env = {}) {
  return spawnSync(process.execPath, [BIN, 'doctor', ...args, '--json'], {
    cwd: root, encoding: 'utf8', env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'],
  });
}

test('doctor --json emits the canonical shape', () => {
  const result = doctor(['.']);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.kind, 'nemesis-doctor');
  assert.ok(report.repository.root);
  assert.ok(['ready', 'stale', 'missing', 'incompatible', 'corrupt'].includes(report.cortex.state));
  assert.ok(['bundled', 'external', 'precomputed'].includes(report.cortex.mode));
  assert.ok(Array.isArray(report.coverage.languages));
  assert.ok(Array.isArray(report.providers.selected));
  assert.ok(typeof report.hostCapabilities.networkSandbox === 'boolean');
  assert.equal(report.cleanClaimPossible, false);
  assert.ok(Array.isArray(report.gaps));
  assert.ok(Array.isArray(report.commands));
});

test('doctor reflects the network guard environment', () => {
  const result = doctor(['.'], { AUDIT_NETWORK_GUARD: 'active' });
  const report = JSON.parse(result.stdout);
  assert.equal(report.hostCapabilities.networkSandbox, true);
});

test('doctor reflects signing key presence', () => {
  const result = doctor(['.'], { AUDIT_PLAN_SIGNING_KEY: 'local-key' });
  const report = JSON.parse(result.stdout);
  assert.equal(report.hostCapabilities.signing, true);
});

test('init dry-run previews without writing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-init-'));
  try {
    const init = spawnSync(process.execPath, [BIN, 'init', dir, '--dry-run'], {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.equal(init.status, 0);
    const preview = JSON.parse(init.stdout);
    assert.equal(preview.kind, 'nemesis-init-preview');
    assert.equal(preview.dryRun, true);
    assert.ok(!existsSync(join(dir, 'nemesis.config.json')), 'dry run must not write config');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('init --write creates config and ignore entries', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nemesis-init-'));
  try {
    const init = spawnSync(process.execPath, [BIN, 'init', dir, '--write'], {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.equal(init.status, 0);
    assert.ok(existsSync(join(dir, 'nemesis.config.json')), 'config written');
    assert.ok(existsSync(join(dir, '.gitignore')), 'gitignore written');
    assert.ok(readFileSync(join(dir, '.gitignore'), 'utf8').includes('.nemesis/'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
