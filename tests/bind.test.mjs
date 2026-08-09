import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const BIN = fileURLToPath(new URL('../bin/legion.mjs', import.meta.url));
const root = fileURLToPath(new URL('..', import.meta.url));

function bind(args = [], cwd = root) {
  return spawnSync(process.execPath, [BIN, 'bind', ...args], {
    cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function makeClaudeCodeDir() {
  const dir = mkdtempSync(join(tmpdir(), 'legion-bind-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  return dir;
}

function markerCount(text) {
  return (text.match(/<!-- legion:bind:start v1 -->/g) ?? []).length;
}

test('bind --check on a fresh .claude/ dir detects claude-code with no drift', () => {
  const dir = makeClaudeCodeDir();
  try {
    const result = bind(['--check', dir]);
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.kind, 'legion-bind-preview');
    assert.equal(report.dryRun, true);
    const claudeCode = report.harnesses.find((h) => h.name === 'claude-code');
    assert.ok(claudeCode, 'claude-code harness detected');
    assert.equal(claudeCode.present, true);
    assert.ok(claudeCode.wouldWrite.length > 0);
    assert.deepEqual(claudeCode.drift, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bind --write then --check reports no drift for tracked files', () => {
  const dir = makeClaudeCodeDir();
  try {
    const written = bind(['--write', dir]);
    assert.equal(written.status, 0, written.stderr);
    const checked = bind(['--check', dir]);
    assert.equal(checked.status, 0, checked.stderr);
    const report = JSON.parse(checked.stdout);
    for (const harness of report.harnesses) {
      assert.deepEqual(harness.drift, [], `no drift expected for ${harness.name} right after write`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bind --write is idempotent across two runs', () => {
  const dir = makeClaudeCodeDir();
  try {
    const first = bind(['--write', dir]);
    assert.equal(first.status, 0, first.stderr);
    const firstReport = JSON.parse(first.stdout);
    const firstWrote = firstReport.harnesses.flatMap((h) => h.wrote ?? []).sort();

    const claudeMdPath = join(dir, 'CLAUDE.md');
    const firstLength = existsSync(claudeMdPath) ? readFileSync(claudeMdPath, 'utf8').length : null;

    const second = bind(['--write', dir]);
    assert.equal(second.status, 0, second.stderr);
    const secondReport = JSON.parse(second.stdout);
    const secondWrote = secondReport.harnesses.flatMap((h) => h.wrote ?? []).sort();

    assert.deepEqual(secondWrote, firstWrote, 'wrote list must be identical across runs');

    if (firstLength !== null) {
      const secondLength = readFileSync(claudeMdPath, 'utf8').length;
      assert.equal(secondLength, firstLength, 'CLAUDE.md byte length unchanged on second write');
      assert.equal(markerCount(readFileSync(claudeMdPath, 'utf8')), 1, 'exactly one marker pair in CLAUDE.md');
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
