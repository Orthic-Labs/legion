import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { auditSuccessfulCommit, commitReceiptRequirement, commitRepository, generatedLockTargets, preEffectDiscipline } from '../lib/discipline-controls.mjs';
import { createHostRuntime } from '../host/host-runtime.mjs';
import { claudeCodeHostAdapter } from '../host/claude-code-adapter.mjs';

test('discipline rejects no-verify before any commit receipt lookup', () => {
  const control = preEffectDiscipline({ tool_input: { command: 'git commit --no-verify -m x' } }, { workspace: tmpdir() });
  assert.equal(control.code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
});

test('runtime applies commit discipline before contracted pre-effect authorization', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-commit-runtime-'));
  try {
    const keyDir = join(workspace, 'keys');
    mkdirSync(keyDir);
    writeFileSync(join(keyDir, 'test.key'), '11'.repeat(32));
    const runtime = createHostRuntime({ adapter: claudeCodeHostAdapter, workspace, keyDir });
    const result = runtime.handle({ hook_event_name: 'PreToolUse', session_id: 's', cwd: workspace, tool_name: 'Bash', tool_use_id: 'u', tool_input: { command: 'git commit --no-verify -m x' } });
    assert.equal(result.code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('discipline protects generated-lock patch targets', () => {
  const payload = { tool_input: { patch: '*** Update File: config/generated-lock.json\n@@\n-x\n+y' } };
  assert.deepEqual(generatedLockTargets(payload), ['config/generated-lock.json']);
  assert.equal(preEffectDiscipline(payload, { workspace: tmpdir() }).code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
});

function commitFixture() {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-commit-tier-'));
  execFileSync('git', ['init', '-q'], { cwd: workspace, windowsHide: true });
  execFileSync('git', ['config', 'user.email', 't@t'], { cwd: workspace, windowsHide: true });
  execFileSync('git', ['config', 'user.name', 't'], { cwd: workspace, windowsHide: true });
  writeFileSync(join(workspace, 'base.txt'), 'base\n');
  execFileSync('git', ['add', '-A'], { cwd: workspace, windowsHide: true });
  execFileSync('git', ['commit', '-qm', 'base'], { cwd: workspace, windowsHide: true });
  return workspace;
}

const lockedPolicy = { lockedDomainsFor: (paths) => paths.filter((path) => path.startsWith('locked/')).map((path) => ({ path })) };

test('ambient commits need no Minimize receipt, while contracted & locked commits do', () => {
  const workspace = commitFixture();
  try {
    writeFileSync(join(workspace, 'ambient.txt'), 'ambient\n');
    execFileSync('git', ['add', 'ambient.txt'], { cwd: workspace, windowsHide: true });
    assert.deepEqual(commitReceiptRequirement({ workspace, policy: lockedPolicy }), { required: false, reason: 'ambient', paths: ['ambient.txt'] });
    assert.equal(preEffectDiscipline({ tool_input: { command: 'git commit -m ambient' } }, { workspace, policy: lockedPolicy }), null);
    assert.equal(preEffectDiscipline({ tool_input: { command: 'git commit -m contracted' } }, { workspace, policy: lockedPolicy, contracted: true }).code, 'ARC_CLAIM_PREREQUISITE_UNMET');

    execFileSync('git', ['reset', '-q'], { cwd: workspace, windowsHide: true });
    mkdirSync(join(workspace, 'locked'));
    writeFileSync(join(workspace, 'locked', 'gate.mjs'), 'export const gate = true;\n');
    execFileSync('git', ['add', 'locked/gate.mjs'], { cwd: workspace, windowsHide: true });
    const locked = commitReceiptRequirement({ workspace, policy: lockedPolicy });
    assert.equal(locked.required, true);
    assert.equal(locked.reason, 'locked-domain');
    assert.equal(preEffectDiscipline({ tool_input: { command: 'git commit -m locked' } }, { workspace, policy: lockedPolicy }).code, 'ARC_CLAIM_PREREQUISITE_UNMET');

    execFileSync('git', ['commit', '-qm', 'locked baseline'], { cwd: workspace, windowsHide: true });
    rmSync(join(workspace, 'locked', 'gate.mjs'));
    execFileSync('git', ['add', '-A'], { cwd: workspace, windowsHide: true });
    assert.equal(commitReceiptRequirement({ workspace, policy: lockedPolicy }).required, true, 'deleting a locked path stays locked');
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('nested repository paths are framed from workspace root before locked-domain matching', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-nested-tier-'));
  // Mirrors the real layout the policy encodes: the pattern is
  // `legion/packages/arcane/**`, so `legion` is a direct child of the
  // workspace root (/workspace/legion). Nesting it deeper here made
  // the fixture contradict its own expectation.
  const repository = join(workspace, 'legion');
  try {
    mkdirSync(join(repository, 'packages', 'arcane'), { recursive: true });
    execFileSync('git', ['init', '-q'], { cwd: repository, windowsHide: true });
    execFileSync('git', ['config', 'user.email', 't@t'], { cwd: repository, windowsHide: true });
    execFileSync('git', ['config', 'user.name', 't'], { cwd: repository, windowsHide: true });
    writeFileSync(join(repository, 'README.md'), 'base\n');
    execFileSync('git', ['add', '-A'], { cwd: repository, windowsHide: true });
    execFileSync('git', ['commit', '-qm', 'base'], { cwd: repository, windowsHide: true });
    writeFileSync(join(repository, 'packages', 'arcane', 'gate.mjs'), 'export const gate = true;\n');
    execFileSync('git', ['add', 'packages/arcane/gate.mjs'], { cwd: repository, windowsHide: true });
    const policy = { lockedDomainsFor: (paths) => paths.filter((path) => path.startsWith('legion/packages/arcane/')).map((path) => ({ path })) };
    const requirement = commitReceiptRequirement({ workspace, repository, policy });
    assert.equal(requirement.required, true);
    assert.deepEqual(requirement.paths, ['legion/packages/arcane/gate.mjs']);
    assert.equal(commitRepository({ tool_input: { command: 'git commit -m nested', workdir: repository } }, workspace), repository);
    assert.equal(commitRepository({ tool_input: { command: 'git -C legion commit -m nested' } }, workspace), repository);
    assert.equal(preEffectDiscipline({ tool_input: { command: 'git commit -m nested', workdir: repository } }, { workspace, policy }).code, 'ARC_CLAIM_PREREQUISITE_UNMET');
    assert.equal(preEffectDiscipline({ tool_input: { command: 'git -C legion commit -m nested' } }, { workspace, policy }).code, 'ARC_CLAIM_PREREQUISITE_UNMET');
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('ambient commit-tier infrastructure failure warns with an audit row instead of blocking', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-commit-advisory-'));
  try {
    assert.equal(preEffectDiscipline({ tool_input: { command: 'git commit -m x' } }, { workspace, policy: null }), null);
    const warning = join(workspace, '.audit', 'arcane', 'commit-discipline-advisories.jsonl');
    assert.equal(existsSync(warning), true);
    assert.equal(JSON.parse(readFileSync(warning, 'utf8')).kind, 'arcane-commit-discipline-advisory');
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('successful shell commit creates identity audit only after success', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-commit-audit-'));
  try {
    auditSuccessfulCommit({ tool_input: { command: 'git commit -m x' } }, { eventType: 'post-effect', result: { outcome: 'success' }, sessionId: 's', runId: 'r', sourceRevision: 'abc' }, { workspace });
    const row = JSON.parse(readFileSync(join(workspace, '.audit', 'arcane', 'commit-identity.jsonl'), 'utf8'));
    assert.equal(row.sessionId, 's');
    assert.equal(row.runId, 'r');
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});
