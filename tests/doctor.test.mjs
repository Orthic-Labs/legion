import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { codexHookTrust, computeHostSection } from '../src/lib/cli/commands/doctor-host.mjs';
import { DOCTOR_BLUEPRINT_TIMEOUT_MS } from '../src/lib/cli/commands/doctor.mjs';
import { COMMAND_PROBE_TIMEOUT_MS, probeCapability } from '../src/lib/capabilities/probe.mjs';

const BIN = fileURLToPath(new URL('../src/bin/legion.mjs', import.meta.url));
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
  assert.equal(report.kind, 'legion-doctor');
  assert.ok(report.repository.root);
  assert.ok(['ready', 'stale', 'missing', 'incompatible', 'corrupt'].includes(report.blueprint.state));
  assert.ok(['packet-file', 'resident-transport', 'bounded-one-shot'].includes(report.blueprint.mode));
  assert.ok(Array.isArray(report.coverage.languages));
  assert.ok(Array.isArray(report.providers.selected));
  assert.ok(typeof report.hostCapabilities.networkSandbox === 'boolean');
  assert.equal(report.cleanClaimPossible, false);
  assert.ok(Array.isArray(report.gaps));
  assert.ok(Array.isArray(report.commands));
  assert.equal(report.host.discovery['claude-code'].capabilities, 22);
  assert.deepEqual(report.host.discovery['claude-code'].entrypoints, ['alchemist', 'coder', 'commit', 'covenant', 'oracle']);
  assert.equal(Object.hasOwn(report.host.discovery['claude-code'], 'roleEntrypoints'), false);
  assert.ok(report.host.guard);
  assert.equal(Object.hasOwn(report.host, 'arcane'), false);
  const lifecycle = result.stderr.trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(lifecycle[0].phase, 'started');
  assert.equal(lifecycle.at(-1).phase, 'finished');
  assert.ok(lifecycle.some(({ phase, detail }) => phase === 'blueprint-probe-started' && detail.timeoutMs === DOCTOR_BLUEPRINT_TIMEOUT_MS));
});

test('host command probes carry finite timeout policy', () => {
  assert.equal(COMMAND_PROBE_TIMEOUT_MS, 3_000);
  const registry = { capabilities: { bounded: { kind: 'external', summary: 'bounded', degradation: 'none', probe: { kind: 'command', command: 'bounded' } } } };
  let calls = 0;
  const result = probeCapability('bounded', { registry, commandExists: () => { calls += 1; return false; } });
  assert.equal(calls, 1);
  assert.equal(result.available, false);
});

test('doctor reflects the network guard environment', () => {
  const result = doctor(['.'], { AUDIT_NETWORK_GUARD: 'active' });
  const report = JSON.parse(result.stdout);
  assert.equal(report.hostCapabilities.networkSandbox, true);
});

test('doctor reports per-skill host requirements with typed degradation', () => {
  const section = computeHostSection(root);
  const coder = section.hostRequirements.skills.find((skill) => skill.id === 'coder');
  assert.ok(coder);
  assert.deepEqual(coder.requirements.map((requirement) => requirement.id), ['pi-cli', 'python-runtime']);
  assert.ok(coder.requirements.every((requirement) => requirement.degradation && requirement.remedy));
});

test('doctor reflects signing key presence', () => {
  const result = doctor(['.'], { AUDIT_PLAN_SIGNING_KEY: 'local-key' });
  const report = JSON.parse(result.stdout);
  assert.equal(report.hostCapabilities.signing, true);
});

test('doctor reports typed Codex hook trust failure without manufacturing hashes', () => {
  const home = mkdtempSync(join(tmpdir(), 'legion-doctor-codex-trust-'));
  try {
    mkdirSync(join(home, '.codex'), { recursive: true });
    writeFileSync(join(home, '.codex', 'config.toml'), '[plugins."arcane@local-brief"]\nenabled = true\n');
    const report = codexHookTrust(home);
    assert.equal(report.state, 'ARC_HOOK_TRUST_REQUIRED');
    assert.equal(report.trusted.length, 0);
    assert.equal(report.missing.length, 8);
    assert.match(report.remediation, /Guard hooks/);
    assert.match(report.remediation, /legacy plugin identity arcane@local-brief/);
    assert.match(report.remediation, /never manufactures trusted_hash/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('doctor binding.receiptPresent is false with no .legion/binding.json', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-doctor-binding-'));
  try {
    const result = doctor([dir]);
    const report = JSON.parse(result.stdout);
    assert.equal(report.binding.receiptPresent, false);
    assert.deepEqual(report.binding.harnesses, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('doctor reports pending Claude Code legacy MCP migration', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-doctor-naming-'));
  try {
    writeFileSync(join(dir, '.mcp.json'), `${JSON.stringify({ mcpServers: { seer: { command: 'python3', args: ['-m', 'legion_kernel.adapters.mcp_server'] } } })}\n`);
    const report = JSON.parse(doctor([dir]).stdout);
    assert.equal(report.naming.bindings.claudeCode.status, 'legacy-present');
    assert.ok(report.gaps.some(({ kind }) => kind === 'naming-migration-pending'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('doctor reports pending Codex legacy MCP migration', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-doctor-codex-naming-'));
  try {
    const codexDir = join(dir, '.codex');
    mkdirSync(codexDir, { recursive: true });
    writeFileSync(join(codexDir, 'config.toml'), '[mcp_servers.seer]\ncommand = "python3"\nargs = ["-m", "legion_kernel.adapters.mcp_server"]\n');
    const report = JSON.parse(doctor([dir]).stdout);
    assert.equal(report.naming.bindings.codex.status, 'legacy-present');
    assert.ok(report.gaps.some(({ kind }) => kind === 'naming-migration-pending'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('init dry-run previews without writing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-init-'));
  try {
    const init = spawnSync(process.execPath, [BIN, 'init', dir, '--dry-run'], {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.equal(init.status, 0);
    const preview = JSON.parse(init.stdout);
    assert.equal(preview.kind, 'legion-init-preview');
    assert.equal(preview.dryRun, true);
    assert.ok(!existsSync(join(dir, 'legion.config.json')), 'dry run must not write config');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('init --write creates config and ignore entries', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-init-'));
  try {
    const init = spawnSync(process.execPath, [BIN, 'init', dir, '--write'], {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.equal(init.status, 0);
    assert.ok(existsSync(join(dir, 'legion.config.json')), 'config written');
    assert.ok(existsSync(join(dir, '.gitignore')), 'gitignore written');
    assert.ok(readFileSync(join(dir, '.gitignore'), 'utf8').includes('.legion/'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
