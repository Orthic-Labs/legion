import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
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
    const firstReceipt = readFileSync(join(dir, '.legion', 'binding.json'), 'utf8');

    const claudeMdPath = join(dir, 'CLAUDE.md');
    const firstLength = existsSync(claudeMdPath) ? readFileSync(claudeMdPath, 'utf8').length : null;

    const second = bind(['--write', dir]);
    assert.equal(second.status, 0, second.stderr);
    const secondReport = JSON.parse(second.stdout);
    const secondWrote = secondReport.harnesses.flatMap((h) => h.wrote ?? []).sort();

    assert.deepEqual(secondWrote, firstWrote, 'wrote list must be identical across runs');
    assert.equal(readFileSync(join(dir, '.legion', 'binding.json'), 'utf8'), firstReceipt, 'receipt is deterministic across unchanged writes');

    if (firstLength !== null) {
      const secondLength = readFileSync(claudeMdPath, 'utf8').length;
      assert.equal(secondLength, firstLength, 'CLAUDE.md byte length unchanged on second write');
      assert.equal(markerCount(readFileSync(claudeMdPath, 'utf8')), 1, 'exactly one marker pair in CLAUDE.md');
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('codex bind writes managed agent pointers and is idempotent', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-codex-bind-'));
  try {
    mkdirSync(join(dir, '.codex'), { recursive: true });
    assert.equal(bind(['--write', '--harness', 'codex', dir]).status, 0);
    const config = readFileSync(join(dir, '.codex', 'config.toml'), 'utf8');
    assert.match(config, /# >>> legion:managed-block v1 >>>/);
    assert.match(config, /config_file = "agents\/sage.toml"/);
    const server = join(root, 'integrations', 'mcp', 'server.mjs').replace(/\\/g, '/');
    assert.ok(existsSync(server), 'generated Legion MCP server must exist at package root');
    assert.match(config, new RegExp(`args = \["${server.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\]`));
    assert.doesNotMatch(config, /\/lib\/integrations\//);
    const sage = readFileSync(join(dir, '.codex', 'agents', 'sage.toml'), 'utf8');
    assert.match(sage, /\nname = "sage"/);
    assert.doesNotMatch(sage, /\nmodel = /);
    assert.match(sage, /frontier-judgment/);
    assert.doesNotMatch(sage, /gpt-5\.6-sol/);
    assert.doesNotMatch(sage, /\ndescription = /);
    for (const name of ['alchemist', 'oracle', 'covenant-seat']) {
      const agent = readFileSync(join(dir, '.codex', 'agents', `${name}.toml`), 'utf8');
      assert.match(agent, new RegExp(`\\nname = "${name}"`));
    }
    assert.equal(bind(['--write', '--harness', 'codex', dir]).status, 0);
    assert.equal(readFileSync(join(dir, '.codex', 'config.toml'), 'utf8'), config);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('codex bind migrates the prior Seer-era unmanaged tables without touching user config', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-codex-legacy-bind-'));
  try {
    mkdirSync(join(dir, '.codex'), { recursive: true });
    writeFileSync(join(dir, '.codex', 'config.toml'), [
      'model = "gpt"', '',
      '[agents.sage]', 'description = "old"', 'config_file = "agents/sage.toml"', '',
      '[agents.seer]', 'description = "old"', 'config_file = "agents/seer.toml"', '',
      '[mcp_servers.legion]', 'command = "node"', 'args = ["old.mjs"]', '',
      '[history]', 'persistence = "save-all"', '',
    ].join('\n'));
    const written = bind(['--write', '--harness', 'codex', dir]);
    assert.equal(written.status, 0, written.stderr);
    const config = readFileSync(join(dir, '.codex', 'config.toml'), 'utf8');
    assert.match(config, /model = "gpt"/);
    assert.match(config, /\[history\]\npersistence = "save-all"/);
    assert.match(config, /# >>> legion:managed-block v1 >>>/);
    assert.match(config, /\[agents\.oracle\]/);
    assert.doesNotMatch(config, /\[agents\.seer\]|agents\/seer\.toml|old\.mjs/);
    assert.equal(bind(['--write', '--harness', 'codex', dir]).status, 0);
    assert.equal(readFileSync(join(dir, '.codex', 'config.toml'), 'utf8'), config);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('codex bind removes a duplicate legacy MCP table outside its managed block', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-codex-duplicate-mcp-'));
  try {
    mkdirSync(join(dir, '.codex'), { recursive: true });
    assert.equal(bind(['--write', '--harness', 'codex', dir]).status, 0);
    const path = join(dir, '.codex', 'config.toml');
    const managed = readFileSync(path, 'utf8');
    writeFileSync(path, `${managed}\n[mcp_servers.legion]\ncommand = "node"\nargs = ["old.mjs"]\n`);
    assert.equal(bind(['--write', '--harness', 'codex', dir]).status, 0);
    const repaired = readFileSync(path, 'utf8');
    assert.equal((repaired.match(/^\[mcp_servers\.legion\]$/gm) ?? []).length, 1);
    assert.doesNotMatch(repaired, /old\.mjs/);
    assert.equal(bind(['--write', '--harness', 'codex', dir]).status, 0);
    assert.equal(readFileSync(path, 'utf8'), repaired);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('gemini bind emits native role commands, context, MCP, and byte-bound receipt', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-gemini-bind-'));
  try {
    mkdirSync(join(dir, '.gemini'), { recursive: true });
    assert.equal(bind(['--write', '--harness', 'gemini', dir]).status, 0);
    const context = readFileSync(join(dir, 'GEMINI.md'), 'utf8');
    const sage = readFileSync(join(dir, '.gemini', 'commands', 'legion', 'sage.toml'), 'utf8');
    const settings = JSON.parse(readFileSync(join(dir, '.gemini', 'settings.json'), 'utf8'));
    const receipt = JSON.parse(readFileSync(join(dir, '.legion', 'binding.json'), 'utf8'));
    assert.match(context, /frontier-judgment/);
    assert.match(sage, /prompt = /);
    assert.equal(settings.mcpServers.legion.command, 'legion');
    assert.deepEqual(settings.mcpServers.legion.args, ['mcp', 'server']);
    assert.equal(receipt.schemaVersion, 2);
    assert.ok(receipt.harnesses[0].files.every((file) => !file.path.includes(':') && typeof file.bytes === 'number' && /^sha256:/.test(file.digest)));
    assert.equal(bind(['--check', '--harness', 'gemini', dir]).status, 0);
    writeFileSync(join(dir, '.gemini', 'commands', 'legion', 'sage.toml'), 'tampered\n');
    const checked = bind(['--check', '--harness', 'gemini', dir]);
    assert.notEqual(checked.status, 0);
    assert.equal(JSON.parse(checked.stdout).harnesses[0].drift[0].kind, 'modified');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('agents-md bind remains a low-fidelity roster projection', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-agents-bind-'));
  try {
    writeFileSync(join(dir, 'AGENTS.md'), '# Project instructions\n');
    assert.equal(bind(['--write', '--harness', 'agents-md', dir]).status, 0);
    const agents = readFileSync(join(dir, 'AGENTS.md'), 'utf8');
    assert.match(agents, /frontier-judgment/);
    assert.match(agents, /balanced-executor/);
    assert.doesNotMatch(agents, /## Purpose/);
    assert.equal(bind(['--check', '--harness', 'agents-md', dir]).status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
