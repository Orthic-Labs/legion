// Live hook-registration enumeration and duplicate detection.
// Pins the 2026-08-10 Mac incident: Arcane was registered via a skills-dir
// plugin, was declared absent after reading only settings.json, and the
// resulting "fix" double-registered it — which would deny every Write with
// ARC_REPLAY_NONCE_SEEN.

import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { enumerateRegistrations, handlerId } from '../src/lib/cli/commands/bind/registrations.mjs';

const ARCANE = 'node "${CLAUDE_PLUGIN_ROOT}/hooks/arcane-hook.mjs"';

function host({ userHooks = {}, pluginHooks = null } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'legion-reg-'));
  mkdirSync(join(home, '.claude'), { recursive: true });
  writeFileSync(join(home, '.claude', 'settings.json'), JSON.stringify({ hooks: userHooks }));
  if (pluginHooks) {
    const dir = join(home, '.claude', 'skills', 'legion');
    mkdirSync(join(dir, '.claude-plugin'), { recursive: true });
    mkdirSync(join(dir, 'hooks'), { recursive: true });
    writeFileSync(join(dir, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'legion' }));
    writeFileSync(join(dir, 'hooks', 'hooks.json'), JSON.stringify({ hooks: pluginHooks }));
  }
  return { home, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

const stopHook = (cmd) => ({ Stop: [{ hooks: [{ type: 'command', command: cmd }] }] });

test('a plugin-supplied hook is visible even when settings.json has none', () => {
  // The exact wrong conclusion: "settings.json has no Arcane, so there is none".
  const h = host({ userHooks: {}, pluginHooks: stopHook(ARCANE) });
  try {
    const { registrations, duplicates } = enumerateRegistrations({ home: h.home });
    assert.equal(duplicates.length, 0);
    const arcane = registrations.filter((r) => r.handler === 'arcane-hook.mjs');
    assert.equal(arcane.length, 1);
    assert.equal(arcane[0].source, 'plugin:legion@skills-dir');
  } finally { h.cleanup(); }
});

test('the incident is caught: settings.json wiring on top of a plugin is a duplicate', () => {
  const h = host({
    userHooks: stopHook('/Users/x/.nvm/versions/node/v26.7.0/bin/node /workspace/legion/hooks/arcane-hook.mjs'),
    pluginHooks: stopHook(ARCANE),
  });
  try {
    const { duplicates } = enumerateRegistrations({ home: h.home });
    assert.equal(duplicates.length, 1);
    assert.equal(duplicates[0].handler, 'arcane-hook.mjs');
    assert.equal(duplicates[0].event, 'Stop');
    assert.deepEqual(duplicates[0].sources.sort(), ['plugin:legion@skills-dir', 'user-settings']);
    assert.match(duplicates[0].detail, /runs 2x on Stop/);
  } finally { h.cleanup(); }
});

test('the same handler on DIFFERENT events is not a duplicate', () => {
  const h = host({
    pluginHooks: {
      Stop: [{ hooks: [{ type: 'command', command: ARCANE }] }],
      PreToolUse: [{ hooks: [{ type: 'command', command: ARCANE }] }],
    },
  });
  try {
    assert.equal(enumerateRegistrations({ home: h.home }).duplicates.length, 0);
  } finally { h.cleanup(); }
});

test('handler identity survives absolute-path differences across machines', () => {
  assert.equal(
    handlerId('node "${CLAUDE_PLUGIN_ROOT}/hooks/arcane-hook.mjs"'),
    handlerId('/Users/x/.nvm/versions/node/v26.7.0/bin/node /workspace/legion/hooks/arcane-hook.mjs'),
  );
  assert.equal(handlerId('D:\\Claude\\.venv-tools\\Scripts\\python.exe C:/x/.claude/hooks/enforce_brief.py'), 'enforce_brief.py');
  // rhook is one binary serving many gates: keyed by subcommand, never merged.
  assert.equal(handlerId('C:\\Users\\x\\.claude\\bin\\rhook.exe', ['bash']), 'rhook bash');
  assert.notEqual(handlerId('/x/rhook', ['bash']), handlerId('/x/rhook', ['brief']));
});

test('project settings are enumerated alongside user settings', () => {
  const h = host({ userHooks: {} });
  const root = mkdtempSync(join(tmpdir(), 'legion-root-'));
  try {
    mkdirSync(join(root, '.claude'), { recursive: true });
    writeFileSync(join(root, '.claude', 'settings.json'), JSON.stringify({ hooks: stopHook('python guard.py') }));
    const { registrations } = enumerateRegistrations({ home: h.home, root });
    assert.equal(registrations.some((r) => r.source === 'project-settings' && r.handler === 'guard.py'), true);
  } finally { h.cleanup(); rmSync(root, { recursive: true, force: true }); }
});
