import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
const root = fileURLToPath(new URL('../..', import.meta.url));
test('Claude and Codex plugin manifests project Legion metadata', () => {
  const claude = JSON.parse(readFileSync(`${root}/.claude-plugin/plugin.json`)); const codex = JSON.parse(readFileSync(`${root}/.codex-plugin/plugin.json`));
  assert.equal(claude.name, 'legion'); assert.equal(codex.name, 'legion'); assert.equal(codex.interface.displayName, 'Legion');
  assert.deepEqual(codex.interface.capabilities, ['Authority agents', 'Arcane lifecycle hooks', 'Covenant review']);
});
