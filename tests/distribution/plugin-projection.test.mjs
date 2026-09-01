import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
const root = fileURLToPath(new URL('../..', import.meta.url));
test('Claude and Codex plugin manifests project Legion metadata', () => {
  const claude = JSON.parse(readFileSync(`${root}/.claude-plugin/plugin.json`)); const codex = JSON.parse(readFileSync(`${root}/.codex-plugin/plugin.json`)); const marketplace = JSON.parse(readFileSync(`${root}/.claude-plugin/marketplace.json`));
  assert.equal(claude.name, 'legion'); assert.equal(codex.name, 'legion'); assert.equal(codex.interface.displayName, 'Legion');
  assert.match(claude.description, /Legion orchestrates capability selection & authority attachment/);
  assert.match(claude.description, /Arcane shapes cognitive processing & response policy/);
  assert.match(claude.description, /Guard gates typed effects/);
  assert.doesNotMatch(claude.description, /Arcane (?:gates|hooks)/);
  assert.deepEqual(codex.interface.capabilities, ['Legion orchestration', 'Arcane cognitive policy', 'Covenant review']);
  assert.match(codex.description, /Legion selects capabilities/);
  assert.match(codex.description, /Arcane shapes cognitive processing/);
  assert.match(codex.description, /Guard enforcement is host-dependent/);
  assert.match(marketplace.plugins[0].description, /Arcane shapes cognitive processing & response policy/);
  assert.match(marketplace.plugins[0].description, /Guard gates typed effects/);
  assert.doesNotMatch(marketplace.plugins[0].description, /Arcane gates/);
});

test('installed client projections do not claim unshipped native client surfaces', () => {
  const setupRegistry = readFileSync(`${root}/engine/crates/legion-host/src/setup_registry.rs`, 'utf8');
  const setupCommand = readFileSync(`${root}/engine/bins/legion/src/commands/setup.rs`, 'utf8');
  const cli = readFileSync(`${root}/engine/bins/legion/src/cli.rs`, 'utf8');
  const clientDocs = readFileSync(`${root}/docs/architecture/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md`, 'utf8');

  assert.match(setupRegistry, /"antigravity-agent-plugins-portable-core"/);
  assert.match(setupRegistry, /input\.client_id == CLIENT_ANTIGRAVITY && input\.projection == "native-plugin"/);
  assert.match(setupCommand, /"agent-plugins-portable-core"/);
  assert.match(cli, /"projection": "agent-plugins-portable-core"/);
  assert.doesNotMatch(cli, /"projection": "antigravity-native-plugin"/);
  assert.match(clientDocs, /\| Cursor \| Agent Plugins portable core/);
  assert.match(clientDocs, /\| Antigravity \| Agent Plugins portable core/);
  assert.match(clientDocs, /\| Windsurf \| No setup projection or packaged client artifact is shipped/);
});

test('shell launchers use argv for fixed commands', () => {
  const qa = readFileSync(`${root}/src/lib/qa-engine/qa.mjs`, 'utf8');
  const designGate = readFileSync(`${root}/src/lib/design-gate.mjs`, 'utf8');
  const auditCollector = readFileSync(`${root}/tools/audit/collect-facts.mjs`, 'utf8');

  assert.match(qa, /command: process\.execPath/);
  assert.match(qa, /: \{ \.\.\.defaultStartCommand\(port\), shell: false \}/);
  assert.match(qa, /configuredStart\.replaceAll/);
  assert.match(designGate, /spawnSync\(bin, \['--version'\], \{ stdio: 'ignore', shell: false, env \}\)/);
  assert.doesNotMatch(designGate, /execFileSync\('command'/);
  assert.match(auditCollector, /const argv = Array\.isArray\(command\)/);
  assert.match(auditCollector, /run\(\['git', 'ls-files'\]\)/);
  assert.match(auditCollector, /shell: !argv/);
});
