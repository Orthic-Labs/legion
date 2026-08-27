import { strict as assert } from 'node:assert';
import test from 'node:test';
import { loadCapabilityRegistry, probeAll, probeCapability } from '../src/lib/capabilities/probe.mjs';

const registry = loadCapabilityRegistry();

test('every declared capability states how it degrades', () => {
  for (const [id, entry] of Object.entries(registry.capabilities)) {
    assert.ok(entry.degradation?.length > 0, `${id} declares no degradation`);
  }
});

test('every declared capability tells the user how to enable it', () => {
  for (const [id, entry] of Object.entries(registry.capabilities)) {
    assert.ok(entry.remedy?.length > 0, `${id} gives the user no remedy`);
  }
});

test('an absent capability reports unavailable with its remedy', () => {
  const result = probeCapability('banana', { env: {} });
  assert.equal(result.available, false);
  assert.match(result.message, /not available on this host/);
  assert.match(result.message, /image-generation MCP server/);
});

test('a present capability reports available and needs no message', () => {
  const result = probeCapability('dataforseo', { env: { DATAFORSEO_LOGIN: 'set' } });
  assert.equal(result.available, true);
  assert.equal(result.message, null);
});

test('a capability with no probe is unknown, never assumed present', () => {
  const result = probeCapability('media-production', { env: {} });
  assert.equal(result.available, null);
  assert.match(result.message, /could not be detected/);
});

test('a command-any probe accepts either declared runtime command', () => {
  const result = probeCapability('python-runtime', {
    registry,
    env: {},
    commandExists: (command) => command === 'python',
  });
  assert.equal(result.available, true);
  assert.equal(result.message, null);
});

test('a missing Pi provider has typed degradation instead of a silent fallback', () => {
  const result = probeCapability('pi-cli', {
    registry,
    env: {},
    commandExists: () => false,
  });
  assert.equal(result.available, false);
  assert.match(result.degradation, /typed unavailable-provider/);
  assert.match(result.remedy, /Pi CLI/);
});

test('probing an undeclared capability is an error, not a silent pass', () => {
  assert.throws(() => probeCapability('not-a-capability'), /not declared in the registry/);
});

test('probeAll covers the whole registry', () => {
  assert.equal(probeAll({ env: {} }).length, Object.keys(registry.capabilities).length);
});
