import test from 'node:test';
import assert from 'node:assert/strict';
import { planMobileHosts } from '../../../../providers/runtime/mobile/host/index.mjs';
import { createMobileDeviceAdapter } from '../../../../providers/runtime/mobile/devices/index.mjs';

test('B4-026 keeps simulated and physical requirements distinct', () => {
  const receipt = planMobileHosts({ target: { id: 'app', artifactDigest: 'sha256:app' }, devices: [{ id: 'sim', tier: 'simulator', status: 'available' }], requirements: [{ id: 'smoke', tier: 'simulator' }, { id: 'battery', tier: 'physical' }] });
  assert.equal(receipt.requirements.find((item) => item.id === 'smoke').status, 'available');
  assert.equal(receipt.requirements.find((item) => item.id === 'battery').gap, 'physical-device-unavailable');
});

test('B4-026 always cleans and releases failed exclusive execution', async () => {
  const calls = [];
  const adapter = createMobileDeviceAdapter({ id: 'phone', tier: 'physical', exclusiveKey: 'usb:1', operations: {
    acquire: async () => calls.push('acquire'), install: async () => calls.push('install'), execute: async () => { calls.push('execute'); throw new Error('crash'); },
    reset: async () => calls.push('reset'), uninstall: async () => calls.push('uninstall'), release: async () => calls.push('release') } });
  const receipt = await adapter.execute({ target: { id: 'app', artifactDigest: 'sha256:app' }, scenarioId: 'launch' });
  assert.equal(receipt.status, 'fail');
  assert.deepEqual(calls, ['acquire', 'install', 'execute', 'reset', 'uninstall', 'release']);
  assert.deepEqual(receipt.cleanup, { reset: 'pass', uninstall: 'pass', release: 'pass' });
});

test('B4-026 blocks physical-only work before simulated acquisition', async () => {
  const receipt = await createMobileDeviceAdapter({ id: 'sim', tier: 'simulator' }).execute({ scenarioId: 'thermal', physicalOnly: true });
  assert.deepEqual(receipt.coverageGaps, ['physical-device-required:thermal']);
});
