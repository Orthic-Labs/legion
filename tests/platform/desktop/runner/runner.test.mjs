import assert from 'node:assert/strict';
import test from 'node:test';

import { collectDesktopRuntime, executeDesktopRuntime } from '../../../../providers/runtime/desktop/runner/index.mjs';

const artifact = { path: 'C:/app/app.exe', digest: `sha256:${'a'.repeat(64)}` };
const capability = { status: 'available', receipt: { nativeSurface: true, cleanEnvironment: true } };

test('B4-017 binds native runtime evidence to exact executable & inventories components', () => {
  const result = collectDesktopRuntime({
    target: { id: 'desktop', framework: 'electron' }, artifact, capability,
    observations: { source: 'native-host', receipt: { terminal: true }, executable: artifact, processes: [{ pid: 10, role: 'main' }], windows: [{ id: 'w1' }], shutdown: { clean: true }, environment: { isolated: true } },
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.binding.artifactDigest, artifact.digest);
  assert.deepEqual(result.components.processes, [{ pid: 10, role: 'main' }]);
});

test('B4-017 rejects browser-only or mismatched executable evidence', () => {
  const browser = collectDesktopRuntime({ target: { id: 'desktop', framework: 'tauri' }, artifact, capability, observations: { browserOnly: true } });
  assert.equal(browser.status, 'partial');
  assert.ok(browser.coverageGaps.includes('native-surface-unproven'));
  const mismatch = collectDesktopRuntime({ target: { id: 'desktop', framework: 'tauri' }, artifact, capability, observations: { executable: { ...artifact, digest: `sha256:${'b'.repeat(64)}` } } });
  assert.equal(mismatch.status, 'unproven');
  assert.ok(mismatch.coverageGaps.includes('executable-binding-mismatch'));
});

test('B4-017 cannot pass an empty inventory & executes a framework-specific host adapter', async () => {
  assert.notEqual(collectDesktopRuntime({ target: { id: 'desktop', framework: 'electron' }, artifact, capability, observations: { executable: artifact } }).status, 'pass');
  const calls = [];
  const host = { launch: async (request) => { calls.push(request.adapter.id); return { source: 'native-host', receipt: { terminal: true }, executable: artifact, processes: [{ pid: 1, role: 'main' }], windows: [{ id: 'native' }], shutdown: { clean: true }, environment: { isolated: true } }; } };
  const result = await executeDesktopRuntime({ target: { id: 'desktop', framework: 'electron' }, artifact, capability, host });
  assert.equal(result.status, 'pass');
  assert.deepEqual(calls, ['electron']);
});
