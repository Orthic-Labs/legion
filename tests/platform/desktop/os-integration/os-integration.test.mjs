import assert from 'node:assert/strict';
import test from 'node:test';
import { compileDesktopOsMatrix, executeDesktopOsMatrix, DESKTOP_OS_CASES } from '../../../../providers/runtime/desktop/os-integration/index.mjs';

const fullCase = (id, overrides = {}) => ({
  id, os: 'windows', version: '11', architecture: 'x64', state: {}, controlIds: ['desktop-native'],
  status: 'pass', terminal: true, ...overrides,
});

test('B4-020 binds native UX/accessibility cases to exact platform state', () => {
  const result = compileDesktopOsMatrix({
    cases: DESKTOP_OS_CASES.map((id) => fullCase(id, id === 'installer-keyboard'
      ? { os: 'macos', version: '15', architecture: 'arm64', status: 'unsupported', reason: 'host-unavailable', hostUnavailable: { type: 'remote-host', detail: 'no macOS arm64 test host' } }
      : {})),
  });
  assert.equal(result.denominator.accounted, DESKTOP_OS_CASES.length);
  assert.equal(result.denominator.required, DESKTOP_OS_CASES.length);
  assert.equal(result.denominator.synthesized, 0);
  assert.equal(result.status, 'pass');
  assert.equal(result.receipts.find(({ id }) => id === 'installer-keyboard').status, 'unsupported');
});

test('B4-020 exposes missing platform bindings', () => {
  const result = compileDesktopOsMatrix({ required: ['resume'], cases: [{ id: 'resume', status: 'pass', terminal: true }] });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.includes('platform-binding-incomplete:resume'));
});

test('B4-020 rejects empty/caller-defined matrix & requires state/control bindings', () => {
  assert.notEqual(compileDesktopOsMatrix({ required: [], cases: [] }).status, 'pass');
  const result = compileDesktopOsMatrix({ required: ['mixed-dpi'], cases: [{ id: 'mixed-dpi', os: 'windows', version: '11', architecture: 'x64', status: 'pass', terminal: true }] });
  assert.ok(result.coverageGaps.includes('native-state-missing:mixed-dpi'));
  assert.ok(result.coverageGaps.includes('control-binding-missing:mixed-dpi'));
});

test('B4-020 validates typed host-unavailable evidence for unsupported cases', () => {
  const invalid = compileDesktopOsMatrix({
    required: ['missing-monitor'],
    cases: [fullCase('missing-monitor', { status: 'unsupported', reason: 'no monitor', hostUnavailable: { type: 'bogus', detail: 'x' } })],
  });
  assert.ok(invalid.coverageGaps.includes('host-unavailable-type-invalid:missing-monitor'));

  const valid = compileDesktopOsMatrix({
    required: ['missing-monitor'],
    cases: [fullCase('missing-monitor', { status: 'unsupported', reason: 'no monitor', hostUnavailable: { type: 'device-not-present', detail: 'no external display' } })],
  });
  assert.ok(!valid.coverageGaps.some((g) => g.includes('host-unavailable-type-invalid')));
});

test('B4-020 executeDesktopOsMatrix delegates to host.probe and compiles matrix', async () => {
  const host = { probe: async ({ id }) => fullCase(id) };
  const result = await executeDesktopOsMatrix({ host, required: ['single-instance', 'keyboard-only'] });
  assert.equal(result.status, 'pass');
  assert.equal(result.receipts.length, 2);
});

test('B4-020 executeDesktopOsMatrix returns empty matrix without host', async () => {
  const result = await executeDesktopOsMatrix({ required: ['exit'] });
  assert.equal(result.status, 'unproven');
  assert.equal(result.denominator.accounted, 0);
});