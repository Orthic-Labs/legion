import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { compileWebMatrix } from '../../../providers/runtime/web/matrix/index.mjs';

const binding = Object.freeze({ targetId: 'web', environment: 'test', actorId: 'editor', tenantId: 'tenant-a', browser: 'chromium', browserVersion: '128', viewport: '1440x900', locale: 'en-GB', sourceRevision: 'abc', artifactDigest: 'sha256:artifact' });
const capability = (id, browserVersion, binary) => ({ id, status: 'available', browserVersion, binary, binding });
const row = (extra = {}) => ({ id: 'desktop-chromium', browser: 'chromium', browserVersion: '128', binary: 'bundled-pinned', viewport: '1440x900', device: 'desktop', physicality: 'physical', dpr: 1, input: 'mouse', colorScheme: 'light', contrast: 'normal', motion: 'reduce', locale: 'en-GB', network: 'online', offline: false, status: 'pass', ...extra });
const registry = JSON.parse(readFileSync(new URL('../../../registry/platform-matrices/web.json', import.meta.url), 'utf8'));
const capabilities = registry.browserPolicy.map((item) => capability(item.id, item.versions[0], item.binaryPolicy));

test('runtime matrix rejects missing or wrong registry-required viewport, physicality and offline values', () => {
  const receipt = compileWebMatrix({ binding, capabilities: [capability('chromium', '128', 'bundled-pinned')], policy: { combinations: [row({ viewport: 'unknown', physicality: undefined, offline: 'false' })], maxCombinations: 4 } });
  assert.notEqual(receipt.status, 'pass');
  for (const dimension of ['viewport', 'physicality', 'offline']) assert.ok(receipt.coverageGaps.includes(`dimension-value-outside-registry:desktop-chromium:${dimension}`));
});

test('runtime matrix couples browser policy to allowed version, binary and exact capability receipt', () => {
  const receipt = compileWebMatrix({ binding, capabilities: [capability('chromium', '999', 'caller-binary')], policy: { combinations: [row({ browserVersion: '999', binary: 'caller-binary' })], maxCombinations: 4 } });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('browser-version-outside-policy:desktop-chromium'));
  assert.ok(receipt.coverageGaps.includes('browser-binary-outside-policy:desktop-chromium'));
});

test('runtime vitals classification trusts registry IDs and device physicality, never caller deviceClass', () => {
  const mobile = row({ id: 'mobile-webkit-emulated', browser: 'webkit', browserVersion: '18.0', viewport: '390x844', device: 'phone', physicality: 'emulated', dpr: 3, input: 'touch', colorScheme: 'dark', contrast: 'more', locale: 'ar', network: 'slow-4g', deviceClass: 'desktop', vitals: { lcp: 1000 } });
  const receipt = compileWebMatrix({ binding, capabilities: [capability('webkit', '18.0', 'bundled-pinned')], policy: { combinations: [mobile], maxCombinations: 4 } });
  assert.notEqual(receipt.status, 'pass');
  assert.ok(receipt.coverageGaps.includes('vitals-device-class-mismatch:mobile-webkit-emulated'));
  assert.ok(receipt.coverageGaps.includes('vitals-metric-missing:mobile-webkit-emulated:cls'));
  assert.ok(receipt.coverageGaps.includes('vitals-metric-missing:mobile-webkit-emulated:inp'));
  assert.deepEqual(receipt.vitalsByDeviceClass.desktop ?? [], []);
});

test('caller observations cannot replace registry mandatory plus bounded pairwise denominator', () => {
  const receipt = compileWebMatrix({ binding, capabilities, policy: { combinations: [row()], maxCombinations: registry.pairwisePolicy.maxCombinations } });
  assert.ok(receipt.denominator.total > 1);
  for (const id of registry.mandatoryCombinations.map((item) => item.id).filter((id) => id !== 'desktop-chromium')) assert.ok(receipt.coverageGaps.includes(`combination-missing:${id}`));
  assert.notEqual(receipt.status, 'pass');
});

test('empty vitals observations gap every exact desktop and mobile denominator row', () => {
  const observations = registry.mandatoryCombinations.map((item) => ({ ...item, status: 'pass' }));
  const receipt = compileWebMatrix({ binding, capabilities, policy: { combinations: observations, maxCombinations: registry.pairwisePolicy.maxCombinations } });
  for (const id of [...registry.vitalsDenominators.desktop.combinationIds, ...registry.vitalsDenominators.mobile.combinationIds]) assert.ok(receipt.coverageGaps.includes(`vitals-observation-missing:${id}`));
  assert.notEqual(receipt.status, 'pass');
});
