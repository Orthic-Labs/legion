import test from 'node:test';
import assert from 'node:assert/strict';
import { compileMobileCompatibility } from '../../../../providers/runtime/mobile/compatibility/index.mjs';

test('B4-031 accounts for accessibility journeys and explicit omitted device or OEM cells', () => {
  const receipt = compileMobileCompatibility({ criticalJourneys: ['onboarding'], executed: [], supported: { platforms: ['ios', 'android'], oemFamilies: ['aosp', 'samsung'] } });
  assert.equal(receipt.status, 'partial');
  assert.ok(receipt.coverageGaps.includes('accessibility-journey-missing:onboarding'));
  assert.ok(receipt.omitted.some((item) => item.dimension === 'oem' && item.value === 'samsung'));
  assert.equal(receipt.denominator.total, receipt.denominator.accounted);
});

test('B4-031 never counts iOS device evidence in Android denominator', () => {
  const receipt = compileMobileCompatibility({ executed: [{ dimension: 'device', value: 'phone', platform: 'ios', status: 'pass' }], supported: { devices: ['phone'] } });
  assert.deepEqual(receipt.denominator.ios, { total: 1, accounted: 1 });
  assert.deepEqual(receipt.denominator.android, { total: 1, accounted: 1 });
  assert.equal(receipt.omitted.filter((item) => item.dimension === 'device' && item.platform === 'android').length, 1);
});

test('B4-031 includes critical accessibility semantics and automation', () => {
  const receipt = compileMobileCompatibility({ criticalJourneys: ['checkout'] });
  for (const mode of ['labels-announcements-errors', 'audio-media-alternatives', 'accessibility-automation']) assert.ok(receipt.omitted.some((item) => item.value === mode));
});
