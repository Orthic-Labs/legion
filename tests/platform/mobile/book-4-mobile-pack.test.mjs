import test from 'node:test';
import assert from 'node:assert/strict';
import { qualifyMobilePlatform } from '../../../qualification/platforms/mobile/qualification.mjs';
import { createMobileQualificationFixtures } from '../../../qualification/platforms/mobile/fixtures.mjs';

test('B4-034 reconciles denominators and never lets simulator evidence satisfy physical controls', () => {
  const fixtures = createMobileQualificationFixtures();
  const receipt = qualifyMobilePlatform({ targetId: 'app', platform: 'ios', fixtures });
  assert.equal(receipt.denominator.total, receipt.denominator.accounted);
  assert.equal(receipt.status, 'partial');
  assert.ok(receipt.coverageGaps.includes('physical-control-unproven:battery'));
  assert.equal(receipt.targets.ios.status, 'partial');
  assert.equal(receipt.targets.android.status, 'unproven');
});
