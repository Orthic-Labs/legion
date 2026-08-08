import test from 'node:test';
import assert from 'node:assert/strict';
import { assessMobilePerformance } from '../../../../providers/runtime/mobile/performance/index.mjs';

test('B4-030 refuses release, battery, and thermal claims without physical measurements', () => {
  const receipt = assessMobilePerformance({ targetId: 'app', artifactDigest: 'sha256:app', measurements: [{ metric: 'cold-start', value: 300, unit: 'ms', tier: 'simulator', buildType: 'release' }] });
  assert.equal(receipt.status, 'partial');
  for (const gap of ['physical-device-measurement-missing', 'battery-measurement-missing', 'thermal-measurement-missing']) assert.ok(receipt.coverageGaps.includes(gap));
  assert.equal(receipt.claims.battery, 'unproven');
  for (const gap of ['profile-missing:main-thread', 'profile-missing:idle-background', 'artifact-inspection-missing:architecture-slices']) assert.ok(receipt.coverageGaps.includes(gap));
});
