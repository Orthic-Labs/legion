import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyMobileRelease } from '../../../../providers/runtime/mobile/release/index.mjs';

test('B4-032 blocks declaration mismatch and binds exact release identity', () => {
  const receipt = verifyMobileRelease({ targetId: 'ios-app', version: '1.2.3', artifact: { path: 'app.ipa', digest: 'sha256:ipa' }, runtimeDataTypes: ['location'], declaredDataTypes: [], symbols: [] });
  assert.equal(receipt.status, 'fail');
  assert.equal(receipt.releaseBlocked, true);
  assert.ok(receipt.coverageGaps.includes('privacy-declaration-mismatch:location'));
  assert.ok(receipt.coverageGaps.includes('symbols-missing'));
  for (const gap of ['privacy-manifest-unproven', 'required-reason-apis-unproven', 'symbolication-unproven', 'store-declarations-unproven']) assert.ok(receipt.coverageGaps.includes(gap));
  assert.deepEqual(receipt.identity, { targetId: 'ios-app', version: '1.2.3', artifactDigest: 'sha256:ipa' });
});
