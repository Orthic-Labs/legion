import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyMobileCommerceOperations } from '../../../../providers/runtime/mobile/commerce/index.mjs';

test('B4-033 rejects client-only entitlements and records provider or operations gaps', () => {
  const receipt = verifyMobileCommerceOperations({ entitlement: { clientDecision: true, serverVerified: false }, push: { accountBound: false, privacySafe: false }, analytics: { consentBound: false }, operations: {} });
  assert.equal(receipt.status, 'fail');
  for (const gap of ['entitlement-server-verification-missing', 'entitlement-state-coverage-missing', 'push-account-binding-missing', 'push-privacy-missing', 'push-state-coverage-missing', 'analytics-consent-missing', 'analytics-operational-evidence-missing', 'operations-readiness-missing']) assert.ok(receipt.coverageGaps.includes(gap));
});
