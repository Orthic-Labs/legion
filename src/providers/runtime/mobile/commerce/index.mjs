export function verifyMobileCommerceOperations({ entitlement = {}, push = {}, analytics = {}, operations = {}, provider = {} } = {}) {
  const gaps = [];
  const covers = (actual, required) => required.every((item) => (actual ?? []).includes(item));
  if (entitlement.clientDecision && !entitlement.serverVerified) gaps.push('entitlement-server-verification-missing');
  if (!covers(entitlement.testedStates, ['purchase', 'restore', 'refund', 'revocation', 'account-switch'])) gaps.push('entitlement-state-coverage-missing');
  if (!push.accountBound) gaps.push('push-account-binding-missing');
  if (!push.privacySafe) gaps.push('push-privacy-missing');
  if (!covers(push.testedStates, ['token-rotation', 'terminated', 'replayed', 'logout'])) gaps.push('push-state-coverage-missing');
  if (!analytics.consentBound) gaps.push('analytics-consent-missing');
  if (!analytics.releaseSegmented || !analytics.schemaValidated) gaps.push('analytics-operational-evidence-missing');
  if (!operations.runbook || !operations.alerting || !operations.restoreEvidence || !operations.owner) gaps.push('operations-readiness-missing');
  if (provider.required && !provider.sandboxReceipt) gaps.push(`provider-evidence-missing:${provider.id ?? 'unknown'}`);
  return { schemaVersion: 1, kind: 'legion-mobile-commerce-operations-evidence', status: gaps.some((gap) => gap.startsWith('entitlement-') || gap.startsWith('push-') || gap.startsWith('analytics-')) ? 'fail' : gaps.length ? 'partial' : 'pass', terminal: true,
    entitlement: { serverVerified: entitlement.serverVerified === true, testedStates: entitlement.testedStates ?? [] }, push: { accountBound: push.accountBound === true, privacySafe: push.privacySafe === true, testedStates: push.testedStates ?? [] }, analytics: { consentBound: analytics.consentBound === true, schemaValidated: analytics.schemaValidated === true }, operations, provider, coverageGaps: gaps.sort() };
}
