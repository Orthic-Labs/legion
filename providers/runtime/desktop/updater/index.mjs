const CHECKS = ['application', 'metadata', 'payload', 'timestamp'];
export const UPDATE_CASES = Object.freeze(['corrupt-manifest', 'forged-payload', 'redirect', 'local-replacement', 'insufficient-disk', 'locked-files', 'interruption-resume', 'updater-crash', 'failed-install', 'rollback', 'bad-release-pause', 'staged-rollout', 'kill-switch', 'offline-grace', 'self-update']);
const verified = (value, digest) => value?.status === 'pass' && value?.artifactDigest === digest;
const sensitive = (value) => /(bearer\s+\S+|https?:\/\/\S+[?&](?:token|signature|sig)=)/i.test(String(value));
const FORGED_CALLER_BOOLS = new Set(['forgedCaller', 'fakeCaller', 'spoofedCaller', 'impersonatedCaller']);

export function evaluateUpdaterEvidence({ artifact = {}, verification = {}, attempts = [], promotion = {} } = {}) {
  const gaps = [];
  for (const key of Object.keys(artifact)) {
    if (FORGED_CALLER_BOOLS.has(key)) gaps.push(`forged-caller-boolean:${key}`);
  }
  for (const check of CHECKS) if (!verified(verification[check], artifact.digest)) gaps.push(`signature-${check}-unproven`);
  if (!artifact.publisher) gaps.push('publisher-identity-unproven');
  const bypass = attempts.some((item) => item.verificationPassed === false && item.executed === true);
  if (bypass) gaps.push('verification-bypass');
  for (const item of attempts) if (item.terminal !== true) gaps.push(`attempt-nonterminal:${item.id ?? 'unknown'}`);
  for (const id of UPDATE_CASES) if (!attempts.some((item) => item.id === id && item.terminal === true)) gaps.push(`updater-case-missing:${id}`);
  const digests = [promotion.qaDigest, promotion.updateDigest, promotion.distributedDigest];
  const promotionSpecified = digests.some(Boolean);
  const promotionEquivalent = promotionSpecified && digests.every((item) => item === artifact.digest);
  if (!promotionSpecified) gaps.push('promotion-evidence-missing');
  else if (!promotionEquivalent) gaps.push('promotion-artifact-mismatch');
  if (promotion.privilegedService?.revalidated !== true) gaps.push('privileged-revalidation-unproven');
  if (!promotion.channel || !promotion.rollout) gaps.push('channel-rollout-unproven');
  if ((promotion.qaGate === 'mandatory' || !promotion.qaGate) && promotion.mandatory !== true) gaps.push('mandatory-qa-promotion-missing');
  if ((promotion.logs ?? []).some(sensitive)) gaps.push('updater-log-sensitive');
  const verificationFailed = CHECKS.some((check) => verification[check]?.status === 'fail');
  const hasForgedCaller = gaps.some((gap) => gap.startsWith('forged-caller-boolean:'));
  return { schemaVersion: 1, kind: 'legion-desktop-updater', status: (verificationFailed || bypass || hasForgedCaller) ? 'fail' : gaps.length ? 'unproven' : 'pass', terminal: true,
    artifact, verification, attempts, promotionEquivalent, stopShip: verificationFailed || bypass || hasForgedCaller, coverageGaps: gaps.sort() };
}

export async function executeUpdaterEvidence({ host, artifact, verification, promotion } = {}) {
  if (!host?.exercise) return evaluateUpdaterEvidence({ artifact, verification, promotion });
  const attempts = [];
  for (const id of UPDATE_CASES) attempts.push(await host.exercise({ id, artifact, promotion }));
  return evaluateUpdaterEvidence({ artifact, verification, promotion, attempts });
}
