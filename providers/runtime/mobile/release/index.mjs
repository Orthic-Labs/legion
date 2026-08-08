export function verifyMobileRelease({ targetId = null, version = null, artifact = {}, runtimeDataTypes = [], declaredDataTypes = [], symbols = [], build = {}, store = {}, promotion = {}, privacy = {} } = {}) {
  const gaps = [];
  for (const type of runtimeDataTypes) if (!declaredDataTypes.includes(type)) gaps.push(`privacy-declaration-mismatch:${type}`);
  if (!artifact.path || !artifact.digest) gaps.push('exact-artifact-missing');
  if (!symbols.length) gaps.push('symbols-missing');
  if (!symbols.length || symbols.some((item) => item.symbolicated !== true)) gaps.push('symbolication-unproven');
  if (!privacy.manifest) gaps.push('privacy-manifest-unproven');
  if (!privacy.requiredReasonApis) gaps.push('required-reason-apis-unproven');
  if (!build.release) gaps.push('release-build-flags-unproven');
  if (!build.toolchain || !build.lockfileDigest) gaps.push('build-reproducibility-unproven');
  if (!build.packageId || !build.signingIdentity) gaps.push('signing-identity-unproven');
  if (!store.track) gaps.push('store-track-unproven');
  if (!store.listing || !store.privacyUrl || !store.supportUrl) gaps.push('store-metadata-unproven');
  if (!store.declarations || !store.regionalVariants) gaps.push('store-declarations-unproven');
  if (!promotion.rolloutCriteria || !promotion.rollbackCriteria || !promotion.monitoring) gaps.push('rollout-readiness-unproven');
  if (promotion.testedDigest && promotion.promotedDigest && promotion.testedDigest !== promotion.promotedDigest) gaps.push('promotion-artifact-mismatch');
  const blocking = gaps.some((gap) => gap.startsWith('privacy-declaration-mismatch:') || gap === 'promotion-artifact-mismatch');
  return { schemaVersion: 1, kind: 'nemesis-mobile-release-evidence', status: blocking ? 'fail' : gaps.length ? 'partial' : 'pass', terminal: true, releaseBlocked: blocking,
    identity: { targetId, version, artifactDigest: artifact.digest ?? null }, artifact, build, store, symbols, promotion, coverageGaps: gaps.sort() };
}
