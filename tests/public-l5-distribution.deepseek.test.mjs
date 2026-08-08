import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// DISPATCH-07 distribution/provenance lane (B8-017, B8-018, B8-024, B8-025)
// exercised against the public distribution machinery.  The named lane exists
// so the distribution surface can be qualified independently of the full
// public-l5 surface; it shares the same module under test.

test('B8-017 generates non-empty package SBOMs, shipped notices, and typed provenance blockers', async () => {
  const { generateSboms, inventoryRuntimeDependencies, inventoryDistribution, reconcileDistributionContents } = await import('../lib/distribution/sbom.mjs');
  const { buildNoticeInventory, renderNotices } = await import('../lib/distribution/notices.mjs');
  const components = [{ name: 'nemesis', version: '1.0.0', license: 'SEE LICENSE', source: 'local', shipped: true, distributionStatus: 'integrated' }];
  const sboms = generateSboms({ name: 'nemesis', components });
  assert.equal(sboms.cyclonedx.components.length, 1);
  assert.equal(sboms.spdx.packages.length, 1);
  const inventory = buildNoticeInventory(components);
  assert.equal(inventory.blockers.length, 0);
  assert.match(renderNotices(inventory.components), /nemesis/);
  assert.deepEqual(buildNoticeInventory([{ name: 'creator', shipped: true, source: 'external', license: null }]).blockers[0].kind, 'redistribution-rights-unresolved');
  const runtimeInventory = inventoryRuntimeDependencies({ packageManifest: { dependencies: { alpha: '1.2.3' } }, provenance: { alpha: { source: 'registry', digest: 'sha256:a', license: 'MIT' } } });
  assert.deepEqual(runtimeInventory[0], { type: 'library', name: 'alpha', version: '1.2.3', source: 'registry', digest: 'sha256:a', license: 'MIT', shipped: true, distributionStatus: 'integrated' });
  const distribution = inventoryDistribution({ runtime: runtimeInventory, creatorMaterial: [{ name: 'designer', shipped: false }] });
  assert.equal(distribution[0].name, 'alpha');
  assert.equal(reconcileDistributionContents(distribution, ['alpha']).decision, 'QUALIFIED');
  assert.equal(reconcileDistributionContents(distribution, []).decision, 'BLOCKED');
});

test('B8-018 release manifests bind final bytes and fail closed on empty SBOM or placeholder signature', async () => {
  const root = mkdtempSync(join(tmpdir(), 'nemesis-release-'));
  mkdirSync(join(root, 'dist'));
  writeFileSync(join(root, 'dist', 'pkg.tgz'), 'final-bytes');
  writeFileSync(join(root, 'sbom.json'), JSON.stringify({ components: [{ name: 'nemesis' }] }));
  writeFileSync(join(root, 'NOTICE.md'), 'notice');
  writeFileSync(join(root, 'SHA256SUMS'), 'sum');
  const { buildReleaseManifest } = await import('../lib/distribution/release-manifest.mjs');
  const { verifyReleaseManifestObject } = await import('../scripts/verify-release.mjs');
  const manifest = buildReleaseManifest({ root, version: '1.0.0', sourceRevision: '1234567', artifacts: [{ path: 'dist/pkg.tgz', type: 'package' }], checksums: [{ path: 'SHA256SUMS' }], sboms: [{ path: 'sbom.json' }], notices: [{ path: 'NOTICE.md' }], signatures: [{ path: 'signature.json', status: 'placeholder' }], channels: [{ id: 'internal' }] });
  assert.ok(manifest.sboms[0].digest?.startsWith('sha256:'));
  const result = verifyReleaseManifestObject(manifest, { root });
  assert.equal(result.valid, false);
  assert.ok(result.issues.some(({ issue }) => issue === 'placeholder-signature'));
  assert.ok(result.issues.some(({ issue }) => issue === 'signature-digest-missing'));
  writeFileSync(join(root, 'sbom.json'), JSON.stringify({ components: [] }));
  assert.ok(verifyReleaseManifestObject(manifest, { root }).issues.some(({ issue }) => issue === 'empty-sbom'));
});

test('B8-024 derives claims from exact measured qualification identity', async () => {
  const { generateClaims, generateClaimsFromQualification, renderSupportMarkdown } = await import('../lib/distribution/claims.mjs');
  const claims = generateClaims([{ id: 'js', subject: 'JavaScript', state: 'deterministic-measured', artifactDigest: 'sha256:a', corpusDigest: 'sha256:c', providerDigest: 'sha256:p', expectedIdentity: { artifactDigest: 'sha256:a', corpusDigest: 'sha256:c', providerDigest: 'sha256:p' }, hostCapabilities: ['process'], authorityLimits: ['source-only'], resourceConstraints: { maxConcurrency: 1 } }]);
  assert.equal(claims[0].state, 'deterministic-measured');
  assert.deepEqual(claims[0].authorityLimits, ['source-only']);
  assert.match(renderSupportMarkdown(claims), /deterministic-measured/);
  const downgraded = generateClaims([{ id: 'bad', subject: 'Bad', state: 'deterministic-measured', artifactDigest: 'sha256:x', corpusDigest: 'sha256:c', providerDigest: 'sha256:p', expectedIdentity: { artifactDigest: 'sha256:a', corpusDigest: 'sha256:c', providerDigest: 'sha256:p' } }]);
  assert.equal(downgraded[0].state, 'unproven');
  assert.equal(generateClaims([{ id: 'self', state: 'deterministic-measured', artifactDigest: 'sha256:x', corpusDigest: 'sha256:y', providerDigest: 'sha256:z' }])[0].state, 'unproven');
  assert.equal(generateClaimsFromQualification({ claims: [{ id: 'self', state: 'deterministic-measured' }] }, null).claims[0].state, 'unproven');
});

test('B8-025 verifies creator archives, transformations, rights, and shipped prose fail closed', async () => {
  const { verifySourceProvenance, writeSourceProvenanceQualification } = await import('../scripts/verify-source-provenance.mjs');
  const blocked = verifySourceProvenance({ sources: [{ id: 'designer', status: 'transformed', digest: 'sha256:source', outputDigest: null, shipped: true, redistributionGrant: false, transformations: [], promptProseShipped: true }] }, { verifyFiles: false });
  assert.equal(blocked.decision, 'BLOCKED');
  assert.ok(blocked.blockers.some(({ kind }) => kind === 'redistribution-right-unresolved'));
  assert.ok(blocked.blockers.some(({ kind }) => kind === 'creator-prompt-prose-shipped'));
  assert.ok(blocked.blockers.some(({ kind }) => kind === 'transformation-manifest-incomplete'));
  const current = JSON.parse(readFileSync(new URL('../references/source-provenance/creator-skills.json', import.meta.url), 'utf8'));
  assert.equal(verifySourceProvenance(current, { verifyFiles: false }).decision, 'BLOCKED');
  const digest = `sha256:${'a'.repeat(64)}`;
  const qualified = verifySourceProvenance({ sources: [{ id: 'designer', status: 'transformed', digest, outputDigest: digest, shipped: false, redistributionGrant: false, transformations: ['rewrite'], promptProseShipped: false, userOwned: true, categoryMappings: ['design'], originalRuleOwnership: 'repository-original', shippedOutputs: [] }] }, { verifyFiles: false });
  assert.equal(qualified.decision, 'QUALIFIED');
  const output = join(mkdtempSync(join(tmpdir(), 'nemesis-provenance-')), 'qualification.json');
  assert.equal(writeSourceProvenanceQualification({ sources: [] }, output, { verifyFiles: false }).decision, 'BLOCKED');
  assert.equal(existsSync(output), true);
});

