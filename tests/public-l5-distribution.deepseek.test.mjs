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
  const { generateSboms, inventoryRuntimeDependencies, inventoryDistribution, reconcileDistributionContents } = await import('../src/lib/distribution/sbom.mjs');
  const { buildNoticeInventory, renderNotices } = await import('../src/lib/distribution/notices.mjs');
  const components = [{ name: 'legion', version: '1.0.0', license: 'SEE LICENSE', source: 'local', shipped: true, distributionStatus: 'integrated' }];
  const sboms = generateSboms({ name: 'legion', components });
  assert.equal(sboms.cyclonedx.components.length, 1);
  assert.equal(sboms.spdx.packages.length, 1);
  const inventory = buildNoticeInventory(components);
  assert.equal(inventory.blockers.length, 0);
  assert.match(renderNotices(inventory.components), /legion/);
  assert.deepEqual(buildNoticeInventory([{ name: 'creator', shipped: true, source: 'external', license: null }]).blockers[0].kind, 'redistribution-rights-unresolved');
  const runtimeInventory = inventoryRuntimeDependencies({ packageManifest: { dependencies: { alpha: '1.2.3' } }, provenance: { alpha: { source: 'registry', digest: 'sha256:a', license: 'MIT' } } });
  assert.deepEqual(runtimeInventory[0], { type: 'library', name: 'alpha', version: '1.2.3', source: 'registry', digest: 'sha256:a', license: 'MIT', shipped: true, distributionStatus: 'integrated' });
  const distribution = inventoryDistribution({ runtime: runtimeInventory, creatorMaterial: [{ name: 'designer', shipped: false }] });
  assert.equal(distribution[0].name, 'alpha');
  assert.equal(reconcileDistributionContents(distribution, ['alpha']).decision, 'QUALIFIED');
  assert.equal(reconcileDistributionContents(distribution, []).decision, 'BLOCKED');
});

test('B8-018 release manifests bind final bytes and fail closed on empty SBOM or placeholder signature', async () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-release-'));
  mkdirSync(join(root, 'dist'));
  writeFileSync(join(root, 'dist', 'pkg.tgz'), 'final-bytes');
  writeFileSync(join(root, 'sbom.json'), JSON.stringify({ components: [{ name: 'legion' }] }));
  writeFileSync(join(root, 'NOTICE.md'), 'notice');
  writeFileSync(join(root, 'SHA256SUMS'), 'sum');
  const { buildReleaseManifest } = await import('../src/lib/distribution/release-manifest.mjs');
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
  const { generateClaims, generateClaimsFromQualification, renderSupportMarkdown } = await import('../src/lib/distribution/claims.mjs');
  const claims = generateClaims([{ id: 'js', subject: 'JavaScript', state: 'deterministic-measured', artifactDigest: 'sha256:a', corpusDigest: 'sha256:c', providerDigest: 'sha256:p', expectedIdentity: { artifactDigest: 'sha256:a', corpusDigest: 'sha256:c', providerDigest: 'sha256:p' }, hostCapabilities: ['process'], authorityLimits: ['source-only'], resourceConstraints: { maxConcurrency: 1 } }]);
  assert.equal(claims[0].state, 'deterministic-measured');
  assert.deepEqual(claims[0].authorityLimits, ['source-only']);
  assert.match(renderSupportMarkdown(claims), /deterministic-measured/);
  const downgraded = generateClaims([{ id: 'bad', subject: 'Bad', state: 'deterministic-measured', artifactDigest: 'sha256:x', corpusDigest: 'sha256:c', providerDigest: 'sha256:p', expectedIdentity: { artifactDigest: 'sha256:a', corpusDigest: 'sha256:c', providerDigest: 'sha256:p' } }]);
  assert.equal(downgraded[0].state, 'unproven');
  assert.equal(generateClaims([{ id: 'self', state: 'deterministic-measured', artifactDigest: 'sha256:x', corpusDigest: 'sha256:y', providerDigest: 'sha256:z' }])[0].state, 'unproven');
  assert.equal(generateClaimsFromQualification({ claims: [{ id: 'self', state: 'deterministic-measured' }] }, null).claims[0].state, 'unproven');
});


