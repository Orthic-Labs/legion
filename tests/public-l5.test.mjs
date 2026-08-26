import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

test('B8-001 exposes one explicit versioned public surface', async () => {
  const api = await import('../src/lib/index.mjs');
  for (const name of ['inspectProduct', 'buildPlan', 'executePlan', 'reconcileRun', 'finalizeRun', 'verifyRun', 'loadReport', 'verifySkillBundle', 'renderHtmlReport', 'editorDiagnostics']) {
    assert.equal(typeof api[name], 'function', `${name} must be public`);
  }
  assert.equal(api.PUBLIC_API_VERSION, 1);
  assert.deepEqual(Object.keys(api.COMPATIBILITY_SURFACES).sort(), ['audit-finalize', 'audit-plan', 'audit-run', 'audit-verify']);
  assert.ok(Object.values(api.COMPATIBILITY_SURFACES).every((entry) => entry.deprecated === true && entry.replacement));
  assert.equal('registry' in api, false);
  assert.equal('loadProviderRegistry' in api, false);
});

test('B8-007 renders offline HTML with real CSP hash and evidence navigation', async () => {
  const { renderHtmlReport } = await import('../src/lib/report/html/index.mjs');
  const html = renderHtmlReport({
    audit_status: 'fail', quality_gate: 'fail',
    findings: [{ id: 'finding-1', ruleId: 'xss', severity: 'high', title: '<img src=x onerror=alert(1)>', file: 'src/a.js', evidence: [{ id: 'evidence-1', detail: 'proof' }] }],
    familyCoverage: [{ id: 'security', status: 'partial', evidenceIds: ['evidence-1'] }],
    coverage_gaps: [{ id: 'gap-1', kind: 'runtime', detail: 'device absent' }],
  });
  assert.doesNotMatch(html, /PLACEHOLDER|<img src=x/);
  assert.match(html, /Content-Security-Policy/);
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const hash = createHash('sha256').update(script).digest('base64');
  assert.match(html, new RegExp(`script-src 'sha256-${hash.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`));
  assert.match(html, /id="evidence-evidence-1"/);
  assert.match(html, /href="#evidence-evidence-1"/);
  assert.match(html, /type="search"/);
  assert.match(html, /data-kind="flow-diagrams"/);
  assert.doesNotMatch(html, /https?:\/\//);
  const aggregate = renderHtmlReport({ findings: [{ id: 'f', evidence: [{ id: 'e' }] }], flows: [{ id: 'flow-1', evidenceIds: ['e'], title: '<unsafe>' }] });
  assert.match(aggregate, /href="#evidence-e"/);
  assert.match(aggregate, /&lt;unsafe&gt;/);
});

test('B8-008 preserves canonical fingerprints, ranges, lineage, gaps, and preview-only actions', async () => {
  const { editorDiagnostics } = await import('../src/lib/report/editor/index.mjs');
  const diagnostics = editorDiagnostics({ report: {
    findings: [{ id: 'finding-1', fingerprint: 'sha256:f', family: 'security', evidenceClass: 'static', severity: 'high', title: 'Unsafe call', file: 'src/a.js', range: { start: { line: 4, column: 2 }, end: { line: 4, column: 9 } }, lineage: { state: 'moved', priorRange: { start: { line: 2, column: 1 }, end: { line: 2, column: 8 } } }, remediation: { id: 'proposal-1', qualified: true, findingFingerprint: 'sha256:f', patch: { path: 'patches/p.patch', digest: `sha256:${'a'.repeat(64)}` } } }],
    coverage_gaps: [{ id: 'gap-1', family: 'runtime', reviewRequired: true, detail: 'device absent' }],
  }, runDir: 'run' });
  assert.equal(diagnostics.length, 2);
  assert.deepEqual(diagnostics[0].range, { start: { line: 4, column: 2 }, end: { line: 4, column: 9 } });
  assert.equal(diagnostics[0].fingerprint, 'sha256:f');
  assert.equal(diagnostics[0].family, 'security');
  assert.equal(diagnostics[0].lineage.state, 'moved');
  assert.equal(diagnostics[0].codeActions[0].previewOnly, true);
  assert.equal(diagnostics[1].coverageIncomplete, true);
  const unbound = editorDiagnostics({ report: { findings: [{ id: 'f', ruleId: 'r', remediation: { id: 'p', qualified: true, findingIds: ['other'], patch: { digest: 'sha256:p' } } }] } });
  assert.equal(unbound[0].codeActions.some(({ kind }) => kind === 'preview'), false);
});

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
