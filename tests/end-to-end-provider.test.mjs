import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { reconcileCompleteRun } from '../tools/audit/audit-complete.mjs';
import { auditVisualArtifacts, encodePng } from '../src/providers/visual-core.mjs';
import { extendRegistryWithNativeFamilies } from '../src/registry/provider-registry-complete.mjs';
import { expandProviderRegistry } from '../src/registry/provider-registry.mjs';

function rawRegistry() {
  return {
    schemaVersion: 1,
    kind: 'audit-provider-registry',
    discoveryOwner: 'cortex',
    planSeal: 'sha256',
    concurrency: '1',
    candidateAdjudication: {},
    legacy: [{ id: 'core.repo', role: 'deterministic', selector: 'always', allowWithoutCortex: true, check: 'repo', tool: 'git', required: 'always', applies: 'git', parallel: true }],
    runtime: [], reasoning: [],
    coverageFamilies: [{ id: 'language.go', kind: 'language', selector: { ext: ['go'] }, qualification: 'unproven', providers: [] }],
  };
}

test('framework, security, and visual providers are frozen before execution without false qualification', () => {
  const registry = extendRegistryWithNativeFamilies(expandProviderRegistry(rawRegistry()));
  const ids = new Set(registry.providers.map((provider) => provider.id));
  assert.ok(ids.has('native.family-suite'));
  assert.ok(ids.has('framework.major-suite'));
  // Security pack providers migrate to the lens registry (appendix §15.3):
  // the runtime registry keeps no duplicate security pack records.
  for (const id of ['security.credentials', 'security.insecure-defaults', 'security.misuse-resistance', 'security.agentic-ci', 'security.agent-skill-mcp']) {
    assert.ok(!ids.has(id), `${id} must live in the security lens registry, not the runtime registry`);
  }
  assert.ok(ids.has('visual.core'));
  const go = registry.coverageFamilies.find((family) => family.id === 'language.go');
  assert.equal(go.qualification, 'unproven');
  assert.ok(go.providers.includes('native.family-suite'));
  assert.equal(registry.providers.find((provider) => provider.id === 'native.family-suite').benchmark.status, 'unproven');
});

test('complete reconciliation fails closed when a selected runtime provider is missing', () => {
  const plan = {
    denominator: { expectedChecks: ['repo'], providerIds: ['core.repo', 'visual.core'] },
    providers: [
      { id: 'core.repo', phase: 'facts', runner: { kind: 'legacy-check', check: 'repo' } },
      { id: 'visual.core', phase: 'runtime', runner: { kind: 'runtime-script', script: 'src/providers/visual-core.mjs' } },
    ],
    coverageFamilies: [], coverageGaps: [], schemaVersion: 1, seal: {}, binding: {},
  };
  const result = reconcileCompleteRun({
    plan,
    facts: { checks: [{ check: 'repo', status: 'ran', findings_count: 0 }], incomplete: false },
    providerResults: [], securityResult: { candidates: [] },
    projection: { state: 'ready', parsedExtensions: [], unsupportedExtensions: [] },
    bindingVerification: { valid: true, drift: [] },
  });
  assert.equal(result.incomplete, true);
  assert.deepEqual(result.provider_reconciliation.missingRuntimeProviders, ['visual.core']);
});

test('visual provider requires a complete matrix and matching baseline', () => {
  const root = mkdtempSync(join(tmpdir(), 'audit-visual-'));
  try {
    const rgba = Buffer.from([255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255]);
    writeFileSync(join(root, 'expected.png'), encodePng({ width: 2, height: 2, rgba }));
    writeFileSync(join(root, 'actual.png'), encodePng({ width: 2, height: 2, rgba }));
    const pass = auditVisualArtifacts({
      root,
      spec: {
        expected: { cases: [{ route: '/', state: 'default', viewport: '2x2', theme: 'default', locale: 'default', platform: 'test' }] },
        captures: [{ id: 'home', route: '/', state: 'default', viewport: '2x2', theme: 'default', locale: 'default', platform: 'test', path: 'actual.png', baseline: 'expected.png' }],
      },
    });
    assert.equal(pass.status, 'pass');
    assert.equal(pass.complete, true);

    const incomplete = auditVisualArtifacts({ root, spec: { expected: { routes: ['/', '/settings'] }, captures: [] } });
    assert.equal(incomplete.status, 'unproven');
    assert.equal(incomplete.complete, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
