// B7-031 — qualified mechanical remediation producers.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  MECHANICAL_REGISTRY,
  assertProducerQualified,
  createMechanicalProposal,
  manualProposal,
  mechanicalAstGrepProposal,
  mechanicalConfigProposal,
  mechanicalDependencyProposal,
  planMechanicalRemediation,
  producerFor,
} from '../../src/lib/remediation/mechanical.mjs';
import { STRUCTURAL_PRODUCERS, renderStructuralPreview } from '../../src/lib/remediation/producers/structural.mjs';
import { CONFIG_PRODUCERS, renderConfigPreview } from '../../src/lib/remediation/producers/config.mjs';

const binding = {
  planDigest: 'sha256:plan',
  repositoryRevision: 'abc123',
  dirtyPatchDigest: null,
  blueprintGenerationId: 'gen',
  blueprintManifestDigest: 'sha256:manifest',
  registryDigest: 'sha256:registry',
};

const sandbox = {
  schemaVersion: 1,
  kind: 'legion-remediation-sandbox',
  sandboxPath: '/repo/.git/legion-sandboxes/run-1',
  primaryRepositoryMutated: false,
  binding,
  findingRunDigest: 'sha256:findingrun',
};

const SOURCE = 'const agent = new Agent({ rejectUnauthorized: false });\nconst other = 1;\n';

function finding(ruleId, overrides = {}) {
  return {
    id: 'sha256:finding',
    ruleId,
    rootCauseDigest: 'sha256:root',
    location: { path: 'src/client.mjs', startLine: 1, endLine: 1 },
    ...overrides,
  };
}

test('only low-risk, rule-specific producers are registered — never generic search-and-replace', () => {
  const all = [...STRUCTURAL_PRODUCERS, ...CONFIG_PRODUCERS];
  assert.ok(all.length > 0);
  for (const producer of all) {
    assert.ok(producer.ruleIds.length > 0, `${producer.id} must name the rules it fixes`);
    assert.ok(['structural', 'config', 'content'].includes(producer.kind));
    assert.equal(producer.risk, 'low');
    // A producer previews; it never owns an apply path.
    assert.equal(typeof producer.preview, 'function');
    assert.equal(producer.apply, undefined);
    assert.ok(Array.isArray(producer.preconditions) && producer.preconditions.length > 0);
  }
  for (const source of ['../../src/lib/remediation/producers/structural.mjs', '../../src/lib/remediation/producers/config.mjs']) {
    const text = readFileSync(new URL(source, import.meta.url), 'utf8');
    assert.ok(!/writeFileSync|writeFile\(|rmSync|node:fs/.test(text), `${source} must not write to disk`);
  }
});

test('the committed mechanical registry is version-bound and matches the producer modules', () => {
  const committed = JSON.parse(readFileSync(new URL('../../src/registry/remediation/mechanical.json', import.meta.url), 'utf8'));
  assert.deepEqual(committed, MECHANICAL_REGISTRY);
  const moduleIds = [...STRUCTURAL_PRODUCERS, ...CONFIG_PRODUCERS].map((producer) => producer.id).sort();
  assert.deepEqual(committed.producers.map((entry) => entry.id).sort(), moduleIds);
  for (const entry of committed.producers) {
    assert.match(entry.producerVersion, /^\d+\.\d+\.\d+$/);
    assert.match(entry.qualificationDigest, /^sha256:/);
    assert.ok(entry.ruleIds.length > 0);
  }
});

test('producer qualification is version-bound in both directions', () => {
  const producer = producerFor('insecure-defaults.tls-reject-unauthorized');
  assert.ok(producer);
  assert.equal(assertProducerQualified(producer, 'insecure-defaults.tls-reject-unauthorized'), true);
  assert.throws(
    () => assertProducerQualified({ ...producer, version: '99.0.0' }, 'insecure-defaults.tls-reject-unauthorized'),
    /qualified version/,
  );
  assert.throws(
    () => assertProducerQualified(producer, 'some.unqualified.rule'),
    /not qualified for rule/,
  );
});

test('producers run only inside a remediation sandbox', () => {
  const call = (sandboxArg) => planMechanicalRemediation({
    finding: finding('insecure-defaults.tls-reject-unauthorized'),
    sandbox: sandboxArg,
    readFile: () => SOURCE,
    binding,
  });
  assert.ok(call(sandbox));
  assert.throws(() => call(null), /remediation sandbox/);
  assert.throws(() => call({ ...sandbox, kind: 'something-else' }), /remediation sandbox/);
  assert.throws(() => call({ ...sandbox, primaryRepositoryMutated: true }), /primary repository/);
});

test('a structural preview is idempotent and leaves unrelated bytes untouched', () => {
  const producer = producerFor('insecure-defaults.tls-reject-unauthorized');
  const preview = producer.preview({ path: 'src/client.mjs', text: SOURCE, finding: finding(producer.ruleIds[0]) });
  const once = renderStructuralPreview(SOURCE, preview.edits);
  const twice = renderStructuralPreview(once, producer.preview({ path: 'src/client.mjs', text: once, finding: finding(producer.ruleIds[0]) }).edits);
  assert.equal(once, twice, 'preview must be idempotent');
  assert.ok(once.includes('rejectUnauthorized: true'));
  assert.ok(once.includes('const other = 1;'), 'unrelated bytes must be unchanged');
  assert.equal(once.split('\n').length, SOURCE.split('\n').length);
  // A source with nothing to fix produces no edits at all.
  assert.deepEqual(producer.preview({ path: 'src/client.mjs', text: 'const other = 1;\n', finding: finding(producer.ruleIds[0]) }).edits, []);
});

test('a config preview sets an exact key and is idempotent', () => {
  const producer = producerFor('browser-http.cookie-samesite');
  const before = '{\n  "cookie": {\n    "secure": true\n  }\n}\n';
  const preview = producer.preview({ path: 'config/app.json', text: before, finding: finding(producer.ruleIds[0]) });
  const once = renderConfigPreview(before, preview.edits);
  const twice = renderConfigPreview(once, producer.preview({ path: 'config/app.json', text: once, finding: finding(producer.ruleIds[0]) }).edits);
  assert.equal(once, twice);
  assert.equal(JSON.parse(once).cookie.sameSite, 'lax');
  assert.equal(JSON.parse(once).cookie.secure, true, 'unrelated keys must be unchanged');
});

test('every mechanical proposal matches SNIP-16 and never carries an apply step', () => {
  const proposal = planMechanicalRemediation({
    finding: finding('insecure-defaults.tls-reject-unauthorized'),
    sandbox,
    readFile: () => SOURCE,
    binding,
  });
  for (const key of [
    'schemaVersion', 'kind', 'id', 'findingIds', 'owner', 'producer', 'targetPaths', 'preconditions',
    'patch', 'expectedBehavior', 'publicSurfaceChanges', 'affectedFamilies', 'validationPlan', 'rollback',
    'tier', 'binding',
  ]) {
    assert.ok(key in proposal, `SNIP-16 proposal missing ${key}`);
  }
  assert.equal(proposal.kind, 'legion-remediation-proposal');
  assert.equal(proposal.tier, 'MECHANICAL');
  assert.equal(proposal.owner, 'code');
  assert.match(proposal.patch.digest, /^sha256:/);
  assert.deepEqual(proposal.targetPaths, ['src/client.mjs']);
  assert.ok(proposal.validationPlan.length > 0);
  assert.ok(proposal.rollback.reversePatch);
  assert.equal(proposal.applied, undefined, 'a proposal never reports itself applied');
  assert.equal(proposal.verified, undefined, 'a producer never verifies its own result');
  assert.deepEqual(proposal.binding, binding);
  // Deterministic identity.
  assert.equal(proposal.id, planMechanicalRemediation({ finding: finding('insecure-defaults.tls-reject-unauthorized'), sandbox, readFile: () => SOURCE, binding }).id);
});

test('unsupported or ambiguous fixes become MANUAL proposals, not guesses', () => {
  const unsupported = planMechanicalRemediation({
    finding: finding('authorization-tenant.missing-owner-check'),
    sandbox,
    readFile: () => SOURCE,
    binding,
  });
  assert.equal(unsupported.tier, 'MANUAL');
  assert.equal(unsupported.owner, 'manual');
  assert.equal(unsupported.patch, null);
  assert.match(unsupported.reason, /no qualified mechanical producer/);

  // Ambiguity — more than one matching site with no unique target — is manual too.
  const ambiguous = planMechanicalRemediation({
    finding: finding('insecure-defaults.tls-reject-unauthorized', { location: null }),
    sandbox,
    readFile: () => `${SOURCE}const b = { rejectUnauthorized: false };\n`,
    binding,
  });
  assert.equal(ambiguous.tier, 'MANUAL');
  assert.match(ambiguous.reason, /ambiguous/);
  assert.equal(manualProposal({ finding: finding('x'), reason: 'ambiguous target', binding }).tier, 'MANUAL');
});

test('the pre-existing mechanical producer helpers still behave', () => {
  const f = { id: 'f1', rootCauseDigest: 'sha256:root' };
  assert.equal(mechanicalAstGrepProposal({ finding: f, edits: [{ file: 'a.ts' }] }).id, mechanicalAstGrepProposal({ finding: f, edits: [{ file: 'a.ts' }] }).id);
  assert.ok(mechanicalConfigProposal({ finding: f, configPath: 'config.json', change: {} }).validationCommands.includes('config-schema-check'));
  assert.equal(mechanicalDependencyProposal({ finding: f, manifestPath: 'package.json', dependencyChange: {} }).targetPaths[0], 'package.json');
});
