// B7-015 — request-boundary, SSRF, file, parser, upload, and serialization
// packs.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runSecurityPack } from '../../src/providers/security/candidate-engine.mjs';
import { entity, controlEntity, relation } from '../../src/providers/security/model-extractors/common.mjs';
import requestBoundariesPack from '../../src/providers/security/packs/request-boundaries.mjs';
import ssrfEgressPack from '../../src/providers/security/packs/ssrf-egress.mjs';
import fileBoundariesPack from '../../src/providers/security/packs/file-boundaries.mjs';
import parserSerializationPack from '../../src/providers/security/packs/parser-serialization.mjs';
import uploadsPack from '../../src/providers/security/packs/uploads.mjs';

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const PACKS = [requestBoundariesPack, ssrfEgressPack, fileBoundariesPack, parserSerializationPack, uploadsPack];

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev', dirtyPatchDigest: null,
  blueprintGenerationId: 'gen', blueprintManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planFor(pack, files) {
  return {
    seal: { digest: BINDING.planDigest },
    binding: {
      repositoryRevision: BINDING.repositoryRevision, dirtyPatchDigest: null,
      blueprint: { generationId: BINDING.blueprintGenerationId, manifestDigest: BINDING.blueprintManifestDigest },
      registryDigest: BINDING.registryDigest,
    },
    providers: [{
      id: pack.id,
      benchmark: { requiredForCleanClaim: true },
      denominator: { pathDigest: 'sha256:denom', pathCount: files.length, paths: files },
    }],
  };
}

function modelFor(files, { extraEntities = [], extraRelations = [] } = {}) {
  const entities = [];
  const evidence = [];
  for (const file of files) {
    const evidenceRef = `ev:${file}`;
    entities.push(entity('repository-artifact', file, { path: file }, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Repository artifact' });
  }
  entities.push(...extraEntities);
  return {
    schemaVersion: 1, kind: 'security-surface-model',
    binding: BINDING, denominatorDigest: 'sha256:denom', complete: true,
    entities, relations: extraRelations, initialFacts: [], evidence,
    coverage: {}, coverageGaps: [],
  };
}

function run(pack, sourceByFile, options = {}) {
  const files = Object.keys(sourceByFile);
  const plan = planFor(pack, files);
  const model = modelFor(files, options);
  const projection = { files, sourceText: sourceByFile, auditFacts: options.auditFacts ?? {} };
  return runSecurityPack({ pack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
}

function artifactIdFor(model, file) {
  return model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes.path === file)?.id;
}

// ---------------------------------------------------------------------------
// Registry <-> pack rule-id parity (both directions).
// ---------------------------------------------------------------------------

test('boundaries registry rule ids and the five packs\' rule ids are in exact parity', () => {
  const registry = JSON.parse(readFileSync(new URL('../../src/registry/rules/security/boundaries.json', import.meta.url), 'utf8'));
  assert.equal(registry.schemaVersion, 1);
  assert.ok(Array.isArray(registry.rules) && registry.rules.length > 0);

  const registryIds = new Set(registry.rules.map((r) => r.id));
  const packIds = new Set(PACKS.flatMap((pack) => pack.rules.map((r) => r.id)));

  for (const id of packIds) assert.ok(registryIds.has(id), `registry is missing pack rule ${id}`);
  for (const id of registryIds) assert.ok(packIds.has(id), `registry has an orphan rule ${id} not exported by any of the five packs`);
  assert.equal(registryIds.size, packIds.size);
  assert.equal(registryIds.size, registry.rules.length, 'registry rule ids must be unique');

  const validPacks = new Set(PACKS.map((p) => p.id));
  for (const rule of registry.rules) {
    assert.equal(typeof rule.version, 'string');
    assert.ok(validPacks.has(rule.pack), `${rule.id} pack ${rule.pack} is not one of the five owned packs`);
    assert.equal(typeof rule.class, 'string');
    assert.equal(typeof rule.decisionMode, 'string');
    assert.equal(typeof rule.cleanClaim, 'string');
    assert.ok(Array.isArray(rule.requiredControls));
    assert.ok(Array.isArray(rule.applicability));
  }
});

// ---------------------------------------------------------------------------
// Forbidden: no live-network / live-filesystem imports anywhere in the five
// owned modules, and no filesystem read outside context.readFile.
// ---------------------------------------------------------------------------

test('none of the five packs import a live network, filesystem, or process module', () => {
  const forbidden = /\bnode:fs\b|\bnode:https?\b|\bnode:net\b|\bnode:dgram\b|\bnode:child_process\b|\bnode:zlib\b/;
  const relatives = [
    '../../src/providers/security/packs/request-boundaries.mjs',
    '../../src/providers/security/packs/ssrf-egress.mjs',
    '../../src/providers/security/packs/file-boundaries.mjs',
    '../../src/providers/security/packs/parser-serialization.mjs',
    '../../src/providers/security/packs/uploads.mjs',
  ];
  for (const relative of relatives) {
    const source = readFileSync(new URL(relative, import.meta.url), 'utf8');
    assert.ok(!forbidden.test(source), `${relative} must not import a live network/filesystem/process module`);
    assert.ok(!/\breadFileSync\b|\bwriteFileSync\b|\bexecSync\b|\bspawnSync\b/.test(source), `${relative} must not read/write the filesystem or spawn a process directly`);
  }
});

// ---------------------------------------------------------------------------
// Every pack: adjudication-only output shape.
// ---------------------------------------------------------------------------

const HAZARD_FIXTURES = [
  [requestBoundariesPack, 'fetch(request.query.url)', 'app.mjs'],
  [ssrfEgressPack, 'fetch(request.query.url)', 'egress.mjs'],
  [fileBoundariesPack, 'fs.readFile(request.query.filename)', 'files.mjs'],
  [parserSerializationPack, 'yaml.load(request.body.doc)', 'parser.mjs'],
  [uploadsPack, "multer()\ndestination: 'public/uploads'", 'uploads.mjs'],
];

test('each of the five packs emits adjudication-only candidates for a representative hazard', () => {
  for (const [pack, source, file] of HAZARD_FIXTURES) {
    const result = run(pack, { [file]: source });
    assert.equal(result.status, 'candidates', `${pack.id} missed its fixture`);
    assert.ok(result.candidates.length > 0, `${pack.id} produced no candidates`);
    assert.deepEqual(result.findings, []);
    for (const candidate of result.candidates) {
      assert.equal(candidate.verdict, 'UNADJUDICATED');
      assert.equal(candidate.adjudicationRequired, true);
      assert.ok(candidate.evidenceRefs.length > 0, `${pack.id}/${candidate.ruleId} candidate must carry evidence`);
      assert.ok(!('severity' in candidate));
      assert.ok(!('evidenceStrength' in candidate));
    }
  }
});

test('each of the five packs emits zero candidates for a neutral source', () => {
  for (const pack of PACKS) {
    const result = run(pack, { 'neutral.mjs': 'export const value = 1;' });
    assert.equal(result.candidates.length, 0, pack.id);
  }
});

// ---------------------------------------------------------------------------
// Exact source/sink/control naming in detectorMetadata.
// ---------------------------------------------------------------------------

test('every candidate names an exact file, line, sourceExpr, sinkApi, and controlObserved in detectorMetadata', () => {
  for (const [pack, source, file] of HAZARD_FIXTURES) {
    const result = run(pack, { [file]: source });
    for (const candidate of result.candidates) {
      const meta = candidate.detectorMetadata;
      assert.equal(meta.file, file, `${pack.id}/${candidate.ruleId} must name the exact file`);
      assert.equal(typeof meta.line, 'number', `${pack.id}/${candidate.ruleId} must name an exact line`);
      assert.ok(typeof meta.sourceExpr === 'string' && meta.sourceExpr.length > 0, `${pack.id}/${candidate.ruleId} must name an exact sourceExpr`);
      assert.ok(typeof meta.sinkApi === 'string' && meta.sinkApi.length > 0, `${pack.id}/${candidate.ruleId} must name an exact sinkApi`);
      assert.ok('controlObserved' in meta, `${pack.id}/${candidate.ruleId} must declare controlObserved (even if null)`);
    }
  }
});

// ---------------------------------------------------------------------------
// Boundary findings preserve attack preconditions.
// ---------------------------------------------------------------------------

test('boundary candidates preserve attack preconditions naming the attacker position', () => {
  for (const [pack, source, file] of HAZARD_FIXTURES) {
    const result = run(pack, { [file]: source });
    for (const candidate of result.candidates) {
      assert.ok(Array.isArray(candidate.preconditions) && candidate.preconditions.length > 0, `${pack.id}/${candidate.ruleId} must have non-empty preconditions`);
      for (const pre of candidate.preconditions) {
        assert.equal(pre.kind, 'attacker-position');
        assert.equal(pre.subject, 'actor:external');
        assert.ok(typeof pre.action === 'string' && pre.action.length > 0, `${pack.id}/${candidate.ruleId} precondition must name what the attacker controls`);
      }
    }
  }
});

// ---------------------------------------------------------------------------
// request-boundaries.mjs — mitigation via observed schema-validation control.
// ---------------------------------------------------------------------------

test('an observed request-schema-validation control downgrades the input-validation candidate instead of hiding it', () => {
  const source = { 'handler.mjs': 'fetch(request.query.url)' };
  const files = Object.keys(source);
  const baselineModel = modelFor(files);
  const artifactId = artifactIdFor(baselineModel, 'handler.mjs');

  const baseline = run(requestBoundariesPack, source);
  const baselineCandidate = baseline.candidates.find((c) => c.ruleId === 'request.unvalidated-input-to-sink');
  assert.ok(baselineCandidate);
  assert.equal(baselineCandidate.severityHint, 'medium');
  assert.deepEqual(baselineCandidate.observedControls, []);

  const control = controlEntity('request-schema-validation', 'joi request schema', ['ev:control']);
  const protects = relation('protects', control.id, artifactId, ['ev:control']);
  const downgraded = run(requestBoundariesPack, source, { extraEntities: [control], extraRelations: [protects] });
  const downgradedCandidate = downgraded.candidates.find((c) => c.ruleId === 'request.unvalidated-input-to-sink');
  assert.ok(downgradedCandidate);
  assert.notEqual(downgradedCandidate.severityHint, 'medium');
  assert.deepEqual(downgradedCandidate.observedControls, [control.id]);
  assert.ok(downgradedCandidate.uncertainty.some((u) => /observed/i.test(u) && /control/i.test(u)));
});

// ---------------------------------------------------------------------------
// ssrf-egress.mjs — unknown egress environment stays bounded; an observed
// allowlist downgrades with the control referenced.
// ---------------------------------------------------------------------------

test('an SSRF candidate with no egress-environment evidence is capped at medium and marked unproven', () => {
  const result = run(ssrfEgressPack, { 'egress.mjs': 'fetch(request.query.url)' });
  const candidate = result.candidates.find((c) => c.ruleId === 'ssrf.request-controlled-destination');
  assert.ok(candidate);
  assert.ok(SEVERITY_RANK[candidate.severityHint] <= SEVERITY_RANK.medium, 'severity must be capped at medium when egress environment is unknown');
  assert.ok(candidate.uncertainty.some((u) => /unknown/i.test(u) && /egress/i.test(u)), 'must carry an explicit unknown-egress-environment uncertainty note');
});

test('a deployment-evidenced egress environment lifts the medium cap on the SSRF candidate', () => {
  const source = { 'egress.mjs': 'fetch(request.query.url)' };
  const auditFacts = { deployment: { httpsEnforced: true } };
  const result = run(ssrfEgressPack, source, { auditFacts });
  const candidate = result.candidates.find((c) => c.ruleId === 'ssrf.request-controlled-destination');
  assert.ok(candidate);
  assert.equal(candidate.severityHint, 'high');
});

test('an observed egress-allowlist control downgrades the SSRF candidate and references the control', () => {
  const source = { 'egress.mjs': 'fetch(request.query.url)' };
  const files = Object.keys(source);
  const baselineModel = modelFor(files);
  const artifactId = artifactIdFor(baselineModel, 'egress.mjs');
  const control = controlEntity('egress-allowlist', 'outbound host allowlist', ['ev:control']);
  const protects = relation('protects', control.id, artifactId, ['ev:control']);

  const result = run(ssrfEgressPack, source, { extraEntities: [control], extraRelations: [protects] });
  const candidate = result.candidates.find((c) => c.ruleId === 'ssrf.request-controlled-destination');
  assert.ok(candidate);
  assert.equal(candidate.severityHint, 'low');
  assert.deepEqual(candidate.observedControls, [control.id]);
});

// ---------------------------------------------------------------------------
// Mitigated fixtures produce no candidates, or clearly downgraded ones.
// ---------------------------------------------------------------------------

test('a size-capped body parser produces no request.body-size-unbounded candidate', () => {
  const result = run(requestBoundariesPack, { 'app.mjs': "app.use(express.json({ limit: '100kb' }));" });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'request.body-size-unbounded'));
});

test('a normalized and confined path produces no file.path-traversal-unvalidated candidate at full severity', () => {
  const vulnerable = run(fileBoundariesPack, { 'files.mjs': 'fs.readFile(request.query.filename)' });
  const vulnerableCandidate = vulnerable.candidates.find((c) => c.ruleId === 'file.path-traversal-unvalidated');
  assert.equal(vulnerableCandidate.severityHint, 'high');

  const mitigated = run(fileBoundariesPack, {
    'files.mjs': 'const safe = path.normalize(x); if (!safe.startsWith(root)) throw new Error();\nfs.readFile(request.query.filename)',
  });
  const mitigatedCandidate = mitigated.candidates.find((c) => c.ruleId === 'file.path-traversal-unvalidated');
  assert.ok(mitigatedCandidate);
  assert.equal(mitigatedCandidate.severityHint, 'low');
});

test('a yaml.load using a SafeLoader marker downgrades the unsafe-deserialization candidate', () => {
  const unsafe = run(parserSerializationPack, { 'parser.mjs': 'yaml.load(request.body.doc)' });
  assert.equal(unsafe.candidates.find((c) => c.ruleId === 'parser.unsafe-deserialization').severityHint, 'high');

  const safer = run(parserSerializationPack, { 'parser.mjs': 'yaml.load(request.body.doc, { Loader: yaml.SafeLoader })' });
  const saferCandidate = safer.candidates.find((c) => c.ruleId === 'parser.unsafe-deserialization');
  assert.ok(saferCandidate);
  assert.equal(saferCandidate.severityHint, 'low');
});

test('a content-type-checked upload handler produces no upload.content-type-unvalidated candidate', () => {
  const result = run(uploadsPack, { 'uploads.mjs': "multer({ fileFilter: onlyImages, limits: { fileSize: 1000000 } })" });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'upload.content-type-unvalidated'));
  assert.ok(!result.candidates.some((c) => c.ruleId === 'upload.size-unbounded'));
});

// ---------------------------------------------------------------------------
// variantStrategies enumerate alternate request/file/parser/upload paths.
// ---------------------------------------------------------------------------

test('every rule in every pack declares a variantStrategy with rootCause and enumerate', () => {
  for (const pack of PACKS) {
    for (const rule of pack.rules) {
      const strategy = pack.variantStrategies[rule.id];
      assert.ok(strategy, `${pack.id} is missing a variantStrategy for ${rule.id}`);
      assert.equal(typeof strategy.rootCause, 'function');
      assert.equal(typeof strategy.enumerate, 'function');
    }
  }
});

test('variantStrategies.enumerate reports a denominator and CONFIRMED matches for a known hazard', () => {
  const [pack, source, file] = HAZARD_FIXTURES[0];
  const result = run(pack, { [file]: source });
  const candidate = result.candidates[0];
  const strategy = pack.variantStrategies[candidate.ruleId];
  const context = { files: [file], readFile: () => source, denominatorDigest: 'sha256:denom' };
  const receipt = strategy.enumerate(context);
  assert.equal(receipt.denominator.kind, 'source-files');
  assert.ok(receipt.matches.length > 0);
  assert.ok(receipt.matches.every((m) => m.disposition === 'CONFIRMED' || m.disposition === 'MITIGATED'));
});
