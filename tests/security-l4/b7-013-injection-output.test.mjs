import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runSecurityPack } from '../../providers/security/candidate-engine.mjs';
import { entity, controlEntity, relation } from '../../providers/security/model-extractors/common.mjs';
import injectionPack from '../../providers/security/packs/injection.mjs';
import outputHandlingPack from '../../providers/security/packs/output-handling.mjs';

const registryPath = fileURLToPath(new URL('../../registry/rules/security/injection-output.json', import.meta.url));
const registry = JSON.parse(readFileSync(registryPath, 'utf8'));

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev', dirtyPatchDigest: null,
  cortexGenerationId: 'gen', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planFor(pack, files) {
  return {
    seal: { digest: BINDING.planDigest },
    binding: {
      repositoryRevision: BINDING.repositoryRevision, dirtyPatchDigest: null,
      cortex: { generationId: BINDING.cortexGenerationId, manifestDigest: BINDING.cortexManifestDigest },
      registryDigest: BINDING.registryDigest,
    },
    providers: [{
      id: pack.id,
      benchmark: { requiredForCleanClaim: true },
      denominator: { pathDigest: 'sha256:denom', pathCount: files.length, paths: files },
    }],
  };
}

// Builds a minimal security-surface-model with one repository-artifact per
// file (each carrying evidence), plus any extra entities/relations a test
// wants to exercise (e.g. control entities wired via a `protects` relation).
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

test('registry rule ids and pack rule ids are in exact parity', () => {
  assert.equal(registry.schemaVersion, 1);
  assert.ok(Array.isArray(registry.rules) && registry.rules.length > 0);

  const registryIds = new Set(registry.rules.map((r) => r.id));
  const packIds = new Set([
    ...injectionPack.rules.map((r) => r.id),
    ...outputHandlingPack.rules.map((r) => r.id),
  ]);

  for (const id of packIds) {
    assert.ok(registryIds.has(id), `registry is missing pack rule ${id}`);
  }
  for (const id of registryIds) {
    assert.ok(packIds.has(id), `registry has an orphan rule ${id} not exported by either pack`);
  }
  assert.equal(registryIds.size, packIds.size);

  for (const rule of registry.rules) {
    assert.equal(typeof rule.version, 'string');
    assert.ok(rule.pack === 'security.injection' || rule.pack === 'security.output-handling');
    assert.equal(typeof rule.sinkClass, 'string');
    assert.equal(typeof rule.decisionMode, 'string');
    assert.equal(typeof rule.cleanClaim, 'string');
    assert.ok(Array.isArray(rule.requiredControls));
    assert.ok(Array.isArray(rule.applicability));
  }
});

// ---------------------------------------------------------------------------
// injection.mjs: sink coverage across the required sink classes.
// ---------------------------------------------------------------------------

const injectionFixtures = [
  ['injection.sql.dynamic-query', 'db.query(`SELECT * FROM users WHERE id = ${request.query.id}`);', 'db.mjs'],
  ['injection.nosql.operator-injection', 'collection.find(request.body);', 'nosql.mjs'],
  ['injection.orm.raw-query-with-input', 'sequelize.query(`SELECT * FROM t WHERE x = ${request.body.x}`);', 'orm.mjs'],
  ['injection.command.shell-exec', 'child_process.exec(request.body.cmd);', 'cmd.mjs'],
  ['injection.ldap.filter-injection', '// ldap search\nconst filter = "(uid=" + request.body.uid + ")";', 'ldap.mjs'],
  ['injection.template.server-side-template-injection', 'nunjucks.renderString(request.body.template, {});', 'tmpl.mjs'],
  ['injection.regex.redos', 'const re = /(a+)+$/;', 'redos.mjs'],
  ['injection.prototype-pollution.unsafe-key-assignment', 'target[request.body.key] = request.body.value;', 'proto.mjs'],
  ['injection.xxe.external-entity-enabled', '// libxmljs parser\nconst opts = { noent: true };', 'xxe.mjs'],
  ['injection.formula.csv-export-unescaped', '// csv export\naddRow([request.body.name, request.body.amount]);', 'formula.mjs'],
];

test('injection pack detects each required sink class as a pattern-only candidate', () => {
  for (const [ruleId, source, file] of injectionFixtures) {
    const result = run(injectionPack, { [file]: source });
    assert.equal(result.status, 'candidates', `${ruleId} missed its fixture`);
    assert.deepEqual(result.findings, []);
    const candidate = result.candidates.find((c) => c.ruleId === ruleId);
    assert.ok(candidate, `${ruleId} did not produce a candidate`);
    assert.equal(candidate.verdict, 'UNADJUDICATED');
    assert.equal(candidate.adjudicationRequired, true);
    assert.ok(candidate.evidenceRefs.length > 0, `${ruleId} candidate must carry evidence`);
    assert.equal(candidate.detectorMetadata.detectionMethod, 'lexical-pattern');
    assert.equal(candidate.detectorMetadata.file, file);
    assert.equal(typeof candidate.detectorMetadata.line, 'number');
    assert.ok(candidate.detectorMetadata.sinkEngine, `${ruleId} must name a sink engine`);
    assert.ok(candidate.uncertainty.length > 0, `${ruleId} must carry explicit uncertainty`);
    assert.ok(
      candidate.uncertainty.some((u) => /lexical pattern|not confirmed by/i.test(u)),
      `${ruleId} must mark itself as a lexical-only detection`,
    );
  }
});

test('injection pack emits no candidates for a neutral source across every rule', () => {
  const result = run(injectionPack, { 'neutral.mjs': 'export const value = 1;' });
  assert.equal(result.candidates.length, 0);
});

// ---------------------------------------------------------------------------
// injection.mjs: mitigation handling — suppression and downgrade.
// ---------------------------------------------------------------------------

test('a genuinely parameterized SQL query produces no injection.sql candidate', () => {
  const result = run(injectionPack, {
    'safe-db.mjs': 'db.query(`SELECT * FROM users WHERE id = ?`, [request.query.id]);',
  });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'injection.sql.dynamic-query'));
});

test('an observed sql-parameterization control downgrades the sql candidate instead of hiding it', () => {
  const control = controlEntity('sql-parameterization', 'query builder parameterization', ['ev:control']);
  const source = { 'db.mjs': 'db.query(`SELECT * FROM users WHERE id = ${request.query.id}`);' };
  const files = Object.keys(source);
  const baselineModel = modelFor(files);
  const artifactId = artifactIdFor(baselineModel, 'db.mjs');
  const protects = relation('protects', control.id, artifactId, ['ev:control']);

  const highSeverity = run(injectionPack, source);
  const highCandidate = highSeverity.candidates.find((c) => c.ruleId === 'injection.sql.dynamic-query');
  assert.ok(highCandidate);
  assert.equal(highCandidate.severityHint, 'high');
  assert.deepEqual(highCandidate.observedControls, []);

  const downgraded = run(injectionPack, source, { extraEntities: [control], extraRelations: [protects] });
  const downgradedCandidate = downgraded.candidates.find((c) => c.ruleId === 'injection.sql.dynamic-query');
  assert.ok(downgradedCandidate);
  assert.notEqual(downgradedCandidate.severityHint, 'high');
  assert.deepEqual(downgradedCandidate.observedControls, [control.id]);
  assert.ok(downgradedCandidate.uncertainty.some((u) => /observed/i.test(u) && /control/i.test(u)));
});

test('injection pack consumes a SAST trace from the projection when present', () => {
  const source = { 'db.mjs': 'db.query(`SELECT * FROM users WHERE id = ${request.query.id}`);' };
  const auditFacts = { injectionTraces: [{ file: 'db.mjs', sinkClass: 'sql' }] };
  const result = run(injectionPack, source, { auditFacts });
  const candidate = result.candidates.find((c) => c.ruleId === 'injection.sql.dynamic-query');
  assert.equal(candidate.detectorMetadata.detectionMethod, 'sast-trace');
});

// ---------------------------------------------------------------------------
// injection.mjs: variantStrategies shape (root cause + enumerate).
// ---------------------------------------------------------------------------

test('injection pack declares variantStrategies with rootCause/enumerate for every rule', () => {
  for (const rule of injectionPack.rules) {
    const strategy = injectionPack.variantStrategies[rule.id];
    assert.ok(strategy, `missing variant strategy for ${rule.id}`);
    assert.equal(typeof strategy.rootCause, 'function');
    assert.equal(typeof strategy.enumerate, 'function');
  }
});

// ---------------------------------------------------------------------------
// injection.mjs: pinned pre-existing behaviour (shell sink, degrade-safe).
// ---------------------------------------------------------------------------

test('injection pack keeps shell sink metadata and command-injection uncertainty (pinned)', () => {
  const model = {
    schemaVersion: 1, kind: 'security-surface-model', binding: BINDING,
    denominatorDigest: 'sha256:denom', complete: true,
    entities: [
      entity('repository-artifact', 'env.ts', { path: 'env.ts' }, ['ev1']),
      controlEntity('secret-exclusion', 'secret exclusion', ['ev1']),
    ],
    relations: [], initialFacts: [],
    evidence: [{ id: 'ev1', kind: 'source-location', file: 'env.ts' }],
    coverage: {}, coverageGaps: [],
  };
  const plan = {
    seal: { digest: BINDING.planDigest },
    binding: {
      repositoryRevision: BINDING.repositoryRevision, dirtyPatchDigest: null,
      cortex: { generationId: BINDING.cortexGenerationId, manifestDigest: BINDING.cortexManifestDigest },
      registryDigest: BINDING.registryDigest,
    },
    providers: [{ id: 'security.injection', benchmark: { requiredForCleanClaim: true }, denominator: { pathDigest: 'sha256:denom', pathCount: 1, paths: ['app.py'] } }],
  };
  const projection = { files: ['app.py'], sourceText: { 'app.py': 'import os\nos.system(request.args.get("cmd"))' }, auditFacts: {} };
  const result = runSecurityPack({ pack: injectionPack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
  assert.ok(result.candidates.length >= 1);
  const shell = result.candidates.find((c) => c.detectorMetadata?.sinkKind === 'shell');
  assert.ok(shell, 'shell sink candidate present');
  assert.ok(shell.uncertainty.some((u) => /not automatically command injection/.test(u)));
  // No repository-artifact entity exists for app.py in this model, so the
  // pack must degrade sources/sinks/evidenceRefs to [] rather than invent
  // or throw on an unknown model reference.
  assert.deepEqual(shell.sources, []);
  assert.deepEqual(shell.sinks, []);
});

// ---------------------------------------------------------------------------
// output-handling.mjs: explicit output context across the required set.
// ---------------------------------------------------------------------------

const outputFixtures = [
  ['output.html.body-unescaped', 'html-body', 'element.innerHTML = request.body.content;', 'html.mjs'],
  ['output.html.attribute-unescaped', 'html-attribute', 'element.setAttribute("href", request.query.url);', 'attr.mjs'],
  ['output.js.inline-script-unescaped', 'js', '<script>var data = ${request.body.value}</script>', 'inline.mjs'],
  ['output.url.open-redirect', 'url', 'res.redirect(request.query.next);', 'redirect.mjs'],
  ['output.css.style-unescaped', 'css', 'element.style.cssText = request.body.style;', 'style.mjs'],
  ['output.shell.command-template', 'shell', 'exec(`rm -rf ${request.query.path}`);', 'shell.mjs'],
  ['output.sql.stored-content-interpolation', 'sql', 'db.query(`SELECT * FROM t WHERE x = ${record.value}`);', 'sql.mjs'],
  ['output.log.newline-injection', 'log', 'logger.info(request.body.username);', 'log.mjs'],
];

test('output-handling pack names an explicit output context for every rule', () => {
  const seenContexts = new Set();
  for (const [ruleId, expectedContext, source, file] of outputFixtures) {
    const result = run(outputHandlingPack, { [file]: source });
    const candidate = result.candidates.find((c) => c.ruleId === ruleId);
    assert.ok(candidate, `${ruleId} did not produce a candidate`);
    assert.equal(candidate.detectorMetadata.outputContext, expectedContext);
    seenContexts.add(candidate.detectorMetadata.outputContext);
  }
  for (const required of ['html-body', 'html-attribute', 'js', 'url', 'css', 'shell', 'sql', 'log']) {
    assert.ok(seenContexts.has(required), `missing required output context ${required}`);
  }
});

test('output-handling pack emits no candidates for a neutral source', () => {
  const result = run(outputHandlingPack, { 'neutral.mjs': 'export const value = 1;' });
  assert.equal(result.candidates.length, 0);
});

// ---------------------------------------------------------------------------
// output-handling.mjs: mitigation handling.
// ---------------------------------------------------------------------------

test('a sanitized HTML sink produces no output.html.body-unescaped candidate', () => {
  const result = run(outputHandlingPack, {
    'safe-html.mjs': 'element.innerHTML = DOMPurify.sanitize(request.body.content);',
  });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'output.html.body-unescaped'));
});

test('a CRLF-stripped log sink produces no output.log.newline-injection candidate', () => {
  const result = run(outputHandlingPack, {
    'safe-log.mjs': "logger.info(request.body.username.replace(/[\\r\\n]/g, ''));",
  });
  assert.ok(!result.candidates.some((c) => c.ruleId === 'output.log.newline-injection'));
});

// ---------------------------------------------------------------------------
// output-handling.mjs: pinned pre-existing behaviour (extended-packs fixture).
// ---------------------------------------------------------------------------

test('output-handling pack keeps the pinned innerHTML fixture behaviour', () => {
  const result = run(outputHandlingPack, { 'app.mjs': 'element.innerHTML = request.body.content' });
  assert.equal(result.status, 'candidates');
  assert.deepEqual(result.findings, []);
  assert.ok(result.candidates.length > 0);
  assert.ok(result.candidates.every((c) => c.verdict === 'UNADJUDICATED'));
  assert.ok(result.candidates.every((c) => c.evidenceRefs.length > 0));
});

test('output-handling pack declares variantStrategies with rootCause/enumerate for every rule', () => {
  for (const rule of outputHandlingPack.rules) {
    const strategy = outputHandlingPack.variantStrategies[rule.id];
    assert.ok(strategy, `missing variant strategy for ${rule.id}`);
    assert.equal(typeof strategy.rootCause, 'function');
    assert.equal(typeof strategy.enumerate, 'function');
  }
});
