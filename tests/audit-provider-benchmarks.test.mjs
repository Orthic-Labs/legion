import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  BENCHMARK_SCHEMA_VERSION,
  RESULTS_KIND,
  UNMEASURED_BENCHMARK_RECORD,
  computeFixturesDigest,
  computeProviderBinding,
  digestFile,
  fileBindings,
  isResultFresh,
  loadBenchmarkResults,
  measureFixtureSet,
  qualificationFromResults,
  resultQualificationDigest,
  runCli,
  validateBenchmarkResults,
  validateFixtures,
} from '../tools/audit/provider-benchmarks.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const cliPath = resolve(root, 'tools/audit/provider-benchmarks.mjs');

function fixturesDoc() {
  return {
    schemaVersion: 1,
    kind: 'audit-benchmark-fixtures',
    cases: [
      { id: 'case-hit', file: 'src/db.ts', text: 'const API_KEY = "sk-1234";\n', expected: [{ ruleId: 'security.credentials.hardcoded-key', line: 1 }] },
      { id: 'case-miss', file: 'src/auth.ts', text: 'const PASSWORD = "hunter2";\n', expected: [{ ruleId: 'security.credentials.hardcoded-key', line: 1 }] },
      { id: 'case-clean', file: 'src/util.ts', text: 'export const sum = (a, b) => a + b;\n', expected: [] },
    ],
  };
}

function runnerDetectsFirstFileOnly({ files }) {
  const [file] = files;
  if (!file.text.includes('API_KEY')) return [];
  return [{ ruleId: 'security.credentials.hardcoded-key', file: file.path, line: 1 }];
}

function bindingFor(paths) {
  return {
    implementationDigests: [{ path: paths.impl ?? 'src/providers/pack.mjs', digest: 'sha256:' + 'a'.repeat(64) }],
    rulePackDigests: [{ path: paths.pack ?? 'src/providers/security/packs/credentials.mjs', digest: 'sha256:' + 'b'.repeat(64) }],
  };
}

function measuredResult() {
  return measureFixtureSet({
    provider: { id: 'security.credentials', version: '1' },
    binding: bindingFor({}),
    runProvider: runnerDetectsFirstFileOnly,
    fixtures: fixturesDoc(),
    measuredAt: '2026-07-21T00:00:00.000Z',
  });
}

test('fixtures validation enforces ground truth shape and counts clean vs planted cases', () => {
  const stats = validateFixtures(fixturesDoc());
  assert.equal(stats.caseCount, 3);
  assert.equal(stats.plantedFindingCount, 2);
  assert.equal(stats.cleanCaseCount, 1);
  assert.throws(() => validateFixtures({ schemaVersion: 2, kind: 'audit-benchmark-fixtures', cases: [] }), /schemaVersion/);
  assert.throws(() => validateFixtures({
    schemaVersion: 1, kind: 'audit-benchmark-fixtures',
    cases: [{ id: 'x', file: 'a.ts', text: '', expected: [{ ruleId: 'r' }] }],
  }), /integer line/);
});

test('fixture digest is content-bound and order-insensitive', () => {
  const doc = fixturesDoc();
  const reordered = { ...doc, cases: [...doc.cases].reverse() };
  assert.equal(computeFixturesDigest(doc), computeFixturesDigest(reordered));
  const mutated = structuredClone(doc);
  mutated.cases[0].text = 'changed';
  assert.notEqual(computeFixturesDigest(doc), computeFixturesDigest(mutated));
});

test('perfect detection yields precision=1 and recall=1 with no synthesis', () => {
  const result = measureFixtureSet({
    provider: { id: 'p.perfect', version: '1' },
    binding: bindingFor({}),
    runProvider: ({ files }) => files.flatMap((f) => f.text.includes('API_KEY') || f.text.includes('PASSWORD')
      ? [{ ruleId: 'security.credentials.hardcoded-key', file: f.path, line: 1 }]
      : []),
    fixtures: fixturesDoc(),
  });
  assert.deepEqual(result.metrics, { truePositives: 2, falsePositives: 0, falseNegatives: 0, precision: 1, recall: 1 });
});

test('missed planted findings lower recall; extra candidates lower precision — both measured, never assumed', () => {
  const result = measuredResult();
  assert.deepEqual(result.metrics, { truePositives: 1, falsePositives: 0, falseNegatives: 1, precision: 1, recall: 0.5 });
  assert.deepEqual(result.fixtures, { caseCount: 3, plantedFindingCount: 2, cleanCaseCount: 1 });
});

test('false positives are counted against precision', () => {
  const result = measureFixtureSet({
    provider: { id: 'p.noisy', version: '1' },
    binding: bindingFor({}),
    runProvider: ({ files }) => {
      const [file] = files;
      const hits = runnerDetectsFirstFileOnly({ files });
      // one spurious emission on the clean fixture only
      return file.path === 'src/util.ts' ? [...hits, { ruleId: 'security.credentials.hardcoded-key', file: file.path, line: 1 }] : hits;
    },
    fixtures: fixturesDoc(),
  });
  assert.deepEqual(result.metrics, { truePositives: 1, falsePositives: 1, falseNegatives: 1, precision: 0.5, recall: 0.5 });
});

test('zero denominators throw instead of synthesizing metrics', () => {
  const emptyTruth = {
    schemaVersion: 1, kind: 'audit-benchmark-fixtures',
    cases: [{ id: 'clean-only', file: 'a.ts', text: 'x\n', expected: [] }],
  };
  assert.throws(
    () => measureFixtureSet({ provider: { id: 'p', version: '1' }, binding: bindingFor({}), runProvider: () => [], fixtures: emptyTruth }),
    /precision is undefined/,
  );
  assert.throws(
    () => measureFixtureSet({ provider: { id: 'p', version: '1' }, binding: bindingFor({}), runProvider: () => [{ ruleId: 'r.x', file: 'a.ts', line: 1 }], fixtures: emptyTruth }),
    /recall is undefined/,
  );
});

test('runner failures and malformed candidates propagate as errors, never as silent zeros', () => {
  assert.throws(
    () => measureFixtureSet({ provider: { id: 'p', version: '1' }, binding: bindingFor({}), runProvider: () => { throw new Error('boom'); }, fixtures: fixturesDoc() }),
    /failed on fixture case/,
  );
  assert.throws(
    () => measureFixtureSet({ provider: { id: 'p', version: '1' }, binding: bindingFor({}), runProvider: () => [{ ruleId: 'r.x' }], fixtures: fixturesDoc() }),
    /unlocatable candidate/,
  );
});

test('results validate against the frozen references schema; violations are named', () => {
  const result = measuredResult();
  const doc = { schemaVersion: BENCHMARK_SCHEMA_VERSION, kind: RESULTS_KIND, results: [result] };
  assert.deepEqual(validateBenchmarkResults(doc), []);
  const broken = structuredClone(doc);
  broken.results[0].metrics.precision = 42;
  assert.ok(validateBenchmarkResults(broken).some((issue) => issue.includes('.metrics.precision')));
  const wrongKind = { ...doc, kind: 'something-else' };
  assert.ok(validateBenchmarkResults(wrongKind).some((issue) => issue.includes(':const')));
});

test('qualification digests are stable over reruns and change when evidence changes', () => {
  const first = measuredResult();
  const again = measuredResult();
  assert.equal(first.qualificationDigest, again.qualificationDigest);
  assert.equal(first.qualificationDigest, resultQualificationDigest(first));
  const drifted = structuredClone(first);
  drifted.metrics.recall = 0.75;
  assert.notEqual(resultQualificationDigest(first), resultQualificationDigest(drifted));
});

test('freshness binds results to implementation plus rule-pack digests', () => {
  const result = measuredResult();
  assert.equal(isResultFresh(result, bindingFor({})), true);
  assert.equal(isResultFresh(result, bindingFor({ pack: 'src/providers/security/packs/injection.mjs' })), false);
  const tampered = structuredClone(result);
  tampered.binding.rulePackDigests[0].digest = `sha256:${'c'.repeat(64)}`;
  assert.equal(isResultFresh(tampered, bindingFor({})), false);
  const unbound = structuredClone(result);
  unbound.binding.implementationDigests = [];
  unbound.binding.rulePackDigests = [];
  assert.equal(isResultFresh(unbound, {}), false);
});

test('measured providers are distinguished from unmeasured ones with audit-plan-shaped gaps', () => {
  const fresh = measuredResult();
  const stale = structuredClone(fresh);
  stale.provider.id = 'security.injection';
  stale.measuredAt = '2026-07-20T00:00:00.000Z'; // older timestamp loses to nothing
  stale.binding.implementationDigests[0] = { path: 'src/providers/pack.mjs', digest: `sha256:${'d'.repeat(64)}` };

  const doc = { schemaVersion: BENCHMARK_SCHEMA_VERSION, kind: RESULTS_KIND, results: [fresh, stale] };
  const currentByProvider = {
    'security.credentials': bindingFor({}),
    'security.injection': bindingFor({}), // recorded digest no longer matches
  };
  const qualification = qualificationFromResults(doc, {
    currentByProvider,
    requiredProviders: ['legacy.security.binary-pins'],
  });
  assert.equal(qualification.records['security.credentials'].status, 'measured');
  assert.match(qualification.records['security.credentials'].qualificationDigest, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(qualification.records['legacy.security.binary-pins'], UNMEASURED_BENCHMARK_RECORD);
  assert.deepEqual(qualification.unmeasuredProviders.sort(), ['legacy.security.binary-pins', 'security.injection']);
  for (const gap of qualification.benchmarkGaps) {
    assert.deepEqual(gap, { kind: 'unmeasured-rule-pack', provider: gap.provider, benchmarkStatus: 'unproven' });
  }
  assert.equal(qualification.precisionMeasured, false);
});

test('computeProviderBinding digests real provider inputs on disk', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'bench-binding-'));
  writeFileSync(join(scratch, 'engine.mjs'), 'export const engine = true;\n');
  writeFileSync(join(scratch, 'pack.mjs'), 'export const rules = [];\n');
  const provider = {
    id: 'security.credentials',
    runner: { kind: 'runtime-script', script: 'engine.mjs', module: 'pack.mjs' },
  };
  const binding = computeProviderBinding(provider, scratch);
  assert.deepEqual(binding.implementationDigests, [{ path: 'engine.mjs', digest: digestFile(join(scratch, 'engine.mjs')) }]);
  assert.deepEqual(binding.rulePackDigests, [{ path: 'pack.mjs', digest: digestFile(join(scratch, 'pack.mjs')) }]);
  assert.throws(() => computeProviderBinding({ id: 'x', runner: { kind: 'reasoning-contract' } }), /no measurable implementation/);
  assert.throws(() => fileBindings(['missing.mjs'], scratch), /missing on disk/);
});

test('CLI measure writes schema-valid bound results; CLI verify accepts them and rejects corruption', async () => {
  const scratch = mkdtempSync(join(tmpdir(), 'bench-cli-'));
  const runnerScript = join(scratch, 'runner.mjs');
  writeFileSync(runnerScript, `export function run({ files }) {\n  return files.flatMap((f) =>\n    f.text.includes('API_KEY') ? [{ ruleId: 'security.credentials.hardcoded-key', file: f.path, line: 1 }] : []);\n}\n`);
  const fixturesPath = join(scratch, 'fixtures.json');
  writeFileSync(fixturesPath, JSON.stringify(fixturesDoc(), null, 2));
  const outPath = join(scratch, 'results.json');

  execFileSync(process.execPath, [cliPath, 'measure', '--fixtures', fixturesPath, '--runner-script', runnerScript, '--out', outPath], { cwd: root });

  const doc = JSON.parse(readFileSync(outPath, 'utf8'));
  assert.deepEqual(validateBenchmarkResults(doc), []);
  assert.equal(doc.kind, RESULTS_KIND);
  const [result] = doc.results;
  assert.deepEqual(result.metrics, { truePositives: 1, falsePositives: 0, falseNegatives: 1, precision: 1, recall: 0.5 });
  assert.equal(result.binding.implementationDigests[0].path.endsWith('runner.mjs'), true);
  assert.equal(isResultFresh(result, {
    implementationDigests: fileBindings([result.binding.implementationDigests[0].path], root),
    rulePackDigests: [],
  }), true);

  // verify subcommand: valid doc passes
  const ok = spawnSync(process.execPath, [cliPath, 'verify', '--results', outPath], { cwd: root, encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).valid, true);

  // corrupted doc is rejected by schema before anything consumes it
  const corruptPath = join(scratch, 'corrupt.json');
  const corrupt = structuredClone(doc);
  corrupt.results[0].binding.fixturesDigest = 'sha256:not-a-digest';
  writeFileSync(corruptPath, JSON.stringify(corrupt, null, 2));
  const bad = spawnSync(process.execPath, [cliPath, 'verify', '--results', corruptPath], { cwd: root, encoding: 'utf8' });
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /error:/);

  // status subcommand distinguishes measured from unmeasured and exits nonzero on gaps
  const statusPath = join(scratch, 'status.json');
  writeFileSync(statusPath, JSON.stringify({ ...doc, results: [doc.results[0]] }));
  const gaps = await runCli(['status', '--results', statusPath, '--require', 'security.injection']);
  assert.equal(gaps, 1); // required-but-unmeasured provider forces exit 1
});
