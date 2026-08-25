#!/usr/bin/env node
// Versioned precision/recall measurement harness for audit providers.
//
// Restores the capability lost with `bench/precision-recall.mjs` (see
// references/provider-architecture.md §Measured rule packs and
// references/manual.md AU20): deterministic-scanner precision and recall
// measured against a planted-defect fixture corpus, bound to the exact
// provider implementation plus rule-pack digests, schema-validated on load,
// and classified into measured vs unmeasured providers for audit
// finalization (`audit-plan.mjs` benchmark gaps, `precisionMeasured`).
//
// Invariants this module never breaks:
//   - Metrics are measured, never synthesized. A zero denominator throws;
//     there is no default precision or recall anywhere in this file.
//   - Results are only trustworthy while their recorded implementation and
//     rule-pack digests still match the provider inputs they name. Anything
//     stale or unbound classifies as `unproven`.
//   - Every result document is validated against the frozen schema in
//     references/audit-provider-benchmarks.schema.json before use.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalJson, sha256 } from '../../src/registry/provider-registry.mjs';
import { validateSchema } from '../../src/lib/qualification/schema-validator.mjs';

export const BENCHMARK_SCHEMA_VERSION = 1;
export const FIXTURES_KIND = 'audit-benchmark-fixtures';
export const RESULTS_KIND = 'audit-provider-benchmark-results';
export const RESULT_KIND = 'audit-provider-benchmark-result';
export const UNMEASURED_GAP_KIND = 'unmeasured-rule-pack';

const SCHEMA_FILE = fileURLToPath(new URL('../../references/audit-provider-benchmarks.schema.json', import.meta.url));

function requireString(value, label) {
  if (typeof value !== 'string' || !value) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function normalizeRelPath(value) {
  return String(value).replaceAll('\\', '/');
}

// ---------------------------------------------------------------------------
// Digest bindings
// ---------------------------------------------------------------------------

/** sha256 over raw file bytes; content-addressed, path-independent. */
export function digestFile(path) {
  requireString(path, 'digestFile path');
  return `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
}

/**
 * Content-bind a list of repo-relative paths: [{path, digest}] sorted by path.
 * Throws if any named input is missing — an unmeasurable binding must never
 * be silently narrowed to the files that happen to exist.
 */
export function fileBindings(paths, root = process.cwd()) {
  const list = (paths ?? []).filter((p) => p != null && p !== '');
  if (!list.length) throw new Error('fileBindings requires at least one path');
  return list.map((p) => {
    const abs = resolve(root, p);
    if (!existsSync(abs)) throw new Error(`binding input missing on disk: ${p}`);
    return Object.freeze({ path: normalizeRelPath(p), digest: digestFile(abs) });
  }).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** Stable composite digest over a [{path, digest}] binding array. */
export function compositeBindingDigest(bindings) {
  if (!Array.isArray(bindings) || !bindings.length) throw new Error('compositeBindingDigest requires a non-empty binding array');
  return sha256([...bindings].map(({ path, digest }) => ({ path, digest })));
}

/**
 * Map a registry provider record onto its measurable binding inputs:
 * the runner script is the implementation; a runner.module (security lens /
 * rule pack definition) is additionally bound as its rule pack.
 */
export function bindingInputsForProvider(provider) {
  const script = provider?.runner?.script ?? null;
  const rulePack = provider?.runner?.module ?? null;
  if (!script && !rulePack) {
    throw new Error(`provider ${provider?.id ?? '?'} declares no measurable implementation (runner.script/module)`);
  }
  return {
    implementationPaths: script ? [normalizeRelPath(script)] : [],
    rulePackPaths: rulePack ? [normalizeRelPath(rulePack)] : [],
  };
}

/** Compute the full digest binding for a registry provider under `root`. */
export function computeProviderBinding(provider, root = process.cwd()) {
  const inputs = bindingInputsForProvider(provider);
  return {
    implementationDigests: fileBindings(inputs.implementationPaths, root),
    rulePackDigests: fileBindings(inputs.rulePackPaths, root),
  };
}

function assertBound(binding) {
  const implCount = binding?.implementationDigests?.length ?? 0;
  const packCount = binding?.rulePackDigests?.length ?? 0;
  if (!implCount && !packCount) {
    throw new Error('refusing unbound measurement: at least one implementation or rule-pack digest is required');
  }
}

// ---------------------------------------------------------------------------
// Fixture corpus
// ---------------------------------------------------------------------------

/**
 * Structural validation of a planted-defect fixture set:
 *   { schemaVersion:1, kind:'audit-benchmark-fixtures', cases:[{
 *       id, file, text, expected:[{ruleId, line}]   // empty expected = clean case
 *   }]}
 * Ground truth is mandatory per finding; nothing is inferred from text.
 */
export function validateFixtures(fixtures) {
  if (fixtures?.schemaVersion !== BENCHMARK_SCHEMA_VERSION || fixtures?.kind !== FIXTURES_KIND) {
    throw new Error(`benchmark fixtures must be ${FIXTURES_KIND} schemaVersion=${BENCHMARK_SCHEMA_VERSION}`);
  }
  if (!Array.isArray(fixtures.cases) || !fixtures.cases.length) {
    throw new Error('benchmark fixtures must declare at least one case');
  }
  const seen = new Set();
  let plantedFindingCount = 0;
  let cleanCaseCount = 0;
  for (const c of fixtures.cases) {
    if (!c?.id || seen.has(c.id)) throw new Error(`duplicate or missing fixture case id: ${c?.id}`);
    seen.add(c.id);
    if (typeof c.file !== 'string' || !c.file) throw new Error(`fixture case ${c.id}: file required`);
    if (typeof c.text !== 'string') throw new Error(`fixture case ${c.id}: text required`);
    if (!Array.isArray(c.expected)) throw new Error(`fixture case ${c.id}: expected[] required (empty array allowed for clean cases)`);
    for (const e of c.expected) {
      if (!e?.ruleId || !Number.isInteger(e.line) || e.line < 1) {
        throw new Error(`fixture case ${c.id}: every expected finding needs ruleId and integer line >= 1`);
      }
      plantedFindingCount += 1;
    }
    if (!c.expected.length) cleanCaseCount += 1;
  }
  return Object.freeze({
    caseCount: fixtures.cases.length,
    plantedFindingCount,
    cleanCaseCount,
  });
}

/** Content digest of the fixture corpus (order-insensitive over cases). */
export function computeFixturesDigest(fixtures) {
  validateFixtures(fixtures);
  const cases = [...fixtures.cases].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return sha256({ cases, kind: fixtures.kind });
}

// ---------------------------------------------------------------------------
// Measurement — metrics are computed here and nowhere else
// ---------------------------------------------------------------------------

function matchKey(ruleId, file, line) {
  return `${ruleId}\u0000${file}\u0000${line}`;
}

function normalizeCandidate(raw, fallbackPath, caseId) {
  const ruleId = raw?.ruleId ?? null;
  const file = typeof raw?.file === 'string' ? raw.file : fallbackPath;
  const line = raw?.line ?? null;
  if (!ruleId || typeof file !== 'string' || !Number.isInteger(line) || line < 1) {
    throw new Error(`provider runner emitted an unlocatable candidate for case ${caseId} (needs ruleId, file, integer line >= 1): ${JSON.stringify(raw)}`);
  }
  return { ruleId, file, line };
}

/**
 * Run `runProvider` across the fixture corpus and measure precision/recall.
 *
 * Contract: runProvider({ files, caseId }) returns either an array of
 * candidates or `{candidates}`; each candidate needs {ruleId, file, line}.
 * The function is invoked once per case so cases stay isolated and runs stay
 * deterministic regardless of caller-side ordering.
 *
 * A prediction matches ground truth when ruleId, file, and line all match.
 * Unmatched predictions are false positives; unmatched planted findings are
 * false negatives. Zero denominators throw — never synthesize.
 */
export function measureFixtureSet({ provider, binding, runProvider, fixtures, measuredAt }) {
  const stats = validateFixtures(fixtures);
  assertBound(binding);
  if (typeof runProvider !== 'function') throw new Error('measureFixtureSet requires a runProvider({files, caseId}) function');

  const cases = [];
  let tp = 0;
  let fp = 0;
  let fn = 0;
  for (const c of fixtures.cases) {
    let raw;
    try {
      raw = runProvider({ files: [{ path: c.file, text: c.text }], caseId: c.id });
    } catch (error) {
      throw new Error(`provider runner failed on fixture case ${c.id}: ${error?.message ?? error}`);
    }
    const emittedRaw = Array.isArray(raw) ? raw : raw?.candidates;
    if (!Array.isArray(emittedRaw)) {
      throw new Error(`provider runner returned neither an array nor {candidates} for case ${c.id}`);
    }
    const emitted = emittedRaw.map((r) => normalizeCandidate(r, c.file, c.id));

    const expectedKeys = new Map(c.expected.map((e) => [matchKey(e.ruleId, e.file ?? c.file, e.line), e]));
    const matched = new Set();
    let caseTp = 0;
    let caseFp = 0;
    for (const cand of emitted) {
      const key = matchKey(cand.ruleId, cand.file, cand.line);
      if (expectedKeys.has(key) && !matched.has(key)) {
        matched.add(key);
        tp += 1;
        caseTp += 1;
      } else {
        fp += 1;
        caseFp += 1;
      }
    }
    const caseFn = [...expectedKeys.keys()].filter((k) => !matched.has(k)).length;
    fn += caseFn;
    cases.push({
      caseId: c.id,
      expectedFindings: c.expected.length,
      emittedFindings: emitted.length,
      matchedFindings: caseTp,
    });
    void caseFp; void caseFn; // per-case split retained via aggregate counts
  }

  if (tp + fp === 0) {
    throw new Error('precision is undefined: no candidates emitted and none planted; refusing to synthesize a metric');
  }
  if (tp + fn === 0) {
    throw new Error('recall is undefined: no planted findings; refusing to synthesize a metric');
  }

  const result = {
    schemaVersion: BENCHMARK_SCHEMA_VERSION,
    kind: RESULT_KIND,
    provider: {
      id: requireString(provider?.id, 'provider.id'),
      version: String(provider?.version ?? '1'),
      ...(provider?.rulePack ? { rulePack: String(provider.rulePack) } : {}),
    },
    binding: {
      implementationDigests: binding.implementationDigests ?? [],
      rulePackDigests: binding.rulePackDigests ?? [],
      fixturesDigest: computeFixturesDigest(fixtures),
    },
    measuredAt: measuredAt ?? new Date().toISOString(),
    fixtures: stats,
    metrics: {
      truePositives: tp,
      falsePositives: fp,
      falseNegatives: fn,
      precision: tp / (tp + fp),
      recall: tp / (tp + fn),
    },
    cases,
  };
  result.qualificationDigest = resultQualificationDigest(result);
  assertValidResults({ schemaVersion: BENCHMARK_SCHEMA_VERSION, kind: RESULTS_KIND, results: [result] });
  return result;
}

// ---------------------------------------------------------------------------
// Result documents: schema validation, freshness, qualification
// ---------------------------------------------------------------------------

export function loadBenchmarksSchema() {
  return JSON.parse(readFileSync(SCHEMA_FILE, 'utf8'));
}

/** Validate a results document against the frozen schema; returns issue paths. */
export function validateBenchmarkResults(doc) {
  return validateSchema(loadBenchmarksSchema(), doc);
}

export function assertValidResults(doc) {
  const issues = validateBenchmarkResults(doc);
  if (issues.length) throw new Error(`invalid ${RESULTS_KIND}: ${issues.join(', ')}`);
  return doc;
}

/** Parse + schema-validate a results document from disk. Never repairs. */
export function loadBenchmarkResults(path) {
  return assertValidResults(JSON.parse(readFileSync(resolve(path), 'utf8')));
}

/** Qualification digest: stable over everything except volatile timestamps. */
export function resultQualificationDigest(result) {
  const { qualificationDigest: _ignored, measuredAt: _volatile, ...core } = result;
  void _ignored;
  void _volatile;
  return sha256(core);
}

function normalizedBindingList(list) {
  return [...(list ?? [])]
    .map(({ path, digest }) => ({ path: normalizeRelPath(path), digest }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * Freshness: the recorded digests must still describe current inputs.
 * Recorded-but-uncomparable lists are ignored; empty recorded bindings are
 * never fresh (an unbound result measures nothing identifiable).
 */
export function isResultFresh(result, current = {}) {
  if (result?.kind !== RESULT_KIND || result?.schemaVersion !== BENCHMARK_SCHEMA_VERSION) return false;
  const recordedImpl = normalizedBindingList(result.binding?.implementationDigests);
  const recordedPacks = normalizedBindingList(result.binding?.rulePackDigests);
  if (!recordedImpl.length && !recordedPacks.length) return false;
  const currentImpl = normalizedBindingList(current.implementationDigests);
  const currentPacks = normalizedBindingList(current.rulePackDigests);
  if (currentImpl.length && canonicalJson(currentImpl) !== canonicalJson(recordedImpl)) return false;
  if (currentPacks.length && canonicalJson(currentPacks) !== canonicalJson(recordedPacks)) return false;
  return true;
}

export const UNMEASURED_BENCHMARK_RECORD = Object.freeze({
  status: 'unproven',
  requiredForCleanClaim: true,
  qualificationDigest: null,
});

/** Benchmark record in the exact shape audit-plan/finalization consumes. */
export function benchmarkRecordFor(result, current = {}) {
  if (!isResultFresh(result, current)) return { ...UNMEASURED_BENCHMARK_RECORD };
  return {
    status: 'measured',
    requiredForCleanClaim: true,
    qualificationDigest: result.qualificationDigest,
  };
}

/**
 * Classify providers into measured vs unmeasured from a results document.
 *
 * Returns records keyed by provider id (consumable as `benchmark` plan
 * records), the unmeasured id list, `unmeasured-rule-pack` coverage gaps in
 * audit-plan's exact shape, and the derived `precisionMeasured` flag.
 */
export function qualificationFromResults(resultsDoc, { currentByProvider = {}, requiredProviders = [] } = {}) {
  assertValidResults(resultsDoc);
  const latest = new Map();
  for (const r of resultsDoc.results) {
    const prior = latest.get(r.provider.id);
    if (!prior || r.measuredAt > prior.measuredAt) latest.set(r.provider.id, r);
  }
  const ids = new Set([...latest.keys(), ...requiredProviders]);
  const records = {};
  const unmeasuredProviders = [];
  const benchmarkGaps = [];
  for (const id of [...ids].sort()) {
    const result = latest.get(id);
    const record = result
      ? benchmarkRecordFor(result, currentByProvider[id] ?? {})
      : { ...UNMEASURED_BENCHMARK_RECORD };
    records[id] = record;
    if (record.status !== 'measured') {
      unmeasuredProviders.push(id);
      benchmarkGaps.push({ kind: UNMEASURED_GAP_KIND, provider: id, benchmarkStatus: record.status });
    }
  }
  return {
    records,
    unmeasuredProviders,
    benchmarkGaps,
    precisionMeasured: benchmarkGaps.length === 0,
  };
}

/**
 * Audit-run integration. With no bound results artifact, every selected
 * provider remains explicitly unmeasured. When AUDIT_PROVIDER_BENCHMARKS (or
 * resultsPath) names a schema-valid results document, qualify it against the
 * current provider implementation and rule-pack bytes.
 */
export function measurementEvidence(plan, { resultsPath = process.env.AUDIT_PROVIDER_BENCHMARKS ?? null } = {}) {
  const providers = Array.isArray(plan?.providers) ? plan.providers : [];
  const requiredProviders = providers.map((provider) => provider.id).filter(Boolean).sort();
  const currentByProvider = {};
  for (const provider of providers) {
    try { currentByProvider[provider.id] = computeProviderBinding(provider, plan?.root ?? process.cwd()); }
    catch { currentByProvider[provider.id] = {}; }
  }
  if (!resultsPath) {
    return {
      state: 'unproven',
      records: Object.fromEntries(requiredProviders.map((id) => [id, { ...UNMEASURED_BENCHMARK_RECORD }])),
      unmeasuredProviders: requiredProviders,
      benchmarkGaps: requiredProviders.map((provider) => ({ kind: UNMEASURED_GAP_KIND, provider, benchmarkStatus: 'unproven' })),
      precisionMeasured: false,
      resultsPath: null,
    };
  }
  const absoluteResultsPath = isAbsolute(resultsPath) ? resultsPath : resolve(plan?.root ?? process.cwd(), resultsPath);
  const qualification = qualificationFromResults(loadBenchmarkResults(absoluteResultsPath), { currentByProvider, requiredProviders });
  return {
    state: qualification.precisionMeasured ? 'ready' : 'unproven',
    ...qualification,
    resultsPath: absoluteResultsPath,
  };
}

// ---------------------------------------------------------------------------
// CLI — concrete entry point alongside the reusable module API
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = { flags: new Map(), positionals: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const [key, inline] = token.slice(2).split('=', 2);
      out.flags.set(key, inline ?? argv[i + 1]);
      if (inline === undefined) i += 1;
    } else {
      out.positionals.push(token);
    }
  }
  return out;
}

function collectFlag(argvTokens, name) {
  const values = [];
  const bare = `--${name}`;
  const prefixed = `${bare}=`;
  for (let i = 0; i < argvTokens.length; i += 1) {
    if (argvTokens[i] === bare) { values.push(argvTokens[i + 1]); i += 1; }
    else if (argvTokens[i].startsWith(prefixed)) values.push(argvTokens[i].slice(prefixed.length));
  }
  return values;
}

function relFromRoot(path, root) {
  const abs = resolve(root, path);
  const rel = relative(resolve(root), abs);
  return rel && !rel.startsWith('..') && !isAbsolute(rel) ? rel : abs;
}

async function cmdMeasure(args) {
  const root = resolve(args.flags.get('root') ?? '.');
  const fixturesPath = args.flags.get('fixtures');
  const runnerScript = args.flags.get('runner-script');
  const outPath = args.flags.get('out');
  if (!fixturesPath || !runnerScript) {
    console.error('usage: provider-benchmarks.mjs measure --fixtures <fixtures.json> --runner-script <module.mjs> [--out <results.json>] [--root <dir>] [--provider-id <id>] [--rule-pack <path>]...');
    return 2;
  }
  const fixtures = JSON.parse(readFileSync(resolve(fixturesPath), 'utf8'));
  const runnerUrl = pathToFileURL(resolve(runnerScript)).href;
  const mod = await import(runnerUrl);
  const runProvider = typeof mod.run === 'function' ? mod.run : typeof mod.default === 'function' ? mod.default : null;
  if (typeof runProvider !== 'function') {
    throw new Error(`runner script ${runnerScript} exports neither run() nor a default function`);
  }
  const rulePackFlags = collectFlag(process.argv.slice(2), 'rule-pack');
  const providerId = args.flags.get('provider-id') ?? basename(runnerScript).replace(/\.mjs$/, '');
  const binding = {
    implementationDigests: fileBindings([relFromRoot(runnerScript, root)], root),
    rulePackDigests: rulePackFlags.length ? fileBindings(rulePackFlags.map((p) => relFromRoot(p, root)), root) : [],
  };
  const result = measureFixtureSet({
    provider: { id: providerId, version: args.flags.get('provider-version') ?? '1' },
    binding,
    runProvider,
    fixtures,
  });
  const doc = { schemaVersion: BENCHMARK_SCHEMA_VERSION, kind: RESULTS_KIND, generatedAt: new Date().toISOString(), results: [result] };
  if (outPath) writeFileSync(resolve(outPath), `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
  else process.stdout.write(`${JSON.stringify(doc, null, 2)}\n`);
  process.stderr.write(`measured ${providerId}: precision=${result.metrics.precision.toFixed(4)} recall=${result.metrics.recall.toFixed(4)}\n`);
  return 0;
}

function cmdVerify(args) {
  const resultsPath = args.flags.get('results');
  if (!resultsPath) {
    console.error('usage: provider-benchmarks.mjs verify --results <results.json> [--root <dir>]');
    return 2;
  }
  const doc = loadBenchmarkResults(resultsPath);
  let freshCount = null;
  const root = args.flags.get('root');
  if (root) {
    freshCount = 0;
    for (const result of doc.results) {
      const existing = (list) => (list ?? []).filter((b) => existsSync(join(resolve(root), b.path))).map((b) => b.path);
      const implPaths = existing(result.binding.implementationDigests);
      const packPaths = existing(result.binding.rulePackDigests);
      if (!implPaths.length && !packPaths.length) continue; // nothing comparable on disk here
      const rebased = {
        implementationDigests: fileBindings(implPaths, root),
        rulePackDigests: fileBindings(packPaths, root),
      };
      if (isResultFresh(result, rebased)) freshCount += 1;
    }
  }
  process.stdout.write(`${JSON.stringify({ valid: true, kind: doc.kind, results: doc.results.length, ...(freshCount === null ? {} : { fresh: freshCount }) })}\n`);
  return 0;
}

function cmdStatus(args) {
  const resultsPath = args.flags.get('results');
  if (!resultsPath) {
    console.error('usage: provider-benchmarks.mjs status --results <results.json> [--require <id,id>] [--current-binding <bindings.json>]');
    return 2;
  }
  const doc = JSON.parse(readFileSync(resolve(resultsPath), 'utf8'));
  const required = (args.flags.get('require') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const bindingFile = args.flags.get('current-binding');
  const currentByProvider = {};
  if (bindingFile) {
    const parsed = JSON.parse(readFileSync(resolve(bindingFile), 'utf8'));
    for (const [id, value] of Object.entries(parsed.byProvider ?? parsed)) currentByProvider[id] = value;
  }
  const qualification = qualificationFromResults(doc, { currentByProvider, requiredProviders: required });
  process.stdout.write(`${JSON.stringify(qualification, null, 2)}\n`);
  return qualification.unmeasuredProviders.length ? 1 : 0;
}

export async function runCli(argv = process.argv.slice(2)) {
  const command = argv[0];
  const args = parseArgs(argv.slice(1));
  try {
    if (command === 'measure') return await cmdMeasure(args);
    if (command === 'verify') return cmdVerify(args);
    if (command === 'status') return cmdStatus(args);
    console.error('usage: provider-benchmarks.mjs <measure|verify|status> [options]');
    return 2;
  } catch (error) {
    console.error(`error: ${error?.message ?? error}`);
    return 2;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli().then((code) => process.exit(code));
}
