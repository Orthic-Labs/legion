// Rule-output measurement: does a detector's own findings land on the right
// rule, file and line? provider-architecture.md reserves the measured-pack
// tier for exactly this, and distinguishes it from provider selection — which
// only asks whether a provider claims a file. The harness shipped without a
// corpus and so could measure nothing; these fixtures are that corpus.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { measureFixtureSet, validateFixtures } from '../tools/audit/provider-benchmarks.mjs';
import { scanSecrets } from '../bench/detectors/secrets.mjs';
import { scanDeadCode } from '../bench/detectors/dead-code.mjs';
import { scanTypes } from '../bench/detectors/types.mjs';
import { scanDuplication } from '../bench/detectors/duplication.mjs';
import { scanDeps } from '../bench/detectors/deps-cve.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const load = (name) => JSON.parse(readFileSync(join(root, 'bench/rule-output', `${name}.fixtures.json`), 'utf8'));

// Each detector returns {line, ...}; the harness matches on ruleId+file+line.
// Two detectors report what they found but not where. Locating the finding in
// the source keeps the match on ruleId+file+line honest rather than loosening
// the harness to accept a finding with no location.
const lineOf = (text, needle) => text.split(/\r?\n/).findIndex((l) => l.includes(needle)) + 1;

const RUNNERS = {
  secrets: (text, ruleId) => scanSecrets(text).map((hit) => ({ ruleId, line: hit.line })),
  dead_code: (text, ruleId) => scanDeadCode(text).map((hit) => ({ ruleId, line: hit.line })),
  types: (text, ruleId) => scanTypes(text).map((hit) => ({ ruleId, line: hit.line })),
  duplication: (text, ruleId) =>
    scanDuplication(text).map((hit) => ({ ruleId, line: lineOf(text, `function ${hit.a}(`) })),
  deps_cve: (text, ruleId) =>
    scanDeps(JSON.parse(text)).map((hit) => ({ ruleId, line: lineOf(text, `"${hit.name}"`) })),
};

// Bind the measurement to the bytes that produced it. A stale binding is
// reclassified as unproven rather than carried forward as a result.
const DETECTOR_FILE = {
  secrets: 'bench/detectors/secrets.mjs',
  dead_code: 'bench/detectors/dead-code.mjs',
  types: 'bench/detectors/types.mjs',
  duplication: 'bench/detectors/duplication.mjs',
  deps_cve: 'bench/detectors/deps-cve.mjs',
};
const digestOf = (relative) =>
  `sha256:${createHash('sha256').update(readFileSync(join(root, relative))).digest('hex')}`;
// A binding records which bytes were measured, not just their hash.
const bind = (relative) => ({ path: relative, digest: digestOf(relative) });

for (const [detector, run] of Object.entries(RUNNERS)) {
  test(`${detector} rule output is measured against planted ground truth`, () => {
    const fixtures = load(detector);
    const stats = validateFixtures(fixtures);
    // A corpus of only positives measures nothing: a detector that fires on
    // everything would score perfectly.
    assert.ok(stats.cleanCaseCount >= 1, `${detector} corpus needs a clean case`);
    assert.ok(stats.plantedFindingCount >= 1, `${detector} corpus needs a planted finding`);

    const result = measureFixtureSet({
      provider: { id: `au20.${detector}`, providerVersion: '1.0.0' },
      binding: {
        implementationDigests: [bind(DETECTOR_FILE[detector])],
        rulePackDigests: [bind(`bench/rule-output/${detector}.fixtures.json`)],
        fixturesDigest: digestOf(`bench/rule-output/${detector}.fixtures.json`),
      },
      fixtures,
      measuredAt: '2026-09-03T00:00:00.000Z',
      runProvider: ({ files }) => run(files[0].text, fixtures.ruleId),
    });

    const { precision, recall, falsePositives, falseNegatives } = result.metrics;
    assert.equal(precision, 1, `${detector} emitted ${falsePositives} false positive(s)`);
    assert.equal(recall, 1, `${detector} missed ${falseNegatives} planted finding(s)`);
  });
}
