#!/usr/bin/env node
/** Deterministically validates and executes Architecture Book Part XIV corpus. */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { executeArchitectureRuntimeCases } from '../src/packages/arcane/lib/s11-runtime-executor.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const corpusRoot = join(root, 'src', 'evals', 'architecture');
const expectedFamilies = [
  'routing', 'convergence', 'evidence', 'authority', 'candidate-quality', 'handoff',
  'scope-authority', 'stop-precedence', 'forward-workload', 'lineage-budgets',
  'integration-ownership', 'seal-reachability', 'outcome-closure', 'machinery-defects',
  'trajectory-resume', 'finding-lifecycle', 'deficit-propagation', 'migration-cutover',
  'evidence-artifacts', 'retry-semantics', 'concurrency-attention', 'gate-validity',
  'state-transitions-replay', 'rehydration-injection', 'effect-classification',
  'evidence-freshness', 'review-verdict-security', 'ownership-disposition',
  'adr-admission', 'canon-drift', 'clarification-convergence',
  'control-plane-budgets', 'control-retirement', 'review-admission', 'negative-triggers',
  'adversarial',
];
const exactKeys = new Set(['schema', 'id', 'family', 'polarity', 'execution', 'status', 'scenario', 'expect']);
const asJson = process.argv.includes('--json');
const issues = [];
const cases = [];
const digest = createHash('sha256');

function issue(message) { issues.push(message); }
function requiredString(value) { return typeof value === 'string' && value.trim().length > 0; }
function stringList(value) { return Array.isArray(value) && value.length > 0 && value.every(requiredString); }
function validateCase(value, family, source, line) {
  const location = `${source}:${line}`;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return issue(`${location}: case must be an object`);
  for (const key of Object.keys(value)) if (!exactKeys.has(key)) issue(`${location}: unknown field ${key}`);
  for (const key of exactKeys) if (!(key in value)) issue(`${location}: missing ${key}`);
  if (value.schema !== 'architecture-eval-case.v1') issue(`${location}: schema`);
  if (!/^AE-[A-Z][A-Z-]*-\d{3}$/.test(value.id ?? '')) issue(`${location}: invalid id`);
  if (value.family !== family) issue(`${location}: family must be ${family}`);
  if (!['positive', 'negative'].includes(value.polarity)) issue(`${location}: invalid polarity`);
  if (!['static', 'runtime'].includes(value.execution)) issue(`${location}: invalid execution`);
  if (!['ready', 'pending'].includes(value.status)) issue(`${location}: invalid status`);
  if (value.execution === 'static' && value.status !== 'ready') issue(`${location}: static cases must be ready`);
  if (value.execution === 'runtime' && value.status !== 'ready') issue(`${location}: runtime cases must be ready after S09 verification`);
  if (!requiredString(value.scenario)) issue(`${location}: scenario`);
  const expect = value.expect;
  if (!expect || typeof expect !== 'object' || Array.isArray(expect)) issue(`${location}: expect`);
  else {
    if (!requiredString(expect.outcome)) issue(`${location}: expect.outcome`);
    if (!stringList(expect.must_include)) issue(`${location}: expect.must_include`);
    if (!Array.isArray(expect.must_not_include) || !expect.must_not_include.every(requiredString)) issue(`${location}: expect.must_not_include`);
  }
  cases.push({ ...value, source, line });
}

let entries = [];
try { entries = readdirSync(corpusRoot, { withFileTypes: true }).filter((entry) => entry.isFile() && entry.name.endsWith('.jsonl')).map((entry) => entry.name).sort(); }
catch (error) { issue(`corpus unreadable: ${error.message}`); }
const actualFamilies = entries.map((entry) => entry.slice(0, -'.jsonl'.length));
for (const family of expectedFamilies) if (!actualFamilies.includes(family)) issue(`missing family ${family}`);
for (const family of actualFamilies) if (!expectedFamilies.includes(family)) issue(`unexpected family ${family}`);
for (const entry of entries) {
  const family = entry.slice(0, -'.jsonl'.length);
  const raw = readFileSync(join(corpusRoot, entry), 'utf8');
  digest.update(`${entry}\0${raw}`);
  raw.split(/\r?\n/).forEach((line, index) => {
    if (!line.trim()) return;
    try { validateCase(JSON.parse(line), family, `evals/architecture/${entry}`, index + 1); }
    catch (error) { issue(`evals/architecture/${entry}:${index + 1}: invalid JSON (${error.message})`); }
  });
}
const seen = new Set();
for (const row of cases) {
  if (seen.has(row.id)) issue(`${row.source}:${row.line}: duplicate id ${row.id}`);
  seen.add(row.id);
}
const caseResults = new Map((await executeArchitectureRuntimeCases(cases)).map((row) => [row.id, row]));
const results = cases.sort((left, right) => left.id.localeCompare(right.id)).map((row) =>
  caseResults.get(row.id) ?? { id: row.id, family: row.family, status: 'FAIL', reason: 'case result missing' });
const summaries = expectedFamilies.map((family) => {
  const rows = results.filter((row) => row.family === family);
  return { family, case_count: rows.length, passed: rows.filter((row) => row.status === 'PASS').length, failed: rows.filter((row) => row.status === 'FAIL').length, pending: rows.filter((row) => row.status === 'PENDING').length };
});
for (const summary of summaries) if (summary.case_count === 0) issue(`family ${summary.family}: no cases`);
const failed = issues.length + results.filter((row) => row.status === 'FAIL').length;
const pending = results.filter((row) => row.status === 'PENDING').length;
const passed = results.filter((row) => row.status === 'PASS').length;
const payload = { schema: 'architecture-eval-result.v1', state: failed ? 'FAIL' : pending ? 'PASS_WITH_PENDING' : 'PASS', corpus_fingerprint: `sha256:${digest.digest('hex')}`, families: summaries, total_cases: results.length, passed, failed, pending, results, issues: issues.sort() };
if (asJson) console.log(JSON.stringify(payload, null, 2));
else console.log(`${payload.state}: ${payload.total_cases} cases (${payload.passed} static pass, ${payload.pending} runtime pending, ${payload.failed} failures)`);
process.exit(failed ? 1 : 0);
