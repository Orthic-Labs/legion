#!/usr/bin/env node
/**
 * Discovers and deterministically validates the behavioural eval fixtures shipped under
 * skills/*​/evals/*.json — the trigger/quality/safety/pressure/compatibility corpus that
 * doctrine claims each skill honours (never push, never print gateway secrets, worker claim
 * is not proof, no-contract-no-effect, out-of-scope stays recorded, ...).
 *
 * This intentionally does NOT grade case behaviour against a live model — nothing here spawns
 * an agent turn and checks what it actually did. That would need a live model call, which is
 * not something CI can run deterministically. Pass --live to opt into that path; by default
 * (and always in CI) this validates structure and coverage only: every case is well-formed,
 * every declared category is populated, ids are unique, and the file matches one of the two
 * known schemas (the current should_trigger/.../compatibility shape, or the legacy
 * assertions-based shape used by legacy-jfdi.json).
 *
 * Modeled on scripts/run-architecture-evals.mjs: same --json flag, same reporting shape
 * (schema/state/summary/results/issues), same exit-code discipline (0 clean, 1 any issue).
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const skillsRoot = join(root, 'skills');
const asJson = process.argv.includes('--json');
const live = process.argv.includes('--live');

const CATEGORIES = ['should_trigger', 'should_not_trigger', 'output_quality', 'safety', 'pressure', 'compatibility'];
// Observed across the whole skills/*/evals corpus, not just alchemist's — this runner validates
// structure for every packaged skill, so its vocabulary must match what is actually shipped.
const SEVERITIES = new Set(['error', 'warning', 'info']);
const MODES = new Set(['discovery', 'output', 'runtime', 'static']);

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

/** Detect which of the two known case shapes one entry uses. Files are not required to be
 * uniform, though in practice every shipped file today is. */
function detectVariant(entry) {
  // legacy-jfdi.json's shape: id/prompt/expected_behavior/assertions only — no severity, no mode,
  // no expected_skill. Assertions there are {type, value} objects that stand in for those fields.
  // Newer fixtures (e.g. skills/ads) instead attach a plain string-array `assertions` alongside a
  // normal severity/mode/expected_skill case — that stays the standard shape.
  if (entry && typeof entry === 'object' && Array.isArray(entry.assertions) && !('severity' in entry) && !('mode' in entry)) {
    return 'legacy-assertions';
  }
  return 'standard';
}

function validateStandardCase(entry, location, issues) {
  if (!isNonEmptyString(entry.id)) issues.push(`${location}: missing or empty id`);
  if (!isNonEmptyString(entry.prompt)) issues.push(`${location}: missing or empty prompt`);
  if (!isNonEmptyString(entry.expected_behavior)) issues.push(`${location}: missing or empty expected_behavior`);
  if ('expected_skill' in entry && entry.expected_skill !== null && typeof entry.expected_skill !== 'string') {
    issues.push(`${location}: expected_skill must be a string or null`);
  }
  if ('forbidden_skills' in entry && !isStringArray(entry.forbidden_skills)) {
    issues.push(`${location}: forbidden_skills must be an array of strings`);
  }
  if ('severity' in entry && !SEVERITIES.has(entry.severity)) {
    issues.push(`${location}: severity ${JSON.stringify(entry.severity)} is outside the observed vocabulary (${[...SEVERITIES].join('|')})`);
  }
  if ('mode' in entry && !MODES.has(entry.mode)) {
    issues.push(`${location}: mode ${JSON.stringify(entry.mode)} is outside the observed vocabulary (${[...MODES].join('|')})`);
  }
  // Some fixtures (e.g. skills/ads) attach free-text acceptance conditions instead of, or
  // alongside, expected_skill/forbidden_skills — accept either shape, just type-check it.
  if ('assertions' in entry) {
    if (!Array.isArray(entry.assertions) || entry.assertions.length === 0) {
      issues.push(`${location}: assertions must be a non-empty array`);
    } else {
      entry.assertions.forEach((assertion, index) => {
        const ok = typeof assertion === 'string'
          ? assertion.trim().length > 0
          : assertion && typeof assertion === 'object' && !Array.isArray(assertion) && isNonEmptyString(assertion.type) && ('value' in assertion);
        if (!ok) issues.push(`${location}#assertions.${index}: assertion must be a non-empty string or a {type, value} object`);
      });
    }
  }
}

function validateLegacyAssertionsCase(entry, location, issues) {
  if (!isNonEmptyString(entry.id)) issues.push(`${location}: missing or empty id`);
  if (!isNonEmptyString(entry.prompt)) issues.push(`${location}: missing or empty prompt`);
  if (!isNonEmptyString(entry.expected_behavior)) issues.push(`${location}: missing or empty expected_behavior`);
  if (!Array.isArray(entry.assertions) || entry.assertions.length === 0) {
    issues.push(`${location}: assertions must be a non-empty array`);
    return;
  }
  entry.assertions.forEach((assertion, index) => {
    const assertionLocation = `${location}#assertions.${index}`;
    if (!assertion || typeof assertion !== 'object' || Array.isArray(assertion)) {
      issues.push(`${assertionLocation}: assertion must be an object`);
      return;
    }
    if (!isNonEmptyString(assertion.type)) issues.push(`${assertionLocation}: missing or empty type`);
    if (!('value' in assertion)) issues.push(`${assertionLocation}: missing value`);
  });
}

/** Not every skills/*​/evals/*.json file is a trigger/quality/safety eval fixture — e.g.
 * skills/commit/evals/evidence-gauntlet.json documents a host-issued mechanical gauntlet check
 * (name/purpose/rerunnable_command/arcane_mapping/layers) with no relation to this schema at all.
 * Detect that explicitly and skip it rather than forcing it through the trigger-eval validator
 * and reporting false failures. */
function looksLikeTriggerEvalFixture(document) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) return false;
  return CATEGORIES.some((category) => Array.isArray(document[category]));
}

function validateFile(relativePath, document) {
  const issues = [];
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    return { issues: [`${relativePath}: fixture must be a JSON object`], caseCount: 0, categories: {} };
  }
  if (typeof document.schema_version !== 'number') issues.push(`${relativePath}: missing numeric schema_version`);
  if (!isNonEmptyString(document.skill)) issues.push(`${relativePath}: missing skill`);
  // Top-level metadata beyond schema_version/skill/the six categories varies a lot across the
  // corpus (route, name, purpose, arcane_mapping, ...) and is not this runner's concern —
  // only the case shape inside each category is validated.

  const seenIds = new Set();
  let caseCount = 0;
  const categories = {};
  for (const category of CATEGORIES) {
    const entries = document[category];
    if (!Array.isArray(entries)) {
      issues.push(`${relativePath}#${category}: must be an array (present, possibly empty)`);
      categories[category] = 0;
      continue;
    }
    categories[category] = entries.length;
    entries.forEach((entry, index) => {
      caseCount += 1;
      const location = `${relativePath}#${category}.${index}`;
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        issues.push(`${location}: case must be an object`);
        return;
      }
      const variant = detectVariant(entry);
      if (variant === 'legacy-assertions') validateLegacyAssertionsCase(entry, location, issues);
      else validateStandardCase(entry, location, issues);
      if (isNonEmptyString(entry.id)) {
        if (seenIds.has(entry.id)) issues.push(`${location}: duplicate id ${entry.id}`);
        seenIds.add(entry.id);
      }
    });
  }
  if (categories.should_trigger === 0 && categories.should_not_trigger === 0) {
    issues.push(`${relativePath}: no trigger coverage at all (should_trigger and should_not_trigger both empty)`);
  }
  return { issues, caseCount, categories };
}

function discoverEvalFiles() {
  let skillDirs = [];
  try {
    skillDirs = readdirSync(skillsRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  } catch (error) {
    return { files: [], error: `skills directory unreadable: ${error.message}` };
  }
  const files = [];
  for (const skill of skillDirs) {
    const evalsDir = join(skillsRoot, skill, 'evals');
    let entries = [];
    try { entries = readdirSync(evalsDir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
      const path = join(evalsDir, entry.name);
      if (!statSync(path).isFile()) continue;
      files.push({ skill, name: entry.name, path, relativePath: `skills/${skill}/evals/${entry.name}` });
    }
  }
  return { files: files.sort((left, right) => left.relativePath.localeCompare(right.relativePath)) };
}

if (live) {
  console.error('Live behavioural grading was requested (--live) but no live grader is wired into this package.');
  console.error('This runner validates structure and coverage deterministically only; grading a case against an');
  console.error('actual model turn requires a caller-supplied grader, which does not exist yet. Run without --live.');
  process.exit(3);
}

const { files, error } = discoverEvalFiles();
const issues = [];
if (error) issues.push(error);

const results = files.map((file) => {
  let document;
  try {
    document = JSON.parse(readFileSync(file.path, 'utf8'));
  } catch (parseError) {
    return { file: file.relativePath, skill: file.skill, status: 'FAIL', issues: [`${file.relativePath}: invalid JSON (${parseError.message})`], caseCount: 0, categories: {} };
  }
  if (!looksLikeTriggerEvalFixture(document)) {
    return { file: file.relativePath, skill: file.skill, status: 'SKIPPED', issues: [], caseCount: 0, categories: {}, note: 'not a trigger-eval fixture (no should_trigger/.../compatibility arrays present)' };
  }
  const validated = validateFile(file.relativePath, document);
  return { file: file.relativePath, skill: file.skill, status: validated.issues.length ? 'FAIL' : 'PASS', issues: validated.issues, caseCount: validated.caseCount, categories: validated.categories };
});

for (const result of results) issues.push(...result.issues);

const totalCases = results.reduce((sum, result) => sum + result.caseCount, 0);
const failedFiles = results.filter((result) => result.status === 'FAIL').length;
const state = issues.length ? 'FAIL' : 'PASS';
const payload = {
  schema: 'skill-eval-result.v1',
  state,
  files_discovered: results.length,
  files_failed: failedFiles,
  total_cases: totalCases,
  results,
  issues: issues.sort(),
};

if (asJson) console.log(JSON.stringify(payload, null, 2));
else console.log(`${state}: ${results.length} eval files, ${totalCases} cases (${failedFiles} files with issues, ${issues.length} total issues)`);
process.exit(issues.length ? 1 : 0);
