#!/usr/bin/env node
/**
 * Validates the skill-eval corpus and provides a deterministic routing scorer.
 *
 * The corpus is deliberately the source of truth for expected behaviour.  A case's
 * trigger category and expected_skill provide the legacy routing expectations; cases
 * may additionally provide `routing` (or the equivalent snake_case fields) for the
 * cognitive dimensions introduced by the Arcane routing contract:
 *
 *   shouldRoute, firstRankedCapability, authority, routeMode,
 *   semanticRequirement, contextSelection
 *
 * `scoreRoutingCase` compares one route observation with those expectations.  It does
 * not call a model, access a network, or invent expectations for dimensions that a
 * fixture has not declared.  This keeps ordinary CI deterministic while allowing a
 * periodic caller-supplied live grader to use the same scorer.
 *
 * CLI compatibility is intentional: the normal and --json invocations retain their
 * existing exit-code discipline (0 clean, 1 fixture issue), and --live remains an
 * explicit opt-in that fails with exit code 3 when no grader is supplied.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const skillsRoot = join(root, 'skills');

export const CATEGORIES = ['should_trigger', 'should_not_trigger', 'output_quality', 'safety', 'pressure', 'compatibility'];
const SEVERITIES = new Set(['error', 'warning', 'info']);
const MODES = new Set(['discovery', 'output', 'runtime', 'static']);
const AUTHORITIES = ['sage', 'alchemist', 'oracle'];
const AUTHORITY_SET = new Set(AUTHORITIES);
const ROUTE_MODES = new Set(['DIRECT', 'MACHINERY']);
const SEMANTIC_REQUIREMENTS = new Set(['FORBIDDEN', 'CONDITIONAL', 'REQUIRED']);
const DIMENSIONS = ['shouldRoute', 'firstRankedCapability', 'authority', 'routeMode', 'semanticRequirement', 'contextSelection'];

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined);
}

function asCapabilityId(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function canonicalLabel(value) {
  return typeof value === 'string' ? value.trim().toUpperCase() : value;
}

/** Detect which of the two known case shapes one entry uses. */
function detectVariant(entry) {
  if (entry && typeof entry === 'object' && Array.isArray(entry.assertions) && !('severity' in entry) && !('mode' in entry)) {
    return 'legacy-assertions';
  }
  return 'standard';
}

function assertionValue(entry, type) {
  const assertion = (entry.assertions ?? []).find((candidate) => isPlainObject(candidate) && candidate.type === type);
  return assertion?.value;
}

function routingBlock(entry) {
  return [entry.routing, entry.expected_routing, entry.expectedRouting, entry.expected]
    .find((value) => isPlainObject(value)) ?? {};
}

function expectedAuthority(entry) {
  const block = routingBlock(entry);
  const value = firstDefined(
    block.authority,
    block.authorities,
    entry.expected_authority,
    entry.expectedAuthority,
    entry.expected_attached_authority,
    entry.expected_attached_authorities,
    entry.authority,
    entry.attached_authority,
    entry.attached_authorities,
    assertionValue(entry, 'authority'),
    assertionValue(entry, 'attached_authority'),
    assertionValue(entry, 'attached_authorities'),
  );
  if (value === undefined) return undefined;
  if (Array.isArray(value)) return value.slice();
  if (isPlainObject(value)) return { ...value };
  return value;
}

/**
 * Convert a legacy or extended fixture into the stable expectation shape consumed by
 * the scorer.  Undefined means "not specified"; null is a meaningful no-route target.
 */
export function normalizeRoutingExpectation(entry, category, skill = null) {
  const block = routingBlock(entry);
  const assertionExpectedSkill = assertionValue(entry, 'expected_skill');
  const expectedSkill = firstDefined(entry.expected_skill, entry.expectedSkill, assertionExpectedSkill);
  const targetSkill = asCapabilityId(skill ?? entry.skill);
  const explicitShouldRoute = firstDefined(
    block.shouldRoute,
    block.should_route,
    entry.shouldRoute,
    entry.should_route,
    entry.expected_route,
    entry.expectedRoute,
    assertionValue(entry, 'should_route'),
  );
  const shouldRoute = explicitShouldRoute !== undefined
    ? explicitShouldRoute
    : category === 'should_trigger'
      ? true
      : category === 'should_not_trigger'
        ? false
        : expectedSkill !== undefined
          ? Boolean(asCapabilityId(expectedSkill))
          : undefined;

  const firstRankedCapability = firstDefined(
    block.firstRankedCapability,
    block.first_ranked_capability,
    entry.firstRankedCapability,
    entry.first_ranked_capability,
    entry.expected_first_ranked_capability,
    entry.expectedFirstRankedCapability,
    entry.expected_first_capability,
    entry.expectedFirstCapability,
    expectedSkill,
    assertionValue(entry, 'first_ranked_capability'),
    assertionValue(entry, 'first_capability'),
  );
  const routeMode = firstDefined(
    block.routeMode,
    block.route_mode,
    entry.routeMode,
    entry.route_mode,
    entry.expected_route_mode,
    entry.expectedRouteMode,
    entry.execution_mode,
    entry.executionMode,
    entry.expected_execution_mode,
    entry.expectedExecutionMode,
  );
  const semanticRequirement = firstDefined(
    block.semanticRequirement,
    block.semantic_requirement,
    entry.semanticRequirement,
    entry.semantic_requirement,
    entry.expected_semantic_requirement,
    entry.expectedSemanticRequirement,
    entry.semantic_requirement_classification,
    entry.semanticRequirementClassification,
  );
  const contextSelection = firstDefined(
    block.contextSelection,
    block.context_selection,
    entry.contextSelection,
    entry.context_selection,
    entry.expected_context_selection,
    entry.expectedContextSelection,
    entry.expected_context_sources,
    entry.expectedContextSources,
    entry.context_sources,
    entry.contextSources,
  );

  return {
    shouldRoute: typeof shouldRoute === 'boolean' ? shouldRoute : undefined,
    firstRankedCapability: firstRankedCapability === null ? null : asCapabilityId(firstRankedCapability),
    authority: expectedAuthority(entry),
    routeMode: canonicalLabel(routeMode),
    semanticRequirement: canonicalLabel(semanticRequirement),
    contextSelection,
    targetSkill,
  };
}

function validateAuthority(value, location, issues) {
  if (Array.isArray(value)) {
    if (!value.every((name) => AUTHORITY_SET.has(name))) issues.push(`${location}: authority array contains an unknown role`);
    if (new Set(value).size !== value.length) issues.push(`${location}: authority array must not contain duplicates`);
    return;
  }
  if (!isPlainObject(value) || AUTHORITIES.some((name) => typeof value[name] !== 'boolean')) {
    issues.push(`${location}: authority must be an array or an object of Sage/Alchemist/Oracle booleans`);
  }
}

function validateContextSelection(value, location, issues) {
  if (isStringArray(value)) return;
  if (isPlainObject(value)) {
    for (const key of ['required', 'forbidden', 'selected']) {
      if (key in value && !isStringArray(value[key])) issues.push(`${location}: context.${key} must be an array of strings`);
    }
    return;
  }
  issues.push(`${location}: contextSelection must be an array of source names or a selection object`);
}

function validateRoutingExpectation(entry, location, issues) {
  const expectation = normalizeRoutingExpectation(entry, entry.__category, entry.__skill);
  const block = routingBlock(entry);
  const rawShouldRoute = firstDefined(block.shouldRoute, block.should_route, entry.shouldRoute, entry.should_route, assertionValue(entry, 'should_route'));
  if (rawShouldRoute !== undefined && typeof rawShouldRoute !== 'boolean') {
    issues.push(`${location}: shouldRoute must be boolean`);
  }
  if (expectation.authority !== undefined) validateAuthority(expectation.authority, `${location}: authority`, issues);
  if (expectation.routeMode !== undefined && !ROUTE_MODES.has(expectation.routeMode)) {
    issues.push(`${location}: routeMode must be DIRECT or MACHINERY`);
  }
  if (expectation.semanticRequirement !== undefined && !SEMANTIC_REQUIREMENTS.has(expectation.semanticRequirement)) {
    issues.push(`${location}: semanticRequirement must be FORBIDDEN, CONDITIONAL, or REQUIRED`);
  }
  if (expectation.contextSelection !== undefined) validateContextSelection(expectation.contextSelection, `${location}: contextSelection`, issues);
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
  validateRoutingExpectation({ ...entry, __category: entry.__category, __skill: entry.__skill }, location, issues);
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
  validateRoutingExpectation({ ...entry, __category: entry.__category, __skill: entry.__skill }, location, issues);
}

function looksLikeTriggerEvalFixture(document) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) return false;
  return CATEGORIES.some((category) => Array.isArray(document[category]));
}

export function validateFile(relativePath, document) {
  const issues = [];
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    return { issues: [`${relativePath}: fixture must be a JSON object`], caseCount: 0, categories: {}, behavioral: {}, routingExpectations: [] };
  }
  if (typeof document.schema_version !== 'number') issues.push(`${relativePath}: missing numeric schema_version`);
  if (!isNonEmptyString(document.skill)) issues.push(`${relativePath}: missing skill`);

  const seenIds = new Set();
  let caseCount = 0;
  const categories = {};
  const behavioral = Object.fromEntries(DIMENSIONS.map((dimension) => [dimension, { specified: 0, cases: 0 }]));
  const routingExpectations = [];
  for (const category of CATEGORIES) {
    const entries = document[category];
    if (!Array.isArray(entries)) {
      issues.push(`${relativePath}#${category}: must be an array (present, possibly empty)`);
      categories[category] = 0;
      continue;
    }
    categories[category] = entries.length;
    entries.forEach((rawEntry, index) => {
      caseCount += 1;
      const location = `${relativePath}#${category}.${index}`;
      if (!rawEntry || typeof rawEntry !== 'object' || Array.isArray(rawEntry)) {
        issues.push(`${location}: case must be an object`);
        return;
      }
      const entry = { ...rawEntry, __category: category, __skill: document.skill };
      const variant = detectVariant(entry);
      if (variant === 'legacy-assertions') validateLegacyAssertionsCase(entry, location, issues);
      else validateStandardCase(entry, location, issues);
      if (isNonEmptyString(entry.id)) {
        if (seenIds.has(entry.id)) issues.push(`${location}: duplicate id ${entry.id}`);
        seenIds.add(entry.id);
      }
      const expectation = normalizeRoutingExpectation(entry, category, document.skill);
      routingExpectations.push({ id: entry.id, category, expectation });
      for (const dimension of DIMENSIONS) {
        behavioral[dimension].cases += 1;
        if (expectation[dimension] !== undefined) behavioral[dimension].specified += 1;
      }
    });
  }
  if (categories.should_trigger === 0 && categories.should_not_trigger === 0) {
    issues.push(`${relativePath}: no trigger coverage at all (should_trigger and should_not_trigger both empty)`);
  }
  return { issues, caseCount, categories, behavioral, routingExpectations };
}

function normalizeRankedCapabilities(observation) {
  const ranked = firstDefined(observation?.rankedCapabilities, observation?.ranked_capabilities, observation?.capabilities, observation?.selectedCapabilities, observation?.selected_capabilities, observation?.ranked);
  if (!Array.isArray(ranked)) {
    const single = asCapabilityId(firstDefined(observation?.firstRankedCapability, observation?.first_ranked_capability, observation?.selectedCapability, observation?.selected_capability));
    return single ? [single] : [];
  }
  return ranked.map((candidate) => asCapabilityId(isPlainObject(candidate) ? firstDefined(candidate.id, candidate.capability, candidate.name) : candidate)).filter(Boolean);
}

function normalizeObservedAuthority(observation) {
  const value = firstDefined(observation?.authority, observation?.authorities, observation?.attachedAuthority, observation?.attached_authority, observation?.attachedAuthorities, observation?.attached_authorities);
  if (Array.isArray(value)) return value.slice();
  if (isPlainObject(value)) return Object.fromEntries(AUTHORITIES.map((name) => [name, value[name] === true]));
  return undefined;
}

function normalizeObservedContext(observation) {
  const value = firstDefined(observation?.contextSelection, observation?.context_selection, observation?.context, observation?.contextSources, observation?.context_sources, observation?.selectedContext, observation?.selected_context);
  if (Array.isArray(value)) return value.slice();
  if (isPlainObject(value)) {
    const selected = firstDefined(value.selected, value.sources, value.selectedSources, value.selected_sources);
    return Array.isArray(selected) ? selected.slice() : value;
  }
  return undefined;
}

export function normalizeRoutingObservation(observation = {}) {
  const source = isPlainObject(observation.route) ? { ...observation, ...observation.route } : observation;
  const rankedCapabilities = normalizeRankedCapabilities(source);
  return {
    shouldRoute: typeof firstDefined(source.shouldRoute, source.should_route, source.routed) === 'boolean'
      ? firstDefined(source.shouldRoute, source.should_route, source.routed)
      : undefined,
    rankedCapabilities,
    firstRankedCapability: rankedCapabilities[0] ?? null,
    authority: normalizeObservedAuthority(source),
    routeMode: canonicalLabel(firstDefined(source.routeMode, source.route_mode, source.mode, source.execution_mode, source.executionMode, source.execution)),
    semanticRequirement: canonicalLabel(firstDefined(source.semanticRequirement, source.semantic_requirement)),
    contextSelection: normalizeObservedContext(source),
  };
}

function compareArrays(expected, actual) {
  if (!Array.isArray(expected) || !Array.isArray(actual)) return false;
  return expected.length === actual.length && expected.every((value, index) => value === actual[index]);
}

function compareContext(expected, actual) {
  if (Array.isArray(expected)) return compareArrays(expected, actual);
  if (!isPlainObject(expected) || actual === undefined) return false;
  const selected = Array.isArray(actual) ? actual : actual.selected;
  if (Array.isArray(expected.selected) && !compareArrays(expected.selected, selected)) return false;
  if (Array.isArray(expected.required) && !expected.required.every((value) => selected?.includes(value))) return false;
  if (Array.isArray(expected.forbidden) && expected.forbidden.some((value) => selected?.includes(value))) return false;
  return true;
}

function compareAuthority(expected, actual) {
  if (actual === undefined) return false;
  if (Array.isArray(expected)) return Array.isArray(actual) && compareArrays(expected, actual);
  return isPlainObject(actual) && AUTHORITIES.every((name) => expected[name] === actual[name]);
}

/**
 * Score one fixture against a route observation.  Every field reports PASS, FAIL, or
 * UNSPECIFIED so a fixture cannot accidentally claim coverage it does not contain.
 */
export function scoreRoutingCase(entry, observation, category = entry.category ?? 'should_trigger', skill = entry.skill ?? null) {
  const expectation = normalizeRoutingExpectation(entry, category, skill);
  const actual = normalizeRoutingObservation(observation);
  const targetSkill = expectation.targetSkill ?? asCapabilityId(skill);
  const actualShouldRoute = actual.shouldRoute ?? (targetSkill !== null && actual.firstRankedCapability === targetSkill);
  const checks = {
    shouldRoute: expectation.shouldRoute === undefined
      ? { status: 'UNSPECIFIED', expected: undefined, actual: actualShouldRoute }
      : { status: actualShouldRoute === expectation.shouldRoute ? 'PASS' : 'FAIL', expected: expectation.shouldRoute, actual: actualShouldRoute },
    firstRankedCapability: expectation.firstRankedCapability === undefined
      ? { status: 'UNSPECIFIED', expected: undefined, actual: actual.firstRankedCapability }
      : { status: actual.firstRankedCapability === expectation.firstRankedCapability ? 'PASS' : 'FAIL', expected: expectation.firstRankedCapability, actual: actual.firstRankedCapability },
    authority: expectation.authority === undefined
      ? { status: 'UNSPECIFIED', expected: undefined, actual: actual.authority }
      : { status: compareAuthority(expectation.authority, actual.authority) ? 'PASS' : 'FAIL', expected: expectation.authority, actual: actual.authority },
    routeMode: expectation.routeMode === undefined
      ? { status: 'UNSPECIFIED', expected: undefined, actual: actual.routeMode }
      : { status: actual.routeMode === expectation.routeMode ? 'PASS' : 'FAIL', expected: expectation.routeMode, actual: actual.routeMode },
    semanticRequirement: expectation.semanticRequirement === undefined
      ? { status: 'UNSPECIFIED', expected: undefined, actual: actual.semanticRequirement }
      : { status: actual.semanticRequirement === expectation.semanticRequirement ? 'PASS' : 'FAIL', expected: expectation.semanticRequirement, actual: actual.semanticRequirement },
    contextSelection: expectation.contextSelection === undefined
      ? { status: 'UNSPECIFIED', expected: undefined, actual: actual.contextSelection }
      : { status: compareContext(expectation.contextSelection, actual.contextSelection) ? 'PASS' : 'FAIL', expected: expectation.contextSelection, actual: actual.contextSelection },
  };
  const specified = Object.values(checks).filter(({ status }) => status !== 'UNSPECIFIED');
  return {
    id: entry.id,
    category,
    skill: targetSkill,
    status: specified.some(({ status }) => status === 'FAIL') ? 'FAIL' : 'PASS',
    checks,
    specifiedFields: specified.length,
    failedFields: specified.filter(({ status }) => status === 'FAIL').length,
  };
}

// Short aliases make the scorer convenient for periodic qualification callers.
export const scoreCase = scoreRoutingCase;
export const scoreDeterministicCase = scoreRoutingCase;

export function discoverEvalFiles(repositoryRoot = root) {
  const discoveredSkillsRoot = join(repositoryRoot, 'skills');
  let skillDirs = [];
  try {
    skillDirs = readdirSync(discoveredSkillsRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  } catch (error) {
    return { files: [], error: `skills directory unreadable: ${error.message}` };
  }
  const files = [];
  for (const skill of skillDirs) {
    const evalsDir = join(discoveredSkillsRoot, skill, 'evals');
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

export function loadEvalCases(repositoryRoot = root) {
  const { files, error } = discoverEvalFiles(repositoryRoot);
  const cases = [];
  for (const file of files) {
    let document;
    try { document = JSON.parse(readFileSync(file.path, 'utf8')); } catch { continue; }
    if (!looksLikeTriggerEvalFixture(document)) continue;
    for (const category of CATEGORIES) {
      for (const entry of document[category] ?? []) {
        cases.push({ ...entry, category, skill: document.skill, source: file.relativePath });
      }
    }
  }
  return { cases, files, error };
}

export function runDeterministicEvaluation(repositoryRoot = root) {
  const { files, error } = discoverEvalFiles(repositoryRoot);
  const issues = [];
  if (error) issues.push(error);
  const results = files.map((file) => {
    let document;
    try {
      document = JSON.parse(readFileSync(file.path, 'utf8'));
    } catch (parseError) {
      return { file: file.relativePath, skill: file.skill, status: 'FAIL', issues: [`${file.relativePath}: invalid JSON (${parseError.message})`], caseCount: 0, categories: {}, behavioral: {}, routingExpectations: [] };
    }
    if (!looksLikeTriggerEvalFixture(document)) {
      return { file: file.relativePath, skill: file.skill, status: 'SKIPPED', issues: [], caseCount: 0, categories: {}, behavioral: {}, routingExpectations: [], note: 'not a trigger-eval fixture (no should_trigger/.../compatibility arrays present)' };
    }
    const validated = validateFile(file.relativePath, document);
    return { file: file.relativePath, skill: file.skill, status: validated.issues.length ? 'FAIL' : 'PASS', issues: validated.issues, caseCount: validated.caseCount, categories: validated.categories, behavioral: validated.behavioral, routingExpectations: validated.routingExpectations };
  });
  for (const result of results) issues.push(...result.issues);
  const totalCases = results.reduce((sum, result) => sum + result.caseCount, 0);
  const failedFiles = results.filter((result) => result.status === 'FAIL').length;
  return {
    // Keep the established result schema for existing CI consumers; behavioral coverage
    // is additive in each result's `behavioral` field.
    schema: 'skill-eval-result.v1',
    routing_schema: 'skill-routing-eval.v1',
    state: issues.length ? 'FAIL' : 'PASS',
    files_discovered: results.length,
    files_failed: failedFiles,
    total_cases: totalCases,
    results,
    issues: issues.sort(),
  };
}

export async function runLiveGrading(cases, grader) {
  if (typeof grader !== 'function') {
    const error = new Error('no live grader is wired');
    error.code = 'LIVE_GRADER_UNAVAILABLE';
    throw error;
  }
  const results = [];
  for (const fixture of cases) {
    const observation = await grader(fixture);
    results.push(scoreRoutingCase(fixture, observation, fixture.category, fixture.skill));
  }
  return results;
}

/**
 * Deterministic by default.  The grader is only invoked when the caller explicitly sets
 * live: true; this is the boundary that keeps CI free of model calls and network use.
 */
export async function evaluateRoutingCases(cases, { live = false, grader } = {}) {
  if (!live) return cases.map((fixture) => scoreRoutingCase(fixture, {}, fixture.category, fixture.skill));
  return runLiveGrading(cases, grader);
}

async function main(args = process.argv.slice(2)) {
  const asJson = args.includes('--json');
  const live = args.includes('--live');
  if (live) {
    // Preserve the historical --live contract until a periodic caller supplies a grader.
    console.error('Live behavioural grading was requested (--live) but no live grader is wired into this package.');
    console.error('This runner validates structure and coverage deterministically only; grading a case against an');
    console.error('actual model turn requires a caller-supplied grader, which does not exist yet. Run without --live.');
    return 3;
  }
  const payload = runDeterministicEvaluation();
  if (asJson) console.log(JSON.stringify(payload, null, 2));
  else console.log(`${payload.state}: ${payload.files_discovered} eval files, ${payload.total_cases} cases (${payload.files_failed} files with issues, ${payload.issues.length} total issues)`);
  return payload.issues.length ? 1 : 0;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) process.exitCode = await main();
