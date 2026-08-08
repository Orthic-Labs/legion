import { readFileSync } from 'node:fs';
import { denominator, exactBinding, finalize, sameBinding, sortById } from '../shared.mjs';

const REGISTRY = Object.freeze(JSON.parse(readFileSync(new URL('../../../../registry/platform-matrices/web.json', import.meta.url), 'utf8')));
const DIMENSIONS = Object.freeze([...REGISTRY.dimensions]);
const TERMINAL = new Set(['pass', 'fail', 'partial', 'unproven', 'blocked', 'error', 'unsupported']);
const BROWSERS = new Map(REGISTRY.browserPolicy.map((item) => [item.id, item]));
const VITALS_CLASSES = new Map(Object.entries(REGISTRY.vitalsDenominators).filter(([, value]) => value && typeof value === 'object').flatMap(([deviceClass, value]) => value.combinationIds.map((id) => [id, { deviceClass, ...value }])));
const allowed = (dimension, value) => REGISTRY.dimensionValues[dimension]?.some((candidate) => Object.is(candidate, value)) === true;
const vector = (row) => JSON.stringify(DIMENSIONS.map((key) => row[key]));
const covers = (row, requirement) => requirement.every(([key, value]) => Object.is(row[key], value));

function registryPlan() {
  const mandatory = REGISTRY.mandatoryCombinations.map((item) => ({ ...item }));
  const requirements = REGISTRY.pairwisePolicy.pairs.flatMap(([left, right]) => REGISTRY.dimensionValues[left].flatMap((leftValue) => REGISTRY.dimensionValues[right].map((rightValue) => [[left, leftValue], [right, rightValue]])));
  const witness = (requirement) => {
    const row = { ...mandatory[0], ...Object.fromEntries(requirement) };
    delete row.id;
    const browser = BROWSERS.get(row.browser);
    row.browserVersion = browser.versions[0];
    row.binary = browser.binaryPolicy;
    return Object.fromEntries(DIMENSIONS.map((key) => [key, row[key]]));
  };
  const mandatoryVectors = new Set(mandatory.map(vector));
  const candidates = [...new Map(requirements.map(witness).filter((row) => !mandatoryVectors.has(vector(row))).map((row) => [vector(row), row])).values()].sort((left, right) => vector(left).localeCompare(vector(right)));
  const selected = [...mandatory];
  let uncovered = requirements.filter((requirement) => !selected.some((row) => covers(row, requirement)));
  let pool = [...candidates];
  while (uncovered.length && selected.length < REGISTRY.pairwisePolicy.maxCombinations) {
    const ranked = pool.map((row) => ({ row, score: uncovered.filter((requirement) => covers(row, requirement)).length })).sort((left, right) => right.score - left.score || vector(left.row).localeCompare(vector(right.row)));
    if (!ranked[0]?.score) break;
    selected.push(ranked[0].row);
    uncovered = uncovered.filter((requirement) => !covers(ranked[0].row, requirement));
    pool = pool.filter((row) => row !== ranked[0].row);
  }
  const generated = selected.filter((row) => !row.id).sort((left, right) => vector(left).localeCompare(vector(right))).map((row, index) => ({ id: `pairwise-${String(index + 1).padStart(3, '0')}`, ...row }));
  return Object.freeze({ rows: sortById([...mandatory, ...generated]), uncovered });
}

const PLAN = registryPlan();

function validPolicyShape(policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return false;
  if (policy.mandatoryDimensions !== undefined) {
    if (!policy.mandatoryDimensions || typeof policy.mandatoryDimensions !== 'object' || Array.isArray(policy.mandatoryDimensions)) return false;
    for (const [dimension, values] of Object.entries(policy.mandatoryDimensions)) {
      if (!DIMENSIONS.includes(dimension) || !Array.isArray(values) || values.some((value) => value === null || !['string', 'number', 'boolean'].includes(typeof value) || (typeof value === 'number' && !Number.isFinite(value)))) return false;
    }
  }
  if (policy.pairwise !== undefined && (!Array.isArray(policy.pairwise) || policy.pairwise.some((pair) => !Array.isArray(pair)
    || pair.length !== 2 || pair.some((dimension) => typeof dimension !== 'string' || !DIMENSIONS.includes(dimension))))) return false;
  return true;
}

const typedScalar = (value) => value !== null && ['string', 'number', 'boolean'].includes(typeof value) && (typeof value !== 'number' || Number.isFinite(value));
const typedPolicyItem = (item, omitted = false) => item && typeof item === 'object' && !Array.isArray(item)
  && typeof item.id === 'string' && item.id.length > 0
  && (!omitted || (item.reason === undefined || typeof item.reason === 'string') && (item.evidence === undefined || item.evidence && typeof item.evidence === 'object' && !Array.isArray(item.evidence)))
  && (omitted || (item.status === undefined || typeof item.status === 'string')
    && (item.terminal === undefined || typeof item.terminal === 'boolean')
    && (item.binding === undefined || item.binding && typeof item.binding === 'object' && !Array.isArray(item.binding))
    && (item.vitals === undefined || item.vitals && typeof item.vitals === 'object' && !Array.isArray(item.vitals))
    && DIMENSIONS.every((dimension) => item[dimension] === undefined || typedScalar(item[dimension])));

export function isWebMatrixCombinationId(id) {
  return PLAN.rows.some((row) => row.id === id);
}

export function compileWebMatrix({ binding = {}, policy = {}, capabilities = [] } = {}) {
  const policyValid = validPolicyShape(policy);
  const collectionsValid = policyValid && Array.isArray(capabilities) && capabilities.every((item) => item && typeof item === 'object' && !Array.isArray(item))
    && (policy.combinations === undefined || Array.isArray(policy.combinations) && policy.combinations.every((item) => typedPolicyItem(item)))
    && (policy.omitted === undefined || Array.isArray(policy.omitted) && policy.omitted.every((item) => typedPolicyItem(item, true)));
  if (!collectionsValid) return finalize('nemesis-web-runtime-matrix', { binding, terminal: true, complete: false, status: 'error', combinations: [], omitted: [], denominator: denominator([], []), vitalsDenominators: {}, vitalsByDeviceClass: {}, coverageGaps: [...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`), ...(!policyValid ? ['matrix-policy-invalid'] : []), 'matrix-collections-invalid'].sort() });
  const supplied = sortById(policy.combinations ?? []);
  const omitted = sortById(policy.omitted ?? []);
  const suppliedGroups = new Map();
  for (const item of supplied) { if (!suppliedGroups.has(item.id)) suppliedGroups.set(item.id, []); suppliedGroups.get(item.id).push(item); }
  const plannedById = new Map(PLAN.rows.map((item) => [item.id, item]));
  const capabilityIds = capabilities.map((item) => item.id);
  const duplicateCapabilityIds = [...new Set(capabilityIds.filter((id, index) => capabilityIds.indexOf(id) !== index))].sort();
  const capabilityById = duplicateCapabilityIds.length ? null : new Map(capabilities.map((item) => [item.id, item]));
  const combinations = sortById(PLAN.rows.map((definition) => {
    const observation = suppliedGroups.get(definition.id)?.[0];
    return { ...definition, status: observation?.status ?? 'unproven', terminal: observation?.terminal === true, observed: Boolean(observation), ...(observation && Object.hasOwn(observation, 'deviceClass') ? { deviceClass: observation.deviceClass } : {}), ...(observation && Object.hasOwn(observation, 'vitals') ? { vitals: observation.vitals } : {}) };
  }));
  const ids = combinations.map((item) => item.id);
  const receipts = combinations.filter((item) => item.observed && item.terminal === true && (item.status === 'pass' && capabilityById?.get(item.browser)?.status === 'available' || item.status === 'unsupported' && capabilityById?.get(item.browser)?.status === 'unsupported'));
  const baseCounts = denominator(ids, receipts, []);
  const counts = { ...baseCounts, omitted: new Set(omitted.map((item) => item.id)).size };
  const gaps = exactBinding(binding).gaps.map((key) => `binding-missing:${key}`);
  if (!PLAN.rows.length) gaps.push('matrix-denominator-empty');
  gaps.push(...duplicateCapabilityIds.map((id) => `capability-id-duplicate:${id}`));
  if (!supplied.length && !omitted.length) gaps.push('matrix-denominator-empty');
  if (PLAN.uncovered.length) gaps.push('registry-pairwise-bound-incomplete');
  if (PLAN.rows.length > REGISTRY.pairwisePolicy.maxCombinations || PLAN.rows.length > (policy.maxCombinations ?? REGISTRY.pairwisePolicy.maxCombinations)) gaps.push('matrix-bound-exceeded');
  const callerIds = [...supplied.map((item) => item.id), ...omitted.map((item) => item.id)];
  for (const id of new Set(callerIds)) if (callerIds.filter((value) => value === id).length > 1) gaps.push(`matrix-id-duplicate:${id}`);
  for (const item of [...supplied, ...omitted]) if (typeof item.id !== 'string' || item.id.length === 0) gaps.push('matrix-id-missing');
  for (const capability of capabilities) if (!sameBinding(binding, capability.binding ?? {})) gaps.push(`capability-binding-mismatch:${capability.id}`);
  for (const dimension of DIMENSIONS) {
    if (policy.mandatoryDimensions && !(policy.mandatoryDimensions[dimension]?.length)) gaps.push(`dimension-missing:${dimension}`);
    for (const value of policy.mandatoryDimensions?.[dimension] ?? []) if (!allowed(dimension, value)) gaps.push(`dimension-policy-value-outside-registry:${dimension}`);
  }
  if (policy.mandatoryDimensions && !(policy.pairwise?.length)) gaps.push('pairwise-policy-missing');
  for (const item of supplied) {
    const definition = plannedById.get(item.id);
    if (!sameBinding(binding, item.binding ?? {})) gaps.push(`observation-binding-mismatch:${item.id}`);
    if (!definition) gaps.push(`combination-unplanned:${item.id}`);
    if (item.terminal !== true) gaps.push(`combination-nonterminal:${item.id}`);
    if (item.status === 'pending') gaps.push(`combination-status-pending:${item.id}`);
    else if (!TERMINAL.has(item.status)) gaps.push(`combination-status-invalid:${item.id}`);
    else if (!['pass', 'unsupported'].includes(item.status)) gaps.push(`combination-status-${item.status}:${item.id}`);
    for (const dimension of DIMENSIONS) if (!Object.hasOwn(item, dimension)) gaps.push(`observation-dimension-missing:${item.id}:${dimension}`); else {
      if (!allowed(dimension, item[dimension])) gaps.push(`dimension-value-outside-registry:${item.id}:${dimension}`);
      if (policy.mandatoryDimensions?.[dimension]?.length && !policy.mandatoryDimensions[dimension].some((value) => Object.is(value, item[dimension]))) gaps.push(`dimension-value-outside-policy:${item.id}:${dimension}`);
      if (definition && !Object.is(item[dimension], definition[dimension])) gaps.push(`observation-definition-mismatch:${item.id}:${dimension}`);
    }
    const browser = BROWSERS.get(item.browser ?? definition?.browser);
    const browserId = item.browser ?? definition?.browser;
    const version = item.browserVersion ?? definition?.browserVersion;
    const binary = item.binary ?? definition?.binary;
    const capability = capabilityById?.get(browserId);
    if (!browser) gaps.push(`browser-outside-policy:${item.id}`);
    else {
      if (!browser.versions.includes(version)) gaps.push(`browser-version-outside-policy:${item.id}`);
      if (binary !== browser.binaryPolicy) gaps.push(`browser-binary-outside-policy:${item.id}`);
    }
    if (!capability) gaps.push(`browser-capability-missing:${browserId}`);
    else {
      if (!['available', 'unsupported'].includes(capability.status)) gaps.push(`browser-capability-${capability.status}:${browserId}`);
      if (capability.status === 'unsupported' && item.status !== 'unsupported') gaps.push(`browser-capability-unsupported-but-${item.status}:${browserId}:${item.id}`);
      if (item.status === 'unsupported' && capability.status !== 'unsupported') gaps.push(`combination-unsupported-without-policy:${item.id}`);
      if (capability.browserVersion !== version) gaps.push(`browser-capability-version-mismatch:${item.id}`);
      if (capability.binary !== binary) gaps.push(`browser-capability-binary-mismatch:${item.id}`);
    }
  }
  for (const [left, right] of policy.pairwise ?? []) for (const leftValue of policy.mandatoryDimensions?.[left] ?? []) for (const rightValue of policy.mandatoryDimensions?.[right] ?? []) if (!supplied.some((item) => Object.is(item[left], leftValue) && Object.is(item[right], rightValue))) gaps.push(`pairwise-uncovered:${left}=${leftValue}:${right}=${rightValue}`);
  gaps.push(...omitted.map((item) => `combination-omitted:${item.id}`), ...supplied.filter((item) => !plannedById.has(item.id)).map((item) => `combination-unplanned:${item.id}`), ...counts.missing.map((id) => `combination-missing:${id}`));
  const vitalsByDeviceClass = {};
  for (const [id, denominatorPolicy] of VITALS_CLASSES) {
    const definition = plannedById.get(id);
    const observation = suppliedGroups.get(id)?.[0];
    if (!observation || !observation.vitals || typeof observation.vitals !== 'object') gaps.push(`vitals-observation-missing:${id}`);
    else {
      if (!sameBinding(binding, observation.vitals.binding ?? {})) gaps.push(`vitals-binding-mismatch:${id}`);
      if ((Object.hasOwn(observation, 'device') && observation.device !== definition.device) || (Object.hasOwn(observation, 'physicality') && observation.physicality !== definition.physicality)) gaps.push(`vitals-trusted-classification-mismatch:${id}`);
      if (observation.deviceClass !== undefined && observation.deviceClass !== denominatorPolicy.deviceClass) gaps.push(`vitals-device-class-mismatch:${id}`);
      for (const metric of denominatorPolicy.requiredMetrics) if (!Object.hasOwn(observation.vitals, metric)) gaps.push(`vitals-metric-missing:${id}:${metric}`); else if (!Number.isFinite(observation.vitals[metric]) || observation.vitals[metric] < 0) gaps.push(`vitals-metric-invalid:${id}:${metric}`);
      (vitalsByDeviceClass[denominatorPolicy.deviceClass] ??= []).push({ id, denominatorId: denominatorPolicy.id, vitals: observation.vitals });
    }
  }
  for (const item of supplied.filter((row) => row.vitals && !VITALS_CLASSES.has(row.id))) gaps.push(`vitals-denominator-id-untrusted:${item.id}`);
  const vitalsDenominators = Object.fromEntries(Object.entries(REGISTRY.vitalsDenominators).filter(([, value]) => value && typeof value === 'object').map(([deviceClass, value]) => { const observedIds = (vitalsByDeviceClass[deviceClass] ?? []).map((item) => item.id).sort(); return [deviceClass, { id: value.id, expectedIds: [...value.combinationIds], observedIds, missingIds: value.combinationIds.filter((id) => !observedIds.includes(id)) }]; }));
  const terminalStatuses = supplied.filter((item) => item.terminal === true).map((item) => item.status);
  const worstStatus = ['error', 'fail', 'blocked', 'partial', 'unproven'].find((status) => terminalStatuses.includes(status));
  return finalize('nemesis-web-runtime-matrix', { binding, registryPolicyId: REGISTRY.id, terminal: true, combinations, omitted, denominator: counts, vitalsDenominators, vitalsByDeviceClass, complete: gaps.length === 0, status: worstStatus ?? (gaps.length ? 'partial' : 'pass'), coverageGaps: [...new Set(gaps)].sort() });
}
