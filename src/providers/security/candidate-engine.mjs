// Security candidate v2 engine per Security Appendix Phase 3. A candidate is
// an allegation about a security primitive — never a vulnerability, never
// carrying a final severity or evidence verdict.

import {
  CHAIN_ROLES,
  FACT_KINDS,
  assertArtifactBinding,
  bindingFromPlan,
  requireArray,
  requireObject,
  requireString,
  stableId,
} from './contracts.mjs';

const SEVERITY_HINTS = new Set(['critical', 'high', 'medium', 'low', 'info']);

function uniqueSorted(values) {
  return [...new Set(values ?? [])].sort();
}

function validateFactPattern(pattern, label) {
  requireObject(pattern, label);
  if (!FACT_KINDS.includes(pattern.kind)) {
    throw new Error(`${label}.kind is unsupported: ${pattern.kind}`);
  }
  return {
    kind: pattern.kind,
    subject: pattern.subject ?? null,
    action: pattern.action ?? null,
    object: pattern.object ?? null,
    scope: pattern.scope ?? null,
    environment: pattern.environment ?? null,
    tenant: pattern.tenant ?? null,
    attributes: pattern.attributes ?? {},
  };
}

function concreteFact(raw, candidateNamespace) {
  const base = validateFactPattern(raw, 'effect');
  if (Object.values(base).includes('*')) {
    throw new Error('candidate effects must be concrete; wildcard is only valid in preconditions');
  }
  return {
    ...base,
    id: raw.id ?? stableId(`${candidateNamespace}:effect`, base),
    evidenceRefs: uniqueSorted(raw.evidenceRefs ?? []),
  };
}

function assertModelReferences(model, ids, label) {
  const known = new Set((model.entities ?? []).map((item) => item.id));
  for (const id of ids) {
    if (!known.has(id)) throw new Error(`${label} references unknown security-model entity ${id}`);
  }
}

export function createSecurityCandidateV2({
  plan,
  model,
  provider,
  providerVersion,
  denominatorDigest,
  observation,
}) {
  const binding = bindingFromPlan(plan);
  assertArtifactBinding(model, binding, 'security model');
  requireObject(observation, 'observation');
  requireString(provider, 'provider');
  requireString(providerVersion, 'providerVersion');
  requireString(denominatorDigest, 'denominatorDigest');
  requireString(observation.ruleId, 'observation.ruleId');
  requireString(observation.candidateClass, 'observation.candidateClass');
  requireString(observation.claim, 'observation.claim');
  if (!SEVERITY_HINTS.has(observation.severityHint)) {
    throw new Error(`invalid severity hint ${observation.severityHint}`);
  }

  const sources = uniqueSorted(observation.sources);
  const sinks = uniqueSorted(observation.sinks);
  const assets = uniqueSorted(observation.assets);
  const boundaries = uniqueSorted(observation.trustBoundaryCrossings);
  const controls = uniqueSorted(observation.requiredControls);
  const observedControls = uniqueSorted(observation.observedControls);
  assertModelReferences(model, sources, 'sources');
  assertModelReferences(model, sinks, 'sinks');
  assertModelReferences(model, assets, 'assets');
  assertModelReferences(model, boundaries, 'trustBoundaryCrossings');
  assertModelReferences(model, controls, 'requiredControls');
  assertModelReferences(model, observedControls, 'observedControls');

  const preconditions = requireArray(observation.preconditions ?? [], 'preconditions')
    .map((item, index) => validateFactPattern(item, `preconditions[${index}]`));
  const namespace = `${provider}:${observation.ruleId}`;
  const effects = requireArray(observation.effects ?? [], 'effects')
    .map((item) => concreteFact(item, namespace));
  if (effects.length === 0) throw new Error('security candidate must declare at least one effect');

  const chainRoles = uniqueSorted(observation.chainRoles);
  for (const role of chainRoles) {
    if (!CHAIN_ROLES.includes(role)) throw new Error(`unsupported chain role ${role}`);
  }

  const identity = {
    provider,
    providerVersion,
    ruleId: observation.ruleId,
    sources,
    sinks,
    evidenceRefs: uniqueSorted(observation.evidenceRefs),
    effects: effects.map(({ id }) => id),
  };

  return {
    schemaVersion: 2,
    kind: 'security-candidate',
    id: stableId('security-candidate-v2', identity),
    provider,
    providerVersion,
    ruleId: observation.ruleId,
    candidateClass: observation.candidateClass,
    claim: observation.claim,
    severityHint: observation.severityHint,
    sources,
    sinks,
    attackerCapabilities: uniqueSorted(observation.attackerCapabilities),
    preconditions,
    effects,
    assets,
    trustBoundaryCrossings: boundaries,
    requiredControls: controls,
    observedControls,
    chainRoles,
    evidenceRefs: uniqueSorted(observation.evidenceRefs),
    detectorMetadata: observation.detectorMetadata ?? {},
    uncertainty: uniqueSorted(observation.uncertainty),
    binding,
    denominatorDigest,
    verdict: 'UNADJUDICATED',
    adjudicationRequired: true,
  };
}

export function validateSecurityCandidateV2(candidate, { plan, model } = {}) {
  requireObject(candidate, 'candidate');
  if (candidate.schemaVersion !== 2) throw new Error(`candidate schemaVersion must be 2; got ${candidate.schemaVersion}`);
  if (candidate.verdict !== 'UNADJUDICATED') throw new Error(`candidate verdict must be UNADJUDICATED; got ${candidate.verdict}`);
  if (candidate.adjudicationRequired !== true) throw new Error('candidate must require adjudication');
  if ('severity' in candidate) throw new Error('candidate must not carry a final severity');
  if ('evidenceStrength' in candidate) throw new Error('candidate must not carry a final evidence verdict');
  if ((candidate.effects ?? []).length === 0) throw new Error('candidate must declare at least one effect');
  if ((candidate.evidenceRefs ?? []).length === 0) throw new Error('candidate must declare evidence refs');
  for (const effect of candidate.effects ?? []) {
    if (Object.values(effect).includes('*')) throw new Error('candidate effects must be concrete');
  }
  if (plan && model) {
    const binding = bindingFromPlan(plan);
    assertArtifactBinding(candidate, binding, 'security candidate');
  }
  return true;
}

export function runSecurityPack({
  pack,
  root,
  plan,
  projection,
  model,
  providerPlan,
}) {
  if (!providerPlan?.denominator?.pathDigest) {
    throw new Error(`provider ${pack.id} has no frozen denominator`);
  }
  const allowed = new Set(providerPlan.denominator.paths ?? projection.files ?? []);
  const evidenceById = new Map(model.evidence.map((item) => [item.id, item]));
  const entityById = new Map(model.entities.map((item) => [item.id, item]));
  const fromIndex = new Map();
  const toIndex = new Map();
  for (const relation of model.relations) {
    if (!fromIndex.has(relation.from)) fromIndex.set(relation.from, []);
    if (!toIndex.has(relation.to)) toIndex.set(relation.to, []);
    fromIndex.get(relation.from).push(relation);
    toIndex.get(relation.to).push(relation);
  }

  const context = {
    root,
    plan,
    projection,
    model,
    files: [...allowed].sort(),
    denominatorDigest: providerPlan.denominator.pathDigest,
    providerId: pack.id,
    providerVersion: pack.version,
    evidenceById,
    entityById,
    relationsFrom: (id) => fromIndex.get(id) ?? [],
    relationsTo: (id) => toIndex.get(id) ?? [],
    readFile(path) {
      if (!allowed.has(path)) throw new Error(`pack attempted to read out-of-denominator path ${path}`);
      return projection.sourceText?.[path] ?? null;
    },
  };

  const observations = pack.analyze(context) ?? [];
  const candidates = observations.map((observation) => createSecurityCandidateV2({
    plan,
    model,
    provider: pack.id,
    providerVersion: pack.version,
    denominatorDigest: providerPlan.denominator.pathDigest,
    observation,
  }));

  return {
    schemaVersion: 1,
    provider: pack.id,
    applicable: true,
    required: providerPlan.benchmark?.requiredForCleanClaim ?? true,
    status: candidates.length ? 'candidates' : 'pass',
    complete: true,
    coverage: {
      denominatorDigest: providerPlan.denominator.pathDigest,
      expected: providerPlan.denominator.pathCount,
      examined: allowed.size,
      unexamined: [],
      rules: pack.rules?.map((rule) => rule.id) ?? [],
    },
    candidates,
    findings: [],
    coverageGaps: [],
    degradation: [],
    artifacts: [],
  };
}
