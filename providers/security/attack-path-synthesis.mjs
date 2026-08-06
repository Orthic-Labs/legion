// Bounded attack-path synthesis per Security Appendix Phase 4. Exact fact
// matching, explicit bridge/objective registries, deterministic bounded BFS.
// A path is a hypothesis until independent chain adjudication; no numeric
// score is ever computed.

import {
  EVIDENCE_RANK,
  PATH_PRIORITY,
  PATH_STATUS,
  assertArtifactBinding,
  bindingFromPlan,
  canonicalize,
  digest,
  stableId,
} from './contracts.mjs';

const FACT_FIELDS = Object.freeze([
  'kind', 'subject', 'action', 'object', 'scope', 'environment', 'tenant',
]);

const DEFAULT_LIMITS = Object.freeze({
  maxHops: 6,
  maxBranching: 12,
  maxHypotheses: 100,
  maxPathsPerObjective: 20,
  maxBridgeDepth: 3,
});

export function factMatches(pattern, fact) {
  for (const key of FACT_FIELDS) {
    const expected = pattern[key];
    if (expected === undefined || expected === null) continue;
    const observed = fact[key] ?? null;
    if (expected === '*') {
      if (observed === null) return false;
      continue;
    }
    if (expected !== observed) return false;
  }
  for (const [key, expected] of Object.entries(pattern.attributes ?? {})) {
    const observed = fact.attributes?.[key];
    if (expected === '*') {
      if (observed === undefined || observed === null) return false;
    } else if (observed !== expected) return false;
  }
  return true;
}

export function canonicalFactKey(fact) {
  const normalized = {};
  for (const key of FACT_FIELDS) normalized[key] = fact[key] ?? null;
  normalized.attributes = fact.attributes ?? {};
  return JSON.stringify(canonicalize(normalized));
}

function findSatisfiedPreconditions(preconditions, facts) {
  const matches = [];
  for (let index = 0; index < preconditions.length; index += 1) {
    const pattern = preconditions[index];
    const fact = facts.find((candidate) => factMatches(pattern, candidate));
    if (!fact) return null;
    matches.push({ preconditionIndex: index, fact });
  }
  return matches;
}

function bridgePatternMatches(pattern, fact) {
  return factMatches(pattern, fact);
}

function mapBridgeFact(bridge, sourceFact, model) {
  const target = {
    kind: bridge.to.kind,
    subject: bridge.to.subject ?? null,
    action: bridge.to.action ?? null,
    object: bridge.to.object ?? null,
    scope: bridge.to.scope ?? null,
    environment: bridge.to.environment ?? null,
    tenant: bridge.to.tenant ?? null,
    attributes: { ...(bridge.to.attributes ?? {}) },
  };
  for (const [targetField, sourceField] of Object.entries(bridge.fieldMap ?? {})) {
    target[targetField] = sourceFact[sourceField] ?? null;
  }

  if (bridge.requiresModelRelation) {
    const compatible = model.relations.filter((relation) =>
      relation.kind === bridge.requiresModelRelation
      && [sourceFact.object, sourceFact.subject].includes(relation.from));
    if (compatible.length === 0) return [];
    return compatible.map((relation) => ({
      fact: {
        ...target,
        object: target.object ?? relation.to,
        id: stableId('bridged-security-fact', {
          bridge: bridge.id,
          sourceFact: sourceFact.id,
          relation: relation.id,
          target: { ...target, object: target.object ?? relation.to },
        }),
        evidenceRefs: [...new Set([
          ...(sourceFact.evidenceRefs ?? []),
          ...(relation.evidenceRefs ?? []),
        ])].sort(),
      },
      support: {
        bridgeId: bridge.id,
        relationId: relation.id,
        evidenceStrength: bridge.evidenceStrength,
        evidenceRefs: relation.evidenceRefs ?? [],
      },
    }));
  }

  return [{
    fact: {
      ...target,
      id: stableId('bridged-security-fact', {
        bridge: bridge.id,
        sourceFact: sourceFact.id,
        target,
      }),
      evidenceRefs: [...new Set(sourceFact.evidenceRefs ?? [])].sort(),
    },
    support: {
      bridgeId: bridge.id,
      relationId: null,
      evidenceStrength: bridge.evidenceStrength,
      evidenceRefs: [],
    },
  }];
}

export function expandBridges(facts, bridges, model) {
  const generated = [];
  for (const fact of facts) {
    for (const bridge of bridges) {
      if (!bridgePatternMatches(bridge.from, fact)) continue;
      generated.push(...mapBridgeFact(bridge, fact, model));
    }
  }
  return generated;
}

function stateKey(state) {
  return stableId('attack-path-state', {
    facts: [...state.facts.values()].map(canonicalFactKey).sort(),
    usedCandidates: [...state.usedCandidates].sort(),
  });
}

function addFact(map, fact) {
  const key = canonicalFactKey(fact);
  if (!map.has(key)) map.set(key, fact);
}

function baseState(model) {
  const facts = new Map();
  for (const fact of model.initialFacts ?? []) addFact(facts, fact);
  return {
    facts,
    usedCandidates: new Set(),
    steps: [],
    joins: [],
    unsupportedAssertions: [],
  };
}

function addFactWithChange(map, fact) {
  const key = canonicalFactKey(fact);
  if (map.has(key)) return false;
  map.set(key, fact);
  return true;
}

function augmentStateWithBridges(state, bridges, model, maxBridgeDepth = 3) {
  const facts = new Map(state.facts);
  let frontier = [...facts.values()].map((fact) => ({ fact, depth: 0 }));
  const expanded = new Set();

  while (frontier.length > 0) {
    const nextFrontier = [];
    for (const { fact, depth } of frontier) {
      if (depth >= maxBridgeDepth) continue;
      for (const bridge of bridges) {
        const expansionKey = `${bridge.id}\0${fact.id}`;
        if (expanded.has(expansionKey)) continue;
        expanded.add(expansionKey);
        if (!bridgePatternMatches(bridge.from, fact)) continue;

        for (const generated of mapBridgeFact(bridge, fact, model)) {
          const bridgedFact = {
            ...generated.fact,
            producedByStep: fact.producedByStep ?? null,
            sourceFactId: fact.id,
            bridgeSupport: {
              bridgeId: generated.support.bridgeId,
              relationId: generated.support.relationId,
            },
            evidenceStrength: generated.support.evidenceStrength,
            evidenceRefs: [...new Set([
              ...(fact.evidenceRefs ?? []),
              ...(generated.support.evidenceRefs ?? []),
            ])].sort(),
          };
          if (addFactWithChange(facts, bridgedFact)) {
            nextFrontier.push({ fact: bridgedFact, depth: depth + 1 });
          }
        }
      }
    }
    frontier = nextFrontier;
  }

  return { ...state, facts };
}

function candidateApplicability(candidate, state) {
  const matches = findSatisfiedPreconditions(
    candidate.preconditions,
    [...state.facts.values()],
  );
  return matches ? { matches } : null;
}

function applyCandidate(candidate, state, matches) {
  const nextFacts = new Map(state.facts);
  const stepIndex = state.steps.length;
  const joins = matches.map((match) => ({
    id: stableId('attack-path-join', {
      candidateId: candidate.id,
      preconditionIndex: match.preconditionIndex,
      factId: match.fact.id,
      stepIndex,
    }),
    fromStep: match.fact.producedByStep ?? null,
    fromFactId: match.fact.id,
    toStep: stepIndex,
    toPreconditionIndex: match.preconditionIndex,
    relation: match.fact.bridgeSupport ? 'bridged-satisfaction' : 'satisfies',
    support: match.fact.bridgeSupport ?? { kind: 'direct-fact-match' },
    evidenceStrength: match.fact.evidenceStrength ?? 'possible',
    evidenceRefs: match.fact.evidenceRefs ?? [],
    status: 'UNADJUDICATED',
  }));
  const effects = candidate.effects.map((effect) => ({
    ...effect,
    producedByStep: stepIndex,
    evidenceStrength: 'possible',
    evidenceRefs: [...new Set([
      ...(effect.evidenceRefs ?? []),
      ...(candidate.evidenceRefs ?? []),
    ])].sort(),
  }));
  for (const effect of effects) addFact(nextFacts, effect);

  return {
    facts: nextFacts,
    usedCandidates: new Set([...state.usedCandidates, candidate.id]),
    steps: [...state.steps, {
      order: stepIndex,
      candidateId: candidate.id,
      requires: matches.map((item) => item.fact.id),
      produces: effects.map((item) => item.id),
      status: 'UNADJUDICATED',
    }],
    joins: [...state.joins, ...joins],
    unsupportedAssertions: [...state.unsupportedAssertions],
  };
}

function globToken(pattern, value) {
  if (typeof value !== 'string') return false;
  const escaped = String(pattern)
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i').test(value);
}

function objectiveMatchesFact(objective, fact, entityById) {
  const rule = objective.matches ?? {};
  if (rule.factKind && fact.kind !== rule.factKind) return false;
  if (rule.factKinds && !rule.factKinds.includes(fact.kind)) return false;
  if (rule.scopePatterns?.length
      && !rule.scopePatterns.some((pattern) => globToken(pattern, fact.scope ?? ''))) {
    return false;
  }
  if (rule.assetKinds?.length) {
    const asset = entityById.get(fact.object);
    if (!asset || !rule.assetKinds.includes(asset.kind)) return false;
  }
  return true;
}

function matchObjectives(facts, model, objectives) {
  const entityById = new Map(model.entities.map((entity) => [entity.id, entity]));
  const matches = [];
  for (const objective of objectives) {
    const matchedFacts = facts.filter((fact) =>
      objectiveMatchesFact(objective, fact, entityById));
    if (matchedFacts.length === 0) continue;
    matches.push({
      id: objective.id,
      priority: objective.priority,
      description: objective.description ?? objective.id,
      matchedFactIds: matchedFacts.map((fact) => fact.id).sort(),
      matchedAssetIds: [...new Set(matchedFacts
        .map((fact) => fact.object)
        .filter((id) => entityById.has(id)))].sort(),
    });
  }
  return matches.sort((left, right) => {
    const priority = PATH_PRIORITY.indexOf(left.priority)
      - PATH_PRIORITY.indexOf(right.priority);
    return priority || left.id.localeCompare(right.id);
  });
}

function deriveStart(state) {
  const initialJoins = state.joins.filter((join) => join.fromStep === null);
  return {
    factIds: [...new Set(initialJoins.map((join) => join.fromFactId))].sort(),
    firstCandidateId: state.steps[0]?.candidateId ?? null,
  };
}

function deriveControls(state, candidateById) {
  const required = new Set();
  const observed = new Set();
  for (const step of state.steps) {
    const candidate = candidateById.get(step.candidateId);
    for (const id of candidate?.requiredControls ?? []) required.add(id);
    for (const id of candidate?.observedControls ?? []) observed.add(id);
  }
  return {
    required: [...required].sort(),
    observed: [...observed].sort(),
    status: 'UNADJUDICATED',
  };
}

function buildHypothesis({
  state,
  objective,
  binding,
  denominatorDigest,
  limits,
  candidateById,
}) {
  const content = {
    start: deriveStart(state),
    objective,
    steps: state.steps,
    joins: state.joins,
    terminalFacts: objective.matchedFactIds,
  };
  return {
    schemaVersion: 1,
    kind: 'attack-path-hypothesis',
    id: stableId('attack-path-hypothesis', content),
    provider: 'security.attack-path-synthesis',
    providerVersion: '1',
    binding,
    denominatorDigest,
    status: 'PROPOSED',
    priority: objective.priority,
    start: content.start,
    objective,
    steps: content.steps,
    joins: content.joins,
    terminalFacts: content.terminalFacts,
    controls: deriveControls(state, candidateById),
    unsupportedAssertions: state.unsupportedAssertions,
    alternateExplanations: [],
    synthesis: {
      maxHops: limits.maxHops,
      maxBranching: limits.maxBranching,
      maxHypotheses: limits.maxHypotheses,
      maxBridgeDepth: limits.maxBridgeDepth,
      truncated: false,
      truncationReasons: [],
    },
  };
}

function hypothesisSignature(path) {
  return JSON.stringify(canonicalize({
    objectiveId: path.objective.id,
    startFactIds: path.start.factIds,
    candidateIds: path.steps.map((step) => step.candidateId),
    terminalFacts: path.terminalFacts,
  }));
}

function weakestJoinRank(path) {
  if (path.joins.length === 0) return EVIDENCE_RANK.possible;
  return Math.min(...path.joins.map((join) =>
    EVIDENCE_RANK[join.evidenceStrength] ?? EVIDENCE_RANK.possible));
}

function betterHypothesis(left, right) {
  const leftUnsupported = left.unsupportedAssertions.length;
  const rightUnsupported = right.unsupportedAssertions.length;
  if (leftUnsupported !== rightUnsupported) return leftUnsupported < rightUnsupported;
  const leftRank = weakestJoinRank(left);
  const rightRank = weakestJoinRank(right);
  if (leftRank !== rightRank) return leftRank > rightRank;
  if (left.steps.length !== right.steps.length) return left.steps.length < right.steps.length;
  return left.id.localeCompare(right.id) < 0;
}

function finalizeHypotheses({
  binding,
  denominatorDigest,
  hypotheses,
  limits,
  truncationReasons,
  model,
  candidatesArtifact,
  statesExamined,
}) {
  const bySignature = new Map();
  for (const path of hypotheses) {
    const signature = hypothesisSignature(path);
    const current = bySignature.get(signature);
    if (!current || betterHypothesis(path, current)) bySignature.set(signature, path);
  }
  const retained = [...bySignature.values()]
    .sort((left, right) => {
      const priority = PATH_PRIORITY.indexOf(left.priority)
        - PATH_PRIORITY.indexOf(right.priority);
      if (priority) return priority;
      if (left.steps.length !== right.steps.length) {
        return left.steps.length - right.steps.length;
      }
      return left.id.localeCompare(right.id);
    });
  const truncated = truncationReasons.length > 0;
  for (const path of retained) {
    path.synthesis.truncated = truncated;
    path.synthesis.truncationReasons = truncationReasons;
  }
  return {
    schemaVersion: 1,
    kind: 'attack-path-hypotheses',
    provider: 'security.attack-path-synthesis',
    providerVersion: '1',
    binding,
    denominatorDigest,
    complete: !truncated && model.complete && candidatesArtifact.complete,
    hypotheses: retained,
    coverage: {
      candidateCount: candidatesArtifact.candidates.length,
      initialFactCount: model.initialFacts.length,
      statesExamined,
      hypothesesProduced: retained.length,
      limits,
    },
    coverageGaps: [
      ...(!model.complete ? [{ kind: 'security-model-incomplete' }] : []),
      ...(!candidatesArtifact.complete ? [{ kind: 'security-candidates-incomplete' }] : []),
      ...truncationReasons.map((reason) => ({
        kind: 'attack-path-search-truncated',
        reason,
      })),
    ],
  };
}

export function synthesizeAttackPaths({
  plan,
  model,
  candidatesArtifact,
  bridges,
  objectives,
  limits = DEFAULT_LIMITS,
}) {
  const binding = bindingFromPlan(plan);
  assertArtifactBinding(model, binding, 'security model');
  assertArtifactBinding(candidatesArtifact, binding, 'security candidates');

  const denominatorDigest = digest({
    model: model.denominatorDigest,
    candidates: candidatesArtifact.denominatorDigest,
    bridges: digest(bridges),
    objectives: digest(objectives),
    limits,
  });
  const candidateById = new Map(
    candidatesArtifact.candidates.map((candidate) => [candidate.id, candidate]),
  );
  const queue = [baseState(model)];
  const seen = new Set();
  const hypotheses = [];
  const truncationReasons = new Set();

  while (queue.length > 0 && hypotheses.length < limits.maxHypotheses) {
    const queuedState = queue.shift();
    const state = augmentStateWithBridges(
      queuedState,
      bridges,
      model,
      limits.maxBridgeDepth,
    );
    const key = stateKey(state);
    if (seen.has(key)) continue;
    seen.add(key);

    const terminal = matchObjectives([...state.facts.values()], model, objectives);
    for (const objective of terminal) {
      if (state.steps.length === 0) continue;
      hypotheses.push(buildHypothesis({
        state,
        objective,
        binding,
        denominatorDigest,
        limits,
        candidateById,
      }));
      if (hypotheses.length >= limits.maxHypotheses) break;
    }
    if (state.steps.length >= limits.maxHops) {
      truncationReasons.add('max-hops');
      continue;
    }

    const expansions = [];
    for (const candidate of candidatesArtifact.candidates) {
      if (state.usedCandidates.has(candidate.id)) continue;
      const applicable = candidateApplicability(candidate, state);
      if (!applicable) continue;
      expansions.push({ candidate, applicable });
    }

    expansions.sort((a, b) => a.candidate.id.localeCompare(b.candidate.id));
    if (expansions.length > limits.maxBranching) {
      truncationReasons.add('max-branching');
    }
    for (const expansion of expansions.slice(0, limits.maxBranching)) {
      queue.push(applyCandidate(expansion.candidate, state, expansion.applicable.matches));
    }
  }

  if (queue.length > 0) truncationReasons.add('max-hypotheses');
  return finalizeHypotheses({
    binding,
    denominatorDigest,
    hypotheses,
    limits,
    truncationReasons: [...truncationReasons].sort(),
    model,
    candidatesArtifact,
    statesExamined: seen.size,
  });
}
