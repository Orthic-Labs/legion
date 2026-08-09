import { createHash } from 'node:crypto';

const PROVIDER = 'narrative.chronology';
const MEDIA_TYPE = 'application/vnd.legion.narrative-analysis+json';

function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

function orderOf(unit) {
  const value = unit?.sourceOrder ?? unit?.order;
  if (value === undefined || value === null || value === '') return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function issue(ruleId, edge, claim, binding, detectorKind = 'deterministic') {
  return {
    schemaVersion: 1,
    producer: PROVIDER,
    ruleId,
    detectorKind,
    edge: { from: edge.from, to: edge.to, kind: edge.kind },
    claim,
    evidenceRefs: evidenceRefs(edge),
    binding,
  };
}

function ordering(edge, classification, reason) {
  return {
    edge: { from: edge.from, to: edge.to, kind: edge.kind },
    classification,
    reason,
    evidenceRefs: evidenceRefs(edge),
  };
}

function evidenceRefs(edge) {
  return Array.isArray(edge?.evidenceRefs) ? edge.evidenceRefs : [];
}

function normalizedKind(edge) {
  const value = edge?.kind ?? edge?.constraintKind ?? edge?.type ?? edge?.constraint?.kind;
  return String(value ?? '').trim().toLowerCase().replaceAll('_', '-');
}

function requiredRelation(edge, from, to) {
  const kind = normalizedKind(edge);
  const relation = String(edge?.relation ?? edge?.constraint?.relation ?? '').trim().toLowerCase();
  if (relation === 'after' || kind === 'after' || kind === 'comes-after') return 'after';
  if (relation === 'before' || kind === 'before' || kind === 'comes-before') return 'before';
  if (['chronology', 'temporal', 'time', 'step-order', 'steporder', 'sequence', 'causality', 'antecedent', 'pronoun', 'callback', 'question-answer', 'questionanswer', 'qa'].includes(kind)) return 'before';
  if (from?.role === 'question' && to?.role === 'answer') return 'before';
  return null;
}

function antecedentLike(edge) {
  return ['antecedent', 'pronoun', 'callback'].includes(normalizedKind(edge));
}

function asRefs(value) {
  if (!Array.isArray(value)) return [];
  return value.map((ref) => typeof ref === 'string' ? { id: ref } : ref).filter((ref) => ref?.id || ref?.unitId || ref?.antecedentId);
}

function derivedEdges(model, units, edges) {
  const derived = [];
  for (const unit of units) {
    const refs = [
      ...asRefs(unit.antecedentRefs ?? unit.pronounRefs ?? unit.antecedent),
      ...asRefs(unit.callbackRefs ?? unit.callbackOf),
    ];
    for (const ref of refs) {
      derived.push({
        from: ref.unitId ?? ref.antecedentId ?? ref.id,
        to: unit.id,
        kind: ref.kind ?? (unit.callbackRefs || unit.callbackOf ? 'callback' : 'antecedent'),
        strength: ref.strength ?? 'derived',
        evidenceRefs: ref.evidenceRefs ?? unit.evidenceRefs ?? [],
      });
    }
    for (const ref of asRefs(unit.attributionRefs ?? unit.attributedTo)) {
      derived.push({
        from: ref.unitId ?? ref.id,
        to: unit.id,
        kind: 'attribution',
        strength: ref.strength ?? 'derived',
        evidenceRefs: ref.evidenceRefs ?? unit.evidenceRefs ?? [],
      });
    }
    for (const target of asRefs(unit.before)) derived.push({ from: unit.id, to: target.unitId ?? target.id, kind: 'before', evidenceRefs: target.evidenceRefs ?? unit.evidenceRefs ?? [] });
    for (const target of asRefs(unit.after)) derived.push({ from: unit.id, to: target.unitId ?? target.id, kind: 'after', evidenceRefs: target.evidenceRefs ?? unit.evidenceRefs ?? [] });
  }
  return [...edges, ...(Array.isArray(model.constraints) ? model.constraints : []), ...derived];
}

function addViolation({ findings, candidates, alternateOrders, edge, binding, ruleId, uncertainRuleId, claim, forbiddenReason, reviewReason }) {
  if (evidenceRefs(edge).length) {
    findings.push(issue(ruleId, edge, claim, binding));
    alternateOrders.push(ordering(edge, 'forbidden', forbiddenReason));
    return;
  }
  candidates.push(issue(uncertainRuleId ?? 'narrative.chronology.sequence-uncertain', edge, claim, binding, 'interpretive'));
  alternateOrders.push(ordering(edge, 'review-required', reviewReason));
}

export function assessChronology(model = {}) {
  const binding = model.binding ?? {};
  const units = model.units ?? [];
  const sourceEdges = Array.isArray(model.edges) ? model.edges : [];
  const edges = derivedEdges(model, units, sourceEdges);
  const byId = new Map();
  const duplicateUnitIds = [];
  for (const unit of units) {
    if (byId.has(unit.id)) duplicateUnitIds.push(unit.id);
    else byId.set(unit.id, unit);
  }
  const findings = [];
  const candidates = [];
  const alternateOrders = [];

  for (const unitId of duplicateUnitIds) findings.push({
    schemaVersion: 1,
    producer: PROVIDER,
    ruleId: 'narrative.chronology.duplicate-unit-id',
    detectorKind: 'deterministic',
    unitIds: [unitId],
    claim: 'Narrative model contains a duplicate unit identity, so graph edges are ambiguous.',
    evidenceRefs: [],
    binding,
  });

  for (const edge of edges) {
    const from = byId.get(edge.from);
    const to = byId.get(edge.to);
    if (!from || !to) {
      const ruleId = antecedentLike(edge)
        ? 'narrative.chronology.missing-antecedent'
        : 'narrative.chronology.missing-unit';
      addViolation({
        findings,
        candidates,
        alternateOrders,
        edge,
        binding,
        ruleId,
        uncertainRuleId: antecedentLike(edge) ? 'narrative.chronology.antecedent-uncertain' : 'narrative.chronology.order-unproven',
        claim: 'Narrative edge references a unit absent from the bound model.',
        forbiddenReason: 'Evidence forbids reordering an edge with an absent endpoint.',
        reviewReason: 'An absent endpoint prevents graph validation.',
      });
      continue;
    }

    const fromOrder = orderOf(from);
    const toOrder = orderOf(to);
    if (fromOrder === null || toOrder === null) {
      candidates.push(issue(
        'narrative.chronology.order-unproven',
        edge,
        'Narrative edge lacks complete source-order evidence.',
        binding,
        'interpretive',
      ));
      alternateOrders.push(ordering(edge, 'review-required', 'Source order is incomplete.'));
      continue;
    }

    const kind = normalizedKind(edge);
    const expectedSourceId = edge.expectedSourceId ?? edge.constraint?.expectedSourceId;
    const observedSourceId = edge.observedSourceId ?? edge.constraint?.observedSourceId;
    if (kind === 'attribution' && expectedSourceId && observedSourceId && expectedSourceId !== observedSourceId) {
      addViolation({
        findings,
        candidates,
        alternateOrders,
        edge,
        binding,
        ruleId: 'narrative.chronology.false-attribution',
        uncertainRuleId: 'narrative.chronology.unsupported-attribution',
        claim: 'Observed attribution contradicts the expected source identity.',
        forbiddenReason: 'Evidence identifies a different source, so the attribution is forbidden.',
        reviewReason: 'Conflicting attribution lacks evidence for a blocking decision.',
      });
      continue;
    }
    const relation = requiredRelation(edge, from, to);
    const violatesOrder = relation === 'before'
      ? fromOrder >= toOrder
      : relation === 'after'
        ? fromOrder <= toOrder
        : false;

    if (violatesOrder) {
      const isAntecedent = antecedentLike(edge);
      addViolation({
        findings,
        candidates,
        alternateOrders,
        edge,
        binding,
        ruleId: isAntecedent ? 'narrative.chronology.missing-antecedent' : 'narrative.chronology.false-sequence',
        uncertainRuleId: isAntecedent ? 'narrative.chronology.antecedent-uncertain' : 'narrative.chronology.sequence-uncertain',
        claim: isAntecedent
          ? 'Dependent unit appears before its evidence-backed antecedent.'
          : 'Observed narrative order contradicts an evidence-backed dependency.',
        forbiddenReason: isAntecedent ? 'Antecedent must precede dependent reference.' : 'Evidence requires the dependency order to be preserved.',
        reviewReason: isAntecedent ? 'Antecedent ordering lacks evidence.' : 'Dependency ordering lacks evidence.',
      });
      continue;
    }

    if (kind === 'causality' && !evidenceRefs(edge).length) {
      candidates.push(issue(
        'narrative.chronology.unsupported-causality',
        edge,
        'Causal edge has no bound evidence and cannot be treated as fact.',
        binding,
        'interpretive',
      ));
      alternateOrders.push(ordering(edge, 'review-required', 'Causal dependency is unproven.'));
      continue;
    }

    if (kind === 'attribution' && !evidenceRefs(edge).length) {
      candidates.push(issue(
        'narrative.chronology.unsupported-attribution',
        edge,
        'Attribution edge has no bound evidence and cannot be treated as fact.',
        binding,
        'interpretive',
      ));
      alternateOrders.push(ordering(edge, 'review-required', 'Attribution is unproven.'));
      continue;
    }

    const coldOpenExplanation = to.coldOpen === true && edge.kind === 'explanation' && fromOrder > toOrder;
    if (coldOpenExplanation) {
      alternateOrders.push(ordering(edge, 'safe', 'Bound explanation preserves an intentional cold open.'));
    } else if (edge.strength === 'inferred' && !evidenceRefs(edge).length) {
      alternateOrders.push(ordering(edge, 'review-required', 'Dependency is inferred and unproven.'));
    } else {
      alternateOrders.push(ordering(edge, 'safe', 'Current order satisfies the bound dependency.'));
    }
  }

  const tutorialSteps = new Map();
  for (const unit of units.filter(({ stepId }) => stepId)) {
    if (tutorialSteps.has(unit.stepId)) findings.push({
      schemaVersion: 1,
      producer: PROVIDER,
      ruleId: 'narrative.chronology.repeated-step',
      detectorKind: 'deterministic',
      unitIds: [tutorialSteps.get(unit.stepId), unit.id],
      claim: 'Tutorial step identity repeats in one narrative model.',
      evidenceRefs: unit.evidenceRefs ?? [],
      binding,
    });
    else tutorialSteps.set(unit.stepId, unit.id);
  }

  const coverageGaps = units.filter((unit) => orderOf(unit) === null).map((unit) => `source-order-missing:${unit.id}`);
  const base = {
    schemaVersion: 1,
    producer: PROVIDER,
    provider: PROVIDER,
    status: findings.length ? 'findings' : candidates.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass',
    subject: {
      kind: model.kind ?? 'legion-narrative-model',
      denominatorDigest: model.denominatorDigest ?? null,
    },
    denominator: { kind: 'narrative-edges', expected: edges.length, examined: edges.length },
    denominatorDigest: model.denominatorDigest ?? digest(edges),
    findings,
    candidates,
    alternateOrders,
    coverageGaps,
    binding,
    mediaType: MEDIA_TYPE,
  };
  return { ...base, digest: digest(base) };
}
