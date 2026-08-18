// Chain adjudication adapter per Security Appendix §27-28. One fresh context
// per path; the synthesizer can never adjudicate its own path; PROVEN requires
// verified steps, verified joins, terminal impact, bound proof, negative
// control, and devil's-advocate challenge.

import { createHash } from 'node:crypto';
import {
  assertArtifactBinding,
  bindingFromPlan,
  requireArray,
  requireObject,
  requireString,
} from '../providers/security/contracts.mjs';

const CHAIN_VERDICTS = new Set([
  'PROVEN',
  'PARTIALLY_SUPPORTED',
  'REFUTED',
  'BLOCKED',
  'UNPROVEN',
]);

function assertSeparateContext(path, adjudicator) {
  if (path.provider === adjudicator.provider) {
    throw new Error('attack-path synthesizer cannot adjudicate its own path');
  }
  if (path.synthesisContextId && path.synthesisContextId === adjudicator.contextId) {
    throw new Error('chain adjudication requires a fresh context');
  }
}

function sliceModelForPath(model, path, stepPackets) {
  const referenced = new Set();
  for (const step of stepPackets) {
    const candidate = step.candidate;
    for (const id of [
      ...(candidate?.sources ?? []),
      ...(candidate?.sinks ?? []),
      ...(candidate?.assets ?? []),
      ...(candidate?.requiredControls ?? []),
      ...(candidate?.observedControls ?? []),
    ]) referenced.add(id);
  }
  const entities = (model.entities ?? []).filter((entity) => referenced.has(entity.id));
  const entityIds = new Set(entities.map((entity) => entity.id));
  const relations = (model.relations ?? []).filter((relation) =>
    entityIds.has(relation.from) || entityIds.has(relation.to));
  const referencedEvidence = new Set();
  for (const entity of entities) for (const ref of entity.evidenceRefs ?? []) referencedEvidence.add(ref);
  for (const relation of relations) for (const ref of relation.evidenceRefs ?? []) referencedEvidence.add(ref);
  const evidence = (model.evidence ?? []).filter((item) => referencedEvidence.has(item.id));
  return { entities, relations, evidence };
}

export function createChainAdjudicationPacket({
  plan,
  path,
  candidates,
  candidateAdjudication,
  model,
  adjudicator,
}) {
  const binding = bindingFromPlan(plan);
  for (const [label, artifact] of Object.entries({
    pathArtifact: { binding: path.binding },
    candidates,
    candidateAdjudication,
    model,
  })) assertArtifactBinding(artifact, binding, label);
  assertSeparateContext(path, adjudicator);

  const candidateById = new Map(candidates.candidates.map((item) => [item.id, item]));
  const verdictById = new Map(candidateAdjudication.verdicts.map((item) => [item.candidateId, item]));
  const stepPackets = path.steps.map((step) => {
    const candidate = candidateById.get(step.candidateId);
    const verdict = verdictById.get(step.candidateId);
    if (!candidate || !verdict) throw new Error(`missing candidate or verdict for ${step.candidateId}`);
    return { step, candidate, verdict };
  });

  return {
    schemaVersion: 1,
    kind: 'security-chain-adjudication-packet',
    packetId: stableIdOf({
      pathId: path.id,
      contextId: adjudicator.contextId,
      binding,
    }),
    pathId: path.id,
    binding,
    synthesizer: {
      provider: path.provider,
      contextId: path.synthesisContextId ?? null,
    },
    adjudicator,
    path,
    steps: stepPackets,
    modelSlice: sliceModelForPath(model, path, stepPackets),
    requiredAnalysis: [
      'step usability',
      'identity compatibility',
      'environment compatibility',
      'tenant compatibility',
      'timing and workflow state',
      'join validity',
      'inter-step controls',
      'terminal impact',
      'safe proof',
      'negative control',
      'strongest benign explanation',
    ],
  };
}

function stableIdOf(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

export function finalizeChainVerdict(packet, rawVerdict) {
  requireObject(rawVerdict, 'chain verdict');
  if (rawVerdict.pathId !== packet.pathId) throw new Error('chain verdict pathId mismatch');
  if (rawVerdict.contextId !== packet.adjudicator.contextId) {
    throw new Error('chain verdict contextId mismatch');
  }
  if (!CHAIN_VERDICTS.has(rawVerdict.verdict)) {
    throw new Error(`unsupported chain verdict ${rawVerdict.verdict}`);
  }

  const stepAssessments = requireArray(rawVerdict.stepAssessments, 'stepAssessments');
  const joinAssessments = requireArray(rawVerdict.joinAssessments, 'joinAssessments');
  const expectedSteps = new Set(packet.path.steps.map((step) => step.candidateId));
  const expectedJoins = new Set(packet.path.joins.map((join) => join.id));
  if (new Set(stepAssessments.map((item) => item.candidateId)).size !== expectedSteps.size
      || stepAssessments.some((item) => !expectedSteps.has(item.candidateId))) {
    throw new Error('chain verdict must assess every path step exactly once');
  }
  if (new Set(joinAssessments.map((item) => item.joinId)).size !== expectedJoins.size
      || joinAssessments.some((item) => !expectedJoins.has(item.joinId))) {
    throw new Error('chain verdict must assess every path join exactly once');
  }

  requireString(rawVerdict.rationale, 'rationale');
  requireString(rawVerdict.devilsAdvocate, 'devilsAdvocate');

  if (rawVerdict.verdict === 'PROVEN') {
    if (rawVerdict.evidenceStrength !== 'verified') {
      throw new Error('PROVEN chain requires verified evidence');
    }
    if (!rawVerdict.severity) throw new Error('PROVEN chain requires severity');
    if (!rawVerdict.terminalImpact) throw new Error('PROVEN chain requires terminalImpact');
    if (!rawVerdict.proof?.digest) throw new Error('PROVEN chain requires bound proof');
    if (!rawVerdict.negativeControl?.rationale) {
      throw new Error('PROVEN chain requires a negative control');
    }
    if (stepAssessments.some((item) => item.usableInChain !== true)) {
      throw new Error('PROVEN chain requires every step to be usable');
    }
    if (joinAssessments.some((item) => item.verdict !== 'VERIFIED')) {
      throw new Error('PROVEN chain requires every join to be verified');
    }
  } else if (rawVerdict.severity !== null && rawVerdict.severity !== undefined) {
    throw new Error(`${rawVerdict.verdict} chain must not carry final severity`);
  }

  if (rawVerdict.verdict === 'BLOCKED') {
    const effective = (rawVerdict.controlAssessments ?? [])
      .some((item) => item.status === 'EFFECTIVE');
    if (!effective) throw new Error('BLOCKED chain requires an effective blocking control');
  }

  if (rawVerdict.verdict === 'REFUTED') {
    const refutedJoin = joinAssessments.some((item) => item.verdict === 'REFUTED');
    const unusableStep = stepAssessments.some((item) => item.usableInChain === false);
    if (!refutedJoin && !unusableStep) {
      throw new Error('REFUTED chain requires a refuted join or unusable step');
    }
  }

  return {
    schemaVersion: 1,
    kind: 'security-chain-verdict',
    pathId: packet.pathId,
    synthesizerProvider: packet.synthesizer.provider,
    adjudicatorProvider: packet.adjudicator.provider,
    contextId: packet.adjudicator.contextId,
    binding: packet.binding,
    verdict: rawVerdict.verdict,
    evidenceStrength: rawVerdict.evidenceStrength,
    stepAssessments,
    joinAssessments,
    controlAssessments: rawVerdict.controlAssessments ?? [],
    terminalImpact: rawVerdict.terminalImpact ?? null,
    proof: rawVerdict.proof ?? null,
    negativeControl: rawVerdict.negativeControl ?? null,
    devilsAdvocate: rawVerdict.devilsAdvocate,
    rationale: rawVerdict.rationale,
    severity: rawVerdict.verdict === 'PROVEN' ? rawVerdict.severity : null,
  };
}
