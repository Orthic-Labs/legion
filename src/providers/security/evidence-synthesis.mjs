// Security evidence synthesis per Security Appendix §43. Materializes final
// findings only from surviving verdicts plus complete variant receipts; proven
// paths separately; systemic root causes grouped relationally; effective
// controls reported.

import {
  assertArtifactBinding,
  bindingFromPlan,
  digest,
  stableId,
} from './contracts.mjs';

const SURVIVING = new Set(['TRUE_POSITIVE', 'LIKELY_TRUE_POSITIVE']);

function completeReceiptByFinding(variants) {
  return new Map((variants.receipts ?? [])
    .filter((receipt) => receipt.complete)
    .map((receipt) => [receipt.findingId, receipt]));
}

function findingFrom({ candidate, verdict, receipt, paths }) {
  const locations = receipt.matches
    .filter((match) => match.disposition === 'CONFIRMED')
    .map((match) => ({ file: match.file, line: match.line, matchId: match.id }));
  const relatedAttackPathIds = paths
    .filter((path) => path.steps.some((step) => step.candidateId === candidate.id))
    .map((path) => path.pathId ?? path.id)
    .sort();
  const content = {
    candidateId: candidate.id,
    verdict: verdict.verdict,
    rootCauseSignature: verdict.rootCauseSignature,
    locations,
  };
  return {
    id: stableId('security-finding', content),
    candidateId: candidate.id,
    ruleId: candidate.ruleId,
    title: verdict.title ?? candidate.claim,
    verdict: verdict.verdict,
    severity: verdict.severity,
    evidenceStrength: verdict.evidenceStrength,
    threatModel: verdict.threatModel,
    attackerControl: verdict.attackerControl,
    reachability: verdict.reachability,
    impact: verdict.impact,
    proof: verdict.proof,
    rootCauseSignature: verdict.rootCauseSignature,
    variantReceiptId: receipt.receiptDigest,
    locations,
    relatedAttackPathIds,
    acceptedRisk: null,
  };
}

function materializeAttackPaths(provenPaths, findings) {
  return provenPaths.map((path) => ({
    id: path.pathId,
    verdict: 'PROVEN',
    severity: path.severity,
    priority: path.priority,
    start: path.start,
    objective: path.objective,
    constituentFindingIds: findings
      .filter((finding) => finding.relatedAttackPathIds.includes(path.pathId))
      .map((finding) => finding.id),
    stepAssessments: path.stepAssessments ?? [],
    joinAssessments: path.joinAssessments ?? [],
    controls: path.controls ?? [],
    terminalImpact: path.terminalImpact,
    proof: path.proof,
    narrative: `Generated from structured fields: ${path.start?.factIds?.join(', ') ?? ''} → ${path.objective?.id ?? ''}`,
  }));
}

function classifyNonProvenPaths(chainAdjudication) {
  const classified = { partiallySupported: [], blocked: [], refuted: [], unproven: [] };
  for (const verdict of chainAdjudication.verdicts ?? []) {
    if (verdict.verdict === 'PROVEN') continue;
    const key = {
      PARTIALLY_SUPPORTED: 'partiallySupported',
      BLOCKED: 'blocked',
      REFUTED: 'refuted',
      UNPROVEN: 'unproven',
    }[verdict.verdict];
    if (key) classified[key].push(verdict);
  }
  return classified;
}

function groupRootCauses(findings) {
  const bySignature = new Map();
  for (const finding of findings) {
    const signature = finding.rootCauseSignature;
    const key = digest(signature ?? {});
    if (!bySignature.has(key)) {
      bySignature.set(key, {
        id: key,
        rootCauseSignature: signature ?? {},
        findingIds: [],
        confirmedVariantCount: 0,
        affectedComponents: [],
        breaksAttackPathIds: [],
        recommendedControl: null,
      });
    }
    bySignature.get(key).findingIds.push(finding.id);
  }
  for (const group of bySignature.values()) {
    group.findingIds.sort();
    group.confirmedVariantCount = group.findingIds.length;
  }
  return [...bySignature.values()];
}

function summarizeControls(model, chainAdjudication, findings) {
  const controls = new Map();
  for (const entity of model.entities ?? []) {
    if (entity.kind !== 'control') continue;
    controls.set(entity.id, {
      controlId: entity.id,
      status: 'UNKNOWN',
      supportsFindingIds: [],
      blocksAttackPathIds: [],
      evidenceRefs: entity.evidenceRefs ?? [],
    });
  }
  for (const verdict of chainAdjudication.verdicts ?? []) {
    if (verdict.verdict !== 'BLOCKED') continue;
    for (const assessment of verdict.controlAssessments ?? []) {
      const control = controls.get(assessment.controlId);
      if (control) {
        control.status = assessment.status;
        control.blocksAttackPathIds.push(verdict.pathId);
      }
    }
  }
  for (const finding of findings) {
    for (const ref of finding.rootCauseSignature?.missingControl ? [] : []) {
      const control = controls.get(ref);
      if (control) control.supportsFindingIds.push(finding.id);
    }
  }
  return [...controls.values()];
}

export function synthesizeSecurityEvidence({
  plan,
  model,
  candidates,
  adjudication,
  chainAdjudication,
  variants,
}) {
  const binding = bindingFromPlan(plan);
  for (const [label, artifact] of Object.entries({
    model, candidates, adjudication, chainAdjudication, variants,
  })) assertArtifactBinding(artifact, binding, label);

  const candidateById = new Map(candidates.candidates.map((item) => [item.id, item]));
  const receiptByFinding = completeReceiptByFinding(variants);
  const provenPaths = (chainAdjudication.verdicts ?? [])
    .filter((item) => item.verdict === 'PROVEN');
  const findings = [];
  const coverageGaps = [];

  for (const verdict of adjudication.verdicts ?? []) {
    if (!SURVIVING.has(verdict.verdict)) continue;
    const candidate = candidateById.get(verdict.candidateId);
    const receipt = receiptByFinding.get(verdict.candidateId);
    if (!candidate || !receipt) {
      coverageGaps.push({
        kind: 'finding-missing-candidate-or-variant-receipt',
        candidateId: verdict.candidateId,
      });
      continue;
    }
    findings.push(findingFrom({
      candidate,
      verdict,
      receipt,
      paths: provenPaths,
    }));
  }

  const attackPaths = materializeAttackPaths(provenPaths, findings);
  const hypotheses = classifyNonProvenPaths(chainAdjudication);
  const systemicRootCauses = groupRootCauses(findings);
  const controls = summarizeControls(model, chainAdjudication, findings);

  return {
    schemaVersion: 1,
    kind: 'security-evidence-synthesis',
    provider: 'security.evidence-synthesis',
    providerVersion: '1',
    binding,
    complete: coverageGaps.length === 0
      && variants.complete === true
      && adjudication.complete === true
      && chainAdjudication.complete === true,
    findings,
    attackPaths,
    systemicRootCauses,
    controls,
    hypotheses,
    coverage: {
      candidates: candidates.candidates.length,
      survivingCandidateVerdicts: findings.length,
      provenPaths: attackPaths.length,
      partialPaths: hypotheses.partiallySupported.length,
      blockedPaths: hypotheses.blocked.length,
      refutedPaths: hypotheses.refuted.length,
      unprovenPaths: hypotheses.unproven.length,
      completeVariantReceipts: variants.receipts.filter((item) => item.complete).length,
      synthesisDigest: digest({
        findings,
        attackPaths,
        systemicRootCauses,
        controls,
        hypotheses,
      }),
    },
    coverageGaps,
  };
}
