// CONTRACT B item 4 — the completion gate.
//
// A completing agent (Alchemist, Legion) may claim a level of done-ness
// (signoff / highRisk / release). This module is the seam that prevents that
// claim from being self-certifying: it resolves which claim levels a set of
// touched paths force (via `policy.lockedDomainsFor`), unions those with the
// level actually claimed, and evaluates every resulting level's prerequisites
// through `policy.evaluateClaimPrerequisites` — Arcane's single claim-release
// authority (lib/policy.mjs).
//
// The load-bearing property: `evidenceClasses`, `staleEvidenceCount`, and
// `enforcementHealth` are derived from `receiptStore.list({runId})` — what
// Arcane itself recorded — never from fields the caller asserts. A completing
// agent cannot talk its way past a prerequisite it did not actually earn.
//
// Derivation rule (mechanical, conservative, from the two receipt kinds the
// frozen contracts define — no new field is invented on either schema):
//   - evidenceClasses:      the union of `evidenceClass` on every
//                            legion-evidence-capability-receipt record for
//                            this run (effect receipts carry no evidenceClass).
//   - staleEvidenceCount:   how many of those evidence records have `stale`.
//   - enforcementHealth:    the WEAKEST per-record health across every record
//                            for this run, mapped from the receipt's own
//                            `authentication` block (capability-signature +
//                            perMessage:true -> strong; capability-signature
//                            without perMessage -> observed; host-connection-
//                            trust -> read_only; unauthenticated -> unsupported).
//                            No records for the run at all -> 'unsupported'
//                            (fail closed rather than assume strong).
//                            Weakest-link because a completion claim must not
//                            be stronger than its least-authenticated evidence.

import { decision } from './errors.mjs';
import { digestValue } from './canonical.mjs';
import { verifyRecord } from './receipt-auth.mjs';
import { AUTHORITY_PROOF_FIELDS } from './authority-invocation-proof.mjs';

// Imported, never re-declared — policy.mjs owns the ordering (policyDuplicationAudit
// enforces this). A divergent local copy would silently let 'advisory' satisfy claim
// levels it must never satisfy.
import { ENFORCEMENT_RANK } from './policy.mjs';
import { verifyAssurance } from './high-risk-assurance.mjs';
import { findCurrentAdvisoryCertification } from './advisory-certification.mjs';

function healthOfRecord(record) {
  const auth = record?.authentication;
  if (!auth) return 'unsupported';
  if (auth.verificationMethod === 'capability-signature') {
    return auth.perMessage === true ? 'strong' : 'observed';
  }
  if (auth.verificationMethod === 'host-connection-trust') return 'read_only';
  return 'unsupported';
}

function deriveFromReceipts(records) {
  const evidenceClasses = new Set();
  let staleEvidenceCount = 0;
  let weakest = null;

  for (const record of records) {
    if (typeof record.evidenceClass === 'string') {
      evidenceClasses.add(record.evidenceClass);
      if (record.stale === true) staleEvidenceCount += 1;
    }
    const health = healthOfRecord(record);
    if (weakest === null || ENFORCEMENT_RANK[health] < ENFORCEMENT_RANK[weakest]) {
      weakest = health;
    }
  }

  return {
    evidenceClasses: [...evidenceClasses],
    staleEvidenceCount,
    enforcementHealth: weakest ?? 'unsupported',
  };
}

/**
 * @param {object} args
 * @param {string} args.runId
 * @param {string} [args.taskId]
 * @param {string} args.claimedLevel one of the policy bundle's claimLevels keys
 * @param {string[]} args.touchedPaths paths the completing unit actually touched
 * @param {object} deps
 * @param {object} deps.policy a PolicyEngine (or failClosedEngine(...))
 * @param {object} deps.receiptStore Arcane's ReceiptStore
 * @returns {object} decision. On denial, `detail.level` names which level in
 *   the union failed; on success, `detail.levelsChecked` lists every level
 *   the union required.
 */
export function evaluateCompletion({ runId, taskId = null, claimedLevel, touchedPaths = [], contractId = null, contractVersion = null, contractDigest = null, sourceRevision = null, completionClaim = null }, { policy, receiptStore, budgetStore = null, assuranceStore = null, keyRing = null, authorityBindingStore = null, currentProof = null, binding = null, execution = null, evidenceRegistry = null, acceptanceProofs = [], integratedState = null, latestMaterialChange = null, now = new Date() }) {
  // Budget state comes only from Arcane's persisted projection. Completion
  // never accepts a caller-authored elapsed time or retry fingerprint.
  if (budgetStore && contractId && Number.isInteger(contractVersion) && taskId && typeof budgetStore.inspect === 'function') {
    const budget = budgetStore.inspect({ contractId, version: contractVersion, taskId, runId });
    if (!budget?.allowed || budget?.stopped) return decision({ allowed: false, code: budget?.code ?? budget?.stopped?.code ?? 'BUDGET_STOP', message: 'completion requires a non-stopped budget projection', detail: { runId, taskId, budget } });
  }
  const lockedMatches = policy.lockedDomainsFor(touchedPaths);
  // `claimedLevel` may be null: a bare host Stop asserts no completion level of
  // its own (see hook-adapter-core.evaluateHostStop). Only the levels the
  // touched paths actually force are then evaluated, so a turn that touched no
  // locked domain has nothing to certify and is not refused. A caller that DOES
  // claim a level still has that level checked exactly as before.
  const levels = new Set([...(claimedLevel ? [claimedLevel] : []), ...lockedMatches.map((m) => m.claimLevel)]);

  const records = receiptStore.list({ runId });
  const { evidenceClasses, staleEvidenceCount, enforcementHealth } = deriveFromReceipts(records);

  if (evidenceRegistry) {
    for (const proof of acceptanceProofs) {
      const current = evidenceRegistry.verify(proof.acceptanceId, proof, { integratedState, latestMaterialChange, now });
      if (!current.allowed) return current;
    }
  }

  let advisoryCertification = null;
  if (completionClaim?.advisoryClaim?.required === true) {
    const advisoryClaim = completionClaim.advisoryClaim;
    advisoryCertification = findCurrentAdvisoryCertification({
      receiptStore,
      artifactDigest: advisoryClaim.artifactDigest,
      expected: {
        artifactDigest: advisoryClaim.artifactDigest,
        briefDigest: advisoryClaim.briefDigest,
        bundleId: advisoryClaim.bundleId,
        bundleVersion: advisoryClaim.bundleVersion,
        profileId: advisoryClaim.profileId,
        manifestDigest: advisoryClaim.manifestDigest,
        profileDigest: advisoryClaim.profileDigest,
        runId,
        taskId,
        contractId,
        contractVersion,
        contractDigest,
        sourceRevision,
      },
    }, { keyRing, authorityBindingStore, now, freshnessMs: policy.evidencePolicy().freshnessSeconds * 1000 });
    if (!advisoryCertification.allowed) return decision({
      allowed: false,
      code: advisoryCertification.code,
      message: advisoryCertification.message,
      detail: { ...advisoryCertification.detail, missingEvidence: ['independent-advisory-certification'] },
      enforcementHealth: 'strong',
    });
  }

  const levelsChecked = [];
  for (const levelName of levels) {
    const level = policy.claimLevel(levelName);
    let assurance = { allowed: true, detail: { covenantVerdict: null, fields: {} } };
    if (level?.requiresCovenant) {
      const expected = { runId, taskId, contractId, contractVersion, contractDigest, sourceRevision };
      const persisted = assuranceStore?.findForExecution(expected);
      const macDomain = currentProof ? `arcane-authority-proof:v1:${currentProof.role}:${currentProof.purpose}` : null;
      const proofValid = Boolean(currentProof && completionClaim && binding && execution
        && currentProof.role === completionClaim.producerAuthority
        && currentProof.purpose === 'completion-claim'
        && digestValue(currentProof) === completionClaim.invocationProofDigest
        && currentProof.sessionId === binding.sessionId
        && ['runId','taskId','contractId','contractVersion','contractDigest','sourceRevision'].every((field) => currentProof[field] === execution[field])
        && verifyRecord(currentProof, currentProof.authentication, { keyRing, boundFields: AUTHORITY_PROOF_FIELDS, macDomain }).allowed);
      assurance = persisted && proofValid
        ? verifyAssurance({ request: persisted.request, receipt: persisted.receipt, expected }, { keyRing, authorityBindingStore, now, freshnessMs: policy.evidencePolicy().freshnessSeconds * 1000 })
        : decision({ allowed: false, code: 'ARC_CLAIM_PREREQUISITE_UNMET', message: 'dedicated assurance or current completion proof is unavailable', detail: {} });
      if (assurance.allowed) {
        const consumption = assuranceStore.consume({ receiptDigest: persisted.receiptDigest, completionClaimDigest: completionClaim.claimId });
        if (!consumption.allowed) assurance = consumption;
      }
    }
    if (!assurance.allowed) return decision({ allowed: false, code: assurance.code, message: assurance.message, detail: { ...assurance.detail, level: levelName, runId, taskId, lockedDomainMatches: lockedMatches, missingEvidence: ['high-risk-assurance'] } });
    const result = policy.evaluateClaimPrerequisites(levelName, {
      evidenceClasses,
      staleEvidenceCount,
      enforcementHealth,
      covenantVerdict: assurance.detail.covenantVerdict,
      fields: assurance.detail.fields,
    });
    levelsChecked.push(levelName);
    if (!result.allowed) {
      return decision({
        allowed: false,
        code: result.code,
        message: result.message,
        detail: { ...result.detail, level: levelName, runId, taskId, lockedDomainMatches: lockedMatches },
        enforcementHealth: result.enforcementHealth ?? enforcementHealth,
      });
    }
  }

  return decision({
    allowed: true,
    message: 'completion claim satisfies every prerequisite the touched paths and claimed level require',
    detail: { runId, taskId, claimedLevel, levelsChecked, lockedDomainMatches: lockedMatches, evidenceClasses, staleEvidenceCount, advisoryCertification: advisoryCertification?.detail ?? null },
    enforcementHealth,
  });
}
