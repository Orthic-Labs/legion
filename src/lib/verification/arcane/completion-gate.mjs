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

import { decision } from '../../contracts/arcane/errors.mjs';

// Imported, never re-declared — policy.mjs owns the ordering (policyDuplicationAudit
// enforces this). A divergent local copy would silently let 'advisory' satisfy claim
// levels it must never satisfy.
import { ENFORCEMENT_RANK } from '../../guard/compat/policy/policy.mjs';
import { findCurrentAdvisoryCertification } from './advisory-certification.mjs';
import { consumeCurrentUserRiskAcceptance, verifyCurrentUserRiskAcceptance } from './current-user-risk-acceptance.mjs';
import { loadCompletionEvidence } from './completion-evidence.mjs';

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

function verifyRequiredAcceptanceEvidence({ evidenceRegistry, acceptanceProofs, integratedState, latestMaterialChange, now }) {
  if (!evidenceRegistry || typeof evidenceRegistry.entries !== 'function' || typeof evidenceRegistry.verify !== 'function') {
    return decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'completion requires Arcane-owned acceptance evidence registry', detail: { missingEvidence: ['acceptance-evidence-registry'] } });
  }
  if (integratedState === null || integratedState === undefined) {
    return decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'completion requires exact integrated-state identity', detail: { missingEvidence: ['integrated-state-identity'] } });
  }
  if (!latestMaterialChange || !Number.isFinite(Date.parse(latestMaterialChange))) {
    return decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'completion requires latest material-change identity for freshness validation', detail: { missingEvidence: ['latest-material-change'] } });
  }
  const entries = evidenceRegistry.entries();
  if (!entries.length) {
    return decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'completion requires registered acceptance evidence', detail: { missingEvidence: ['acceptance-proof'] } });
  }
  if (!Array.isArray(acceptanceProofs) || acceptanceProofs.length === 0) {
    return decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'completion requires fresh acceptance proofs', detail: { missingEvidence: entries.map((entry) => entry.acceptanceId) } });
  }
  const proofs = new Map();
  for (const proof of acceptanceProofs) {
    if (!proof?.acceptanceId || proofs.has(proof.acceptanceId)) {
      return decision({ allowed: false, code: 'ARC_BINDING_MISMATCH', message: 'completion acceptance proofs must contain one proof per acceptance id', detail: { acceptanceId: proof?.acceptanceId ?? null } });
    }
    proofs.set(proof.acceptanceId, proof);
  }
  const requiredIds = new Set(entries.map((entry) => entry.acceptanceId));
  const missing = [...requiredIds].filter((id) => !proofs.has(id));
  const unexpected = [...proofs.keys()].filter((id) => !requiredIds.has(id));
  if (missing.length || unexpected.length) {
    return decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'completion proofs must exactly cover registered acceptance evidence', detail: { missing, unexpected } });
  }
  for (const [acceptanceId, proof] of proofs) {
    const current = evidenceRegistry.verify(acceptanceId, proof, { integratedState, latestMaterialChange, now });
    if (!current.allowed) return current;
  }
  return decision({ allowed: true, message: 'registered acceptance evidence is fresh for exact integrated state', detail: { acceptanceIds: [...requiredIds] } });
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
export function evaluateCompletion({ runId, taskId = null, claimedLevel, touchedPaths = [], contractId = null, contractVersion = null, contractDigest = null, sourceRevision = null, completionClaim = null }, { policy, receiptStore, ledgerStore = null, budgetStore = null, keyRing = null, authorityBindingStore = null, currentProof = null, binding = null, execution = null, authorityProofIssuer = null, integratedState = null, latestMaterialChange = null, requireAcceptanceEvidence = false, now = new Date() }) {
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

  // Receipt totals prove only that checks ran. Every completion level is
  // additionally bound to the registered acceptance surface & current exact
  // integrated state; callers cannot omit this packet to downgrade review.
  // A genuine completion is still a completion when it claims no policy
  // level (and therefore has no `levels` entries).  Its acceptance surface
  // must be current all the same; only a non-completion Stop avoids this
  // path by never requesting acceptance enforcement.
  if (requireAcceptanceEvidence) {
    // Never accept a caller-built registry/proof list. Reconstruct it from
    // authenticated Oracle receipts using this exact execution binding.
    const trustedExecution = execution && execution.runId === runId && execution.taskId === taskId
      && execution.contractId === contractId && execution.contractVersion === contractVersion
      && execution.contractDigest === contractDigest && execution.sourceRevision === sourceRevision
      ? execution : null;
    const trusted = trustedExecution && keyRing
      ? loadCompletionEvidence({ receiptStore, keyRing, authorityProofIssuer, execution: trustedExecution, integratedState, latestMaterialChange, now })
      : null;
    const acceptance = trusted
      ? verifyRequiredAcceptanceEvidence({ ...trusted, now })
      : decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'completion requires authenticated execution-bound Oracle evidence', detail: { missingEvidence: ['trusted-completion-evidence'] } });
    if (!acceptance.allowed) return acceptance;
  }

  // A material risk is explicit: ordinary completion claims retain existing
  // acceptance-evidence behavior. Verify here; consume only after all gates.
  const materialRiskExpected = completionClaim && Object.hasOwn(completionClaim, 'riskDigest') ? {
    riskId: completionClaim.riskId,
    riskDigest: completionClaim.riskDigest,
    acceptanceLedgerFingerprint: completionClaim.acceptanceLedgerFingerprint,
    integratedStateIdentity: completionClaim.integratedStateIdentity,
    sourceSetDigest: completionClaim.sourceSetDigest,
    userPromptEventDigest: completionClaim.userPromptEventDigest,
    challengeToken: completionClaim.challengeToken,
  } : null;
  if (materialRiskExpected) {
    const acceptance = verifyCurrentUserRiskAcceptance(materialRiskExpected, { ledgerStore, receiptStore, keyRing, now });
    if (!acceptance.allowed) return acceptance;
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
    const result = policy.evaluateClaimPrerequisites(levelName, {
      evidenceClasses,
      staleEvidenceCount,
      enforcementHealth,
      fields: completionClaim?.highRiskContext ?? {},
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

  if (materialRiskExpected) {
    const consumed = consumeCurrentUserRiskAcceptance(materialRiskExpected, { ledgerStore, receiptStore, keyRing, now });
    if (!consumed.allowed) return consumed;
  }

  return decision({
    allowed: true,
    message: 'completion claim satisfies every prerequisite the touched paths and claimed level require',
    detail: { runId, taskId, claimedLevel, levelsChecked, lockedDomainMatches: lockedMatches, evidenceClasses, staleEvidenceCount, advisoryCertification: advisoryCertification?.detail ?? null },
    enforcementHealth,
  });
}
