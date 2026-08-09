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

// Imported, never re-declared — policy.mjs owns the ordering (policyDuplicationAudit
// enforces this). A divergent local copy would silently let 'advisory' satisfy claim
// levels it must never satisfy.
import { ENFORCEMENT_RANK } from './policy.mjs';

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
export function evaluateCompletion({ runId, taskId = null, claimedLevel, touchedPaths = [] }, { policy, receiptStore }) {
  const lockedMatches = policy.lockedDomainsFor(touchedPaths);
  // `claimedLevel` may be null: a bare host Stop asserts no completion level of
  // its own (see hook-adapter-core.evaluateHostStop). Only the levels the
  // touched paths actually force are then evaluated, so a turn that touched no
  // locked domain has nothing to certify and is not refused. A caller that DOES
  // claim a level still has that level checked exactly as before.
  const levels = new Set([...(claimedLevel ? [claimedLevel] : []), ...lockedMatches.map((m) => m.claimLevel)]);

  const records = receiptStore.list({ runId });
  const { evidenceClasses, staleEvidenceCount, enforcementHealth } = deriveFromReceipts(records);

  const levelsChecked = [];
  for (const levelName of levels) {
    const result = policy.evaluateClaimPrerequisites(levelName, {
      evidenceClasses,
      staleEvidenceCount,
      enforcementHealth,
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
    detail: { runId, taskId, claimedLevel, levelsChecked, lockedDomainMatches: lockedMatches, evidenceClasses, staleEvidenceCount },
    enforcementHealth,
  });
}
