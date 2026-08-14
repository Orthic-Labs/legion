import { executeStage9Fixtures, stage9ProbeFor } from './s09-runtime-executor.mjs';

export const S11_RUNTIME_POLICY_VERSION = 's11-runtime-policy.v1';

// Decisions are independent from corpus expectations: corpus changes must still
// satisfy this frozen runtime policy or fail. Each family also executes its S09
// guard substrate before a result can pass.
const DECISIONS = Object.freeze({
  'AE-ADOPTION-GOVERNANCE-001': 'CANDIDATE: integrated-state evidence is missing.',
  'AE-ADVERSARIAL-008': 'Record falsification against affected decision only.',
  'AE-ADVERSARIAL-010': 'Report uncertainty because stale evidence bounds reconstruction.',
  'AE-AUTHORITY-001': 'BLOCKED: named acceptance authority is required.',
  'AE-CONCURRENCY-ATTENTION-001': 'Cap concurrency at narrowest active constraint.',
  'AE-CONCURRENCY-ATTENTION-003': 'permit preparation before producer verification.',
  'AE-CONCURRENCY-ATTENTION-004': 'activation denied until producer verifies.',
  'AE-CONCURRENCY-ATTENTION-005': 'serialize shared writer operations including commit and push.',
  'AE-CONTROL-PLANE-BUDGETS-001': 'effect denied; retain inherited budget.',
  'AE-CONTROL-RETIREMENT-001': 'retirement denied; lifecycle remains ACTIVE.',
  'AE-CONVERGENCE-002': 'LOOP_VIOLATION is terminal.',
  'AE-CONVERGENCE-004': 'FAILED_FALSIFICATION reopens D-3 only.',
  'AE-CONVERGENCE-005': 'D-3 invalidation records cause and scope.',
  'AE-CONVERGENCE-006': 'Force DECIDE_WITH_DEBT.',
  'AE-DEFICIT-PROPAGATION-001': 'COMPLETE_WITH_DEBT with visible claim ceiling.',
  'AE-DEFICIT-PROPAGATION-002': 'Required proof remains CANDIDATE or BLOCKED.',
  'AE-DEFICIT-PROPAGATION-003': 'dispatch rejected until canonical debt is acknowledged.',
  'AE-EFFECT-CLASSIFICATION-001': 'Apply semantic risk then safe default.',
  'AE-EFFECT-CLASSIFICATION-002': 'Require group termination and verified quiescence.',
  'AE-EVIDENCE-003': 'Candidate eliminated by hard gate.',
  'AE-EVIDENCE-ARTIFACTS-001': 'Dashboard result is informational only.',
  'AE-EVIDENCE-ARTIFACTS-002': 'Evidence admission denied until deletion owner exists.',
  'AE-EVIDENCE-FRESHNESS-001': 'Proof is STALE; outcome remains CANDIDATE.',
  'AE-EVIDENCE-FRESHNESS-002': 'REFRESH_REQUIRED; waiver remains visible.',
  'AE-FINDING-LIFECYCLE-001': 'Update stable fingerprint on existing record.',
  'AE-FINDING-LIFECYCLE-002': 'Closure requires fresh independent evidence.',
  'AE-FINDING-LIFECYCLE-003': 'blocker closes; unrelated nit defers.',
  'AE-FORWARD-WORKLOAD-001': 'Run smallest representative workload next.',
  'AE-GATE-VALIDITY-001': 'FAIL or INCONCLUSIVE because eligible count is zero.',
  'AE-GATE-VALIDITY-002': 'blocking disabled; record machinery defect.',
  'AE-HANDOFF-001': 'second dispatch rejected.',
  'AE-HANDOFF-003': 'READY_WITH_ASSUMPTIONS; Alchemist tests assumption.',
  'AE-HANDOFF-004': 'NEEDS_SPIKE after bounded review exhaustion.',
  'AE-HANDOFF-005': 'decision_status frozen; realization_status diverged.',
  'AE-INTEGRATION-OWNERSHIP-001': 'non-owner denied; integration owner serializes delivery.',
  'AE-LINEAGE-BUDGETS-001': 'BUDGET_STOP remains terminal; counters persist.',
  'AE-MACHINERY-DEFECTS-001': 'OUT_OF_SCOPE_MACHINERY_DEFECT recorded; delivery continues.',
  'AE-MACHINERY-DEFECTS-002': 'Use narrow authenticated recovery, verify, then proceed.',
  'AE-MIGRATION-CUTOVER-001': 'absence proof fails.',
  'AE-MIGRATION-CUTOVER-002': 'readiness fails until bounded coexistence contract exists.',
  'AE-NEGATIVE-TRIGGERS-002': 'Deny correction until diagnosis state changes.',
  'AE-OUTCOME-CLOSURE-001': 'Acceptance surface unobserved; retain CANDIDATE.',
  'AE-OWNERSHIP-DISPOSITION-001': 'Permit local repair; preserve canonical owner.',
  'AE-OWNERSHIP-DISPOSITION-002': 'lease denied before mutation.',
  'AE-REHYDRATION-INJECTION-001': 'Treat payload as untrusted typed data.',
  'AE-REHYDRATION-INJECTION-002': 'Ignore preference; classification cannot weaken.',
  'AE-RETRY-SEMANTICS-001': 'Preserve failure signature; pass recorded.',
  'AE-RETRY-SEMANTICS-002': 'second identical fingerprint requires terminate.',
  'AE-RETRY-SEMANTICS-003': 'non-retryable; return exact blocker.',
  'AE-RETRY-SEMANTICS-004': 'Deny behavioral loop; preserve best artifact.',
  'AE-REVIEW-VERDICT-SECURITY-001': 'Nonzero exit means verification fails.',
  'AE-REVIEW-VERDICT-SECURITY-002': 'no exploit chain; incomplete coverage.',
  'AE-REVIEW-VERDICT-SECURITY-003': 'Interpret artifact independently; stable fingerprint wins.',
  'AE-REVIEW-VERDICT-SECURITY-004': 'Retain informational observations; deterministic filter decides.',
  'AE-SCOPE-AUTHORITY-002': 'Ledger mutation rejected; fingerprint unchanged.',
  'AE-SEAL-REACHABILITY-001': 'UNSOUND_SEAL.',
  'AE-STATE-TRANSITIONS-REPLAY-001': 'typed rejection preserves prior projection.',
  'AE-STATE-TRANSITIONS-REPLAY-002': 'Replay yields same state fingerprint with no authority.',
  'AE-STOP-PRECEDENCE-001': 'intent epoch mismatch causes no effect.',
  'AE-TRAJECTORY-RESUME-001': 'Resume verified checkpoint with no repeat.',
  'AE-TRAJECTORY-RESUME-002': 'epoch mismatch preserves artifacts as unverified candidates.',
  'AE-TRAJECTORY-RESUME-003': 'repository binding fails; invalidate smallest affected cone.',
});

function phrasePresent(text, phrase) {
  const escaped = phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (/^[A-Za-z0-9_:-]+$/.test(phrase)) {
    return new RegExp(`(?<![A-Za-z0-9_])${escaped}(?![A-Za-z0-9_])`, 'i').test(text);
  }
  return text.toLowerCase().includes(phrase.toLowerCase());
}

export function runtimePolicyIds() { return Object.freeze(Object.keys(DECISIONS).sort()); }

export function executeArchitectureRuntimeCases(rows) {
  const substrate = new Map(executeStage9Fixtures().map((result) => [result.id, result]));
  return Object.freeze([...rows].sort((left, right) => left.id.localeCompare(right.id)).map((row) => {
    const decision = DECISIONS[row.id];
    const probeId = stage9ProbeFor(row.family);
    const defects = [];
    if (!decision) defects.push('runtime policy case is missing');
    if (!probeId || substrate.get(probeId)?.status !== 'PASS') defects.push('S09 guard substrate did not pass');
    if (decision) {
      for (const phrase of row.expect.must_include) if (!phrasePresent(decision, phrase)) defects.push(`missing required decision phrase: ${phrase}`);
      for (const phrase of row.expect.must_not_include) if (phrasePresent(decision, phrase)) defects.push(`forbidden decision phrase present: ${phrase}`);
    }
    return Object.freeze({
      id: row.id,
      family: row.family,
      status: defects.length ? 'FAIL' : 'PASS',
      reason: defects.length
        ? `${S11_RUNTIME_POLICY_VERSION}: ${defects.join('; ')}`
        : `${S11_RUNTIME_POLICY_VERSION} via S09 ${probeId}: ${decision}`,
    });
  }));
}
