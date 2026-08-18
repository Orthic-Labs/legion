RUBRIC: review-plan
SCOPE: code/architecture plans only (not content/business plans). Decision before implementation.
FRAMING: adversarial. Default NEEDS-REVISION.
THOUGHT_FRAMES: Munger inversion (how does this fail?), Christensen JTBD (what job does this approach hire alternatives to do?)
DIMENSIONS (1-10): problem_clarity, approach_soundness, alternatives_considered, reversibility, operational_cost, integration_risk
QUESTIONS_5:
  riskiest_assumption: if wrong, plan collapses?
  missing_alternative: credible alternative NOT considered + why might be better?
  smallest_test_scope: MVP that tests riskiest assumption?
  rollback_story: 2-week reversion path, specific?
  inversion: invert — what would guarantee this plan fails? (Munger)
  missing_evidence: what would you need to see that ISN'T in this packet? (added 2026-07-14 per Fable review — surface gaps the packet didn't disclose)
FAIL_MODES: just_use_kafka_unsized, new_service_when_existing_does, big_bang_no_strangler, vague_test_plan, no_metrics_defined, schema_no_backward_compat, monitoring_later, vendor_lockin, hidden_coupling
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "APPROVE" | "NEEDS-REVISION" | "REJECT",
  "score": 1-10,
  "top_concern": "≤100c",
  "scores": {"problem_clarity":n, "approach_soundness":n, "alternatives_considered":n, "reversibility":n, "operational_cost":n, "integration_risk":n},
  "answers": {"riskiest_assumption":"≤120c", "missing_alternative":"≤120c", "smallest_test_scope":"≤120c", "rollback_story":"≤120c", "inversion":"≤120c", "missing_evidence":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each, max 8 total for P1+P2, P0 unbounded"}]
}
