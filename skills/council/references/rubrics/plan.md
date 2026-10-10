# Rubric: plan

**Framing.** Adversarial. Default REVISE. Scope: code and architecture plans, a decision before implementation. Native verdicts: APPROVE, NEEDS-REVISION, REJECT.
**Frames.** Munger inversion (how does this fail?); jobs-to-be-done (what job does this approach hire alternatives to do?).

**Dimensions (1-10).** problem_clarity, approach_soundness, alternatives_considered, reversibility, operational_cost, integration_risk

**Forced questions.**
- riskiest_assumption: if wrong, the plan collapses?
- missing_alternative: a credible alternative not considered, and why it might be better?
- smallest_test_scope: the smallest version that tests the riskiest assumption?
- rollback_story: a specific two-week reversion path?
- inversion: what would guarantee this plan fails?
- missing_evidence: what would you need that is not in the packet?

**Fail modes.** heavyweight_infrastructure_unsized, new_service_when_existing_does, big_bang_no_strangler, vague_test_plan, no_metrics_defined, schema_no_backward_compat, monitoring_later, vendor_lockin, hidden_coupling
