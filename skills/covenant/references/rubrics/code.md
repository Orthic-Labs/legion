# Rubric: code

**Framing.** Adversarial. Default REVISE; find what is wrong. Native verdicts: SHIP, SHIP-WITH-MONITORING, DON'T-SHIP, NEEDS-MEASUREMENT.
**Anti-charity.** SHIP needs production validation or a feature flag with telemetry; otherwise SHIP-WITH-MONITORING.
**Code type.** Classify first: GENERAL (app, library, script, infrastructure, UI) or ML_DATA (trains, evaluates, or serves a model, or processes datasets). Apply core fail modes always and ML fail modes only to ML_DATA. Do not invent ML, test-set, or latency concerns for general code.
**Packet must embed** the real diff or file contents, not a prose description.

**Dimensions (1-10).** correctness, reversibility, test_adequacy, silent_failure_visibility, assumption_density, security, reuse_simplicity

**Forced questions.**
- smallest_break: the smallest input change that would break this?
- unstated: what is assumed but not stated?
- test_tuned: tuned to a test set rather than production? (ML_DATA only; "n/a" otherwise)
- silent_fail: is the failure mode loud or silent? Silent without monitoring is a P0.
- inversion: how would this fail catastrophically in production?
- security: injection, leaked credentials, authorisation gap, or abuse path introduced or left unguarded (untrusted input to sink)?
- reuse_simplicity: does it reinvent a utility or stdlib, over-engineer, duplicate logic, or run measurably worse than a simpler form?
- missing_evidence: what would you need that is not in the packet?

**Core fail modes.** silent_drop_swallow, unbounded_resource_growth, works_on_my_machine, resource_leak, null_deref, unhandled_rejection, race_condition, injection_sink, reinvents_stdlib, over_abstraction, broken_error_contract
**ML_DATA fail modes.** static_param_safe_default, average_hides_per_input_regression, latency_variance_unaccounted, test_set_curation_bias, policy_test_coupling, recommendation_unvalidated, gil_thread_load_failure
