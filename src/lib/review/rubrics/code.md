RUBRIC: review-code
FRAMING: adversarial. Default DON'T-SHIP. Find what's wrong.
ANTI-CHARITY: SHIP requires production validation OR feature-flag+telemetry. Else SHIP-WITH-MONITORING.
CODE_TYPE: first classify the artifact — GENERAL (app / lib / script / infra / UI) or ML_DATA (trains, evaluates, or serves a model, or processes datasets / data pipelines). Apply CORE_FAIL_MODES always; apply ML_FAIL_MODES ONLY if ML_DATA. Do NOT invent ML/test-set/latency concerns for GENERAL code — that is noise.
DIMENSIONS (1-10 each): correctness, reversibility, test_adequacy, silent_failure_visibility, assumption_density, security, reuse_simplicity
QUESTIONS_7 (must answer all):
  smallest_break: smallest input change that would break this?
  unstated: what assumed but not stated?
  test_tuned: tuned to a test set instead of production? (ML_DATA only; answer "n/a" for GENERAL)
  silent_fail: failure mode loud or silent? silent without monitoring = SHIP-BLOCKER
  inversion: how would this catastrophically fail in production? (Munger inversion)
  security: injection / secret-leak / authz-gap / abuse-path introduced or left unguarded? (untrusted input -> sink)
  reuse_simplicity: reinvents an existing util/stdlib, over-engineers (abstraction or indirection the task does not need), duplicates logic, or is measurably less efficient than a simpler form?
  missing_evidence: what would you need to see that ISN'T in this packet? (added 2026-07-14 per Fable review — surface gaps the packet didn't disclose)
CORE_FAIL_MODES (always): silent_drop_swallow, unbounded_resource_growth, works_on_my_machine, resource_leak, null_deref, unhandled_rejection, race_condition, injection_sink, reinvents_stdlib, over_abstraction, broken_error_contract
ML_FAIL_MODES (ML_DATA only): static_param_safe_default, avg_hides_per_input_regression, latency_variance_unaccounted, test_set_curation_bias, policy_test_coupling, recommendation_unvalidated, gil_thread_load_failure
OUTPUT (strict JSON, ≤950 tokens, no prose outside):
{
  "verdict": "SHIP" | "SHIP-WITH-MONITORING" | "DON'T-SHIP" | "NEEDS-MEASUREMENT",
  "code_type": "GENERAL" | "ML_DATA",
  "score": 1-10,
  "top_concern": "≤100 chars",
  "scores": {"correctness":n, "reversibility":n, "test_adequacy":n, "silent_failure_visibility":n, "assumption_density":n, "security":n, "reuse_simplicity":n},
  "answers": {"smallest_break":"≤120c", "unstated":"≤120c", "test_tuned":"≤120c", "silent_fail":"≤120c", "inversion":"≤120c", "security":"≤120c", "reuse_simplicity":"≤120c", "missing_evidence":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each, max 8 total for P1+P2, P0 unbounded"}]
}
