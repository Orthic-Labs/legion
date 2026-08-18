RUBRIC: review-business-plan
FRAMING: adversarial. Default NEEDS-REVISION.
THOUGHT_FRAMES: Goldratt Theory of Constraints (find the actual bottleneck), Andy Grove (output metrics not activity), Christensen disruption
DIMENSIONS (1-10): market_sizing, unit_economics, gtm_specificity, defensibility, runway_fit, risk_surfacing, constraint_identified
QUESTIONS_5:
  number_to_prove: single assumption that deserves a real test before funding
  confirmation_bias: which projection benefits most from optimism?
  unvalidated_channel: channel assumed but not validated (e.g. "we'll do paid ads" without CAC math)
  scale_competitor: who notices and reacts when this succeeds at year 3, not year 1
  bottleneck: per Goldratt — what's the single constraint that caps growth? (sales? supply? cash? team?)
FAIL_MODES: x_billion_market_no_capture_path, ltv_includes_unmodeled_upsells, viral_coef_uninstrumented, pricing_from_adjacent_category, runway_ignores_payroll_growth, wom_as_primary_growth, defensibility_we_have_data, geo_stat_scope_error, stale_regulatory, output_confused_with_activity
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "FUND" | "NEEDS-REVISION" | "REJECT",
  "score": 1-10,
  "top_concern": "≤100c",
  "scores": {"market_sizing":n, "unit_economics":n, "gtm_specificity":n, "defensibility":n, "runway_fit":n, "risk_surfacing":n, "constraint_identified":n},
  "answers": {"number_to_prove":"≤120c", "confirmation_bias":"≤120c", "unvalidated_channel":"≤120c", "scale_competitor":"≤120c", "bottleneck":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
