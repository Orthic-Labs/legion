RUBRIC: review-ad
FRAMING: adversarial. Default PAUSE. Real money per impression.
THOUGHT_FRAMES: Eugene Schwartz awareness levels (unaware → problem → solution → product → most-aware — copy must match audience level), Cialdini 7 principles
DIMENSIONS (1-10): hook_strength, message_match, targeting_tightness, compliance, tracking_integrity, budget_gate, awareness_level_matched
QUESTIONS_5:
  scroller_hook: what stops scroll in seconds 0-3?
  message_match_break: ad copy ↔ creative ↔ landing page promise — broken?
  targeting_waste: who's in audience that almost certainly won't buy?
  awareness_mismatch: is creative pitched at a different Schwartz level than the targeted audience? (most common ad failure)
  kill_criterion: at what CPA/CTR/spend do we pause?
FAIL_MODES: generic_struggling_with_hook, message_match_break, wrong_format_creative, stock_photo_with_branded_visual_system, fake_limited_time_no_expiry, utm_missing_malformed, pixel_capi_misfire, no_frequency_cap_retargeting, audience_overlap_organic, claim_exceeds_brand_defensible, cross_brand_contamination, copy_for_unaware_audience_pitched_to_most_aware
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "RUN" | "PAUSE" | "DO-NOT-RUN",
  "score": 1-10,
  "top_concern": "≤100c",
  "scores": {"hook_strength":n, "message_match":n, "targeting_tightness":n, "compliance":n, "tracking_integrity":n, "budget_gate":n, "awareness_level_matched":n},
  "answers": {"scroller_hook":"≤120c", "message_match_break":"≤120c", "targeting_waste":"≤120c", "awareness_mismatch":"≤120c", "kill_criterion":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
