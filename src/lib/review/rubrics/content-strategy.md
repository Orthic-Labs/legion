RUBRIC: review-content-strategy
FRAMING: constructive but rigorous. Default NEEDS-REVISION.
THOUGHT_FRAMES: April Dunford (positioning before content — competitive alternatives + unique attributes + value + segment + category), Bob Moesta JTBD (trigger event, struggling moment, hiring criteria), Andrew Chen (acquisition/content/referral/retention LOOPS not funnels), Eugene Schwartz awareness (unaware → problem-aware → solution-aware → product-aware → most-aware)
DIMENSIONS (1-10): audience_specificity, opportunity_gap, distribution_realism, voice_brand_fit, cadence_vs_capacity, growth_loop_present, awareness_level_matched
QUESTIONS_5:
  single_persona: ONE specific person this is for (not "founders/consumers")
  growth_loop: what self-compounding loop — acquisition/content/referral/retention — does this trigger? (Andrew Chen)
  awareness_level: what Schwartz awareness level is the audience, and does the content match it?
  jtbd_trigger: what trigger event makes this content the right hire? (Moesta)
  fastest_falsification: cheapest test that would falsify the topic-channel-audience fit?
FAIL_MODES: solo_founder_seven_channels, topic_for_seo_volume_no_authority_match, cross_brand_contamination, calendar_is_titles_no_angles, awareness_funnel_no_distribution_math, influencer_assumed_no_outreach, voice_drift, no_cite_or_cut_rule, no_growth_loop_just_publish_and_pray, content_for_unaware_audience_in_product_aware_voice
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "APPROVE" | "NEEDS-REVISION" | "REJECT",
  "score": 1-10,
  "top_concern": "≤100c",
  "scores": {"audience_specificity":n, "opportunity_gap":n, "distribution_realism":n, "voice_brand_fit":n, "cadence_vs_capacity":n, "growth_loop_present":n, "awareness_level_matched":n},
  "answers": {"single_persona":"≤120c", "growth_loop":"≤120c", "awareness_level":"≤120c", "jtbd_trigger":"≤120c", "fastest_falsification":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
