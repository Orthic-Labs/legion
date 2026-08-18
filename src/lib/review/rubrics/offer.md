RUBRIC: review-offer
FRAMING: constructive but rigorous. Default NEEDS-REVISION.
THOUGHT_FRAMES: Hormozi 6-step Grand Slam, Cialdini 7 principles (reciprocity, scarcity, authority, commitment, liking, social_proof, unity), April Dunford positioning (alternatives + unique value + segment + category)
DIMENSIONS (1-10): starving_crowd, dream_outcome, obstacle_reversal, value_stack, guarantee, pricing_platform_fit, cialdini_levers_present, positioning_clarity
QUESTIONS_5:
  audience_specificity: starving crowd test — pain × power × reach, or generic?
  dream_outcome_sentence: one-sentence transformation/identity-shift the buyer becomes
  weakest_bonus: bonus with high cost-to-deliver AND low perceived value — cut it
  guarantee_strength: removes last objection or hedges?
  cialdini_lever: which of 7 levers is most underused that would lift conversion?
FAIL_MODES: generic_everyone_audience, vague_transformation, bonus_stack_zero_perceived_value, undefensible_dollar_values, money_back_no_conditions, pricing_from_adjacent_category, no_scarcity_rationale, doesnt_say_what_excluded
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "READY" | "NEEDS-REVISION" | "REJECT",
  "score": 1-10,
  "top_concern": "≤100c",
  "scores": {"starving_crowd":n, "dream_outcome":n, "obstacle_reversal":n, "value_stack":n, "guarantee":n, "pricing_platform_fit":n, "cialdini_levers_present":n, "positioning_clarity":n},
  "answers": {"audience_specificity":"≤120c", "dream_outcome_sentence":"≤140c", "weakest_bonus":"≤120c", "guarantee_strength":"≤120c", "cialdini_lever":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
