RUBRIC: review-brand-voice
FRAMING: constructive but rigorous. Default REVISE.
THOUGHT_FRAMES: April Dunford positioning lens (does the content reinforce the brand's positioning vs alternatives?)
DIMENSIONS (1-10): tonal_match, vocabulary_fit, claim_accuracy, cross_brand_isolation, visual_conventions, audience_match, positioning_reinforcement
QUESTIONS_5:
  off_voice_sentence: quote single most off-voice sentence
  banned_words: any words from brand's banned-vocab list?
  cross_brand_contamination: visual/voice/claim that belongs to another venture?
  fabricated_claim: anything stated brand can't back up?
  highest_leverage_edit: single edit that closes the biggest gap
BRAND_RULES:
  DD: never fabricate quotes/stats/testimonials. Quiet confidence not loud. Premium EDC not tactical.
  RH: scope geo stats correctly. Honest grounded not preachy. Verify regulatory against current date.
  HR: ban revolutionary,disruptive,AI-powered,game-changing,empower,leverage,unlock,limited_time. ONE copper accent. Real accent examples (Aiyer told Nitin) not abstract.
  TS: ALL CAPS condensed headlines, two-beat pattern. Toxic green on punchline only. Founder voice (the operator) first-person from lived experience. Ban: eco-friendly,conscious,drop,limited_drop,influencer_slang.
  SS: PASSION PROJECT — REFUSE the review if input is SS-tagged.
FAIL_MODES: fabricated_quote_testimonial_story, hand_drawn_when_ai_assisted, only_first_best_no_proof, cross_brand_asset, voice_drift_to_neutral, geo_stat_scope_error, stale_regulatory, wrong_audience_addressing
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "ON-BRAND" | "REVISE" | "OFF-BRAND",
  "score": 1-10,
  "top_concern": "≤100c",
  "scores": {"tonal_match":n, "vocabulary_fit":n, "claim_accuracy":n, "cross_brand_isolation":n, "visual_conventions":n, "audience_match":n, "positioning_reinforcement":n},
  "answers": {"off_voice_sentence":"≤140c", "banned_words":"≤80c", "cross_brand_contamination":"≤120c", "fabricated_claim":"≤120c", "highest_leverage_edit":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
