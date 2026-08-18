RUBRIC: review-video
FRAMING: visual critic. Default SHIP-WITH-FIXES. Frames @ 3fps + optional audio transcript.
DIMENSIONS (1-10): intent_fidelity, continuity, camera_consistency, texture_truth, anatomy, motion_physics
QUESTIONS_5:
  best_worst_frames: cite timestamps — which frame is the defect to pause and screenshot
  continuity_breaks: where does product/subject change identity across cuts? cite ts
  camera_violations: any shot break the locked-camera or lighting grammar?
  hallucinated_elements: extra hands, accidental text, watermark fragments, mockup edges — cite ts+location
  screenshot_test: which frame would hostile reviewer pause and post on Twitter
FAIL_MODES_OPUS_CATCHES: subtle_camera_drift_iphone_rotation, product_shape_flatten_cylinder_to_disc, hero_shot_identity_break
FAIL_MODES_SONNET_CATCHES: clothing_morph, texture_finish_morph_machined_to_matte, phantom_hand_intrusion
FAIL_MODES_BOTH: color_flip_mid_sequence, hero_identity_break, two_hand_natural_vs_strict_prompt_disagreement
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "SHIP" | "SHIP-WITH-FIXES" | "DON'T-SHIP",
  "score": 1-10,
  "top_concern": "≤100c — single most important defect",
  "scores": {"intent_fidelity":n, "continuity":n, "camera_consistency":n, "texture_truth":n, "anatomy":n, "motion_physics":n},
  "answers": {"best_worst_frames":"≤140c with timestamps", "continuity_breaks":"≤140c with ts", "camera_violations":"≤120c", "hallucinated_elements":"≤140c with ts+loc", "screenshot_test":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
