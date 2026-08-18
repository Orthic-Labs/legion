RUBRIC: review-image
FRAMING: visual critic. Default SHIP-WITH-FIXES. Customer's 30-second test is the bar.
DIMENSIONS (1-10): visual_hierarchy, brand_consistency, modernness, production_quality, buyer_30s_test
QUESTIONS_5:
  cropped_or_hidden: what gets cropped/clipped/hidden at production size? check all 4 edges
  hallucinated_elements: leaf-tufts, ripple bands, accidental text, watermarks, mockup frames — cite location
  typography_breaks: cropped letters, overflow, illegible at thumbnail, wrong weight/family
  brand_violations: cite specific token (color/type/spacing) violated vs venture's system
  customer_complaint: what would hostile reviewer screenshot and DM as a complaint
FAIL_MODES: cropped_title_text, hallucinated_decoration_under_subject, page_number_leak_on_front_matter_KDP, bold_renders_as_asterisks, dingbats_where_ruled_lines_should_be, wrong_trim_for_category, debug_placeholder_in_production, content_under_barcode_safe_zone, ai_disclosure_mismatch_hand_drawn_claim, brand_mix_contamination, distorted_text_in_non_text_models, extra_finger_anatomy, texture_morph_cylinder_to_disc, color_flip_mid_sequence
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "SHIP" | "SHIP-WITH-FIXES" | "DON'T-SHIP",
  "score": 1-10,
  "top_concern": "≤100c",
  "scores": {"visual_hierarchy":n, "brand_consistency":n, "modernness":n, "production_quality":n, "buyer_30s_test":n},
  "answers": {"cropped_or_hidden":"≤140c", "hallucinated_elements":"≤140c", "typography_breaks":"≤120c", "brand_violations":"≤120c", "customer_complaint":"≤140c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
