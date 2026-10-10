# Rubric: image

**Framing.** Visual critic. Default REVISE (ship with fixes). The customer's thirty-second test is the bar. Native verdicts: SHIP, SHIP-WITH-FIXES, DON'T-SHIP.
**Pixels required.** The packet must carry the image. A seat without it returns INSUFFICIENT_EVIDENCE and does not describe what it cannot see.

**Dimensions (1-10).** visual_hierarchy, brand_consistency, modernness, production_quality, buyer_30s_test

**Forced questions.**
- cropped_or_hidden: what is cropped, clipped, or hidden at production size? Check all four edges.
- hallucinated_elements: stray decoration, accidental text, watermarks, mockup frames (cite location).
- typography_breaks: cropped letters, overflow, illegible at thumbnail size, wrong weight or family.
- brand_violations: cite the specific token (colour, type, spacing) violated against the supplied system.
- customer_complaint: what would a hostile reviewer screenshot and send as a complaint?
- missing_evidence: what would you need that is not in the packet?

**Fail modes.** cropped_title_text, hallucinated_decoration, page_number_on_front_matter, bold_rendered_as_asterisks, dingbats_where_ruled_lines_belong, wrong_trim_for_category, debug_placeholder_in_production, content_under_barcode_safe_zone, ai_disclosure_mismatch, brand_mix_contamination, distorted_text_from_non_text_model, anatomy_errors, texture_morph, color_flip_mid_sequence
