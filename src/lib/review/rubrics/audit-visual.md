RUBRIC: audit-visual
SCOPE: STRICT RENDERED FRONTEND/UI VISUAL AUDIT of finished screenshots for apps, websites, dashboards, landing pages, ecommerce, forms, and components. Judge the actual pixels plus any supplied expectation/context. This is not code review and not mockup invention.

GROUNDING (do this FIRST): An image IS attached to this message. Look at it now. In one sentence state what is literally rendered - visible text, header, buttons, layout, viewport/state - and put that in the "seen" field. Every finding MUST be based on what you actually see. If no image was received, set "seen" to "NO_IMAGE" and verdict to "DON'T-SHIP".

FRAMING: rigorous specialist QA. Default to REVISE when a meaningful defect is visible. Report only what is visible in the supplied screenshots. If a state, motion, off-screen panel, code path, or interaction cannot be judged from pixels, say "not judgeable from this screenshot" rather than guessing.

STRICT LENSES (apply all visible/relevant):
  rendered_truth: cite visible regions, not assumptions.
  task_cognition: is the primary action/next step visually obvious; are there too many equal-weight choices?
  visual_hierarchy: first read, second read, CTA weight, scan path, information grouping.
  layout_spacing_whitespace: alignment, rhythm, density, proximity, stable dimensions, no nested-card mush.
  typography: readable sizes, type hierarchy, line length, wrapping, cramped/oversized text.
  color_contrast_semantics: visible contrast, state colors, default-blue/purple-gradient tells, color-only states.
  iconography_assets: icons meaningful and consistent; real images/assets sharp; no broken image/placeholder/raw alt text.
  responsive_fit: if multiple viewports supplied, content fits each; no horizontal scroll, clipped controls, or broken mobile/tablet layout.
  visible_states: loading/empty/error/success/active/disabled states visible in screenshots render intentionally; no "undefined", "{{var}}", "NaN", broken image, stuck spinner.
  motion_artifacts: if screenshot catches animation/reveal state, flag blank content, awkward overlay, obstructive confetti, or motion state hiding utility; do not infer timing.
  accessibility_visible: visible contrast/legibility/focus-ring clipping/target size issues.
  brand_domain_specificity: does the surface look product/brand-specific or like a generic AI/SaaS template?
  peak_end: does the key visible moment and final/empty/success/footer state look designed?

FAIL MODES: no_image, wrong_route_or_blank_capture, text_overflow_or_truncation, horizontal_scroll, element_overlap, content_escapes_container, collapsed_zero_height_region, misaligned_grid, raw_placeholder_or_token_visible, broken_image_icon, alt_text_rendered_as_text, stuck_loading_spinner, undesigned_empty_or_error_state_visible, unreadable_contrast, invisible_or_washed_out_text, color_only_error_or_state, primary_action_not_visible, too_many_equal_ctas, off_brand_legacy_color_visible, wrong_font_rendered, generic_ai_template_visuals, decorative_icon_spam, layout_breaks_at_supplied_width, overlapping_modals_or_toasts, cut_off_focus_ring, tiny_or_unreliable_touch_targets

DIMENSIONS (1-10), judged only from visible pixels:
  task_clarity,
  visual_hierarchy,
  layout_spacing,
  typography_readability,
  color_contrast_semantics,
  icon_asset_quality,
  responsive_fit,
  visible_state_quality,
  accessibility_visible,
  brand_specificity,
  craft_polish

QUESTIONS_6:
  primary_visible_defect: the single biggest visible defect, with screen region, or "nothing visibly broken"
  hierarchy_problem: the clearest hierarchy/choice-load issue, or "none visible"
  layout_type_spacing_problem: the clearest spacing/type/layout issue, or "none visible"
  state_or_asset_problem: any placeholder/broken/loading/error/image/icon issue, or "none visible"
  contrast_or_a11y_problem: worst visible contrast/focus/target-size issue, or "none visible"
  brand_or_slop_problem: visible generic/template/brand-drift issue, or "none visible"

VERDICT:
  SHIP = no visible blockers, no major hierarchy/fit/state/contrast issues in supplied shots.
  REVISE = meaningful visual/craft/usability issues visible, but core task likely still possible.
  DON'T-SHIP = blocker: no image, blank/wrong route, core content clipped/overlapped, primary action invisible, unreadable contrast, raw placeholder, broken state, unusable responsive layout, or visible accessibility blocker.

  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, <=1000 tokens):
{
  "seen": "<=160c - what is literally rendered in the image; or NO_IMAGE",
  "verdict": "SHIP" | "REVISE" | "DON'T-SHIP",
  "score": 1-10,
  "top_concern": "<=140c - biggest visible defect with location",
  "scores": {
    "task_clarity": n,
    "visual_hierarchy": n,
    "layout_spacing": n,
    "typography_readability": n,
    "color_contrast_semantics": n,
    "icon_asset_quality": n,
    "responsive_fit": n,
    "visible_state_quality": n,
    "accessibility_visible": n,
    "brand_specificity": n,
    "craft_polish": n
  },
  "answers": {
    "primary_visible_defect": "<=150c cite region",
    "hierarchy_problem": "<=150c cite region",
    "layout_type_spacing_problem": "<=150c cite region",
    "state_or_asset_problem": "<=150c cite region",
    "contrast_or_a11y_problem": "<=150c cite region",
    "brand_or_slop_problem": "<=150c cite region"
  },
  "blockers": [{"tier": "P0|P1|P2", "text": "specific visible defects with on-screen location; ≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
