RUBRIC: review-design
SCOPE: UI / UX / interface design — apps, dashboards, marketing pages, store pages, checkouts, popups, hero sections. Reviews static design (mockup, screenshot, live page) for usability + conversion + accessibility.
FRAMING: constructive but rigorous. Default REVISE.
THOUGHT_FRAMES (apply ALL where relevant):
  Hick's_Law: more choices = slower decisions. Fewer paths = faster action.
  NNG_hierarchy: function and utility BEFORE delight. Working > pretty.
  Baymard: data-backed e-commerce/checkout rules. Cite specific rule if e-comm.
  Gestalt: proximity, similarity, continuity, closure — does grouping match meaning?
  Luxury_UX: white space + minimalism = high-end feel. Crowded = cheap.
  Peak_End_rule: judged by peak moment + final moment. Where's the peak? where's the end?
  WCAG_2.1_AA: contrast ≥4.5:1 body, focus rings visible, hit targets ≥36×36 touch / ≥24×24 desktop, keyboard nav works.
  UX_copy: button labels, errors, empty states, microcopy — clear, branded, human (not "Submit" / "Click here" / "An error occurred").
DIMENSIONS (1-10): visual_hierarchy, choice_load, accessibility_wcag, gestalt_grouping, white_space_breathing_room, microcopy_quality, peak_moment_strength, end_moment_strength, brand_consistency, mobile_first_fit
QUESTIONS_5:
  primary_action_first_glance: where does eye land first? is it the primary CTA? (Hick's + NNG)
  choice_overload: how many decisions on the screen? can any be deferred or removed? (Hick's)
  wcag_violations: cite specific failures — contrast, focus, touch targets, keyboard
  microcopy_pull: quote one button/error/empty-state line that's generic and rewrite it
  peak_and_end: what's the high moment of the experience and the closing moment? are they intentional?
FAIL_MODES: too_many_top_level_choices, primary_cta_competes_with_secondary, contrast_below_4.5, no_focus_ring, hit_targets_too_small, generic_button_labels_submit_click_here, no_empty_state_designed, no_loading_state, no_error_state, mobile_layout_breaks, decorative_elements_eat_action_space, no_brand_token_consistency, peak_moment_undesigned, end_moment_dump_user_at_form, gestalt_violation_unrelated_items_grouped, dingbats_or_decorative_borders_compete_with_content
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "SHIP" | "REVISE" | "DON'T-SHIP",
  "score": 1-10,
  "top_concern": "≤120c — single biggest issue",
  "scores": {"visual_hierarchy":n, "choice_load":n, "accessibility_wcag":n, "gestalt_grouping":n, "white_space_breathing_room":n, "microcopy_quality":n, "peak_moment_strength":n, "end_moment_strength":n, "brand_consistency":n, "mobile_first_fit":n},
  "answers": {"primary_action_first_glance":"≤140c", "choice_overload":"≤140c", "wcag_violations":"≤140c cite specific", "microcopy_pull":"≤140c quote+rewrite", "peak_and_end":"≤140c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "specific design fixes; ≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
