# Rubric: design

**Framing.** Constructive but rigorous. Default REVISE. Scope: UI and UX design (apps, dashboards, marketing pages, store pages, checkouts, popups, hero sections) as mockup, screenshot, or live page, judged for usability, conversion, and accessibility. Native verdicts: SHIP, REVISE, DON'T-SHIP.
**Pixels required.** A visual verdict needs the actual pixels in the packet. A seat without them returns INSUFFICIENT_EVIDENCE and does not describe what it cannot see. A text-only description earns at most a "text rubric only, not visual QA" label.

**Frames (apply where relevant).** Hick's law (more choices, slower decisions); function and utility before delight; checkout and e-commerce usability rules (cite the rule); Gestalt grouping; whitespace as quality signal; peak-end rule; WCAG 2.1 AA (body contrast at least 4.5:1, visible focus rings, adequate touch and pointer targets, keyboard navigation); UX copy (specific, human, on-brand).

**Dimensions (1-10).** visual_hierarchy, choice_load, accessibility_wcag, gestalt_grouping, white_space, microcopy_quality, peak_moment_strength, end_moment_strength, brand_consistency, mobile_first_fit

**Forced questions.**
- primary_action_first_glance: where does the eye land first, and is it the primary action?
- choice_overload: how many decisions are on screen, and can any be deferred or removed?
- wcag_violations: cite specific failures (contrast, focus, targets, keyboard).
- microcopy_pull: quote one generic button, error, or empty-state line and rewrite it.
- peak_and_end: what are the high moment and the closing moment, and are they intentional?
- missing_evidence: what would you need that is not in the packet?

**Fail modes.** too_many_top_level_choices, primary_action_competes_with_secondary, contrast_below_threshold, no_focus_ring, targets_too_small, generic_button_labels, no_designed_empty_state, no_loading_state, no_error_state, mobile_layout_breaks, decoration_eats_action_space, inconsistent_brand_tokens, undesigned_peak_moment, user_dumped_at_form_at_end, unrelated_items_grouped, decorative_borders_compete_with_content
