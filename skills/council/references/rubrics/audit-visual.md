# Rubric: audit-visual

**Scope.** A strict audit of finished rendered screenshots of a UI (apps, websites, dashboards, landing pages, e-commerce, forms, components). Judge the actual pixels plus any supplied expectation. This is not code review and not mockup invention.

**Grounding (do first).** Look at the attached image. In one sentence, state what is literally rendered (visible text, header, buttons, layout, viewport, state) and return it as `seen`. Every finding must rest on what you see. If no image was received, return `seen: NO_IMAGE`, position UNRESOLVED, and stop.

**Framing.** Rigorous specialist QA. Default REVISE when a meaningful defect is visible. Report only what is visible. If a state, motion, off-screen panel, code path, or interaction cannot be judged from pixels, write "not judgeable from this screenshot". Native verdicts: SHIP (no visible blockers), REVISE (meaningful visual or usability issues, core task still possible), DON'T-SHIP (no image, blank or wrong route, core content clipped or overlapped, primary action invisible, unreadable contrast, raw placeholder, broken state, unusable responsive layout, or visible accessibility blocker).

**Lenses (apply all that are visible).** rendered truth; task cognition (is the next step obvious, too many equal-weight choices?); visual hierarchy; layout, spacing, whitespace; typography; colour, contrast, and state semantics; icons and assets; responsive fit across supplied viewports; visible states (loading, empty, error, success, disabled); motion artefacts only as caught in the frame; visible accessibility; brand and domain specificity versus a generic template; peak and end moments.

**Dimensions (1-10, judged from visible pixels only).** task_clarity, visual_hierarchy, layout_spacing, typography_readability, color_contrast_semantics, icon_asset_quality, responsive_fit, visible_state_quality, accessibility_visible, brand_specificity, craft_polish

**Forced questions (cite the screen region, or "none visible").**
- primary_visible_defect: the single biggest visible defect.
- hierarchy_problem: the clearest hierarchy or choice-load issue.
- layout_type_spacing_problem: the clearest spacing, type, or layout issue.
- state_or_asset_problem: any placeholder, broken, loading, error, image, or icon issue.
- contrast_or_a11y_problem: the worst visible contrast, focus, or target-size issue.
- brand_or_slop_problem: visible generic-template or brand-drift issue.
- missing_evidence: what would you need that is not in the packet?

**Fail modes.** no_image, wrong_route_or_blank_capture, text_overflow_or_truncation, horizontal_scroll, element_overlap, content_escapes_container, collapsed_zero_height_region, misaligned_grid, raw_placeholder_or_token_visible, broken_image_icon, alt_text_rendered_as_text, stuck_loading_spinner, undesigned_empty_or_error_state, unreadable_contrast, washed_out_text, color_only_state, primary_action_not_visible, too_many_equal_actions, off_brand_color_visible, wrong_font_rendered, generic_template_visuals, decorative_icon_spam, layout_breaks_at_supplied_width, overlapping_modals_or_toasts, cut_off_focus_ring, tiny_touch_targets
