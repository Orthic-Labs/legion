# Rubric: video

**Framing.** Visual critic. Default REVISE (ship with fixes). Native verdicts: SHIP, SHIP-WITH-FIXES, DON'T-SHIP.
**Evidence required.** Frames sampled at a stated rate (about three per second), plus an audio transcript if audio matters. A seat without frames returns INSUFFICIENT_EVIDENCE. Cite timestamps for every defect.

**Dimensions (1-10).** intent_fidelity, continuity, camera_consistency, texture_truth, anatomy, motion_physics

**Forced questions.**
- best_worst_frames: which frames are the defect to pause and screenshot (timestamps)?
- continuity_breaks: where does the product or subject change identity across cuts (timestamps)?
- camera_violations: any shot that breaks the locked camera or lighting grammar?
- hallucinated_elements: extra hands, accidental text, watermark fragments, mockup edges (timestamp and location).
- screenshot_test: which frame would a hostile reviewer pause and post?
- missing_evidence: what would you need that is not in the packet?

**Fail modes.** subtle_camera_drift, product_shape_flatten, hero_identity_break, clothing_morph, texture_finish_morph, phantom_hand_intrusion, color_flip_mid_sequence, prompt_and_result_disagree_on_hands
