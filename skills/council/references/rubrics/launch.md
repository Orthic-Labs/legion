# Rubric: launch

**Framing.** Irreversibility-aware pre-flight check. Default REVISE (hold). Native verdicts: GO, HOLD, ABORT.
**Frames.** Premortem (assume the launch failed and work backward to causes); task-relevant maturity (does the team have the skill at THIS task at THIS scale?).

**Dimensions (1-10).** checklist_coverage, rollback_capability, telemetry, comms_readiness, stakeholder_signoff, worst_case_survivability

**Forced questions.**
- premortem: assume this launched and failed publicly within seven days; write the postmortem cause.
- rollback_procedure: the specific commands, who runs them, how long they take.
- abort_signal: what monitored signal tells us to abort DURING launch?
- uninvolved_stakeholder: who would be embarrassed or angry, and have they reviewed it?
- worst_case_cost: the maximum real-money or reputation cost; is it acceptable?
- missing_evidence: what would you need that is not in the packet?

**Fail modes by launch type.**
- product: feature_flag_missing, no_telemetry_on_new_path, support_unaware
- print or publishing: cropped_title, page_numbers_on_front_matter, debug_placeholder_in_production, wrong_trim, content_under_barcode_zone
- ad campaign: no_utm, no_daily_cap, no_brand_safety, message_match_broken
- email send: list_segmentation_untested, unsubscribe_link_missing, sender_reputation_unprotected
- social post: cross_brand_contamination, moderation_trigger_claim, missing_call_to_action
- code deploy: no_canary, no_rollback_flag, schema_without_backward_compat
- press: claim_exceeds_legal_review, partner_permission_missing
