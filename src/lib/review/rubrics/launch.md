RUBRIC: review-launch
FRAMING: irreversibility-aware. Default HOLD. Pre-flight check.
THOUGHT_FRAMES: Kahneman premortem (assume launch failed — work backward to causes), Andy Grove task-relevant maturity (does the team have the skill at THIS task at THIS scale?)
DIMENSIONS (1-10): checklist_coverage, rollback_capability, telemetry, comms_readiness, stakeholder_signoff, worst_case_survivability
QUESTIONS_5:
  premortem: assume this launched and failed publicly within 7 days — write the postmortem cause
  rollback_procedure: specific commands, who runs them, how long
  abort_signal: what monitored signal would tell us to abort DURING launch
  uninvolved_stakeholder: who would be embarrassed/angry — have they reviewed?
  worst_case_cost: max real-money/reputation cost — acceptable?
LAUNCH_TYPE_FAIL_MODES:
  product: feature_flag_missing, no_telemetry_new_path, support_unaware
  kdp_print: cropped_title, page_numbers_on_front_matter, debug_placeholder_in_prod, wrong_trim_for_category, content_under_barcode_zone
  ad_campaign: no_utm, no_daily_cap, no_brand_safety, message_match_broken
  email_send: list_segmentation_untested, unsub_link_missing, sender_rep_unsealed
  social_post: cross_brand_contamination, moderation_trigger_claim, missing_cta
  code_deploy: no_canary, no_rollback_flag, schema_no_backward_compat
  press: claim_exceeds_legal_review, partner_permission_missing
  missing_evidence: ≤200c — what would you need to see that ISN't in this packet? (added 2026-07-14 per Fable review)
OUTPUT (strict JSON, ≤900 tokens):
{
  "verdict": "GO" | "HOLD" | "ABORT",
  "score": 1-10,
  "top_concern": "≤100c",
  "scores": {"checklist_coverage":n, "rollback_capability":n, "telemetry":n, "comms_readiness":n, "stakeholder_signoff":n, "worst_case_survivability":n},
  "answers": {"premortem":"≤140c", "rollback_procedure":"≤140c", "abort_signal":"≤120c", "uninvolved_stakeholder":"≤120c", "worst_case_cost":"≤120c"},
  "blockers": [{"tier": "P0|P1|P2", "text": "≤200c each; P1+P2 share max 8; P0 unbounded"}]
}
