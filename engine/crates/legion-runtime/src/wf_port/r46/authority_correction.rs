//! Port of `authority_correction_errors()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~2142-2434).

use super::labels::authority_label_value;
use super::route_scan::label_value;
use super::tables::table_rows;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

const REQUIRED_ORDER: &str = "LATEST_USER_INTENT > DECISION_OBJECTIVE > STAGE_CONTRACT > INHERITED_DOCUMENT > EXISTING_IMPLEMENTATION_OR_PROGRESS";

fn semantic_correction_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^SEMANTIC_CORRECTION:\s*ID:[^;]+;\s*SOURCE:(?:USER_REQUEST|AUTHORITATIVE_SPEC:[^;]+)$")
            .unwrap()
    })
}

fn none_correction_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^NONE:\s*\S").unwrap())
}

fn correction_audit_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)^INVENTORY_SOURCE:([^;]+);\s*SEMANTIC_DELTA:(YES|NO);\s*EVIDENCE:(.+)$").unwrap()
    })
}

fn path_re() -> &'static Regex {
    super::labels::path_re()
}

/// Port of `authority_correction_errors()`.
pub fn authority_correction_errors(text: &str, allow_template: bool) -> Vec<String> {
    if allow_template {
        return Vec::new();
    }
    let mut errors = Vec::new();

    let authority_order = label_value(text, "**Authority order:**").unwrap_or_default();
    if authority_order.trim().to_uppercase() != REQUIRED_ORDER {
        errors.push(format!(
            "**Authority order:** must be {REQUIRED_ORDER}"
        ));
    }

    let correction = label_value(text, "**Correction state:**").unwrap_or_default();
    let semantic_correction = semantic_correction_re().is_match(&correction);
    if !semantic_correction && !none_correction_re().is_match(&correction) {
        errors.push(
            "**Correction state:** requires NONE:<reason> or SEMANTIC_CORRECTION: ID:<id>; SOURCE:USER_REQUEST|AUTHORITATIVE_SPEC:<path>"
                .to_string(),
        );
    }

    let correction_audit = label_value(text, "**Correction audit:**").unwrap_or_default();
    let audit_match = correction_audit_re().captures(&correction_audit);
    let audit_evidence = audit_match
        .as_ref()
        .map(|c| c.get(3).unwrap().as_str())
        .unwrap_or("");
    if audit_match.is_none() || !path_re().is_match(audit_evidence) {
        errors.push(
            "**Correction audit:** requires INVENTORY_SOURCE, SEMANTIC_DELTA:YES|NO, & evidence path"
                .to_string(),
        );
    } else if let Some(caps) = &audit_match {
        let delta_yes = caps.get(2).unwrap().as_str().eq_ignore_ascii_case("YES");
        if delta_yes != semantic_correction {
            errors.push("Correction audit semantic delta must match Correction state".to_string());
        }
    }

    let invalidation = label_value(text, "**Plan invalidation:**").unwrap_or_default();
    if semantic_correction {
        let required_tokens = [
            "PLAN_INVALIDATED:ALL",
            "DOWNSTREAM_INVALIDATED_FROM:ROOT",
            "ACTIVE_WORK:STOP_AND_QUARANTINE",
            "LOCAL_PATCH:FORBIDDEN",
        ];
        let upper = invalidation.to_uppercase();
        if !required_tokens.iter().all(|t| upper.contains(t)) {
            errors.push(
                "semantic correction requires PLAN_INVALIDATED:ALL, DOWNSTREAM_INVALIDATED_FROM:ROOT, ACTIVE_WORK:STOP_AND_QUARANTINE, & LOCAL_PATCH:FORBIDDEN"
                    .to_string(),
            );
        }
    } else {
        static NOT_APPLICABLE_RE: OnceLock<Regex> = OnceLock::new();
        let re = NOT_APPLICABLE_RE
            .get_or_init(|| Regex::new(r"(?i)^NOT_APPLICABLE:\s*NO_SEMANTIC_CORRECTION\b").unwrap());
        if !re.is_match(&invalidation) {
            errors.push(
                "uncorrected dispatch requires Plan invalidation NOT_APPLICABLE:NO_SEMANTIC_CORRECTION"
                    .to_string(),
            );
        }
    }

    let rederivation = label_value(text, "**Re-derivation status:**").unwrap_or_default().to_uppercase();
    for token in [
        "FROM_ZERO:COMPLETE",
        "OBJECTIVE_RESTATED:COMPLETE",
        "REQUIREMENTS_RECLASSIFIED:COMPLETE",
        "STAGES_REBUILT:COMPLETE",
        "COMMANDS_REBOUND:COMPLETE",
    ] {
        if !rederivation.contains(token) {
            errors.push(format!("Re-derivation status missing {token}"));
        }
    }

    let progress = label_value(text, "**Progress disposition:**").unwrap_or_default().to_uppercase();
    for token in ["PRESERVE_EVIDENCE_ONLY", "REUSE_ONLY_IF:", "STALE_PROGRESS:REJECT"] {
        if !progress.contains(token) {
            errors.push(format!("Progress disposition missing {token}"));
        }
    }

    static SPLIT_RE: OnceLock<Regex> = OnceLock::new();
    let split_re = SPLIT_RE.get_or_init(|| Regex::new(r"[\s,|]+").unwrap());
    let semantics_raw = label_value(text, "**Task semantics:**").unwrap_or_default().to_uppercase();
    let semantics: BTreeSet<&str> = split_re
        .split(&semantics_raw)
        .filter(|s| !s.trim().is_empty())
        .collect();
    let non_routine: BTreeSet<&str> = [
        "EXPERIMENT",
        "BENCHMARK",
        "PERFORMANCE",
        "MODEL",
        "RESEARCH",
        "REPEATED_FAILURE",
    ]
    .into_iter()
    .collect();
    let alchemist_required = semantics.iter().any(|s| non_routine.contains(s));

    let typed_binding =
        authority_label_value(text, "**Alchemist typed-stage binding:**").unwrap_or_default();
    if alchemist_required {
        static TYPED_RE: OnceLock<Regex> = OnceLock::new();
        let typed_re = TYPED_RE.get_or_init(|| {
            Regex::new(r"(?i)^SCHEMA:dispatch\.stage\.v1;\s*RUN_ID:([0-9a-f-]{36});\s*STATE:(?:alchemist|forge)://run/([0-9a-f-]{36})/state;\s*CHECKPOINT:TYPED_STAGES$").unwrap()
        });
        let alchemist_gate = authority_label_value(text, "**Alchemist gate:**").unwrap_or_default();
        let gate_run = alchemist_gate
            .split_once('=')
            .map(|(_, r)| r.trim())
            .unwrap_or("");
        match typed_re.captures(&typed_binding) {
            Some(caps) if caps.get(1).unwrap().as_str().to_lowercase() == caps.get(2).unwrap().as_str().to_lowercase() => {
                if caps.get(1).unwrap().as_str().to_lowercase() != gate_run.to_lowercase() {
                    errors.push("Alchemist typed-stage binding run ID must match Alchemist gate".to_string());
                }
            }
            _ => {
                errors.push(
                    "non-routine work requires typed Alchemist binding schema, matching run/state IDs, & TYPED_STAGES checkpoint"
                        .to_string(),
                );
            }
        }
    } else {
        static NOT_REQUIRED_RE: OnceLock<Regex> = OnceLock::new();
        let re = NOT_REQUIRED_RE.get_or_init(|| Regex::new(r"(?i)^NOT_REQUIRED:\s*\S").unwrap());
        if !re.is_match(&typed_binding) {
            errors.push(
                "routine work requires Alchemist typed-stage binding NOT_REQUIRED:<reason>".to_string(),
            );
        }
    }

    let inherited = table_rows(
        text,
        "### Inherited instruction disposition",
        "## 1C. Goal Route & Critical Path",
    );
    let rows: Vec<&Vec<String>> = inherited.iter().skip(1).filter(|r| r.len() == 6).collect();
    let clause_ids: Vec<String> = rows.iter().map(|r| r[0].trim_matches('`').to_string()).collect();
    {
        let unique: BTreeSet<&String> = clause_ids.iter().collect();
        if unique.len() != clause_ids.len() {
            errors.push("inherited instruction disposition contains duplicate clause IDs".to_string());
        }
    }

    let allowed_ranks: BTreeSet<&str> = [
        "LATEST_USER_INTENT",
        "DECISION_OBJECTIVE",
        "STAGE_CONTRACT",
        "INHERITED_DOCUMENT",
        "EXISTING_PROGRESS",
    ]
    .into_iter()
    .collect();
    let allowed_compatibility: BTreeSet<&str> = ["ALIGNED", "CONFLICTS", "NO_DECISION_VALUE"].into_iter().collect();

    static FENCE_RE: OnceLock<Regex> = OnceLock::new();
    let fence_re = FENCE_RE.get_or_init(|| Regex::new(r"(?s)```[^\n]*\n(.*?)\n```").unwrap());
    let executable_blocks: String = fence_re
        .captures_iter(text)
        .map(|c| c.get(1).unwrap().as_str())
        .filter(|b| b.contains("STAGE_COMMAND:"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();

    let mut active_contract_parts = vec![
        label_value(text, "**Decision rule:**").unwrap_or_default(),
        label_value(text, "**Acceptance metrics only:**").unwrap_or_default(),
        label_value(text, "**Required inputs:**").unwrap_or_default(),
    ];
    for (start, end) in [
        ("### Model, tool & dependency relevance", "## 1B. Authority, Correction & Global Re-Derivation"),
        ("### Stage decision funnel", "### Typed stage records"),
        ("### Typed stage records", "### Fixture-stage ownership"),
        ("### Fixture-stage ownership", "### Stage command bindings"),
        ("## 7. Verification & Acceptance Map", "## 8. Evidence & Artifact Contract"),
    ] {
        let table = table_rows(text, start, end);
        for row in table.iter().skip(1) {
            if start == "### Typed stage records" && row.len() == 10 {
                let mut combined = row[..7].to_vec();
                combined.extend_from_slice(&row[8..]);
                active_contract_parts.push(combined.join(" | "));
            } else {
                active_contract_parts.push(row.join(" | "));
            }
        }
    }
    active_contract_parts.push(executable_blocks);
    let active_contract = active_contract_parts.join("\n").to_lowercase();

    static KEEP_RE: OnceLock<Regex> = OnceLock::new();
    let keep_re = KEEP_RE.get_or_init(|| Regex::new(r"(?i)^KEEP:").unwrap());
    static DELETE_RE: OnceLock<Regex> = OnceLock::new();
    let delete_re = DELETE_RE.get_or_init(|| Regex::new(r"(?i)^DELETE:").unwrap());
    static REWRITE_RE: OnceLock<Regex> = OnceLock::new();
    let rewrite_re = REWRITE_RE.get_or_init(|| Regex::new(r"(?i)^REWRITE:").unwrap());
    static DECISION_EFFECT_RE: OnceLock<Regex> = OnceLock::new();
    let decision_effect_re =
        DECISION_EFFECT_RE.get_or_init(|| Regex::new(r"(?i)\bDECISION_EFFECT:QUESTION_\d+\b").unwrap());
    static MATCH_TEXT_RE: OnceLock<Regex> = OnceLock::new();
    let match_text_re = MATCH_TEXT_RE.get_or_init(|| Regex::new(r"(?i)\bMATCH_TEXT:([^;]+)").unwrap());
    static EXCLUDE_FROM_RE: OnceLock<Regex> = OnceLock::new();
    let exclude_from_re = EXCLUDE_FROM_RE.get_or_init(|| Regex::new(r"(?i)\bEXCLUDE_FROM:[^;]+").unwrap());
    static NO_DECISION_EFFECT_RE: OnceLock<Regex> = OnceLock::new();
    let no_decision_effect_re =
        NO_DECISION_EFFECT_RE.get_or_init(|| Regex::new(r"(?i)\bNO_DECISION_EFFECT:\S").unwrap());
    static REWRITE_TO_RE: OnceLock<Regex> = OnceLock::new();
    let rewrite_to_re = REWRITE_TO_RE.get_or_init(|| Regex::new(r"(?i)\bREWRITE_TO:([^;]+)").unwrap());

    let mut dispositions: Vec<String> = Vec::new();
    let mut latest_intent_rows = 0;
    for row in &rows {
        let clause_id = row[0].trim_matches('`');
        let source_rank = row[2].trim_matches('`').to_uppercase();
        let compatibility = row[3].trim_matches('`').to_uppercase();
        let owner = row[4].trim_matches('`');
        let disposition = row[5].trim().to_string();
        dispositions.push(disposition.clone());
        if source_rank == "LATEST_USER_INTENT" {
            latest_intent_rows += 1;
        }
        if !allowed_ranks.contains(source_rank.as_str()) {
            errors.push(format!("inherited clause {clause_id} has invalid source rank"));
        }
        if !allowed_compatibility.contains(compatibility.as_str()) {
            errors.push(format!("inherited clause {clause_id} has invalid objective compatibility"));
        }

        if keep_re.is_match(&disposition) {
            if compatibility != "ALIGNED" || owner == "NONE" {
                errors.push(format!("inherited clause {clause_id} KEEP requires ALIGNED + stage owner"));
            }
            if !decision_effect_re.is_match(&disposition) {
                errors.push(format!("inherited clause {clause_id} KEEP lacks numbered decision effect"));
            }
        } else if delete_re.is_match(&disposition) {
            let token_match = match_text_re.captures(&disposition);
            if owner != "NONE" || !matches!(compatibility.as_str(), "CONFLICTS" | "NO_DECISION_VALUE") {
                errors.push(format!(
                    "inherited clause {clause_id} DELETE requires NONE owner + conflict/no-decision-value"
                ));
            }
            if token_match.is_none()
                || !exclude_from_re.is_match(&disposition)
                || !no_decision_effect_re.is_match(&disposition)
            {
                errors.push(format!(
                    "inherited clause {clause_id} DELETE lacks MATCH_TEXT, EXCLUDE_FROM, or NO_DECISION_EFFECT"
                ));
            } else if let Some(m) = &token_match {
                let matched = m.get(1).unwrap().as_str().trim().to_lowercase();
                if active_contract.contains(&matched) {
                    errors.push(format!("deleted inherited match text survives active contract: {clause_id}"));
                }
            }
        } else if rewrite_re.is_match(&disposition) {
            if owner == "NONE" {
                errors.push(format!("inherited clause {clause_id} REWRITE requires stage owner"));
            }
            let old_match = match_text_re.captures(&disposition);
            let new_match = rewrite_to_re.captures(&disposition);
            if old_match.is_none() || new_match.is_none() || !decision_effect_re.is_match(&disposition) {
                errors.push(format!(
                    "inherited clause {clause_id} REWRITE lacks MATCH_TEXT, REWRITE_TO, or numbered decision effect"
                ));
            } else {
                let old_text = old_match.unwrap().get(1).unwrap().as_str().trim().to_lowercase();
                let new_text = new_match.unwrap().get(1).unwrap().as_str().trim().to_lowercase();
                if active_contract.contains(&old_text) {
                    errors.push(format!("rewritten inherited match text survives active contract: {clause_id}"));
                }
                if !active_contract.contains(&new_text) {
                    errors.push(format!(
                        "rewritten inherited replacement is absent from active contract: {clause_id}"
                    ));
                }
            }
        } else {
            errors.push(format!("inherited clause {clause_id} must be KEEP, DELETE, or REWRITE"));
        }

        if source_rank == "LATEST_USER_INTENT" && !keep_re.is_match(&disposition) {
            errors.push("LATEST_USER_INTENT clause cannot be deleted or rewritten".to_string());
        }
    }

    if latest_intent_rows < 1 {
        errors.push("inherited instruction disposition requires at least one LATEST_USER_INTENT row".to_string());
    }
    if semantic_correction
        && !dispositions
            .iter()
            .any(|d| delete_re.is_match(d) || rewrite_re.is_match(d))
    {
        errors.push("semantic correction requires at least one DELETE or REWRITE disposition".to_string());
    }

    let reconciliation = label_value(text, "**Inherited inventory reconciliation:**").unwrap_or_default();
    static RECON_RE: OnceLock<Regex> = OnceLock::new();
    let recon_re = RECON_RE.get_or_init(|| {
        Regex::new(r"(?is)^INVENTORY_TOTAL:(\d+);\s*CLASSIFIED_TOTAL:(\d+);\s*UNCLASSIFIED:(\d+);\s*EVIDENCE:(.+)$").unwrap()
    });
    match recon_re.captures(&reconciliation) {
        Some(caps) if path_re().is_match(caps.get(4).unwrap().as_str()) => {
            let inventory_total: i64 = caps.get(1).unwrap().as_str().parse().unwrap_or(-1);
            let classified_total: i64 = caps.get(2).unwrap().as_str().parse().unwrap_or(-1);
            let unclassified: i64 = caps.get(3).unwrap().as_str().parse().unwrap_or(-1);
            if inventory_total != rows.len() as i64 || classified_total != rows.len() as i64 || unclassified != 0 {
                errors.push("inherited inventory totals must equal classified rows with UNCLASSIFIED:0".to_string());
            }
        }
        _ => {
            errors.push(
                "**Inherited inventory reconciliation:** requires numeric totals, UNCLASSIFIED:0, & evidence path"
                    .to_string(),
            );
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_template_short_circuits() {
        assert!(authority_correction_errors("", true).is_empty());
    }

    #[test]
    fn flags_wrong_authority_order() {
        let text = "- **Authority order:** WRONG > ORDER\n";
        let errors = authority_correction_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("Authority order")));
    }

    #[test]
    fn requires_correction_state_shape() {
        let text = "- **Correction state:** GARBAGE\n";
        let errors = authority_correction_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("Correction state")));
    }

    #[test]
    fn uncorrected_dispatch_requires_plan_invalidation_not_applicable() {
        let text = "- **Correction state:** NONE: no correction needed\n\
- **Plan invalidation:** SOMETHING_ELSE\n";
        let errors = authority_correction_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("Plan invalidation")));
    }
}
