//! Port of `src/lib/review/value_gate_runner.py` (matched blind/PeerDebate
//! branch runner for the frozen Agent Room value gate, dated 2026-07-19).
//!
//! **Ported faithfully (pure, filesystem/network/subprocess-free):**
//! - `validate_implementer_output` — the "one typed disposition per stable
//!   blind finding" contract: exact-count and exact-id-set matching,
//!   duplicate rejection, `action` restricted to `folded`/`refuted`,
//!   required non-empty `rationale`, required non-empty `revision_text`
//!   only when `folded`, and clearing `revision_text` when `refuted` — see
//!   [`validate_implementer_output`]
//! - `apply_folded_addendum` — inserting the `EXPERIMENTAL IMPLEMENTER
//!   REVISIONS:` block immediately before the packet's `SUCCESS_CRITERIA:`
//!   marker, or returning the packet unchanged when there are no folded
//!   dispositions — see [`apply_folded_addendum`]
//! - `_peer_projection`'s typed-evidence-only projection of `rebuttal`/
//!   `response` juror seats (raw model transcripts never cross branches;
//!   `resolution` is included only for `response` seats, mirroring
//!   `resolution=True`/`False`) — see [`peer_projection`]
//! - `PEER_KEYS`, the set of keys stripped from the blind branch's copied
//!   advisory (`prepare_blind_branch`) — see [`PEER_KEYS`]
//!
//! **Not ported (depends on `Engine`/`providers.py` live LLM dispatch, and
//! on `dual_review.py`/`review_evidence.py`, neither of which exists in
//! this workspace):** `_parse_json_object` (best-effort brace-scanning JSON
//! extraction from raw model text — trivial to add if a caller needs it,
//! but nothing in this chunk exercises it without a live model response to
//! parse), `run_implementer`'s provider fallback chain, `_complete_branch`,
//! `prepare_blind_branch`'s disk I/O, `seed_peer_branch`, `run_pair`, and
//! `main()`. A caller wiring this to live evidence validates each
//! implementer response with [`validate_implementer_output`], builds the
//! revised packet with [`apply_folded_addendum`], and builds peer context
//! with [`peer_projection`] before dispatching through this crate's own
//! provider/orchestration surface.

use std::collections::BTreeSet;

/// Port of `PEER_KEYS`.
pub const PEER_KEYS: &[&str] =
    &["rebuttal", "response", "position_shifts", "contest_audit", "resolution_audit"];

/// Port of one item accepted or produced by `validate_implementer_output`
/// (mirrors the raw `dict` shape read from/written to `dispositions: []`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawDisposition {
    pub finding_id: String,
    pub action: String,
    pub rationale: String,
    pub revision_text: String,
}

/// Port of the `ValueError` messages `validate_implementer_output` raises.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    #[error("implementer output requires dispositions: []")]
    MissingDispositions,
    #[error("every input finding must appear exactly once")]
    FindingSetMismatch,
    #[error("every disposition must be an object")]
    NotAnObject,
    #[error("invalid action for {finding_id}: {action}")]
    InvalidAction { finding_id: String, action: String },
    #[error("rationale is required for {finding_id}")]
    MissingRationale { finding_id: String },
    #[error("revision_text is required when {finding_id} is folded")]
    MissingRevisionText { finding_id: String },
}

/// Port of `validate_implementer_output(value, findings)`.
///
/// `value` is the caller-parsed `dispositions` list (the Python source
/// requires `value["dispositions"]` to be a `list`; a caller here passes
/// `None` for a value with no `dispositions` key/wrong type, matching the
/// first `ValueError`).
pub fn validate_implementer_output(
    dispositions: Option<&[RawDisposition]>,
    findings: &[String],
) -> Result<Vec<RawDisposition>, ValidationError> {
    let items = dispositions.ok_or(ValidationError::MissingDispositions)?;

    let expected: Vec<&str> = findings.iter().map(String::as_str).collect();
    let observed: Vec<&str> = items.iter().map(|item| item.finding_id.as_str()).collect();
    let mut expected_sorted = expected.clone();
    expected_sorted.sort_unstable();
    let mut observed_sorted = observed.clone();
    observed_sorted.sort_unstable();
    if items.len() != expected.len() || observed_sorted != expected_sorted {
        return Err(ValidationError::FindingSetMismatch);
    }

    let mut normalized = Vec::with_capacity(items.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for item in items {
        let finding_id = item.finding_id.clone();
        if !seen.insert(finding_id.clone()) {
            return Err(ValidationError::FindingSetMismatch);
        }
        let action = item.action.to_lowercase();
        if action != "folded" && action != "refuted" {
            return Err(ValidationError::InvalidAction { finding_id, action });
        }
        let rationale = item.rationale.trim().to_string();
        let revision_text = item.revision_text.trim().to_string();
        if rationale.is_empty() {
            return Err(ValidationError::MissingRationale { finding_id });
        }
        if action == "folded" && revision_text.is_empty() {
            return Err(ValidationError::MissingRevisionText { finding_id });
        }
        normalized.push(RawDisposition {
            finding_id,
            action: action.clone(),
            rationale,
            revision_text: if action == "folded" { revision_text } else { String::new() },
        });
    }
    Ok(normalized)
}

/// Port of the `ValueError` `apply_folded_addendum` raises when the packet
/// lacks a `SUCCESS_CRITERIA:` marker.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("packet lacks SUCCESS_CRITERIA section")]
pub struct MissingSuccessCriteria;

/// Port of `apply_folded_addendum(packet, dispositions)`.
pub fn apply_folded_addendum(
    packet: &str,
    dispositions: &[RawDisposition],
) -> Result<String, MissingSuccessCriteria> {
    let folded: Vec<&RawDisposition> =
        dispositions.iter().filter(|item| item.action == "folded").collect();
    if folded.is_empty() {
        return Ok(packet.to_string());
    }
    const MARKER: &str = "SUCCESS_CRITERIA:";
    let index = packet.find(MARKER).ok_or(MissingSuccessCriteria)?;
    let mut lines = vec!["EXPERIMENTAL IMPLEMENTER REVISIONS:".to_string()];
    for item in &folded {
        lines.push(format!("  - [{}] {}", item.finding_id, item.revision_text));
    }
    let addendum = lines.join("\n") + "\n\n";
    let mut out = String::with_capacity(packet.len() + addendum.len());
    out.push_str(&packet[..index]);
    out.push_str(&addendum);
    out.push_str(&packet[index..]);
    Ok(out)
}

/// Port of one raw blocker entry as read from `seat.get("blockers")`: either
/// a bare string or an object with the allow-listed keys.
#[derive(Clone, Debug)]
pub enum RawBlocker {
    Text(String),
    Object(std::collections::BTreeMap<String, serde_json::Value>),
}

/// Port of one juror seat (`rebuttal`/`response` entries), the input to
/// `seat_projection`.
#[derive(Clone, Debug, Default)]
pub struct RawSeat {
    pub juror_id: Option<serde_json::Value>,
    pub verdict: Option<serde_json::Value>,
    pub top_concern: Option<serde_json::Value>,
    pub blockers: Vec<RawBlocker>,
    pub parsed_ok: bool,
}

/// Port of one `seat_projection(seat, resolution=...)` output.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ProjectedSeat {
    pub juror_id: Option<serde_json::Value>,
    pub verdict: Option<serde_json::Value>,
    pub top_concern: Option<serde_json::Value>,
    pub blockers: Vec<serde_json::Value>,
}

fn seat_projection(seat: &RawSeat, resolution: bool) -> ProjectedSeat {
    let mut blockers = Vec::with_capacity(seat.blockers.len());
    for blocker in &seat.blockers {
        match blocker {
            RawBlocker::Text(text) => blockers.push(serde_json::Value::String(text.clone())),
            RawBlocker::Object(fields) => {
                let mut out = serde_json::Map::new();
                for key in [
                    "tier",
                    "text",
                    "rationale",
                    "evidence_refs",
                    "proposed_change",
                    "confidence",
                    "contest",
                    "resolution",
                ] {
                    if key == "resolution" && !resolution {
                        continue;
                    }
                    if let Some(value) = fields.get(key) {
                        out.insert(key.to_string(), value.clone());
                    }
                }
                if !out.is_empty() {
                    blockers.push(serde_json::Value::Object(out));
                }
            }
        }
    }
    ProjectedSeat {
        juror_id: seat.juror_id.clone(),
        verdict: seat.verdict.clone(),
        top_concern: seat.top_concern.clone(),
        blockers,
    }
}

/// Port of the `_peer_projection` output shape (only `rebuttal_positions`
/// and `responses` are filled by [`peer_projection`]; `position_shifts` and
/// the two audit fields are opaque JSON in the Python source and are passed
/// through unchanged by the caller, not reconstructed here).
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PeerProjection {
    pub rebuttal_positions: Vec<ProjectedSeat>,
    pub responses: Vec<ProjectedSeat>,
}

/// Port of `_peer_projection(advisory)`'s seat-filtering logic:
/// `rebuttal.jurors` project with `resolution=False`, `response.jurors`
/// project with `resolution=True`, and only seats with `parsed_ok` (default
/// `True`) are kept.
pub fn peer_projection(rebuttal_jurors: &[RawSeat], response_jurors: &[RawSeat]) -> PeerProjection {
    PeerProjection {
        rebuttal_positions: rebuttal_jurors
            .iter()
            .filter(|seat| seat.parsed_ok)
            .map(|seat| seat_projection(seat, false))
            .collect(),
        responses: response_jurors
            .iter()
            .filter(|seat| seat.parsed_ok)
            .map(|seat| seat_projection(seat, true))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn disp(id: &str, action: &str, rationale: &str, revision: &str) -> RawDisposition {
        RawDisposition {
            finding_id: id.into(),
            action: action.into(),
            rationale: rationale.into(),
            revision_text: revision.into(),
        }
    }

    #[test]
    fn validate_rejects_missing_dispositions() {
        let err = validate_implementer_output(None, &["f1".into()]).unwrap_err();
        assert_eq!(err, ValidationError::MissingDispositions);
    }

    #[test]
    fn validate_rejects_finding_set_mismatch() {
        let items = vec![disp("f1", "folded", "r", "rev")];
        let err = validate_implementer_output(Some(&items), &["f1".into(), "f2".into()]).unwrap_err();
        assert_eq!(err, ValidationError::FindingSetMismatch);
    }

    #[test]
    fn validate_rejects_duplicate_finding_id() {
        let items = vec![disp("f1", "folded", "r", "rev"), disp("f1", "refuted", "r2", "")];
        let err = validate_implementer_output(Some(&items), &["f1".into()]).unwrap_err();
        assert_eq!(err, ValidationError::FindingSetMismatch);
    }

    #[test]
    fn validate_rejects_invalid_action() {
        let items = vec![disp("f1", "dismissed", "r", "")];
        let err = validate_implementer_output(Some(&items), &["f1".into()]).unwrap_err();
        assert_eq!(
            err,
            ValidationError::InvalidAction { finding_id: "f1".into(), action: "dismissed".into() }
        );
    }

    #[test]
    fn validate_requires_rationale() {
        let items = vec![disp("f1", "refuted", "  ", "")];
        let err = validate_implementer_output(Some(&items), &["f1".into()]).unwrap_err();
        assert_eq!(err, ValidationError::MissingRationale { finding_id: "f1".into() });
    }

    #[test]
    fn validate_requires_revision_text_when_folded() {
        let items = vec![disp("f1", "folded", "r", "  ")];
        let err = validate_implementer_output(Some(&items), &["f1".into()]).unwrap_err();
        assert_eq!(err, ValidationError::MissingRevisionText { finding_id: "f1".into() });
    }

    #[test]
    fn validate_clears_revision_text_when_refuted() {
        let items = vec![disp("f1", "refuted", "r", "should be dropped")];
        let out = validate_implementer_output(Some(&items), &["f1".into()]).unwrap();
        assert_eq!(out[0].revision_text, "");
    }

    #[test]
    fn validate_lowercases_action_and_trims_fields() {
        let items = vec![disp("f1", "FOLDED", "  reason  ", "  text  ")];
        let out = validate_implementer_output(Some(&items), &["f1".into()]).unwrap();
        assert_eq!(out[0].action, "folded");
        assert_eq!(out[0].rationale, "reason");
        assert_eq!(out[0].revision_text, "text");
    }

    #[test]
    fn addendum_returns_packet_unchanged_without_folded_items() {
        let packet = "PLAN\n\nSUCCESS_CRITERIA:\n- x\n";
        let items = vec![disp("f1", "refuted", "r", "")];
        let out = apply_folded_addendum(packet, &items).unwrap();
        assert_eq!(out, packet);
    }

    #[test]
    fn addendum_inserts_before_success_criteria_marker() {
        let packet = "PLAN\n\nSUCCESS_CRITERIA:\n- x\n";
        let items = vec![disp("f1", "folded", "r", "add the guard clause")];
        let out = apply_folded_addendum(packet, &items).unwrap();
        assert_eq!(
            out,
            "PLAN\n\nEXPERIMENTAL IMPLEMENTER REVISIONS:\n  - [f1] add the guard clause\n\nSUCCESS_CRITERIA:\n- x\n"
        );
    }

    #[test]
    fn addendum_lists_only_folded_items_in_order() {
        let packet = "SUCCESS_CRITERIA:\n";
        let items = vec![
            disp("f1", "refuted", "r", ""),
            disp("f2", "folded", "r", "fix a"),
            disp("f3", "folded", "r", "fix b"),
        ];
        let out = apply_folded_addendum(packet, &items).unwrap();
        assert!(out.contains("- [f2] fix a\n  - [f3] fix b\n"));
        assert!(!out.contains("f1"));
    }

    #[test]
    fn addendum_errors_without_marker() {
        let err = apply_folded_addendum("no marker here", &[disp("f1", "folded", "r", "x")])
            .unwrap_err();
        assert_eq!(err, MissingSuccessCriteria);
    }

    #[test]
    fn peer_projection_filters_unparsed_seats() {
        let seats = vec![
            RawSeat { parsed_ok: true, juror_id: Some("a".into()), ..Default::default() },
            RawSeat { parsed_ok: false, juror_id: Some("b".into()), ..Default::default() },
        ];
        let projection = peer_projection(&seats, &[]);
        assert_eq!(projection.rebuttal_positions.len(), 1);
    }

    #[test]
    fn peer_projection_drops_resolution_for_rebuttal_but_keeps_for_response() {
        let mut fields = BTreeMap::new();
        fields.insert("text".to_string(), serde_json::json!("blocker text"));
        fields.insert("resolution".to_string(), serde_json::json!("resolved"));
        let seat = RawSeat {
            parsed_ok: true,
            blockers: vec![RawBlocker::Object(fields)],
            ..Default::default()
        };
        let projection = peer_projection(std::slice::from_ref(&seat), std::slice::from_ref(&seat));
        let rebuttal_blocker = &projection.rebuttal_positions[0].blockers[0];
        assert!(rebuttal_blocker.get("resolution").is_none());
        let response_blocker = &projection.responses[0].blockers[0];
        assert_eq!(response_blocker.get("resolution").unwrap(), "resolved");
    }

    #[test]
    fn peer_projection_passes_through_string_blockers() {
        let seat = RawSeat {
            parsed_ok: true,
            blockers: vec![RawBlocker::Text("plain blocker".into())],
            ..Default::default()
        };
        let projection = peer_projection(&[seat], &[]);
        assert_eq!(projection.rebuttal_positions[0].blockers[0], serde_json::json!("plain blocker"));
    }

    #[test]
    fn peer_keys_match_python_set() {
        let expected: BTreeSet<&str> =
            ["rebuttal", "response", "position_shifts", "contest_audit", "resolution_audit"]
                .into_iter()
                .collect();
        let actual: BTreeSet<&str> = PEER_KEYS.iter().copied().collect();
        assert_eq!(actual, expected);
    }
}
