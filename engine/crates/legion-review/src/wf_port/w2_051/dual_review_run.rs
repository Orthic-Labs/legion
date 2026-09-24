//! r58/r60: closes the orchestration gap `dual_review_logic.rs` left open
//! — `run_rebuttal_round`, `run_response_round`, `run_advisory_review`,
//! `run_verdict_review`, `run_dual_review`, and `main()` from
//! `src/lib/review/dual_review.py`. Wires the pure protocol logic in
//! `dual_review_logic.rs` to the now-ported `engine_run::Engine` (r59),
//! `w2_050::room_driver::run_room_advisory`, and `w2_054::review_evidence`
//! / `w2_054::synthesizer`, following the same "logic module + `*_run`
//! orchestration module" split `engine_run.rs` and `health_check_run.rs`
//! already established in this chunk.
//!
//! One faithful deviation: Python's `run_rebuttal_round`/`run_response_round`
//! take an `Optional[Engine]` that defaults to a fresh `Engine()`; this
//! port always takes `&Engine` explicitly (Rust has no ambient global to
//! construct one from), matching how `run_advisory_review` already always
//! passes its own `engine` through to both in Python.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::super::w2_050::config::Juror;
use super::super::w2_050::now_iso;
use super::super::w2_050::room_driver::{
    self, CommandRunner as RoomCommandRunner, RoomDriverError, RunsEvidence,
};
use super::super::w2_052::packet::render_packet_skeleton;
use super::super::w2_054::review_evidence::{
    self, archive_verified_room_memory, pin_run_evidence, verify_run_evidence,
    verify_terminal_finding_ledger, RealCommandRunner,
};
use super::super::w2_054::synthesizer::render as render_result;
use super::dual_review_logic::{
    contest_audit_v, contests_by_target, digest, peer_positions_block, position_shifts_v,
    rebuttal_instruction, render_cli_result_route, resolution_audit_v, resolution_record_v,
    strip_unsupported_adoptions, sum_accounting, synthesize_combined, AccountingSummaryInput,
    CliResultRoute, RESPONSE_INSTRUCTION,
};
use super::engine_run::{Engine, EngineError, VisionPrep};
use super::jury_cli;

/// Port of `RevisionCallback`: given the packet text and the advisory
/// result, returns the revised packet text and the disposition object.
pub trait Reviser {
    fn revise(&self, input_text: &str, advisory: &Value) -> (String, Value);
}

/// Errors this module's orchestration functions can raise, mirroring the
/// Python `ValueError`/`PacketValidationError` sites in `dual_review.py`.
#[derive(Debug, Clone)]
pub enum DualReviewError {
    Engine(String),
    Value(String),
    Io(String),
}

impl fmt::Display for DualReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DualReviewError::Engine(m) | DualReviewError::Value(m) | DualReviewError::Io(m) => {
                f.write_str(m)
            }
        }
    }
}
impl std::error::Error for DualReviewError {}

impl From<EngineError> for DualReviewError {
    fn from(e: EngineError) -> Self {
        DualReviewError::Engine(e.to_string())
    }
}
impl From<std::io::Error> for DualReviewError {
    fn from(e: std::io::Error) -> Self {
        DualReviewError::Io(e.to_string())
    }
}
impl From<serde_json::Error> for DualReviewError {
    fn from(e: serde_json::Error) -> Self {
        DualReviewError::Io(e.to_string())
    }
}

/// Port of `_read_json`.
fn read_json(path: &Path) -> Result<Value, DualReviewError> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

/// Port of `_write_json`.
fn write_json(path: &Path, value: &Value) -> Result<(), DualReviewError> {
    let text = serde_json::to_string_pretty(value)?;
    std::fs::write(path, text)?;
    Ok(())
}

/// Port of `_validate_input`. Only hard-fails (mirrors
/// `PacketValidationError`) when `enforce_packet` is true; otherwise the
/// caller inspects `validation.errors` from the returned envelope, exactly
/// as `Engine.run` itself does.
fn validate_input(
    skill: &str,
    input_text: &str,
    enforce_packet: bool,
) -> Result<super::super::w2_052::packet::PacketValidation, DualReviewError> {
    let validation = super::super::w2_052::packet::validate_packet(input_text);
    if !validation.errors.is_empty() && enforce_packet {
        return Err(DualReviewError::Value(format!(
            "review packet invalid for '{skill}': {}",
            validation.errors[0]
        )));
    }
    Ok(validation)
}

/// Port of `_valid_disposition`.
fn valid_disposition(value: &Value) -> Result<(), DualReviewError> {
    let obj = value
        .as_object()
        .ok_or_else(|| DualReviewError::Value("revision disposition must be an object".into()))?;
    if !obj.get("self_review").is_some_and(Value::is_array) {
        return Err(DualReviewError::Value(
            "revision disposition requires self_review: []".into(),
        ));
    }
    if !obj.get("advisory_dispositions").is_some_and(Value::is_array) {
        return Err(DualReviewError::Value(
            "revision disposition requires advisory_dispositions: []".into(),
        ));
    }
    Ok(())
}

/// Port of `Engine.run`'s dict-return shape, converting a `RunResult`
/// (r59's `engine_run::Engine::run`) into the same envelope
/// `src/lib/review/engine.py`'s `Engine.run` produces, so downstream code
/// (`_synthesize_combined`, `render_cli_result`, on-disk `council.*.json`)
/// sees an identical shape either way.
pub fn run_result_to_value(r: &super::engine_run::RunResult) -> Value {
    json!({
        "skill": r.skill,
        "panel": r.panel,
        "flags": r.flags,
        "rubric_file": r.rubric_file,
        "prompt_version": r.prompt_version,
        "packet_validation": {
            "ok": r.packet_ok,
            "errors": r.packet_errors,
            "warnings": r.packet_warnings,
            "section_count": r.packet_section_count,
            "has_packet": r.has_packet,
        },
        "jurors": r.jurors.iter().map(|j| j.to_dict()).collect::<Vec<_>>(),
        "escalation": r.escalation.iter().map(|j| j.to_dict()).collect::<Vec<_>>(),
        "accounting": {
            "calls": r.accounting.calls,
            "usage": {
                "input_tokens": r.accounting.usage.input_tokens,
                "output_tokens": r.accounting.usage.output_tokens,
                "total_tokens": r.accounting.usage.total_tokens,
            },
            "usage_complete": r.accounting.usage_complete,
            "cache_hits": r.accounting.cache_hits,
        },
        "synthesis": {
            "majority_verdict": r.synthesis.majority_verdict,
            "majority_count": r.synthesis.majority_count,
            "avg_score": r.synthesis.avg_score,
            "split": r.synthesis.split,
            "any_degraded": r.synthesis.any_degraded,
            "any_error": r.synthesis.any_error,
        },
    })
}

fn accounting_input_present(r: &super::engine_logic::Accounting) -> AccountingSummaryInput {
    AccountingSummaryInput {
        calls: r.calls,
        input_tokens: r.usage.input_tokens,
        output_tokens: r.usage.output_tokens,
        total_tokens: r.usage.total_tokens,
        usage_complete: r.usage_complete,
        present: true,
    }
}

fn accounting_input_absent() -> AccountingSummaryInput {
    AccountingSummaryInput {
        calls: 0,
        input_tokens: 0,
        output_tokens: 0,
        total_tokens: 0,
        usage_complete: false,
        present: false,
    }
}

fn summed_to_value(s: &super::dual_review_logic::SummedAccounting) -> Value {
    json!({
        "calls": s.calls,
        "usage": {
            "input_tokens": s.input_tokens,
            "output_tokens": s.output_tokens,
            "total_tokens": s.total_tokens,
        },
        "usage_complete": s.usage_complete,
    })
}

/// Port of `run_rebuttal_round`.
pub fn run_rebuttal_round(
    engine: &Engine,
    skill: &str,
    input_text: &str,
    advisory: &Value,
    dissent_policy: &str,
    vision_prep: &dyn VisionPrep,
) -> Result<Value, DualReviewError> {
    if !matches!(dissent_policy, "none" | "advocate" | "required_contest") {
        return Err(DualReviewError::Value(format!(
            "invalid dissent_policy: {dissent_policy}"
        )));
    }
    let seats: &[Juror] = &engine
        .config
        .panels
        .get("advisory")
        .ok_or_else(|| DualReviewError::Engine("no 'advisory' panel in models.yaml".to_string()))?
        .jurors;

    let mut rebuttals: Vec<Value> = Vec::new();
    let mut accounting: Vec<AccountingSummaryInput> = Vec::new();

    for (index, seat) in seats.iter().enumerate() {
        let peers = peer_positions_block(advisory, &seat.id);
        if peers.is_empty() {
            continue;
        }
        let require_contest =
            dissent_policy == "required_contest" || (dissent_policy == "advocate" && index == 0);
        let instruction = if require_contest {
            rebuttal_instruction()
        } else {
            super::dual_review_logic::PEER_DEBATE_INSTRUCTION.to_string()
        };
        let prompt = format!("{input_text}\n\n{instruction}\n{peers}\n");
        let flags = BTreeMap::new();
        match engine.run(
            skill,
            &prompt,
            &flags,
            true,
            true,
            false,
            "council",
            Some(std::slice::from_ref(seat)),
            vision_prep,
        ) {
            Ok(result) => {
                accounting.push(accounting_input_present(&result.accounting));
                for j in &result.jurors {
                    rebuttals.push(j.to_dict());
                }
            }
            Err(e) => {
                accounting.push(accounting_input_absent());
                rebuttals.push(json!({
                    "juror_id": seat.id,
                    "parsed_ok": false,
                    "verdict": "ERROR",
                    "error": e.to_string(),
                }));
            }
        }
    }

    let jurors: Vec<super::dual_review_logic::JurorVerdict> =
        jurors_verdicts_from_advisory(advisory);
    let findings = super::dual_review_logic::finding_records(&jurors);
    let mut finding_index = Map::new();
    for f in &findings {
        finding_index.insert(
            f.finding_id.clone(),
            json!({"author_seat": f.author_seat, "claim": f.claim}),
        );
    }

    Ok(json!({
        "round": "PeerDebate",
        "dissent_policy": dissent_policy,
        "jurors": rebuttals,
        "accounting": summed_to_value(&sum_accounting(&accounting)),
        "finding_index": finding_index,
    }))
}

fn jurors_verdicts_from_advisory(advisory: &Value) -> Vec<super::dual_review_logic::JurorVerdict> {
    advisory
        .get("jurors")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|j| super::dual_review_logic::JurorVerdict {
                    juror_id: j
                        .get("juror_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    parsed_ok: j
                        .get("parsed_ok")
                        .map(|v| v.as_bool().unwrap_or(true))
                        .unwrap_or(true),
                    blockers: j
                        .get("blockers")
                        .and_then(Value::as_array)
                        .map(|bs| {
                            bs.iter()
                                .map(|b| match b {
                                    Value::String(s) => {
                                        super::dual_review_logic::Blocker::Text(s.clone())
                                    }
                                    Value::Object(o) => {
                                        super::dual_review_logic::Blocker::Structured(o.clone())
                                    }
                                    other => super::dual_review_logic::Blocker::Text(other.to_string()),
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Port of `run_response_round`.
pub fn run_response_round(
    engine: &Engine,
    skill: &str,
    input_text: &str,
    rebuttal: &Value,
    vision_prep: &dyn VisionPrep,
) -> Value {
    let seats: BTreeMap<String, Juror> = engine
        .config
        .panels
        .get("advisory")
        .map(|p| p.jurors.iter().map(|j| (j.id.clone(), j.clone())).collect())
        .unwrap_or_default();
    let routed = contests_by_target(rebuttal);
    let mut responses: Vec<Value> = Vec::new();
    let mut accounting: Vec<AccountingSummaryInput> = Vec::new();

    let invoke = |prompt_text: &str, seat: &Juror| -> (Value, AccountingSummaryInput) {
        let flags = BTreeMap::new();
        match engine.run(
            skill,
            prompt_text,
            &flags,
            true,
            true,
            false,
            "council",
            Some(std::slice::from_ref(seat)),
            vision_prep,
        ) {
            Ok(result) => {
                let acc = accounting_input_present(&result.accounting);
                if let Some(j) = result.jurors.first() {
                    (j.to_dict(), acc)
                } else {
                    (
                        json!({
                            "juror_id": seat.id,
                            "parsed_ok": false,
                            "verdict": "ERROR",
                            "error": "response seat returned no juror",
                        }),
                        acc,
                    )
                }
            }
            Err(e) => (
                json!({
                    "juror_id": seat.id,
                    "parsed_ok": false,
                    "verdict": "ERROR",
                    "error": e.to_string(),
                }),
                accounting_input_absent(),
            ),
        }
    };

    for (seat_id, contests) in &routed {
        let Some(seat) = seats.get(seat_id) else {
            continue;
        };
        let contests_arr = contests.as_array().cloned().unwrap_or_default();
        let block: String = contests_arr
            .iter()
            .map(|c| {
                let from = c.get("from").and_then(Value::as_str).unwrap_or("");
                format!(
                    "### Typed contest from {from}\n{}\n",
                    serde_json::to_string(c).unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let prompt = format!("{input_text}\n\n{RESPONSE_INSTRUCTION}\n{block}\n");
        let (mut juror, observed) = invoke(&prompt, seat);
        accounting.push(observed);

        let resolved_ids: std::collections::HashSet<String> = juror
            .get("blockers")
            .and_then(Value::as_array)
            .map(|bs| {
                bs.iter()
                    .filter_map(resolution_record_v)
                    .filter_map(|r| {
                        r.get("finding_id")
                            .and_then(Value::as_str)
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        let missing: Vec<&Value> = contests_arr
            .iter()
            .filter(|c| {
                let fid = c.get("finding_id").and_then(Value::as_str).unwrap_or("");
                !resolved_ids.contains(fid)
            })
            .collect();

        juror["rewake_count"] = json!(0);
        if !missing.is_empty() {
            let missing_block: String = missing
                .iter()
                .map(|c| {
                    let from = c.get("from").and_then(Value::as_str).unwrap_or("");
                    format!(
                        "### Still-unanswered typed contest from {from}\n{}\n",
                        serde_json::to_string(c).unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let retry_prompt = format!(
                "{input_text}\n\n{RESPONSE_INSTRUCTION}\nThis is the single bounded re-wake. Answer only the still-unanswered IDs below.\n{missing_block}\n"
            );
            let (retry, retry_accounting) = invoke(&retry_prompt, seat);
            accounting.push(retry_accounting);
            juror["rewake_count"] = json!(1);
            if retry.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false) {
                let missing_ids: std::collections::HashSet<String> = missing
                    .iter()
                    .filter_map(|c| c.get("finding_id").and_then(Value::as_str).map(|s| s.to_string()))
                    .collect();
                let retry_resolutions: Vec<Value> = retry
                    .get("blockers")
                    .and_then(Value::as_array)
                    .map(|bs| {
                        bs.iter()
                            .filter(|b| {
                                resolution_record_v(b)
                                    .and_then(|r| {
                                        r.get("finding_id")
                                            .and_then(Value::as_str)
                                            .map(|s| missing_ids.contains(s))
                                    })
                                    .unwrap_or(false)
                            })
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                if juror.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false) {
                    let entry = juror
                        .as_object_mut()
                        .expect("juror is an object")
                        .entry("blockers")
                        .or_insert_with(|| Value::Array(vec![]));
                    if let Some(arr) = entry.as_array_mut() {
                        arr.extend(retry_resolutions);
                    }
                    juror["rewake_raw_response"] = retry.get("raw_response").cloned().unwrap_or(Value::Null);
                } else {
                    juror = retry;
                    juror["rewake_count"] = json!(1);
                }
            } else {
                juror["rewake_error"] = retry
                    .get("error")
                    .cloned()
                    .filter(|v| !v.is_null())
                    .unwrap_or_else(|| Value::String("unparseable re-wake".to_string()));
            }
        }

        if juror.get("juror_id").and_then(Value::as_str).unwrap_or("").is_empty() {
            juror["juror_id"] = json!(seat_id);
            juror["parsed_ok"] = json!(false);
            juror["verdict"] = json!("ERROR");
            juror["error"] = json!("response seat identity missing");
        }
        let froms: Vec<Value> = contests_arr
            .iter()
            .map(|c| c.get("from").cloned().unwrap_or(Value::Null))
            .collect();
        let fids: Vec<Value> = contests_arr
            .iter()
            .map(|c| c.get("finding_id").cloned().unwrap_or(Value::Null))
            .collect();
        juror["answering_contests"] = Value::Array(froms);
        juror["answering_findings"] = Value::Array(fids);
        responses.push(juror);
    }

    json!({
        "round": "PeerDebateReply",
        "jurors": responses,
        "routed_contests": routed,
        "accounting": summed_to_value(&sum_accounting(&accounting)),
    })
}

/// Options threading the Agent-Room lane through `run_advisory_review`,
/// mirroring `agent_room_driver.run_room_advisory`'s parameters that
/// `dual_review.py`'s Python caller never sets explicitly (so they take
/// the same defaults there: `workspace_root` = cwd, `room_binary` = None).
pub struct RoomOptions<'a> {
    pub workspace_root: &'a Path,
    pub room_binary: Option<&'a Path>,
    pub engine_dir: &'a Path,
    pub runner: &'a dyn RoomCommandRunner,
}

struct EvidenceAdapter;
impl RunsEvidence for EvidenceAdapter {
    fn verify_run_evidence(&self, run_dir: &Path, runs_root: &Path) -> Result<bool, RoomDriverError> {
        let v = review_evidence::verify_run_evidence(run_dir, runs_root)
            .map_err(|e| RoomDriverError(e.to_string()))?;
        Ok(v.get("ok").and_then(Value::as_bool).unwrap_or(false))
    }
    fn persist_finding_ledger(
        &self,
        output: &Path,
        ledger: &Value,
        lane: &str,
        transcript_path: &str,
    ) -> Result<(), RoomDriverError> {
        let t = if transcript_path.is_empty() {
            None
        } else {
            Some(transcript_path)
        };
        review_evidence::persist_finding_ledger(output, ledger, lane, t)
            .map(|_| ())
            .map_err(|e| RoomDriverError(e.to_string()))
    }
    fn verify_terminal_finding_ledger(&self, output: &Path) -> Result<(), RoomDriverError> {
        review_evidence::verify_terminal_finding_ledger(output)
            .map(|_| ())
            .map_err(|e| RoomDriverError(e.to_string()))
    }
    fn start_room_fallback(
        &self,
        state_path: &Path,
        pinned_packet_path: &str,
        pinned_packet_digest: &str,
        partial_ledger_path: &str,
        partial_ledger_digest: &str,
    ) -> Result<Value, RoomDriverError> {
        review_evidence::start_room_fallback(
            state_path,
            pinned_packet_path,
            pinned_packet_digest,
            partial_ledger_path,
            partial_ledger_digest,
        )
        .map_err(|e| RoomDriverError(e.to_string()))
    }
    fn pin_run_evidence(&self, output: &Path, runs_root: &Path) -> Result<(), RoomDriverError> {
        review_evidence::pin_run_evidence(output, runs_root)
            .map(|_| ())
            .map_err(|e| RoomDriverError(e.to_string()))
    }
}

/// Port of `run_advisory_review`.
#[allow(clippy::too_many_arguments)]
pub fn run_advisory_review(
    engine: &Engine,
    skill: &str,
    input_text: &str,
    out_dir: &Path,
    enforce_packet: bool,
    resume: bool,
    rebuttal: bool,
    runs_root: &Path,
    dissent_policy: &str,
    no_cache: bool,
    room: bool,
    acknowledge_room_link_delivery: bool,
    room_options: Option<&RoomOptions>,
    vision_prep: &dyn VisionPrep,
) -> Result<Value, DualReviewError> {
    if room && rebuttal {
        return Err(DualReviewError::Value(
            "--room and --rebuttal are mutually exclusive".to_string(),
        ));
    }
    if room {
        validate_input(skill, input_text, enforce_packet)?;
        let opts = room_options.ok_or_else(|| {
            DualReviewError::Value("--room requires RoomOptions".to_string())
        })?;
        let evidence = EvidenceAdapter;
        return room_driver::run_room_advisory(
            skill,
            input_text,
            out_dir,
            runs_root,
            opts.workspace_root,
            opts.room_binary,
            opts.engine_dir,
            opts.runner,
            &evidence,
            acknowledge_room_link_delivery,
        )
        .map_err(|e| DualReviewError::Value(e.to_string()));
    }

    let runs_root_canon = runs_root.canonicalize().unwrap_or_else(|_| runs_root.to_path_buf());
    if rebuttal {
        let out_parent = out_dir
            .canonicalize()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| out_dir.parent().unwrap_or(out_dir).to_path_buf());
        if out_parent != runs_root_canon {
            return Err(DualReviewError::Value(format!(
                "P-1 peer-debate runs must be under {}",
                runs_root_canon.display()
            )));
        }
    }
    std::fs::create_dir_all(out_dir)?;
    validate_input(skill, input_text, enforce_packet)?;
    let input_hash = digest(input_text);
    let advisory_path = out_dir.join("council.advisory.json");
    let state_path = out_dir.join("review.state.json");
    let packet_path = out_dir.join("packet.md");

    if resume && advisory_path.is_file() && state_path.is_file() {
        let state = read_json(&state_path)?;
        let matches = state.get("skill").and_then(Value::as_str) == Some(skill)
            && state.get("input_hash").and_then(Value::as_str) == Some(input_hash.as_str())
            && state.get("rebuttal").and_then(Value::as_bool).unwrap_or(false) == rebuttal
            && state
                .get("dissent_policy")
                .and_then(Value::as_str)
                .unwrap_or("none")
                == (if rebuttal { dissent_policy } else { "none" });
        if matches {
            if rebuttal {
                let verification = verify_run_evidence(out_dir, runs_root)
                    .map_err(|e| DualReviewError::Value(e.to_string()))?;
                if !verification.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                    return Err(DualReviewError::Value(
                        "P-1 checkpoint evidence digest is invalid".to_string(),
                    ));
                }
            }
            return read_json(&advisory_path);
        }
    }

    std::fs::write(&packet_path, input_text)?;
    let flags = BTreeMap::new();
    let advisory_seats: &[Juror] = &engine
        .config
        .panels
        .get("advisory")
        .ok_or_else(|| DualReviewError::Engine("no 'advisory' panel in models.yaml".to_string()))?
        .jurors;
    let run = engine.run(
        skill,
        input_text,
        &flags,
        no_cache || rebuttal,
        true,
        false,
        "council",
        Some(advisory_seats),
        vision_prep,
    )?;
    let mut advisory = run_result_to_value(&run);

    if rebuttal {
        let mut second = run_rebuttal_round(engine, skill, input_text, &advisory, dissent_policy, vision_prep)?;
        strip_unsupported_adoptions(&mut second, &advisory);
        advisory["position_shifts"] = position_shifts_v(&advisory, &second);
        advisory["contest_audit"] = contest_audit_v(&second);
        advisory["rebuttal"] = second.clone();
        write_json(&out_dir.join("council.rebuttal.json"), &second)?;

        let mut third = run_response_round(engine, skill, input_text, &second, vision_prep);
        let audit = resolution_audit_v(&third);
        third["resolution_audit"] = audit.clone();
        advisory["response"] = third.clone();
        advisory["resolution_audit"] = audit;
        write_json(&out_dir.join("council.response.json"), &third)?;
    }

    write_json(&advisory_path, &advisory)?;
    write_json(
        &state_path,
        &json!({
            "schema_version": 1,
            "skill": skill,
            "status": "awaiting_revision",
            "input_hash": input_hash,
            "rebuttal": rebuttal,
            "lane": if rebuttal { "p-1-peer-debate" } else { "isolated" },
            "dissent_policy": if rebuttal { dissent_policy } else { "none" },
            "peer_phase": if rebuttal { Value::String("PeerDebate".to_string()) } else { Value::Null },
            "no_cache": no_cache || rebuttal,
            "updated_at": now_iso(),
        }),
    )?;
    if rebuttal {
        pin_run_evidence(out_dir, runs_root).map_err(|e| DualReviewError::Value(e.to_string()))?;
    }
    Ok(advisory)
}

/// Port of `run_verdict_review`.
pub fn run_verdict_review(
    engine: &Engine,
    skill: &str,
    revised_input_text: &str,
    disposition: &Value,
    out_dir: &Path,
    enforce_packet: bool,
    no_cache: bool,
    vision_prep: &dyn VisionPrep,
) -> Result<Value, DualReviewError> {
    valid_disposition(disposition)?;
    let validation = validate_input(skill, revised_input_text, enforce_packet)?;
    let advisory_path = out_dir.join("council.advisory.json");
    if !advisory_path.is_file() {
        return Err(DualReviewError::Value(
            "missing council.advisory.json; run the advisory stage first".to_string(),
        ));
    }
    let state_path = out_dir.join("review.state.json");
    let prior_state = if state_path.is_file() {
        read_json(&state_path)?
    } else {
        json!({})
    };
    let lane = prior_state.get("lane").and_then(Value::as_str).unwrap_or("");
    if lane == "room-fallback" {
        let fallback_status = prior_state
            .get("fallback")
            .and_then(|f| f.get("status"))
            .and_then(Value::as_str);
        if fallback_status != Some("ready_for_verdict") {
            return Err(DualReviewError::Value(
                "room fallback disposition check is not complete".to_string(),
            ));
        }
    }
    if matches!(lane, "room" | "room-fallback") {
        verify_terminal_finding_ledger(out_dir).map_err(|e| DualReviewError::Value(e.to_string()))?;
    }

    let flags = BTreeMap::new();
    let jury_run = engine.run(
        skill,
        revised_input_text,
        &flags,
        no_cache,
        true,
        false,
        "jury",
        None,
        vision_prep,
    )?;
    let jury = run_result_to_value(&jury_run);

    let advisory = read_json(&advisory_path)?;
    let original_hash = prior_state.get("input_hash").cloned().unwrap_or(Value::Null);
    let revised_hash = digest(revised_input_text);

    let envelope = json!({
        "schema_version": 2,
        "skill": skill,
        "ts": now_iso(),
        "packet_validation": {
            "ok": validation.ok,
            "errors": validation.errors,
            "warnings": validation.warnings,
            "section_count": validation.sections.len(),
        },
        "revision": {
            "original_hash": original_hash,
            "revised_hash": revised_hash,
            "changed": original_hash.as_str() != Some(revised_hash.as_str()),
        },
        "council": {"framing": "advisory", "result": advisory},
        "jury": {"framing": "verdict", "result": jury},
        "synthesis": synthesize_combined(&advisory, &jury),
    });
    write_json(&out_dir.join("review.disposition.json"), disposition)?;
    write_json(&out_dir.join("jury.verdict.json"), &jury)?;
    write_json(&out_dir.join("council-review.json"), &envelope)?;

    let mut next_state = prior_state.clone();
    let obj = next_state.as_object_mut().expect("state is an object");
    obj.insert("schema_version".to_string(), json!(1));
    obj.insert("skill".to_string(), json!(skill));
    obj.insert("status".to_string(), json!("complete"));
    obj.insert("input_hash".to_string(), original_hash.clone());
    obj.insert("revised_hash".to_string(), json!(revised_hash));
    obj.insert("updated_at".to_string(), json!(now_iso()));
    write_json(&state_path, &next_state)?;

    if next_state.get("auto_memory").and_then(Value::as_bool).unwrap_or(false) {
        let runner = RealCommandRunner;
        let _ = archive_verified_room_memory(out_dir, None, "crypt", &runner);
    }
    if prior_state.get("evidence").is_some() {
        pin_run_evidence(out_dir, runs_root_default(out_dir)).map_err(|e| DualReviewError::Value(e.to_string()))?;
    }
    Ok(envelope)
}

/// `dual_review.py`'s `RUNS_ROOT` is `Path(__file__).parent / ".council-runs"`
/// — a module-relative default this port has no direct equivalent for
/// (see `review_evidence.rs`'s module doc comment: callers own the root).
/// `run_verdict_review`'s final `pin_run_evidence` call is the one call
/// site in `dual_review.py` that uses the bare module default rather than
/// a caller-supplied `runs_root`; this derives the same directory from
/// `out_dir`'s parent, which is where every other call in this file
/// already requires `runs_root` to be.
fn runs_root_default(out_dir: &Path) -> &Path {
    out_dir.parent().unwrap_or(out_dir)
}

/// Port of `run_dual_review`.
pub fn run_dual_review(
    engine: &Engine,
    skill: &str,
    input_text: &str,
    out_dir: &Path,
    reviser: &dyn Reviser,
    enforce_packet: bool,
    rebuttal: bool,
    dissent_policy: &str,
    runs_root: &Path,
    vision_prep: &dyn VisionPrep,
) -> Result<Value, DualReviewError> {
    let advisory = run_advisory_review(
        engine,
        skill,
        input_text,
        out_dir,
        enforce_packet,
        true,
        rebuttal,
        runs_root,
        dissent_policy,
        false,
        false,
        false,
        None,
        vision_prep,
    )?;
    let (revised_text, disposition) = reviser.revise(input_text, &advisory);
    run_verdict_review(
        engine,
        skill,
        &revised_text,
        &disposition,
        out_dir,
        enforce_packet,
        false,
        vision_prep,
    )
}

/// Port of `render_cli_result`: closes the `NeedsRender` branch
/// `render_cli_result_route` left open by applying `synthesizer::render`.
pub fn render_cli_result(result: &Value, lens_questions: &BTreeMap<String, String>) -> String {
    match render_cli_result_route(result) {
        CliResultRoute::RoomNotificationRequired(text) => text,
        CliResultRoute::RoomLinkDelivered => "Council Room link delivered. Room remains active.\n".to_string(),
        CliResultRoute::NeedsRender(payload) => render_result(&payload, lens_questions),
    }
}

/// Port of `dual_review.py`'s `main()` CLI entrypoint. `args` mirrors
/// `sys.argv[1:]`. Returns the text to print on stdout and the process
/// exit code, matching `jury_cli`/`health_check_run`'s `run()` shape.
/// `providers`/`cache`/`lenses` build the `Engine` the same way the CLI-
/// level caller of `jury_cli::run` must; `runs_root` and `room_options`
/// are the same caller-owned values `run_advisory_review` needs above.
#[allow(clippy::too_many_arguments)]
pub fn run(
    args: &[String],
    engine: &Engine,
    runs_root: &Path,
    room_options: Option<&RoomOptions>,
    vision_prep: &dyn VisionPrep,
) -> (String, i32) {
    let mut skill: Option<String> = None;
    let mut stage: Option<String> = None;
    let mut input: Option<String> = None;
    let mut output_dir: Option<String> = None;
    let mut disposition_path: Option<String> = None;
    let mut skeleton = false;
    let mut no_packet_enforce = false;
    let mut no_resume = false;
    let mut no_cache = false;
    let mut rebuttal = false;
    let mut room = false;
    let mut ack_room = false;
    let mut dissent_policy = "required_contest".to_string();
    let mut json_out = false;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--stage" => {
                i += 1;
                stage = args.get(i).cloned();
            }
            "--input" => {
                i += 1;
                input = args.get(i).cloned();
            }
            "--output-dir" => {
                i += 1;
                output_dir = args.get(i).cloned();
            }
            "--disposition" => {
                i += 1;
                disposition_path = args.get(i).cloned();
            }
            "--skeleton" => skeleton = true,
            "--no-packet-enforce" => no_packet_enforce = true,
            "--no-resume" => no_resume = true,
            "--no-cache" => no_cache = true,
            "--rebuttal" => rebuttal = true,
            "--room" => room = true,
            "--ack-room-link-delivered" => ack_room = true,
            "--dissent-policy" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    dissent_policy = v.clone();
                }
            }
            "--json" => json_out = true,
            other if !other.starts_with("--") && skill.is_none() => {
                skill = Some(other.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    if skeleton {
        return (render_packet_skeleton(skill.as_deref()).to_string(), 0);
    }
    let (Some(skill), Some(stage), Some(input_arg), Some(output_dir)) =
        (skill, stage, input, output_dir)
    else {
        return (
            "error: skill, --stage, --input, and --output-dir are required\n".to_string(),
            2,
        );
    };

    let input_text = if input_arg == "-" {
        use std::io::Read;
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            return ("error: failed to read stdin\n".to_string(), 1);
        }
        buf
    } else {
        match std::fs::read_to_string(&input_arg) {
            Ok(s) => s,
            Err(e) => return (format!("error: {}: {e}\n", input_arg), 1),
        }
    };
    let out_dir = PathBuf::from(&output_dir);

    let result = if stage == "advisory" {
        run_advisory_review(
            engine,
            &skill,
            &input_text,
            &out_dir,
            !no_packet_enforce,
            !no_resume,
            rebuttal,
            runs_root,
            &dissent_policy,
            no_cache,
            room,
            ack_room,
            room_options,
            vision_prep,
        )
    } else {
        let Some(disposition_path) = disposition_path else {
            return (
                "error: --disposition is required for verdict stage\n".to_string(),
                2,
            );
        };
        let disposition = match read_json(&PathBuf::from(&disposition_path)) {
            Ok(v) => v,
            Err(e) => return (format!("error: {e}\n"), 1),
        };
        run_verdict_review(
            engine,
            &skill,
            &input_text,
            &disposition,
            &out_dir,
            !no_packet_enforce,
            no_cache,
            vision_prep,
        )
    };

    let result = match result {
        Ok(v) => v,
        Err(e) => return (format!("error: {e}\n"), 1),
    };

    let lens_questions: BTreeMap<String, String> = engine
        .lenses
        .iter()
        .filter(|(_, cfg)| !cfg.lens_question.is_empty())
        .map(|(name, cfg)| (name.clone(), cfg.lens_question.clone()))
        .collect();

    let output = if json_out {
        serde_json::to_string_pretty(&result).unwrap_or_default()
    } else {
        render_cli_result(&result, &lens_questions)
    };
    (output, 0)
}

/// Re-exported for callers that only need `jury.py`'s `parse_flag`
/// alongside this module (the two CLIs live side by side in the Python
/// source tree).
pub use jury_cli::parse_flag;
