//! Tests for chunk w2_051's port of `src/lib/review/{dual_review,engine,
//! health_check,jury,ledger}.py`, ported from the chunk's Python
//! assertions (there is no dedicated `test_ledger.py`/etc. in the legacy
//! tree for this area, so these assert the documented and observed
//! behavior of each ported function directly).
//!
//! These tests exercise `legion_review::wf_port::w2_051::*`, which the
//! integrator wires via `pub mod wf_port;` / `pub mod w2_051;` in
//! `legion-review`'s `lib.rs`. Until that wiring lands this file does not
//! compile as part of the crate's test target — see the chunk report.

use std::collections::BTreeMap;

use legion_review::wf_port::w2_051::dual_review_logic::{
    contest_audit_v, contest_record_v, contests_by_target, digest, finding_records, is_adoption,
    peer_positions_block, position_shifts_v, rebuttal_instruction, render_blocker,
    render_cli_result_route, resolution_audit_v, resolution_record_v, strip_unsupported_adoptions,
    sum_accounting, synthesize_combined, AccountingSummaryInput, Blocker, CliResultRoute,
    JurorVerdict, PEER_DEBATE_INSTRUCTION, REQUIRED_CONTEST_INSTRUCTION,
};
use legion_review::wf_port::w2_051::engine_logic::{
    accounting, execution_units, normalized_usage, parse_juror_json, provider_prompts,
    synthesize, triggered_escalations, EscalationRule, JurorResultSummary, JurorSeat, Usage,
};
use legion_review::wf_port::w2_051::health_check_logic::{
    classify, enumerate_models, primary_broken, ClassifyResult, EscalationSpec, JurorSpec,
    ModelRow, ModelsConfig, ProbeOutcome,
};
use legion_review::wf_port::w2_051::jury_cli::parse_flag;
use legion_review::wf_port::w2_051::ledger::{
    dispose_blocker, ledger_path_for, load_ledger, normalize_blocker, parse_dispose_arg,
    register_verdict_round, save_ledger, status_payload, BlockerEntry, Ledger, RawBlocker, Round,
};

// ---------- ledger.py ----------

#[test]
fn ledger_path_for_matches_python_naming() {
    let p = ledger_path_for(std::path::Path::new("out/shot3.mp4"));
    assert_eq!(p, std::path::PathBuf::from("out/shot3.verdict.ledger.json"));
}

#[test]
fn round_trip_save_and_load_ledger() {
    let dir = std::env::temp_dir().join(format!("wf_w2_051_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let artifact = dir.join("shot3.mp4");
    let mut ledger = Ledger::new(artifact.to_string_lossy().to_string());
    let mut juror_blockers = BTreeMap::new();
    juror_blockers.insert(
        "code_specialist".to_string(),
        vec![RawBlocker::Text("[P0] unhandled timeout in capture-loop".to_string())],
    );
    register_verdict_round(&mut ledger, "out/shot3.verdict.json", &juror_blockers);

    let path = ledger_path_for(&artifact);
    let saved = save_ledger(&ledger, Some(&path)).unwrap();
    assert_eq!(saved, path);

    let loaded = load_ledger(&path).expect("ledger should load back");
    assert_eq!(loaded.rounds.len(), 1);
    assert_eq!(loaded.rounds[0].round, 1);
    assert_eq!(loaded.rounds[0].blockers.len(), 1);
    assert_eq!(loaded.rounds[0].blockers[0].tier, "P0");
    assert_eq!(loaded.rounds[0].blockers[0].text, "unhandled timeout in capture-loop");
    assert!(!loaded.is_clean());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn normalize_blocker_extracts_tier_prefix() {
    let (tier, text) = normalize_blocker(&RawBlocker::Text("[P2] minor nit".to_string()));
    assert_eq!(tier, "P2");
    assert_eq!(text, "minor nit");

    let (tier, text) = normalize_blocker(&RawBlocker::Text("no tier prefix here".to_string()));
    assert_eq!(tier, "P1");
    assert_eq!(text, "no tier prefix here");

    let (tier, text) = normalize_blocker(&RawBlocker::Structured {
        tier: Some("bogus".to_string()),
        text: "  padded  ".to_string(),
    });
    assert_eq!(tier, "P1"); // unrecognised tier falls back to P1
    assert_eq!(text, "padded");
}

#[test]
fn register_verdict_round_assigns_sequential_ids_in_juror_order() {
    let mut ledger = Ledger::new("a.mp4");
    let mut juror_blockers = BTreeMap::new();
    juror_blockers.insert(
        "zebra".to_string(),
        vec![RawBlocker::Text("z issue".to_string())],
    );
    juror_blockers.insert(
        "alpha".to_string(),
        vec![RawBlocker::Text("a issue".to_string())],
    );
    register_verdict_round(&mut ledger, "a.verdict.json", &juror_blockers);
    let round = ledger.latest_round().unwrap();
    // alpha sorts before zebra (BTreeMap key order), so b1 belongs to alpha.
    assert_eq!(round.blockers[0].from_juror, "alpha");
    assert_eq!(round.blockers[0].id, "b1");
    assert_eq!(round.blockers[1].from_juror, "zebra");
    assert_eq!(round.blockers[1].id, "b2");
}

#[test]
fn register_verdict_round_inherits_prior_disposition_by_text_match() {
    let mut ledger = Ledger::new("a.mp4");
    ledger.rounds.push(Round {
        round: 1,
        ts: "2026-01-01T00:00:00+00:00".to_string(),
        verdict_path: "a.verdict.json".to_string(),
        blockers: vec![BlockerEntry {
            id: "b1".to_string(),
            tier: "P1".to_string(),
            text: "flaky retry logic".to_string(),
            from_juror: "j1".to_string(),
            disposition: Some("fixed".to_string()),
            evidence: Some("src/retry.rs:10".to_string()),
            disposed_at: Some("2026-01-01T00:00:00+00:00".to_string()),
        }],
    });
    let mut juror_blockers = BTreeMap::new();
    juror_blockers.insert(
        "j1".to_string(),
        vec![RawBlocker::Text("Flaky Retry Logic".to_string())], // case differs
    );
    register_verdict_round(&mut ledger, "a.verdict2.json", &juror_blockers);
    let round2 = ledger.latest_round().unwrap();
    assert_eq!(round2.round, 2);
    assert_eq!(round2.blockers[0].disposition.as_deref(), Some("fixed"));
    assert_eq!(round2.blockers[0].evidence.as_deref(), Some("src/retry.rs:10"));
}

#[test]
fn dispose_blocker_updates_latest_round_only() {
    let mut ledger = Ledger::new("a.mp4");
    ledger.rounds.push(Round {
        round: 1,
        ts: "t".to_string(),
        verdict_path: "v1".to_string(),
        blockers: vec![BlockerEntry {
            id: "b1".to_string(),
            tier: "P0".to_string(),
            text: "old".to_string(),
            from_juror: "j".to_string(),
            disposition: None,
            evidence: None,
            disposed_at: None,
        }],
    });
    ledger.rounds.push(Round {
        round: 2,
        ts: "t".to_string(),
        verdict_path: "v2".to_string(),
        blockers: vec![BlockerEntry {
            id: "b1".to_string(),
            tier: "P0".to_string(),
            text: "new".to_string(),
            from_juror: "j".to_string(),
            disposition: None,
            evidence: None,
            disposed_at: None,
        }],
    });

    let updated = dispose_blocker(&mut ledger, "b1", "fixed", Some("src/x.rs:1".to_string())).unwrap();
    assert!(updated);
    // Round 1's b1 must remain untouched.
    assert!(ledger.rounds[0].blockers[0].disposition.is_none());
    assert_eq!(ledger.rounds[1].blockers[0].disposition.as_deref(), Some("fixed"));

    let missing = dispose_blocker(&mut ledger, "b99", "fixed", None).unwrap();
    assert!(!missing);
}

#[test]
fn dispose_blocker_rejects_invalid_disposition_and_id() {
    let mut ledger = Ledger::new("a.mp4");
    assert!(dispose_blocker(&mut ledger, "b1", "not_a_real_disposition", None).is_err());
    assert!(dispose_blocker(&mut ledger, "not-an-id", "fixed", None).is_err());
}

#[test]
fn is_clean_true_iff_no_pending_in_latest_round() {
    let mut ledger = Ledger::new("a.mp4");
    assert!(ledger.is_clean()); // no rounds at all -> clean
    ledger.rounds.push(Round {
        round: 1,
        ts: "t".to_string(),
        verdict_path: "v".to_string(),
        blockers: vec![BlockerEntry {
            id: "b1".to_string(),
            tier: "P0".to_string(),
            text: "x".to_string(),
            from_juror: "j".to_string(),
            disposition: None,
            evidence: None,
            disposed_at: None,
        }],
    });
    assert!(!ledger.is_clean());
    dispose_blocker(&mut ledger, "b1", "waived_by_operator", None).unwrap();
    assert!(ledger.is_clean());
}

#[test]
fn parse_dispose_arg_splits_id_disposition_evidence() {
    let (id, disp, ev) = parse_dispose_arg("b1=fixed:src/foo.rs:42").unwrap();
    assert_eq!(id, "b1");
    assert_eq!(disp, "fixed");
    assert_eq!(ev.as_deref(), Some("src/foo.rs:42"));

    let (id, disp, ev) = parse_dispose_arg("b3=rebutted:rubric does not apply").unwrap();
    assert_eq!(id, "b3");
    assert_eq!(disp, "rebutted");
    assert_eq!(ev.as_deref(), Some("rubric does not apply"));

    let (id, disp, ev) = parse_dispose_arg("b2=fixed").unwrap();
    assert_eq!(id, "b2");
    assert_eq!(disp, "fixed");
    assert_eq!(ev, None);

    assert!(parse_dispose_arg("no equals sign").is_err());
}

#[test]
fn status_payload_reports_pending_and_clean_flags() {
    let mut ledger = Ledger::new("a.mp4");
    let mut jb = BTreeMap::new();
    jb.insert("j".to_string(), vec![RawBlocker::Text("[P1] x".to_string())]);
    register_verdict_round(&mut ledger, "v.json", &jb);
    let payload = status_payload(&ledger, std::path::Path::new("a.verdict.ledger.json"));
    assert_eq!(payload.rounds, 1);
    assert_eq!(payload.latest_round, Some(1));
    assert_eq!(payload.pending_count, 1);
    assert!(!payload.is_clean);
}

// ---------- engine.py ----------

#[test]
fn normalized_usage_computes_total_when_missing() {
    let mut m = serde_json::Map::new();
    m.insert("input_tokens".to_string(), serde_json::json!(10));
    m.insert("output_tokens".to_string(), serde_json::json!(5));
    let usage = normalized_usage(Some(&m)).unwrap();
    assert_eq!(usage.total_tokens, 15);
}

#[test]
fn normalized_usage_accepts_prompt_completion_aliases() {
    let mut m = serde_json::Map::new();
    m.insert("prompt_tokens".to_string(), serde_json::json!(3));
    m.insert("completion_tokens".to_string(), serde_json::json!(4));
    let usage = normalized_usage(Some(&m)).unwrap();
    assert_eq!(usage.input_tokens, 3);
    assert_eq!(usage.output_tokens, 4);
    assert_eq!(usage.total_tokens, 7);
}

#[test]
fn normalized_usage_none_when_fields_missing() {
    assert!(normalized_usage(None).is_none());
    let m = serde_json::Map::new();
    assert!(normalized_usage(Some(&m)).is_none());
}

#[test]
fn accounting_sums_calls_usage_and_cache_hits() {
    let results = vec![
        JurorResultSummary {
            juror_id: "a".to_string(),
            call_count: 1,
            usage: Usage { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
            usage_complete: true,
            cache_hit: true,
            ..Default::default()
        },
        JurorResultSummary {
            juror_id: "b".to_string(),
            call_count: 2,
            usage: Usage { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
            usage_complete: false,
            cache_hit: false,
            ..Default::default()
        },
    ];
    let acc = accounting(&results);
    assert_eq!(acc.calls, 3);
    assert_eq!(acc.usage.total_tokens, 17);
    assert!(!acc.usage_complete);
    assert_eq!(acc.cache_hits, 1);
}

#[test]
fn parse_juror_json_strips_think_blocks_and_fences() {
    let raw = "<think>reasoning here</think>```json\n{\"verdict\": \"PASS\", \"score\": 9}\n```";
    let parsed = parse_juror_json(Some(raw));
    assert!(parsed.parsed_ok);
    let obj = parsed.object.unwrap();
    assert_eq!(obj.get("verdict").unwrap().as_str(), Some("PASS"));
    assert_eq!(obj.get("score").unwrap().as_i64(), Some(9));
}

#[test]
fn parse_juror_json_extracts_substring_when_surrounded_by_prose() {
    let raw = "Sure, here is my verdict: {\"verdict\": \"FAIL\", \"score\": 2} thanks!";
    let parsed = parse_juror_json(Some(raw));
    assert!(parsed.parsed_ok);
    assert_eq!(parsed.object.unwrap().get("verdict").unwrap().as_str(), Some("FAIL"));
}

#[test]
fn parse_juror_json_reports_parse_error_on_garbage() {
    let parsed = parse_juror_json(Some("not json at all"));
    assert!(!parsed.parsed_ok);
    assert_eq!(parsed.verdict, "PARSE_ERROR");
    assert_eq!(parsed.top_concern, "not json at all");
}

#[test]
fn parse_juror_json_handles_none_response() {
    let parsed = parse_juror_json(None);
    assert!(!parsed.parsed_ok);
    assert_eq!(parsed.verdict, "PARSE_ERROR");
}

#[test]
fn provider_prompts_compacts_only_for_nim_text() {
    let (sys, user) = provider_prompts("nim", "system text", "RUBRIC:\nR\n\nINPUT:\nI\n", false);
    assert_eq!(sys, "Return one minified JSON object only. No markdown. No prose.");
    assert!(user.contains("CRITERIA:\nR"));
    assert!(user.contains("ARTIFACT:\nI"));

    let (sys2, user2) = provider_prompts("openai", "system text", "RUBRIC:\nR\n", false);
    assert_eq!(sys2, "system text");
    assert_eq!(user2, "RUBRIC:\nR\n");

    // Vision prompts are left untouched even for nim.
    let (sys3, user3) = provider_prompts("nim", "system text", "user text", true);
    assert_eq!(sys3, "system text");
    assert_eq!(user3, "user text");
}

#[test]
fn execution_units_splits_parallel_safe_and_serializes_others() {
    let jurors = vec![
        JurorSeat { provider: "openai".to_string() },
        JurorSeat { provider: "nim".to_string() },
        JurorSeat { provider: "nim".to_string() },
    ];
    let units = execution_units(&jurors, &|p| p == "openai");
    // openai is parallel_safe -> its own singleton unit; nim is not -> one
    // unit holding both nim seats.
    assert_eq!(units.len(), 2);
    let openai_units: Vec<&Vec<JurorSeat>> = units.iter().filter(|u| u[0].provider == "openai").collect();
    assert_eq!(openai_units.len(), 1);
    assert_eq!(openai_units[0].len(), 1);
    let nim_units: Vec<&Vec<JurorSeat>> = units.iter().filter(|u| u[0].provider == "nim").collect();
    assert_eq!(nim_units.len(), 1);
    assert_eq!(nim_units[0].len(), 2);
}

#[test]
fn triggered_escalations_matches_always_flag_and_split_and_dedups() {
    let rules = vec![
        EscalationRule { trigger: "always".to_string(), provider: "p1".to_string(), model: "m1".to_string() },
        EscalationRule { trigger: "flag.irreversible".to_string(), provider: "p2".to_string(), model: "m2".to_string() },
        EscalationRule { trigger: "jury_split".to_string(), provider: "p3".to_string(), model: "m3".to_string() },
        // duplicate provider+model as an "always" rule should be de-duped.
        EscalationRule { trigger: "always".to_string(), provider: "p1".to_string(), model: "m1".to_string() },
    ];
    let mut flags = std::collections::HashMap::new();
    flags.insert("irreversible".to_string(), true);
    let verdicts = vec!["PASS".to_string(), "FAIL".to_string()]; // split
    let out = triggered_escalations(&rules, &verdicts, &flags);
    assert_eq!(out.len(), 3); // p1/m1 (deduped), p2/m2, p3/m3
}

#[test]
fn triggered_escalations_no_split_when_verdicts_agree() {
    let rules = vec![EscalationRule {
        trigger: "jury_split".to_string(),
        provider: "p".to_string(),
        model: "m".to_string(),
    }];
    let flags = std::collections::HashMap::new();
    let verdicts = vec!["PASS".to_string(), "PASS".to_string()];
    let out = triggered_escalations(&rules, &verdicts, &flags);
    assert!(out.is_empty());
}

#[test]
fn synthesize_reports_majority_split_and_avg_score() {
    let results = vec![
        JurorResultSummary { juror_id: "a".to_string(), parsed_ok: true, verdict: "PASS".to_string(), score: 8, ..Default::default() },
        JurorResultSummary { juror_id: "b".to_string(), parsed_ok: true, verdict: "PASS".to_string(), score: 6, ..Default::default() },
        JurorResultSummary { juror_id: "c".to_string(), parsed_ok: true, verdict: "FAIL".to_string(), score: 3, ..Default::default() },
        JurorResultSummary { juror_id: "d".to_string(), parsed_ok: false, verdict: "ERROR".to_string(), ..Default::default() },
    ];
    let synth = synthesize(&results, &[]);
    assert_eq!(synth.majority_verdict, "PASS");
    assert_eq!(synth.majority_count, "2/3");
    assert!((synth.avg_score - 5.7).abs() < 1e-9);
    assert!(synth.split);
    assert!(synth.any_error);
    assert!(!synth.any_degraded);
}

#[test]
fn synthesize_undecided_with_no_parsed_results() {
    let synth = synthesize(&[], &[]);
    assert_eq!(synth.majority_verdict, "UNDECIDED");
    assert_eq!(synth.majority_count, "0/0");
    assert_eq!(synth.avg_score, 0.0);
    assert!(!synth.split);
}

// ---------- dual_review.py ----------

#[test]
fn digest_matches_known_sha256() {
    // sha256("hello") is a well-known test vector.
    assert_eq!(
        digest("hello"),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn sum_accounting_treats_missing_summary_as_incomplete() {
    let summaries = vec![
        AccountingSummaryInput { calls: 2, input_tokens: 10, output_tokens: 5, total_tokens: 15, usage_complete: true, present: true },
        AccountingSummaryInput { present: false, ..Default::default() },
    ];
    let out = sum_accounting(&summaries);
    assert_eq!(out.calls, 2);
    assert_eq!(out.total_tokens, 15);
    assert!(!out.usage_complete);
}

#[test]
fn sum_accounting_complete_only_when_every_summary_complete() {
    let summaries = vec![
        AccountingSummaryInput { calls: 1, usage_complete: true, present: true, ..Default::default() },
        AccountingSummaryInput { calls: 1, usage_complete: false, present: true, ..Default::default() },
    ];
    let out = sum_accounting(&summaries);
    assert!(!out.usage_complete);
}

#[test]
fn render_blocker_preserves_tier_prefix() {
    let mut obj = serde_json::Map::new();
    obj.insert("tier".to_string(), serde_json::json!("P0"));
    obj.insert("text".to_string(), serde_json::json!("critical issue"));
    assert_eq!(render_blocker(&Blocker::Structured(obj)), "[P0] critical issue");

    let mut obj2 = serde_json::Map::new();
    obj2.insert("text".to_string(), serde_json::json!("no tier field"));
    assert_eq!(render_blocker(&Blocker::Structured(obj2)), "no tier field");

    assert_eq!(render_blocker(&Blocker::Text("legacy string".to_string())), "legacy string");
}

#[test]
fn finding_records_skips_unparsed_jurors_and_empty_claims() {
    let jurors = vec![
        JurorVerdict { juror_id: "unparsed".to_string(), parsed_ok: false, blockers: vec![Blocker::Text("x".to_string())] },
        JurorVerdict { juror_id: "empty".to_string(), parsed_ok: true, blockers: vec![Blocker::Text("   ".to_string())] },
        JurorVerdict { juror_id: "good".to_string(), parsed_ok: true, blockers: vec![Blocker::Text("real finding".to_string())] },
    ];
    let findings = finding_records(&jurors);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].author_seat, "good");
    assert_eq!(findings[0].claim, "real finding");
    assert_eq!(findings[0].severity, "P1");
    assert!(findings[0].finding_id.starts_with("finding_"));
}

#[test]
fn finding_records_are_stable_and_unique_per_author_index_claim() {
    let jurors = vec![JurorVerdict {
        juror_id: "j".to_string(),
        parsed_ok: true,
        blockers: vec![Blocker::Text("a".to_string()), Blocker::Text("b".to_string())],
    }];
    let f1 = finding_records(&jurors);
    let f2 = finding_records(&jurors);
    assert_eq!(f1[0].finding_id, f2[0].finding_id); // stable across calls
    assert_ne!(f1[0].finding_id, f1[1].finding_id); // unique per entry
}

#[test]
fn finding_records_uses_structured_fields_when_present() {
    let mut obj = serde_json::Map::new();
    obj.insert("text".to_string(), serde_json::json!("structured claim"));
    obj.insert("tier".to_string(), serde_json::json!("P0"));
    obj.insert("rationale".to_string(), serde_json::json!("because reasons"));
    obj.insert("proposed_change".to_string(), serde_json::json!("do the fix"));
    obj.insert("confidence".to_string(), serde_json::json!(0.9));
    let jurors = vec![JurorVerdict {
        juror_id: "j".to_string(),
        parsed_ok: true,
        blockers: vec![Blocker::Structured(obj)],
    }];
    let findings = finding_records(&jurors);
    assert_eq!(findings[0].severity, "P0");
    assert_eq!(findings[0].rationale, "because reasons");
    assert_eq!(findings[0].proposed_change, "do the fix");
    assert_eq!(findings[0].confidence, Some(serde_json::json!(0.9)));
}

// ---------- health_check.py ----------

#[test]
fn enumerate_models_notes_primary_and_fallback_seats() {
    let mut cfg = ModelsConfig::default();
    cfg.panels.insert(
        "jury".to_string(),
        vec![JurorSpec {
            id: "j1".to_string(),
            provider: "openai".to_string(),
            model: "gpt-x".to_string(),
            fallbacks: vec![("anthropic".to_string(), "claude-x".to_string())],
        }],
    );
    cfg.skills.insert(
        "review-code".to_string(),
        (
            vec![JurorSpec {
                id: "s1".to_string(),
                provider: "openai".to_string(),
                model: "gpt-x".to_string(),
                fallbacks: vec![],
            }],
            vec![EscalationSpec { provider: Some("groq".to_string()), model: Some("k2".to_string()) }],
        ),
    );
    let models = enumerate_models(&cfg);
    let openai = models.get(&("openai".to_string(), "gpt-x".to_string())).unwrap();
    assert_eq!(openai.primary_seats, vec!["panel:jury:j1".to_string(), "review-code:s1".to_string()]);
    let fallback = models.get(&("anthropic".to_string(), "claude-x".to_string())).unwrap();
    assert_eq!(fallback.fallback_seats, vec!["panel:jury:j1.fb".to_string()]);
    let escalation = models.get(&("groq".to_string(), "k2".to_string())).unwrap();
    assert!(escalation.primary_seats.is_empty());
    assert_eq!(escalation.fallback_seats, vec!["review-code:escalation".to_string()]);
}

#[test]
fn classify_ok_truncates_and_trims_detail() {
    let result = classify(&ProbeOutcome::Ok { raw: Some("  ok  ".to_string()), latency_ms: 12 });
    assert_eq!(result, ClassifyResult { status: "ok".to_string(), http: None, detail: "ok".to_string(), latency_ms: Some(12) });
}

#[test]
fn classify_kinds_from_provider_error() {
    let not_found = classify(&ProbeOutcome::ProviderError {
        status: Some(404),
        is_quota: false,
        message: "model not found".to_string(),
        latency_ms: 5,
    });
    assert_eq!(not_found.status, "unreachable");

    let auth = classify(&ProbeOutcome::ProviderError {
        status: Some(401),
        is_quota: false,
        message: "unauthorized".to_string(),
        latency_ms: 5,
    });
    assert_eq!(auth.status, "auth");

    let busy = classify(&ProbeOutcome::ProviderError {
        status: Some(429),
        is_quota: false,
        message: "rate limited".to_string(),
        latency_ms: 5,
    });
    assert_eq!(busy.status, "busy");

    let no_key = classify(&ProbeOutcome::ProviderError {
        status: None,
        is_quota: false,
        message: "no API key configured".to_string(),
        latency_ms: 5,
    });
    assert_eq!(no_key.status, "no_key");

    let other = classify(&ProbeOutcome::ProviderError {
        status: Some(500),
        is_quota: false,
        message: "server exploded".to_string(),
        latency_ms: 5,
    });
    assert_eq!(other.status, "error");
}

#[test]
fn classify_no_provider_and_other_exception() {
    let np = classify(&ProbeOutcome::NoProvider);
    assert_eq!(np.status, "no_provider");

    let other = classify(&ProbeOutcome::Other { type_name: "ValueError".to_string(), message: "boom".to_string() });
    assert_eq!(other.status, "error");
    assert_eq!(other.detail, "ValueError: boom");
}

#[test]
fn primary_broken_filters_primary_unreachable_only() {
    let rows = vec![
        ModelRow { primary: true, status: "unreachable".to_string() },
        ModelRow { primary: false, status: "unreachable".to_string() }, // fallback-only: not counted
        ModelRow { primary: true, status: "ok".to_string() },
        ModelRow { primary: true, status: "auth".to_string() },
    ];
    let broken = primary_broken(&rows);
    assert_eq!(broken.len(), 2);
}

// ---------- jury.py ----------

#[test]
fn parse_flag_coerces_bool_int_and_string() {
    let (k, v) = parse_flag("irreversible=true");
    assert_eq!(k, "irreversible");
    assert_eq!(v, serde_json::json!(true));

    let (k, v) = parse_flag("skip=0");
    assert_eq!(k, "skip");
    assert_eq!(v, serde_json::json!(false));

    let (k, v) = parse_flag("retries=3");
    assert_eq!(k, "retries");
    assert_eq!(v, serde_json::json!(3));

    let (k, v) = parse_flag("mode=strict");
    assert_eq!(k, "mode");
    assert_eq!(v, serde_json::json!("strict"));

    let (k, v) = parse_flag("bare_flag");
    assert_eq!(k, "bare_flag");
    assert_eq!(v, serde_json::json!(true));
}

// ---------- dual_review.py: peer-debate protocol (packet r58) ----------

#[test]
fn rebuttal_instruction_concatenates_peer_debate_and_required_contest() {
    assert_eq!(
        rebuttal_instruction(),
        format!("{PEER_DEBATE_INSTRUCTION}{REQUIRED_CONTEST_INSTRUCTION}")
    );
}

#[test]
fn contest_record_v_requires_finding_id_rationale_and_list_evidence_refs() {
    let ok = serde_json::json!({"text": "x", "contest": {"finding_id": "f1", "rationale": "wrong", "evidence_refs": []}});
    assert!(contest_record_v(&ok).is_some());

    let missing_id = serde_json::json!({"contest": {"finding_id": "", "rationale": "wrong"}});
    assert!(contest_record_v(&missing_id).is_none());

    let blank_rationale = serde_json::json!({"contest": {"finding_id": "f1", "rationale": "  "}});
    assert!(contest_record_v(&blank_rationale).is_none());

    let no_contest = serde_json::json!({"text": "x"});
    assert!(contest_record_v(&no_contest).is_none());

    let bad_refs = serde_json::json!({"contest": {"finding_id": "f1", "rationale": "r", "evidence_refs": "nope"}});
    assert!(contest_record_v(&bad_refs).is_none());
}

#[test]
fn resolution_record_v_requires_valid_choice_id_and_reason() {
    let concede = serde_json::json!({"resolution": {"finding_id": "f1", "choice": "concede", "reason": "moved me", "evidence_refs": []}});
    assert!(resolution_record_v(&concede).is_some());

    let bad_choice = serde_json::json!({"resolution": {"finding_id": "f1", "choice": "shrug", "reason": "r"}});
    assert!(resolution_record_v(&bad_choice).is_none());

    let blank_reason = serde_json::json!({"resolution": {"finding_id": "f1", "choice": "sustain", "reason": ""}});
    assert!(resolution_record_v(&blank_reason).is_none());
}

#[test]
fn is_adoption_matches_exact_and_40_char_prefix_case_insensitively() {
    let peers = vec!["The retry loop never bounds its attempts and can spin forever".to_string()];
    assert!(is_adoption(
        "the retry loop never bounds its attempts and can spin forever",
        &peers
    ));
    // 40-char-prefix containment, embedded in a longer restated sentence.
    assert!(is_adoption(
        "well, the retry loop never bounds its attempts to be honest",
        &peers
    ));
    assert!(!is_adoption("totally unrelated claim", &peers));
    assert!(!is_adoption("", &peers));
}

#[test]
fn strip_unsupported_adoptions_discards_unsupported_restatement_keeps_contest_and_supported() {
    let advisory = serde_json::json!({
        "jurors": [
            {"juror_id": "seatA", "parsed_ok": true, "blockers": [
                {"text": "The retry loop never bounds its attempts and can spin forever"}
            ]}
        ]
    });
    let mut rebuttal = serde_json::json!({
        "jurors": [
            {"juror_id": "seatB", "parsed_ok": true, "blockers": [
                {"text": "The retry loop never bounds its attempts and can spin forever"},
                {"text": "On re-read, the retry loop never bounds its attempts and can spin forever"},
                {"text": "unrelated", "contest": {"finding_id": "f1", "rationale": "weak", "evidence_refs": []}}
            ]}
        ]
    });
    strip_unsupported_adoptions(&mut rebuttal, &advisory);
    let juror = &rebuttal["jurors"][0];
    let kept = juror["blockers"].as_array().unwrap();
    assert_eq!(kept.len(), 2, "unsupported restatement dropped, supported + contest kept");
    let discarded = juror["discarded_adoptions"].as_array().unwrap();
    assert_eq!(discarded.len(), 1);
}

#[test]
fn contest_audit_v_flags_herding_when_not_all_seats_contest() {
    let rebuttal = serde_json::json!({
        "jurors": [
            {"juror_id": "seatA", "parsed_ok": true, "blockers": [
                {"text": "x", "contest": {"finding_id": "f1", "rationale": "r", "evidence_refs": []}}
            ]},
            {"juror_id": "seatB", "parsed_ok": true, "blockers": []},
            {"juror_id": "seatC", "parsed_ok": false, "error": "wedged"}
        ]
    });
    let audit = contest_audit_v(&rebuttal);
    assert_eq!(audit["answering_seats"], 2);
    assert_eq!(audit["contesting_seats"], 1);
    assert_eq!(audit["total_seats"], 3);
    assert_eq!(audit["failed_seats"], serde_json::json!(["seatC"]));
    assert_eq!(audit["non_contesting_seats"], serde_json::json!(["seatB"]));
    assert_eq!(audit["herding_suspected"], true);
    assert_eq!(audit["fully_compliant"], false);
}

#[test]
fn contests_by_target_routes_via_finding_index_and_skips_self_contest() {
    let rebuttal = serde_json::json!({
        "finding_index": {"f1": {"author_seat": "seatB", "claim": "c"}},
        "jurors": [
            {"juror_id": "seatA", "parsed_ok": true, "blockers": [
                {"text": "x", "contest": {"finding_id": "f1", "rationale": "weak", "evidence_refs": []}}
            ]},
            {"juror_id": "seatB", "parsed_ok": true, "blockers": [
                {"text": "y", "contest": {"finding_id": "does-not-exist", "rationale": "n/a", "evidence_refs": []}}
            ]}
        ]
    });
    let routed = contests_by_target(&rebuttal);
    assert!(routed.contains_key("seatB"));
    assert_eq!(routed["seatB"].as_array().unwrap().len(), 1);
    assert_eq!(routed["seatB"][0]["from"], "seatA");
    assert!(!routed.contains_key("seatA"));
}

#[test]
fn resolution_audit_v_counts_conceded_sustained_and_unanswered() {
    let response = serde_json::json!({
        "routed_contests": {
            "seatB": [{"from": "seatA", "finding_id": "f1", "rationale": "r", "evidence_refs": []}],
            "seatC": [{"from": "seatA", "finding_id": "f2", "rationale": "r", "evidence_refs": []}]
        },
        "jurors": [
            {"juror_id": "seatB", "parsed_ok": true, "blockers": [
                {"text": "x", "resolution": {"finding_id": "f1", "choice": "concede", "reason": "fair", "evidence_refs": []}}
            ]},
            {"juror_id": "seatC", "parsed_ok": true, "blockers": [
                {"text": "y", "resolution": {"finding_id": "f2", "choice": "sustain", "reason": "see line 40", "evidence_refs": ["file.rs:40"]}}
            ]}
        ]
    });
    let audit = resolution_audit_v(&response);
    assert_eq!(audit["conceded_count"], 1);
    assert_eq!(audit["sustained_count"], 1);
    assert_eq!(audit["unanswered_count"], 0);
    assert_eq!(audit["open_contests"], 0);
    assert_eq!(audit["all_contests_resolved"], true);
}

#[test]
fn resolution_audit_v_unanswered_when_contested_seat_missing() {
    let response = serde_json::json!({
        "routed_contests": {
            "seatB": [{"from": "seatA", "finding_id": "f1", "rationale": "r", "evidence_refs": []}]
        },
        "jurors": []
    });
    let audit = resolution_audit_v(&response);
    assert_eq!(audit["unanswered_count"], 1);
    assert_eq!(audit["all_contests_resolved"], false);
}

#[test]
fn resolution_audit_v_legacy_fixture_without_router_envelope() {
    let response = serde_json::json!({
        "jurors": [
            {"juror_id": "seatB", "parsed_ok": true, "blockers": [
                {"text": "x", "resolution": {"finding_id": "f1", "choice": "concede", "reason": "fair", "evidence_refs": []}}
            ]},
            {"juror_id": "seatD", "parsed_ok": false, "error": "wedged"}
        ]
    });
    let audit = resolution_audit_v(&response);
    assert_eq!(audit["conceded_count"], 1);
    assert_eq!(audit["unanswered_count"], 1);
}

#[test]
fn position_shifts_v_reports_verdict_delta_and_score_delta() {
    let advisory = serde_json::json!({
        "jurors": [
            {"juror_id": "seatA", "parsed_ok": true, "verdict": "PASS", "score": 7}
        ]
    });
    let rebuttal = serde_json::json!({
        "jurors": [
            {"juror_id": "seatA", "parsed_ok": true, "verdict": "FAIL", "score": 4, "top_concern": "retry loop"}
        ]
    });
    let shifts = position_shifts_v(&advisory, &rebuttal);
    let shift = &shifts[0];
    assert_eq!(shift["juror_id"], "seatA");
    assert_eq!(shift["verdict_before"], "PASS");
    assert_eq!(shift["verdict_after"], "FAIL");
    assert_eq!(shift["changed"], true);
    assert_eq!(shift["score_delta"], -3.0);
    assert_eq!(shift["top_concern_after"], "retry loop");
}

#[test]
fn peer_positions_block_excludes_own_seat_and_projects_stable_fields() {
    let advisory = serde_json::json!({
        "jurors": [
            {"juror_id": "seatA", "blockers": ["missing null check"]},
            {"juror_id": "seatB", "blockers": ["off-by-one in loop"]}
        ]
    });
    let block = peer_positions_block(&advisory, "seatA");
    assert!(block.contains("### Peer finding"));
    assert!(block.contains("off-by-one in loop"));
    assert!(!block.contains("missing null check"));
}

#[test]
fn synthesize_combined_notes_disagreement_and_defaults_to_undecided() {
    let council = serde_json::json!({"synthesis": {"majority_verdict": "PASS"}});
    let jury = serde_json::json!({"synthesis": {"majority_verdict": "FAIL"}});
    let combined = synthesize_combined(&council, &jury);
    assert_eq!(combined["decision"], "FAIL");
    assert_eq!(combined["council_majority"], "PASS");
    assert_eq!(combined["jury_majority"], "FAIL");
    let notes = combined["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 1);
    assert!(notes[0].as_str().unwrap().contains("advisory=PASS vs verdict=FAIL"));

    let empty_jury = serde_json::json!({});
    let combined2 = synthesize_combined(&council, &empty_jury);
    assert_eq!(combined2["decision"], "UNDECIDED");
}

#[test]
fn render_cli_result_route_dispatches_room_notification_delivered_and_render() {
    let notify = serde_json::json!({
        "status": "room_active",
        "user_notification": {"required": true, "message": "Room link: https://example.invalid/room/1"}
    });
    match render_cli_result_route(&notify) {
        CliResultRoute::RoomNotificationRequired(text) => {
            assert!(text.starts_with("MANDATORY USER NOTIFICATION\n"));
            assert!(text.contains("Room link: https://example.invalid/room/1"));
            assert!(text.contains("--ack-room-link-delivered"));
        }
        other => panic!("expected RoomNotificationRequired, got {other:?}"),
    }

    let delivered = serde_json::json!({"status": "room_active"});
    assert_eq!(render_cli_result_route(&delivered), CliResultRoute::RoomLinkDelivered);

    let normal = serde_json::json!({"jury": {"result": {"verdict": "PASS"}}});
    match render_cli_result_route(&normal) {
        CliResultRoute::NeedsRender(payload) => assert_eq!(payload["verdict"], "PASS"),
        other => panic!("expected NeedsRender, got {other:?}"),
    }
}
