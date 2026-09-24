//! Port of `topology_errors()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~2435-3097).

use super::labels::path_re;
use super::route_scan::label_value;
use super::tables::table_rows;
use crate::wf_port::w2_045::path_utils::normalized_path;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

fn broad_all_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Lookaround-free reimplementation of `(?<![\w-])--all(?:\s|$)`.
    RE.get_or_init(|| Regex::new(r"(?i)--all(?:\s|$)").unwrap())
}

fn has_broad_all(haystack: &str) -> bool {
    for m in broad_all_re().find_iter(haystack) {
        let start = m.start();
        let preceded_ok = match haystack[..start].chars().next_back() {
            Some(c) => !(c.is_alphanumeric() || c == '_' || c == '-'),
            None => true,
        };
        if preceded_ok {
            return true;
        }
    }
    false
}

fn wildcard_corpus_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)--candidates?(?:-from)?\s+["']?\*|--corpus\s+(?:all|full)\b"#).unwrap()
    })
}

fn fence_bodies(text: &str) -> Vec<&str> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?s)```[^\n]*\n(.*?)\n```").unwrap());
    re.captures_iter(text).map(|c| c.get(1).unwrap().as_str()).collect()
}

struct StageEntry {
    row: Vec<String>,
    max_inputs: Option<i64>,
    max_jobs: Option<i64>,
    survivor_path: String,
    actual_path: String,
    selector: String,
}

struct TypedEntry {
    provider_name: String,
    dataset: String,
    mode: String,
    estimated_runs: Option<i64>,
    min_wall_ms: Option<i64>,
}

/// Port of `topology_errors()`.
pub fn topology_errors(text: &str, allow_template: bool) -> Vec<String> {
    if allow_template {
        return Vec::new();
    }
    let mut errors = Vec::new();

    let topology = label_value(text, "**Topology mode:**").unwrap_or_default().trim().to_uppercase();
    let allowed_topologies: BTreeSet<&str> =
        ["SELECTION_FUNNEL", "FULL_COMPARATIVE_DATASET", "SINGLE_PATH"].into_iter().collect();
    if !allowed_topologies.contains(topology.as_str()) {
        errors.push(
            "**Topology mode:** must be SELECTION_FUNNEL, FULL_COMPARATIVE_DATASET, or SINGLE_PATH".to_string(),
        );
    }

    let authorization = label_value(text, "**Full-matrix authorization:**").unwrap_or_default();
    static FULL_AUTH_RE: OnceLock<Regex> = OnceLock::new();
    let full_auth_re = FULL_AUTH_RE.get_or_init(|| {
        Regex::new(r"(?i)^FULL_COMPARATIVE_DATASET_AUTHORIZED:\s*SOURCE:(?:USER_REQUEST|AUTHORITATIVE_SPEC:[^;]+)\s*;\s*REASON:\s*\S").unwrap()
    });
    static NOT_AUTHORIZED_RE: OnceLock<Regex> = OnceLock::new();
    let not_authorized_re = NOT_AUTHORIZED_RE.get_or_init(|| Regex::new(r"(?i)^NOT_AUTHORIZED:\s*\S").unwrap());
    if topology == "FULL_COMPARATIVE_DATASET" {
        if !full_auth_re.is_match(&authorization) {
            errors.push(
                "full comparative dataset requires FULL_COMPARATIVE_DATASET_AUTHORIZED with SOURCE:USER_REQUEST or SOURCE:AUTHORITATIVE_SPEC:<path> plus REASON"
                    .to_string(),
            );
        }
    } else if !not_authorized_re.is_match(&authorization) {
        errors.push("non-comparative topology requires NOT_AUTHORIZED with exact reason".to_string());
    }

    let value_rule = label_value(text, "**Value-of-information rule:**").unwrap_or_default();
    static RUN_ONLY_IF_RE: OnceLock<Regex> = OnceLock::new();
    let run_only_if_re = RUN_ONLY_IF_RE.get_or_init(|| Regex::new(r"(?i)\bRUN_ONLY_IF:\s*\S").unwrap());
    static SKIP_RE: OnceLock<Regex> = OnceLock::new();
    let skip_re = SKIP_RE.get_or_init(|| Regex::new(r"(?i)\bSKIP:\s*\S").unwrap());
    if !(run_only_if_re.is_match(&value_rule) && skip_re.is_match(&value_rule)) {
        errors.push("**Value-of-information rule:** requires RUN_ONLY_IF and SKIP decisions".to_string());
    }

    let ceiling_raw = label_value(text, "**Declared launch ceiling:**").unwrap_or_default();
    static CEILING_RE: OnceLock<Regex> = OnceLock::new();
    let ceiling_re = CEILING_RE.get_or_init(|| Regex::new(r"(?i)^JOB_TOTAL_MAX:\s*(\d+)$").unwrap());
    let declared_total: Option<i64> = ceiling_re
        .captures(&ceiling_raw)
        .and_then(|c| c.get(1).unwrap().as_str().parse().ok());
    if declared_total.is_none_or(|v| v < 1) {
        errors.push("**Declared launch ceiling:** requires positive JOB_TOTAL_MAX integer".to_string());
    }

    let wall_total_raw = label_value(text, "**Declared minimum wall time:**").unwrap_or_default();
    static WALL_TOTAL_RE: OnceLock<Regex> = OnceLock::new();
    let wall_total_re = WALL_TOTAL_RE.get_or_init(|| Regex::new(r"(?i)^MIN_WALL_MS_TOTAL:\s*(\d+)$").unwrap());
    let declared_wall_total: Option<i64> = wall_total_re
        .captures(&wall_total_raw)
        .and_then(|c| c.get(1).unwrap().as_str().parse().ok());
    if declared_wall_total.is_none_or(|v| v < 1) {
        errors.push("**Declared minimum wall time:** requires positive MIN_WALL_MS_TOTAL integer".to_string());
    }

    let estimate_status = label_value(text, "**Launch estimate status:**").unwrap_or_default();
    if estimate_status.to_uppercase() != "RESOLVED:RUNS_WALL_TIME_CONCURRENCY" {
        errors.push("**Launch estimate status:** must be RESOLVED:RUNS_WALL_TIME_CONCURRENCY".to_string());
    }

    let reconciliation = label_value(text, "**Launch-count reconciliation:**").unwrap_or_default();
    static RECONCILE_RE: OnceLock<Regex> = OnceLock::new();
    let reconcile_re = RECONCILE_RE.get_or_init(|| Regex::new(r"(?i)^RECONCILE:").unwrap());
    let recon_upper = reconciliation.to_uppercase();
    if !(reconcile_re.is_match(&reconciliation)
        && recon_upper.contains("STAGE_ACTUAL_SUM")
        && recon_upper.contains("JOB_TOTAL_MAX")
        && recon_upper.contains("BLOCK_IF_MISMATCH")
        && path_re().is_match(&reconciliation))
    {
        errors.push(
            "**Launch-count reconciliation:** requires STAGE_ACTUAL_SUM, JOB_TOTAL_MAX, BLOCK_IF_MISMATCH, & evidence path"
                .to_string(),
        );
    }

    let supervisor = label_value(text, "**Supervisor topology checkpoint:**").unwrap_or_default();
    static READBACK_RE: OnceLock<Regex> = OnceLock::new();
    let readback_re = READBACK_RE.get_or_init(|| Regex::new(r"(?i)^READBACK_REQUIRED:").unwrap());
    static BEFORE_STAGE_RE: OnceLock<Regex> = OnceLock::new();
    let before_stage_re =
        BEFORE_STAGE_RE.get_or_init(|| Regex::new(r"(?is)\bBEFORE_STAGE:\s*.*\b\d+\b.*\bstage").unwrap());
    static BATCH_SCOPE_RE: OnceLock<Regex> = OnceLock::new();
    let batch_scope_re = BATCH_SCOPE_RE.get_or_init(|| Regex::new(r"(?i)\b(?:batch|scope change)\b").unwrap());
    if !(readback_re.is_match(&supervisor)
        && before_stage_re.is_match(&supervisor)
        && batch_scope_re.is_match(&supervisor))
    {
        errors.push(
            "**Supervisor topology checkpoint:** requires readback plus numeric stage cadence before batch/scope change"
                .to_string(),
        );
    }

    let broad_policy = label_value(text, "**Broad selector policy:**").unwrap_or_default();
    static AUTH_SCOPE_RE: OnceLock<Regex> = OnceLock::new();
    let auth_scope_re = AUTH_SCOPE_RE.get_or_init(|| Regex::new(r"(?i)^AUTHORIZED_SCOPE:\s*\S").unwrap());
    static FORBID_BROAD_RE: OnceLock<Regex> = OnceLock::new();
    let forbid_broad_re = FORBID_BROAD_RE.get_or_init(|| Regex::new(r"(?i)^FORBID_BROAD_SELECTORS:\s*\S").unwrap());
    if topology == "FULL_COMPARATIVE_DATASET" {
        if !auth_scope_re.is_match(&broad_policy) {
            errors.push("full comparative dataset requires AUTHORIZED_SCOPE broad-selector policy".to_string());
        }
    } else if !forbid_broad_re.is_match(&broad_policy) {
        errors.push("selection/single topology requires FORBID_BROAD_SELECTORS policy".to_string());
    }

    let stage_table = table_rows(text, "### Stage decision funnel", "### Typed stage records");
    let stage_rows: Vec<Vec<String>> = stage_table.into_iter().skip(1).filter(|r| r.len() == 10).collect();
    let stage_ids: Vec<String> = stage_rows.iter().map(|r| r[0].trim_matches('`').to_string()).collect();
    {
        let unique: BTreeSet<&String> = stage_ids.iter().collect();
        if unique.len() != stage_ids.len() {
            errors.push("stage decision funnel contains duplicate stage IDs".to_string());
        }
    }

    let expected_gate_types: BTreeMap<&str, &str> = [
        ("TECHNICAL_RUNNABILITY", "TECHNICAL"),
        ("BEHAVIORAL_UTILITY", "BEHAVIORAL"),
        ("PERFORMANCE_SHORTLIST", "PERFORMANCE"),
        ("SAFETY_NEGATIVES", "SAFETY_VALIDATION"),
        ("SYSTEM_INTERFERENCE", "SYSTEM_INTERFERENCE"),
        ("FULL_COMPARATIVE_MATRIX", "FULL_MATRIX"),
        ("SINGLE_PATH_EXECUTION", "SINGLE_PATH"),
    ]
    .into_iter()
    .collect();

    static MAX_INPUTS_RE: OnceLock<Regex> = OnceLock::new();
    let max_inputs_re = MAX_INPUTS_RE.get_or_init(|| Regex::new(r"(?i)\bMAX_INPUTS:\s*(\d+)").unwrap());
    static WORKLOAD_RE: OnceLock<Regex> = OnceLock::new();
    let workload_re = WORKLOAD_RE.get_or_init(|| {
        Regex::new(r"(?i)\bFACTORS:\s*(\d+(?:\s*[xX]\s*\d+)+)\s*;\s*MAX_JOBS:\s*(\d+)\s*;\s*ACTUAL_COUNT:\s*([^;]+)")
            .unwrap()
    });
    static FACTOR_SPLIT_RE: OnceLock<Regex> = OnceLock::new();
    let factor_split_re = FACTOR_SPLIT_RE.get_or_init(|| Regex::new(r"(?i)\s*x\s*").unwrap());
    static SELECTOR_RE: OnceLock<Regex> = OnceLock::new();
    let selector_re = SELECTOR_RE.get_or_init(|| Regex::new(r"(?i)^SELECTOR:\s*\S").unwrap());
    static PASS_IF_RE: OnceLock<Regex> = OnceLock::new();
    let pass_if_re = PASS_IF_RE.get_or_init(|| Regex::new(r"(?i)^PASS_IF:\s*\S").unwrap());
    static SURVIVOR_RE: OnceLock<Regex> = OnceLock::new();
    let survivor_re = SURVIVOR_RE.get_or_init(|| {
        Regex::new(r"(?i)\bSURVIVORS:\s*([^;]+)\s*;\s*ACTUAL_COUNT:\s*([^;]+)").unwrap()
    });

    let mut stage_data: BTreeMap<String, StageEntry> = BTreeMap::new();
    let mut stage_job_sum: i64 = 0;

    for row in &stage_rows {
        let stage_id = row[0].trim_matches('`').to_string();
        let gate_type = row[1].trim_matches('`').to_uppercase();
        if let Some(expected_gate) = expected_gate_types.get(stage_id.as_str()) {
            if gate_type != *expected_gate {
                errors.push(format!("stage {stage_id} gate type must be {expected_gate}"));
            }
        }
        if !row[2].to_uppercase().contains("QUESTION_") {
            errors.push(format!("stage {stage_id} lacks numbered decision question"));
        }

        let max_inputs: Option<i64> = max_inputs_re
            .captures(&row[3])
            .and_then(|c| c.get(1).unwrap().as_str().parse().ok());
        if max_inputs.is_none_or(|v| v < 1) {
            errors.push(format!("stage {stage_id} requires positive MAX_INPUTS"));
        }

        let workload_match = workload_re.captures(&row[5]);
        let mut max_jobs: Option<i64> = None;
        let mut workload_actual_path = String::new();
        if workload_match.is_none() {
            errors.push(format!("stage {stage_id} workload requires FACTORS, MAX_JOBS, & ACTUAL_COUNT path"));
        } else if let Some(caps) = workload_match {
            let factors: Vec<i64> = factor_split_re
                .split(caps.get(1).unwrap().as_str())
                .filter_map(|v| v.trim().parse().ok())
                .collect();
            let mj: i64 = caps.get(2).unwrap().as_str().parse().unwrap_or(0);
            max_jobs = Some(mj);
            workload_actual_path = caps.get(3).unwrap().as_str().trim().trim_matches('`').to_string();
            let product: i64 = factors.iter().product();
            if product != mj {
                errors.push(format!("stage {stage_id} MAX_JOBS does not equal factor product"));
            }
            if let (Some(mi), Some(first)) = (max_inputs, factors.first()) {
                if *first != mi {
                    errors.push(format!("stage {stage_id} first workload factor must equal MAX_INPUTS"));
                }
            }
            if !path_re().is_match(&workload_actual_path) {
                errors.push(format!("stage {stage_id} ACTUAL_COUNT lacks path"));
            }
            stage_job_sum += mj;
        }

        let selector = row[6].clone();
        if !selector_re.is_match(&selector) {
            errors.push(format!("stage {stage_id} requires exact SELECTOR"));
        }
        if !pass_if_re.is_match(&row[7]) {
            errors.push(format!("stage {stage_id} requires PASS_IF exit gate"));
        }

        let survivor_match = survivor_re.captures(&row[8]);
        let mut survivor_path = String::new();
        let mut survivor_actual_path = String::new();
        if survivor_match.is_none() {
            errors.push(format!("stage {stage_id} requires SURVIVORS & ACTUAL_COUNT paths"));
        } else if let Some(caps) = survivor_match {
            survivor_path = caps.get(1).unwrap().as_str().trim().trim_matches('`').to_string();
            survivor_actual_path = caps.get(2).unwrap().as_str().trim().trim_matches('`').to_string();
            if !path_re().is_match(&survivor_path) {
                errors.push(format!("stage {stage_id} survivor artifact lacks path"));
            }
            if !path_re().is_match(&survivor_actual_path) {
                errors.push(format!("stage {stage_id} survivor ACTUAL_COUNT lacks path"));
            }
            if !workload_actual_path.is_empty()
                && normalized_path(&workload_actual_path, None) != normalized_path(&survivor_actual_path, None)
            {
                errors.push(format!("stage {stage_id} actual-count ledger paths do not match"));
            }
        }

        stage_data.insert(
            stage_id,
            StageEntry {
                row: row.clone(),
                max_inputs,
                max_jobs,
                survivor_path,
                actual_path: survivor_actual_path,
                selector,
            },
        );
    }

    let typed_table = table_rows(text, "### Typed stage records", "### Fixture-stage ownership");
    let typed_rows: Vec<Vec<String>> = typed_table.into_iter().skip(1).filter(|r| r.len() == 10).collect();
    let typed_ids: Vec<String> = typed_rows.iter().map(|r| r[0].trim_matches('`').to_string()).collect();
    if typed_ids != stage_ids {
        errors.push("typed stage records must match stage decision funnel IDs and order".to_string());
    }

    static QUESTION_RE: OnceLock<Regex> = OnceLock::new();
    let question_re = QUESTION_RE.get_or_init(|| Regex::new(r"(?i)\bQUESTION_\d+\b").unwrap());
    static PROVIDER_RE: OnceLock<Regex> = OnceLock::new();
    let provider_re =
        PROVIDER_RE.get_or_init(|| Regex::new(r"(?i)^PROVIDER:([^;]+);\s*REQUIRED_FOR:(QUESTION_\d+):(\S.+)$").unwrap());
    static NO_PROVIDER_RE: OnceLock<Regex> = OnceLock::new();
    let no_provider_re = NO_PROVIDER_RE.get_or_init(|| Regex::new(r"(?i)^NO_PROVIDER:(QUESTION_\d+)\s+\S").unwrap());
    static DATASET_RE: OnceLock<Regex> = OnceLock::new();
    let dataset_re = DATASET_RE.get_or_init(|| Regex::new(r"(?i)^DATASET:\S.+;\s*ROLE:\S").unwrap());
    static MODE_RE: OnceLock<Regex> = OnceLock::new();
    let mode_re = MODE_RE.get_or_init(|| Regex::new(r"(?i)^MODE:([A-Z][A-Z0-9_]*)$").unwrap());
    static ADMIT_IF_RE: OnceLock<Regex> = OnceLock::new();
    let admit_if_re = ADMIT_IF_RE.get_or_init(|| Regex::new(r"(?i)^ADMIT_IF:\S").unwrap());
    static PASS_IF2_RE: OnceLock<Regex> = OnceLock::new();
    let pass_if2_re = PASS_IF2_RE.get_or_init(|| Regex::new(r"(?i)^PASS_IF:\S").unwrap());
    static EXCLUDE_RE: OnceLock<Regex> = OnceLock::new();
    let exclude_re = EXCLUDE_RE.get_or_init(|| Regex::new(r"(?i)^EXCLUDE:\S").unwrap());
    static RUNS_RE: OnceLock<Regex> = OnceLock::new();
    let runs_re = RUNS_RE.get_or_init(|| Regex::new(r"(?i)^ESTIMATED_RUNS:(\d+)$").unwrap());
    static WALL_RE: OnceLock<Regex> = OnceLock::new();
    let wall_re = WALL_RE.get_or_init(|| {
        Regex::new(r"(?i)^WALL_FACTORS:RUNS=(\d+);\s*MS_PER_RUN_MIN=(\d+);\s*MAX_CONCURRENCY=(\d+);\s*MIN_WALL_MS=(\d+)(?:;\s*EVIDENCE:(.+))?$").unwrap()
    });
    static PASS_IF_STRIP_RE: OnceLock<Regex> = OnceLock::new();
    let pass_if_strip_re = PASS_IF_STRIP_RE.get_or_init(|| Regex::new(r"(?i)^PASS_IF:\s*").unwrap());

    let mut typed_data: BTreeMap<String, TypedEntry> = BTreeMap::new();
    let mut stage_wall_sum: i64 = 0;

    for row in &typed_rows {
        let stage_id = row[0].trim_matches('`').to_string();
        let decision = row[1].clone();
        let question_match = question_re.find(&decision);
        if question_match.is_none() {
            errors.push(format!("typed stage {stage_id} lacks numbered decision"));
        }

        let provider = row[2].trim().to_string();
        let provider_match = provider_re.captures(&provider);
        let no_provider = no_provider_re.captures(&provider);
        let mut provider_name = String::new();
        let mut provider_question = String::new();
        if let Some(caps) = &provider_match {
            provider_name = caps.get(1).unwrap().as_str().trim().to_string();
            provider_question = caps.get(2).unwrap().as_str().to_uppercase();
        } else if let Some(caps) = &no_provider {
            provider_question = caps.get(1).unwrap().as_str().to_uppercase();
        } else {
            errors.push(format!(
                "typed stage {stage_id} provider must bind PROVIDER + REQUIRED_FOR or NO_PROVIDER + question"
            ));
        }
        if let Some(qm) = question_match {
            if !provider_question.is_empty() && provider_question != qm.as_str().to_uppercase() {
                errors.push(format!("typed stage {stage_id} provider justification targets wrong question"));
            }
        }

        let dataset = row[3].trim().to_string();
        if !dataset_re.is_match(&dataset) {
            errors.push(format!("typed stage {stage_id} dataset requires DATASET + ROLE"));
        }

        let mode_match = mode_re.captures(row[4].trim());
        let mode = mode_match.map(|c| c.get(1).unwrap().as_str().to_uppercase()).unwrap_or_default();
        if mode.is_empty() {
            errors.push(format!("typed stage {stage_id} requires exact MODE"));
        }
        if !admit_if_re.is_match(&row[5]) {
            errors.push(format!("typed stage {stage_id} requires ADMIT_IF"));
        }
        if !pass_if2_re.is_match(&row[6]) {
            errors.push(format!("typed stage {stage_id} requires PASS_IF"));
        }
        if !exclude_re.is_match(&row[7]) {
            errors.push(format!("typed stage {stage_id} requires explicit EXCLUDE"));
        }

        let estimated_runs: Option<i64> = runs_re
            .captures(row[8].trim())
            .and_then(|c| c.get(1).unwrap().as_str().parse().ok());
        if estimated_runs.is_none_or(|v| v < 1) {
            errors.push(format!("typed stage {stage_id} requires positive ESTIMATED_RUNS"));
        }

        let wall_match = wall_re.captures(row[9].trim());
        let mut min_wall_ms: Option<i64> = None;
        if wall_match.is_none() {
            errors.push(format!("typed stage {stage_id} requires integer WALL_FACTORS"));
        } else if let Some(caps) = wall_match {
            let wall_runs: i64 = caps.get(1).unwrap().as_str().parse().unwrap_or(0);
            let ms_per_run: i64 = caps.get(2).unwrap().as_str().parse().unwrap_or(0);
            let concurrency: i64 = caps.get(3).unwrap().as_str().parse().unwrap_or(0);
            let mwm: i64 = caps.get(4).unwrap().as_str().parse().unwrap_or(0);
            min_wall_ms = Some(mwm);
            let wall_evidence = caps.get(5).map(|m| m.as_str()).unwrap_or("");
            if concurrency < 1 || ms_per_run < 1 {
                errors.push(format!("typed stage {stage_id} wall factors require positive duration + concurrency"));
            } else {
                let computed = (wall_runs * ms_per_run + concurrency - 1) / concurrency;
                if mwm != computed {
                    errors.push(format!("typed stage {stage_id} MIN_WALL_MS does not equal expanded wall-time formula"));
                }
            }
            if let Some(er) = estimated_runs {
                if wall_runs != er {
                    errors.push(format!("typed stage {stage_id} wall RUNS must equal ESTIMATED_RUNS"));
                }
            }
            if !path_re().is_match(wall_evidence) {
                errors.push(format!("typed stage {stage_id} wall factors require evidence path"));
            }
            stage_wall_sum += mwm;
        }

        if let Some(stage) = stage_data.get(&stage_id) {
            if let Some(mj) = stage.max_jobs {
                if estimated_runs != Some(mj) {
                    errors.push(format!("typed stage {stage_id} ESTIMATED_RUNS must equal stage MAX_JOBS"));
                }
            }
            let stage_decision = stage.row.get(2).cloned().unwrap_or_default();
            let stage_question = question_re.find(&stage_decision);
            if let (Some(qm), Some(sq)) = (question_match, stage_question) {
                if qm.as_str().to_uppercase() != sq.as_str().to_uppercase() {
                    errors.push(format!("typed stage {stage_id} decision does not match funnel question"));
                }
            }
            if decision.trim().to_lowercase() != stage_decision.trim().to_lowercase() {
                errors.push(format!("typed stage {stage_id} decision text differs from funnel decision"));
            }
            let typed_pass = pass_if_strip_re.replace(&row[6], "").trim().to_lowercase();
            let funnel_pass = pass_if_strip_re
                .replace(stage.row.get(7).map(|s| s.as_str()).unwrap_or(""), "")
                .trim()
                .to_lowercase();
            if typed_pass != funnel_pass {
                errors.push(format!("typed stage {stage_id} pass rule differs from funnel exit gate"));
            }
        }

        typed_data.insert(
            stage_id,
            TypedEntry {
                provider_name,
                dataset,
                mode,
                estimated_runs,
                min_wall_ms,
            },
        );
    }
    if let Some(dt) = declared_total {
        if stage_job_sum != dt {
            errors.push(format!("JOB_TOTAL_MAX {dt} does not equal stage MAX_JOBS sum {stage_job_sum}"));
        }
    }
    if let Some(dwt) = declared_wall_total {
        if stage_wall_sum != dwt {
            errors.push(format!("MIN_WALL_MS_TOTAL {dwt} does not equal typed stage wall sum {stage_wall_sum}"));
        }
    }

    if topology == "SELECTION_FUNNEL" {
        let required_order = [
            "TECHNICAL_RUNNABILITY",
            "BEHAVIORAL_UTILITY",
            "PERFORMANCE_SHORTLIST",
            "SAFETY_NEGATIVES",
            "SYSTEM_INTERFERENCE",
        ];
        if stage_ids != required_order {
            errors.push(format!(
                "selection funnel requires exact ordered stages: {}",
                required_order.join(" -> ")
            ));
        }
        for (index, stage_id) in required_order.iter().enumerate() {
            let current = match stage_data.get(*stage_id) {
                Some(c) => c,
                None => continue,
            };
            let row = &current.row;
            let selector_text = &current.selector;
            if has_broad_all(selector_text) {
                errors.push(format!("stage {stage_id} selector contains forbidden broad --all"));
            }
            if wildcard_corpus_re().is_match(selector_text) {
                errors.push(format!("stage {stage_id} selector contains wildcard/full-corpus scope"));
            }
            if index == 0 {
                static ALL_CANDIDATES_RE: OnceLock<Regex> = OnceLock::new();
                let re = ALL_CANDIDATES_RE.get_or_init(|| Regex::new(r"(?i)\bALL_CANDIDATES\b").unwrap());
                if !re.is_match(&row[3]) {
                    errors.push("TECHNICAL_RUNNABILITY input must be ALL_CANDIDATES".to_string());
                }
                static START_RE: OnceLock<Regex> = OnceLock::new();
                let start_re = START_RE.get_or_init(|| Regex::new(r"(?i)^START:\s*\S").unwrap());
                if !start_re.is_match(&row[4]) {
                    errors.push("TECHNICAL_RUNNABILITY entry gate must be START".to_string());
                }
            } else {
                let prior_id = required_order[index - 1];
                let prior = stage_data.get(prior_id);
                let expected_source = format!("SURVIVORS_FROM:{prior_id}");
                if !row[3].to_uppercase().contains(&expected_source) {
                    errors.push(format!("stage {stage_id} must consume {expected_source}"));
                }
                let pass_from_re = Regex::new(&format!(r"(?i)^PASS_FROM:{}\b", regex::escape(prior_id))).unwrap();
                if !pass_from_re.is_match(&row[4]) {
                    errors.push(format!("stage {stage_id} entry gate must PASS_FROM:{prior_id}"));
                }
                let prior_path = prior.map(|p| p.survivor_path.as_str()).unwrap_or("");
                let prior_key = prior_path.replace('\\', "/").to_lowercase();
                let selector_key = current.selector.replace('\\', "/").to_lowercase();
                if !prior_key.is_empty() && !selector_key.contains(&prior_key) {
                    errors.push(format!("stage {stage_id} selector must use upstream survivor artifact"));
                }
                if let (Some(pm), Some(cm)) = (prior.and_then(|p| p.max_inputs), current.max_inputs) {
                    if cm > pm {
                        errors.push(format!("stage {stage_id} MAX_INPUTS exceeds upstream population"));
                    }
                }
            }

            if index < required_order.len() - 1 {
                let expected_prohibition = format!("PROHIBITED_UNTIL:{stage_id}:PASS");
                if !row[9].to_uppercase().contains(&expected_prohibition) {
                    errors.push(format!("stage {stage_id} downstream gate must be {expected_prohibition}"));
                }
            } else {
                static TERMINAL_RE: OnceLock<Regex> = OnceLock::new();
                let re = TERMINAL_RE.get_or_init(|| Regex::new(r"(?i)^TERMINAL:\s*\S").unwrap());
                if !re.is_match(&row[9]) {
                    errors.push("SYSTEM_INTERFERENCE downstream state must be TERMINAL".to_string());
                }
            }
        }

        let fenced = fence_bodies(text).join("\n");
        if has_broad_all(&fenced) {
            errors.push("selection funnel command contains forbidden broad --all selector".to_string());
        }
        if wildcard_corpus_re().is_match(&fenced) {
            errors.push("selection funnel command contains wildcard/full-corpus selector".to_string());
        }
    } else if topology == "FULL_COMPARATIVE_DATASET" {
        if stage_ids != ["FULL_COMPARATIVE_MATRIX"] {
            errors.push("full comparative dataset requires one FULL_COMPARATIVE_MATRIX stage".to_string());
        }
    } else if topology == "SINGLE_PATH" && stage_ids != ["SINGLE_PATH_EXECUTION"] {
        errors.push("single-path topology requires one SINGLE_PATH_EXECUTION stage".to_string());
    }

    let requirement_trace = table_rows(text, "### Requirement-to-decision trace", "### Model, tool & dependency relevance");
    for row in requirement_trace.iter().skip(1) {
        if row.len() != 6 {
            continue;
        }
        let requirement_id = row[0].trim_matches('`');
        let requirement_class = row[1].trim_matches('`');
        let owner = row[3].trim_matches('`');
        if matches!(requirement_class, "ACCEPTANCE" | "EXECUTION_INPUT") {
            if !stage_ids.iter().any(|s| s == owner) {
                errors.push(format!("requirement {requirement_id} lacks declared stage owner"));
            }
        } else if owner != "NONE" && !stage_ids.iter().any(|s| s == owner) {
            errors.push(format!("requirement {requirement_id} has invalid stage owner"));
        }
    }

    let inherited_table = table_rows(text, "### Inherited instruction disposition", "## 1C. Goal Route & Critical Path");
    for row in inherited_table.iter().skip(1) {
        if row.len() != 6 {
            continue;
        }
        let clause_id = row[0].trim_matches('`');
        let owner = row[4].trim_matches('`');
        if owner != "NONE" && !stage_ids.iter().any(|s| s == owner) {
            errors.push(format!("inherited clause {clause_id} has undeclared stage owner"));
        }
    }

    let fixture_table = table_rows(text, "### Fixture-stage ownership", "### Stage command bindings");
    let fixture_rows: Vec<Vec<String>> = fixture_table.into_iter().skip(1).filter(|r| r.len() == 7).collect();
    let fixture_ids: Vec<String> = fixture_rows.iter().map(|r| r[0].trim_matches('`').to_string()).collect();
    {
        let unique: BTreeSet<&String> = fixture_ids.iter().collect();
        if unique.len() != fixture_ids.len() {
            errors.push("fixture-stage ownership contains duplicate fixture IDs".to_string());
        }
    }
    static SOURCE_TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    let source_token_re = SOURCE_TOKEN_RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_.:-]{4,}$").unwrap());
    static RUN_ONLY_ENTRY_RE_TMPL: &str = r"(?i)^RUN_ONLY_IF:{}:ENTRY_PASS\b";
    static FORBID_NONE_RE: OnceLock<Regex> = OnceLock::new();
    let forbid_none_re = FORBID_NONE_RE.get_or_init(|| Regex::new(r"(?i)^(?:FORBID:|NONE_AUTHORIZED:)\s*\S").unwrap());

    for row in &fixture_rows {
        let fixture_id = row[0].trim_matches('`');
        let owner = row[2].trim_matches('`');
        if !stage_ids.iter().any(|s| s == owner) {
            errors.push(format!("fixture {fixture_id} owner is not a declared stage: {owner}"));
        }
        if !(path_re().is_match(&row[1]) || source_token_re.is_match(&row[1])) {
            errors.push(format!("fixture {fixture_id} lacks exact source"));
        }
        let re = Regex::new(&RUN_ONLY_ENTRY_RE_TMPL.replace("{}", &regex::escape(owner))).unwrap();
        if !re.is_match(&row[5]) {
            errors.push(format!("fixture {fixture_id} use condition must bind owning stage entry"));
        }
        if !forbid_none_re.is_match(&row[6]) {
            errors.push(format!("fixture {fixture_id} requires forbidden-outside scope"));
        }
    }

    static STAGE_COMMAND_TAG_RE: OnceLock<Regex> = OnceLock::new();
    let stage_command_tag_re =
        STAGE_COMMAND_TAG_RE.get_or_init(|| Regex::new(r"(?mi)^\s*#\s*STAGE_COMMAND:\s*([A-Z][A-Z0-9_]*)\s*$").unwrap());
    let mut command_blocks: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for block in fence_bodies(text) {
        if let Some(caps) = stage_command_tag_re.captures(block) {
            command_blocks
                .entry(caps.get(1).unwrap().as_str().to_uppercase())
                .or_default()
                .push(block);
        }
    }

    static SLEEP_RE: OnceLock<Regex> = OnceLock::new();
    let sleep_re = SLEEP_RE.get_or_init(|| {
        Regex::new(r"(?im)\bStart-Sleep\b|(?:^|\s)sleep(?:\.exe)?(?:\s|$)|\btime\.sleep\s*\(|\bThread\.Sleep\s*\(|\bTask\.Delay\s*\(|\btimeout(?:\.exe)?\s+/t\b|\bWait-Event\b|--(?:real-?time|wall-clock)\b").unwrap()
    });

    for stage_id in &stage_ids {
        let blocks = command_blocks.get(stage_id).cloned().unwrap_or_default();
        if blocks.len() != 1 {
            errors.push(format!("stage {stage_id} requires exactly one STAGE_COMMAND block"));
            continue;
        }
        let block_key = blocks[0].replace('\\', "/").to_lowercase();
        if let Some(stage) = stage_data.get(stage_id) {
            let expected = stage.survivor_path.replace('\\', "/").to_lowercase();
            if !expected.is_empty() && !block_key.contains(&expected) {
                errors.push(format!("stage {stage_id} command lacks declared survivor artifact path"));
            }
            let expected = stage.actual_path.replace('\\', "/").to_lowercase();
            if !expected.is_empty() && !block_key.contains(&expected) {
                errors.push(format!("stage {stage_id} command lacks declared actual-count ledger path"));
            }
        }
        if let Some(typed) = typed_data.get(stage_id) {
            let provider_name = typed.provider_name.to_lowercase();
            if !provider_name.is_empty() && !block_key.contains(&provider_name) {
                errors.push(format!("stage {stage_id} command lacks required provider binding"));
            }
            let mode = &typed.mode;
            if !mode.is_empty() && !block_key.contains(&mode.to_lowercase()) {
                errors.push(format!("stage {stage_id} command lacks declared execution mode"));
            }
            if mode == "OFFLINE_LOGICAL_CHUNKS" && sleep_re.is_match(blocks[0]) {
                errors.push(format!("offline stage {stage_id} command contains physical sleep/realtime pacing"));
            }
        }
    }

    if topology == "SELECTION_FUNNEL" {
        for (index, stage_id) in stage_ids.iter().enumerate() {
            let blocks = command_blocks.get(stage_id).cloned().unwrap_or_default();
            if blocks.len() != 1 {
                continue;
            }
            let block_key = blocks[0].replace('\\', "/").to_lowercase();
            if index > 0 {
                let prior_stage_id = &stage_ids[index - 1];
                let prior_path = stage_data
                    .get(prior_stage_id)
                    .map(|p| p.survivor_path.replace('\\', "/").to_lowercase())
                    .unwrap_or_default();
                if !prior_path.is_empty() && !block_key.contains(&prior_path) {
                    errors.push(format!("stage {stage_id} command does not consume upstream survivor artifact"));
                }
            }
            if has_broad_all(blocks[0]) {
                errors.push(format!("stage {stage_id} command contains forbidden broad --all selector"));
            }
            if wildcard_corpus_re().is_match(blocks[0]) {
                errors.push(format!("stage {stage_id} command contains wildcard/full-corpus selector"));
            }
        }
    }

    for row in &fixture_rows {
        let fixture_id = row[0].trim_matches('`');
        let source = row[1].trim_matches('`');
        let owner = row[2].trim_matches('`');
        let blocks = command_blocks.get(owner).cloned().unwrap_or_default();
        let source_key = source.replace('\\', "/").to_lowercase();
        if blocks.len() == 1 {
            let block_key = blocks[0].replace('\\', "/").to_lowercase();
            if !block_key.contains(&source_key) {
                errors.push(format!("fixture {fixture_id} source is absent from owning stage command"));
            }
            let typed_dataset = typed_data
                .get(owner)
                .map(|t| t.dataset.replace('\\', "/").to_lowercase())
                .unwrap_or_default();
            if !typed_dataset.contains(&source_key) {
                errors.push(format!("fixture {fixture_id} source is absent from owning typed stage dataset"));
            }
        }
        for (other_stage, other_blocks) in &command_blocks {
            if other_stage == owner || other_blocks.len() != 1 {
                continue;
            }
            let other_key = other_blocks[0].replace('\\', "/").to_lowercase();
            if other_key.contains(&source_key) {
                errors.push(format!("fixture {fixture_id} leaks into non-owning stage command {other_stage}"));
            }
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_template_short_circuits() {
        assert!(topology_errors("", true).is_empty());
    }

    #[test]
    fn flags_invalid_topology_mode() {
        let text = "- **Topology mode:** NOT_A_MODE\n";
        let errors = topology_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("Topology mode")));
    }

    #[test]
    fn requires_full_matrix_authorization_for_full_comparative_dataset() {
        let text = "- **Topology mode:** FULL_COMPARATIVE_DATASET\n";
        let errors = topology_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("FULL_COMPARATIVE_DATASET_AUTHORIZED")));
    }

    #[test]
    fn flags_missing_launch_ceiling() {
        let text = "- **Declared launch ceiling:** JOB_TOTAL_MAX: 0\n";
        let errors = topology_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("Declared launch ceiling")));
    }
}
