//! Port of `src/lib/review/synthesizer.py` — renders the council result as
//! a human-readable markdown verdict table.
//!
//! GAP: Python's `_load_lenses()` reads `lenses.yaml` (via `PyYAML`) from
//! disk next to the module, caches it process-wide, and looks up
//! `lens_question` for a juror's `lens` name. This crate has no YAML
//! dependency (`serde_yaml` is a workspace dependency used elsewhere — see
//! the w2_054 report for the Cargo.toml patch if pulling it in here is
//! wanted later). Rather than hand a config load a home in this owned
//! module dir, `render` takes the lens → `lens_question` map as a plain
//! `&BTreeMap<String, String>` parameter; the caller resolves it from
//! `lenses.yaml` (or a compiled-in table) however it likes. Passing an
//! empty map reproduces Python's `_load_lenses()` failing open to `{}`.

use std::collections::BTreeMap;

use serde_json::Value;

/// Pull the lens's headline answer from `answers[lens_question]`, if any.
///
/// Mirrors `_lens_answer`: empty string if the juror has no lens, no
/// `lens_question` is registered for it, or no answer was emitted.
fn lens_answer(juror: &Value, lens_questions: &BTreeMap<String, String>) -> String {
    let lens_name = juror.get("lens").and_then(Value::as_str).unwrap_or("");
    if lens_name.is_empty() {
        return String::new();
    }
    let Some(question) = lens_questions.get(lens_name) else {
        return String::new();
    };
    if question.is_empty() {
        return String::new();
    }
    juror
        .get("answers")
        .and_then(|a| a.get(question))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Normalize a blocker into (tier, text). Mirrors `_tier_and_text`.
///
/// Accepts a dict `{"tier": "P0", "text": "..."}` (new shape), a bare
/// string (legacy), or a `"[P0] text"` legacy prefix. Missing tier
/// defaults to `P1`.
fn tier_and_text(blocker: &Value) -> (String, String) {
    if let Value::Object(map) = blocker {
        let mut tier = map
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or("P1")
            .to_uppercase();
        if !matches!(tier.as_str(), "P0" | "P1" | "P2") {
            tier = "P1".to_string();
        }
        let text = map
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        return (tier, text);
    }
    let text = match blocker {
        Value::String(s) => s.trim().to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    if let Some(rest) = text.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let tier_candidate = rest[..close].trim();
            if matches!(tier_candidate, "P0" | "P1" | "P2") {
                let remainder = rest[close + 1..].trim().to_string();
                return (tier_candidate.to_string(), remainder);
            }
        }
    }
    ("P1".to_string(), text)
}

/// Render the union of all jurors' blockers, grouped by tier. Mirrors
/// `_render_blockers_by_tier`.
///
/// Locked policy 2026-07-14: P0 has no count or length cap (critical,
/// ship-blocker). P1+P2 share a combined 8-cap.
fn render_blockers_by_tier(all_jurors: &[Value]) -> Vec<String> {
    let mut p0: Vec<String> = Vec::new();
    let mut p_rest: Vec<(String, String, String)> = Vec::new(); // (tier, juror, text)
    let mut seen_text: std::collections::HashSet<String> = std::collections::HashSet::new();

    for j in all_jurors {
        let juror = j
            .get("juror_id")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        let blockers = j
            .get("blockers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for blocker in &blockers {
            if blocker.is_null() {
                continue;
            }
            let (tier, text) = tier_and_text(blocker);
            if text.is_empty() {
                continue;
            }
            let key = text.to_lowercase();
            if !seen_text.insert(key) {
                continue;
            }
            if tier == "P0" {
                p0.push(format!("- {text} (from {juror})"));
            } else {
                p_rest.push((tier, juror.clone(), text));
            }
        }
    }

    let mut out: Vec<String> = Vec::new();
    if !p0.is_empty() {
        out.push(format!(
            "### Blockers — P0 (critical, ship-blocker; no count cap; n={})",
            p0.len()
        ));
        out.extend(p0);
    }

    if !p_rest.is_empty() {
        p_rest.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
        let cap = 8usize;
        let kept: Vec<_> = p_rest.iter().take(cap).cloned().collect();
        let dropped = p_rest.len().saturating_sub(cap);
        out.push(format!(
            "### Blockers — P1+P2 (combined cap 8 at ≤200c each; {} shown, {dropped} dropped)",
            kept.len()
        ));
        for (tier, juror, text) in &kept {
            out.push(format!("- [{tier}] {text} (from {juror})"));
        }
        if dropped > 0 {
            let sample = all_jurors
                .first()
                .and_then(|j| j.get("juror_id"))
                .and_then(Value::as_str)
                .unwrap_or("?");
            out.push(format!(
                "_({dropped} more P1/P2 blockers suppressed by shared 8-cap; full list in {sample}.verdict.json)_"
            ));
        }
    }

    out
}

fn char_prefix(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Render the council `result` (a `jury.verdict.json`-shaped payload) as
/// markdown. Mirrors `render`.
///
/// Panics if `result` lacks the required `skill`/`synthesis`/`jurors`
/// fields — mirrors Python's `KeyError` on `result["skill"]` /
/// `result["synthesis"]` / `result["jurors"]` for a malformed payload
/// (both are a fail-loud contract violation, not a recoverable case).
pub fn render(result: &Value, lens_questions: &BTreeMap<String, String>) -> String {
    let mut out: Vec<String> = Vec::new();
    let skill = result
        .get("skill")
        .and_then(Value::as_str)
        .expect("result.skill is required");
    let syn = result
        .get("synthesis")
        .expect("result.synthesis is required");
    let flags = result.get("flags").and_then(Value::as_object);

    // Packet validation (locked 2026-07-14)
    let pv = result.get("packet_validation").and_then(Value::as_object);
    if let Some(pv) = pv.filter(|m| !m.is_empty()) {
        let ok = pv.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let verdict = if ok { "✅ passed" } else { "❌ failed" };
        out.push(format!("## Jury Verdict — `{skill}`  | packet: {verdict}"));
        if let Some(errors) = pv.get("errors").and_then(Value::as_array) {
            if !errors.is_empty() {
                out.push(format!("_packet errors ({}):_", errors.len()));
                for e in errors.iter().take(5) {
                    out.push(format!("  - {}", value_display(e)));
                }
            }
        }
        if let Some(warnings) = pv.get("warnings").and_then(Value::as_array) {
            if !warnings.is_empty() {
                out.push(format!("_packet warnings ({}):_", warnings.len()));
                for w in warnings.iter().take(5) {
                    out.push(format!("  - {}", value_display(w)));
                }
            }
        }
        out.push(String::new());
    } else {
        out.push(format!("## Jury Verdict — `{skill}`"));
    }
    if let Some(flags) = flags.filter(|m| !m.is_empty()) {
        let flag_str = flags
            .iter()
            .map(|(k, v)| format!("`{k}={}`", value_display(v)))
            .collect::<Vec<_>>()
            .join(" ");
        out.push(format!("_flags: {flag_str}_\n"));
    }

    out.push("| Juror | Lens | Provider/Model | Verdict | Score | Top concern | Lens answer | Evidence gap |".to_string());
    out.push("|---|---|---|---|---|---|---|---|".to_string());
    let jurors = result
        .get("jurors")
        .and_then(Value::as_array)
        .expect("result.jurors is required");
    for j in jurors {
        out.push(juror_row(j, lens_questions));
    }

    if let Some(escalation) = result.get("escalation").and_then(Value::as_array) {
        if !escalation.is_empty() {
            out.push("\n### Escalation jurors".to_string());
            out.push("| Juror | Provider/Model | Verdict | Score | Top concern | Latency |".to_string());
            out.push("|---|---|---|---|---|---|".to_string());
            for j in escalation {
                let verdict_raw = j.get("verdict").and_then(Value::as_str).unwrap_or("?");
                let parsed_ok = j.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false);
                let verdict = if !parsed_ok {
                    format!("❌ {verdict_raw}")
                } else {
                    verdict_raw.to_string()
                };
                let model = j.get("model").and_then(Value::as_str).unwrap_or("");
                let model_short = char_prefix(model.rsplit('/').next().unwrap_or(model), 40);
                let juror_id = j.get("juror_id").and_then(Value::as_str).unwrap_or("");
                let provider = j.get("provider").and_then(Value::as_str).unwrap_or("");
                let score = j.get("score").cloned().unwrap_or(Value::from(0));
                let concern = j
                    .get("top_concern")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .or_else(|| j.get("error").and_then(Value::as_str))
                    .unwrap_or("");
                let concern_short = char_prefix(concern, 80);
                let latency = j.get("latency_ms").cloned().unwrap_or(Value::from(0));
                out.push(format!(
                    "| {juror_id} | {provider}/{model_short} | **{verdict}** | {} | {concern_short} | {}ms |",
                    value_display(&score),
                    value_display(&latency),
                ));
            }
        }
    }

    out.push(String::new());
    let majority_verdict = syn
        .get("majority_verdict")
        .and_then(Value::as_str)
        .unwrap_or("");
    let majority_count = syn.get("majority_count").cloned().unwrap_or(Value::Null);
    let avg_score = syn.get("avg_score").cloned().unwrap_or(Value::Null);
    out.push(format!(
        "### Majority: **{majority_verdict}** ({}) | Avg score: {}",
        value_display(&majority_count),
        value_display(&avg_score)
    ));
    let mut notes: Vec<&str> = Vec::new();
    if syn.get("split").and_then(Value::as_bool).unwrap_or(false) {
        notes.push("⚠ split verdict");
    }
    if syn.get("any_degraded").and_then(Value::as_bool).unwrap_or(false) {
        notes.push("⚠ degraded juror used");
    }
    if syn.get("any_error").and_then(Value::as_bool).unwrap_or(false) {
        notes.push("❌ one or more jurors failed");
    }
    if !notes.is_empty() {
        out.push(notes.join(" · "));
    }

    // Blockers, grouped by tier.
    let mut all_jurors: Vec<Value> = jurors.clone();
    if let Some(escalation) = result.get("escalation").and_then(Value::as_array) {
        all_jurors.extend(escalation.iter().cloned());
    }
    let blocker_lines = render_blockers_by_tier(&all_jurors);
    if !blocker_lines.is_empty() {
        out.push(String::new());
        out.extend(blocker_lines);
    }

    out.push("\n_legend: ⚠=degraded ↩=fallback used 💾=cache hit ❌=error_".to_string());
    out.join("\n")
}

fn juror_row(j: &Value, lens_questions: &BTreeMap<String, String>) -> String {
    let mut verdict = j
        .get("verdict")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    if j.get("degraded").and_then(Value::as_bool).unwrap_or(false) {
        verdict.push_str(" ⚠");
    }
    if j.get("fallback_used").and_then(Value::as_bool).unwrap_or(false) {
        verdict.push_str(" ↩");
    }
    if j.get("cache_hit").and_then(Value::as_bool).unwrap_or(false) {
        verdict.push_str(" 💾");
    }
    let parsed_ok = j.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false);
    let cache_hit = j.get("cache_hit").and_then(Value::as_bool).unwrap_or(false);
    if !parsed_ok && !cache_hit {
        verdict = format!("❌ {verdict}");
    }
    let model = j.get("model").and_then(Value::as_str).unwrap_or("");
    let model_short = char_prefix(model.rsplit('/').next().unwrap_or(model), 40);
    let lens = j
        .get("lens")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("-");
    let missing = j
        .get("answers")
        .and_then(|a| a.get("missing_evidence"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let missing_short = if missing.is_empty() {
        String::new()
    } else {
        char_prefix(missing, 80)
    };
    let lens_ans = lens_answer(j, lens_questions);
    let lens_short = if lens_ans.is_empty() {
        "-".to_string()
    } else {
        char_prefix(&lens_ans, 80)
    };
    let juror_id = j.get("juror_id").and_then(Value::as_str).unwrap_or("");
    let provider = j.get("provider").and_then(Value::as_str).unwrap_or("");
    let score = j.get("score").cloned().unwrap_or(Value::from(0));
    let concern = j
        .get("top_concern")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| j.get("error").and_then(Value::as_str))
        .unwrap_or("");
    let concern_short = char_prefix(concern, 80);
    format!(
        "| {juror_id} | {lens} | {provider}/{model_short} | **{verdict}** | {} | {concern_short} | {lens_short} | {missing_short} |",
        value_display(&score),
    )
}

/// Render a JSON scalar the way Python's f-string `{value}` would (numbers
/// without quotes, strings bare, `None` as empty for our uses here).
fn value_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lens_map() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(
            "red_team".to_string(),
            "strongest_known_counterexample".to_string(),
        );
        m
    }

    #[test]
    fn tier_and_text_dict_shape() {
        let b = json!({"tier": "p0", "text": "  bad thing  "});
        assert_eq!(tier_and_text(&b), ("P0".to_string(), "bad thing".to_string()));
    }

    #[test]
    fn tier_and_text_invalid_tier_defaults_p1() {
        let b = json!({"tier": "P9", "text": "x"});
        assert_eq!(tier_and_text(&b), ("P1".to_string(), "x".to_string()));
    }

    #[test]
    fn tier_and_text_legacy_prefix() {
        let b = json!("[P0] critical thing");
        assert_eq!(
            tier_and_text(&b),
            ("P0".to_string(), "critical thing".to_string())
        );
    }

    #[test]
    fn tier_and_text_bare_string() {
        let b = json!("no prefix here");
        assert_eq!(
            tier_and_text(&b),
            ("P1".to_string(), "no prefix here".to_string())
        );
    }

    #[test]
    fn lens_answer_missing_lens_is_empty() {
        let j = json!({"answers": {"strongest_known_counterexample": "x"}});
        assert_eq!(lens_answer(&j, &lens_map()), "");
    }

    #[test]
    fn lens_answer_resolves_question() {
        let j = json!({"lens": "red_team", "answers": {"strongest_known_counterexample": " the answer "}});
        assert_eq!(lens_answer(&j, &lens_map()), "the answer");
    }

    #[test]
    fn render_blockers_p0_no_cap_p_rest_capped_at_8() {
        let mut jurors = Vec::new();
        for i in 0..10 {
            jurors.push(json!({
                "juror_id": format!("j{i}"),
                "blockers": [{"tier": "P1", "text": format!("issue {i}")}],
            }));
        }
        jurors.push(json!({"juror_id": "j0", "blockers": [{"tier": "P0", "text": "critical"}]}));
        let lines = render_blockers_by_tier(&jurors);
        assert!(lines[0].starts_with("### Blockers — P0"));
        assert!(lines.iter().any(|l| l.contains("2 dropped")));
    }

    #[test]
    fn render_blockers_dedupes_case_insensitively() {
        let jurors = vec![
            json!({"juror_id": "a", "blockers": [{"tier": "P1", "text": "Same Issue"}]}),
            json!({"juror_id": "b", "blockers": [{"tier": "P1", "text": "same issue"}]}),
        ];
        let lines = render_blockers_by_tier(&jurors);
        let count = lines.iter().filter(|l| l.contains("same issue") || l.contains("Same Issue")).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn render_full_payload_smoke() {
        let result = json!({
            "skill": "review",
            "packet_validation": {"ok": true},
            "flags": {"strict": true},
            "jurors": [
                {"juror_id": "j1", "provider": "openai", "model": "gpt/foo", "verdict": "APPROVE",
                 "score": 8, "parsed_ok": true, "top_concern": "none", "blockers": []}
            ],
            "escalation": [],
            "synthesis": {"majority_verdict": "APPROVE", "majority_count": 1, "avg_score": 8.0},
        });
        let text = render(&result, &lens_map());
        assert!(text.contains("Jury Verdict"));
        assert!(text.contains("APPROVE"));
        assert!(text.contains("legend"));
    }
}
