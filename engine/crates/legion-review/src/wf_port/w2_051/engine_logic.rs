//! Port of the pure, network-free logic in `src/lib/review/engine.py`.
//!
//! `Engine.run`/`Engine._run_juror`/`Engine._maybe_escalate` orchestrate
//! live HTTP calls through `providers.py`, a YAML `models.yaml` config, and
//! an on-disk response cache — none of which this crate owns or has a Rust
//! counterpart for in this chunk. What ports cleanly, faithfully, and is
//! meaningfully unit-testable without that infrastructure is the
//! deterministic transformation logic: usage normalization/accounting,
//! juror JSON parsing, the nim provider prompt-compaction rewrite,
//! execution-unit grouping, escalation-trigger matching, and verdict
//! synthesis. See `w2_051/README` note in the chunk report for the
//! network-calling gap.

use std::collections::{BTreeMap, HashMap};

use regex::Regex;
use serde_json::{Map, Value};

/// Mirrors `_normalized_usage`: accepts either the `input_tokens`/
/// `output_tokens` or the `prompt_tokens`/`completion_tokens` key spelling,
/// computes `total_tokens` when absent, and returns `None` (Python: `{}`)
/// when any of the three fields cannot be determined — never estimates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
}

pub fn normalized_usage(usage: Option<&Map<String, Value>>) -> Option<Usage> {
    let usage = usage?;
    let get_i64 = |keys: &[&str]| -> Option<i64> {
        for k in keys {
            if let Some(v) = usage.get(*k) {
                return v.as_i64();
            }
        }
        None
    };
    let input_tokens = get_i64(&["input_tokens", "prompt_tokens"]);
    let output_tokens = get_i64(&["output_tokens", "completion_tokens"]);
    let mut total_tokens = usage.get("total_tokens").and_then(|v| v.as_i64());
    if total_tokens.is_none() {
        if let (Some(i), Some(o)) = (input_tokens, output_tokens) {
            total_tokens = Some(i + o);
        }
    }
    match (input_tokens, output_tokens, total_tokens) {
        (Some(input_tokens), Some(output_tokens), Some(total_tokens)) => Some(Usage {
            input_tokens,
            output_tokens,
            total_tokens,
        }),
        _ => None,
    }
}

/// Minimal shape of a `JurorResult` needed by `_accounting`/`_synthesize`.
#[derive(Debug, Clone, Default)]
pub struct JurorResultSummary {
    pub juror_id: String,
    pub call_count: i64,
    pub usage: Usage,
    pub usage_complete: bool,
    pub cache_hit: bool,
    pub parsed_ok: bool,
    pub verdict: String,
    pub score: i64,
    pub degraded: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Accounting {
    pub calls: i64,
    pub usage: Usage,
    pub usage_complete: bool,
    pub cache_hits: i64,
}

/// Port of `_accounting`.
pub fn accounting(results: &[JurorResultSummary]) -> Accounting {
    let mut usage = Usage::default();
    let mut calls = 0i64;
    let mut cache_hits = 0i64;
    let mut usage_complete = true;
    for r in results {
        usage.input_tokens += r.usage.input_tokens;
        usage.output_tokens += r.usage.output_tokens;
        usage.total_tokens += r.usage.total_tokens;
        calls += r.call_count;
        usage_complete = usage_complete && r.usage_complete;
        if r.cache_hit {
            cache_hits += 1;
        }
    }
    Accounting {
        calls,
        usage,
        usage_complete,
        cache_hits,
    }
}

#[derive(Debug, Clone)]
pub struct Synthesis {
    pub majority_verdict: String,
    pub majority_count: String,
    pub avg_score: f64,
    pub split: bool,
    pub any_degraded: bool,
    pub any_error: bool,
}

/// Port of `Engine._synthesize`. `results` and `escalation` are
/// concatenated, matching Python's `list(results) + list(escalation)`.
pub fn synthesize(results: &[JurorResultSummary], escalation: &[JurorResultSummary]) -> Synthesis {
    let all: Vec<&JurorResultSummary> = results.iter().chain(escalation.iter()).collect();
    let parsed: Vec<&&JurorResultSummary> = all.iter().filter(|r| r.parsed_ok).collect();

    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    // Preserve Python `Counter.most_common(1)` tie-break: first-seen order
    // among equally-frequent verdicts wins. BTreeMap loses insertion order,
    // so we track first-seen index separately.
    let mut first_seen: HashMap<String, usize> = HashMap::new();
    for (i, r) in parsed.iter().enumerate() {
        *counts.entry(r.verdict.clone()).or_insert(0) += 1;
        first_seen.entry(r.verdict.clone()).or_insert(i);
    }
    let majority: (String, i64) = counts
        .iter()
        .max_by_key(|entry| {
            let (verdict, count): (&String, &i64) = *entry;
            (*count, std::cmp::Reverse(first_seen[verdict]))
        })
        .map(|(verdict, count): (&String, &i64)| (verdict.clone(), *count))
        .unwrap_or_else(|| ("UNDECIDED".to_string(), 0));

    let scores: Vec<i64> = parsed.iter().map(|r| r.score).filter(|s| *s > 0).collect();
    let avg_score = if scores.is_empty() {
        0.0
    } else {
        let sum: i64 = scores.iter().sum();
        (sum as f64 / scores.len() as f64 * 10.0).round() / 10.0
    };

    let distinct_verdicts: std::collections::BTreeSet<&str> =
        parsed.iter().map(|r| r.verdict.as_str()).collect();

    Synthesis {
        majority_verdict: majority.0,
        majority_count: if parsed.is_empty() {
            "0/0".to_string()
        } else {
            format!("{}/{}", majority.1, parsed.len())
        },
        avg_score,
        split: distinct_verdicts.len() > 1,
        any_degraded: all.iter().any(|r| r.degraded),
        any_error: all.iter().any(|r| !r.parsed_ok),
    }
}

/// Result of `_parse_juror_json`: either the parsed JSON object (with the
/// `_parsed_ok`/verdict fields Python injects folded into the returned
/// map) or the `PARSE_ERROR` fallback.
#[derive(Debug, Clone)]
pub struct ParsedJuror {
    pub parsed_ok: bool,
    /// Present when parsing succeeded: the raw parsed JSON object.
    pub object: Option<Map<String, Value>>,
    /// Present when parsing failed: truncated raw text and error marker,
    /// mirroring the Python fallback dict's `verdict`/`top_concern`.
    pub verdict: String,
    pub top_concern: String,
}

/// Port of `Engine._parse_juror_json`. Strips `<think>...</think>` blocks
/// (and an unclosed trailing `<think>...EOF`), then code fences, then
/// tries direct `serde_json::from_str`, then falls back to the first
/// `{...}` substring (greedy, matching Python's `re.search(r"\{.*\}", ...,
/// re.DOTALL)`).
pub fn parse_juror_json(raw: Option<&str>) -> ParsedJuror {
    let Some(raw) = raw else {
        return ParsedJuror {
            parsed_ok: false,
            object: None,
            verdict: "PARSE_ERROR".to_string(),
            top_concern: String::new(),
        };
    };

    let think_closed = Regex::new(r"(?s)<think>.*?</think>").expect("static regex");
    let mut s = think_closed.replace_all(raw, "").trim().to_string();
    let think_unclosed = Regex::new(r"(?s)^<think>.*$").expect("static regex");
    s = think_unclosed.replace(&s, "").trim().to_string();

    if let Some(stripped) = s.strip_prefix("```") {
        let mut s2 = stripped.to_string();
        if let Some(rest) = s2.strip_prefix("json") {
            s2 = rest.to_string();
        }
        s2 = s2.trim_start().to_string();
        if let Some(rest) = s2.strip_suffix("```") {
            s2 = rest.trim_end().to_string();
        }
        s = s2;
    }

    if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&s) {
        return ParsedJuror {
            parsed_ok: true,
            object: Some(obj),
            verdict: String::new(),
            top_concern: String::new(),
        };
    }

    if let (Some(start), Some(end)) = (s.find('{'), s.rfind('}')) {
        if end >= start {
            if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&s[start..=end]) {
                return ParsedJuror {
                    parsed_ok: true,
                    object: Some(obj),
                    verdict: String::new(),
                    top_concern: String::new(),
                };
            }
        }
    }

    let top_concern: String = s.chars().take(200).collect();
    ParsedJuror {
        parsed_ok: false,
        object: None,
        verdict: "PARSE_ERROR".to_string(),
        top_concern,
    }
}

/// Port of `Engine._provider_prompts`: only the `nim` provider gets the
/// compaction rewrite, and only for non-vision prompts.
pub fn provider_prompts(provider_name: &str, system: &str, user: &str, is_vision: bool) -> (String, String) {
    if is_vision || provider_name != "nim" {
        return (system.to_string(), user.to_string());
    }
    let compact_system = "Return one minified JSON object only. No markdown. No prose.".to_string();
    let rewritten = user.replace("RUBRIC:\n", "CRITERIA:\n").replace("\n\nINPUT:\n", "\n\nARTIFACT:\n");
    let compact_user = format!(
        "Evaluate ARTIFACT using CRITERIA. Return JSON matching the output schema.\n\n{rewritten}"
    );
    (compact_system, compact_user)
}

/// A juror seat, reduced to the fields `_execution_units` needs.
#[derive(Debug, Clone)]
pub struct JurorSeat {
    pub provider: String,
}

/// Port of `_execution_units`: providers marked `parallel_safe` split each
/// seat into its own unit; other providers keep all their seats serialized
/// in one unit. Grouping preserves each provider's first-seen order;
/// `parallel_safe` seats are then emitted as singleton units in that same
/// per-provider order, and unit order across providers follows each
/// provider's first appearance in `jurors` (matching Python dict
/// insertion-order iteration).
pub fn execution_units(jurors: &[JurorSeat], parallel_safe: &dyn Fn(&str) -> bool) -> Vec<Vec<JurorSeat>> {
    let mut order: Vec<String> = Vec::new();
    let mut grouped: HashMap<String, Vec<JurorSeat>> = HashMap::new();
    for j in jurors {
        if !grouped.contains_key(&j.provider) {
            order.push(j.provider.clone());
        }
        grouped.entry(j.provider.clone()).or_default().push(j.clone());
    }
    let mut units = Vec::new();
    for provider_name in order {
        let seats = grouped.remove(&provider_name).unwrap_or_default();
        if parallel_safe(&provider_name) {
            for seat in seats {
                units.push(vec![seat]);
            }
        } else {
            units.push(seats);
        }
    }
    units
}

/// An escalation rule, reduced to what trigger-matching needs.
#[derive(Debug, Clone)]
pub struct EscalationRule {
    pub trigger: String,
    pub provider: String,
    pub model: String,
}

/// Port of the trigger-matching half of `Engine._maybe_escalate`
/// (everything up to and including provider+model de-dup). The actual HTTP
/// call and `JurorResult` construction are out of scope without the
/// provider layer; callers drive the live call per returned rule.
pub fn triggered_escalations<'a>(
    rules: &'a [EscalationRule],
    verdicts: &[String],
    flags: &HashMap<String, bool>,
) -> Vec<&'a EscalationRule> {
    let is_split = {
        let distinct: std::collections::BTreeSet<&str> = verdicts.iter().map(|s| s.as_str()).collect();
        !verdicts.is_empty() && distinct.len() > 1
    };

    let mut triggered = Vec::new();
    for rule in rules {
        let fires = if rule.trigger == "always" {
            true
        } else if let Some(flag_name) = rule.trigger.strip_prefix("flag.") {
            *flags.get(flag_name).unwrap_or(&false)
        } else {
            rule.trigger == "jury_split" && is_split
        };
        if fires {
            triggered.push(rule);
        }
    }

    let mut seen: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for rule in triggered {
        let key = (rule.provider.clone(), rule.model.clone());
        if seen.insert(key) {
            out.push(rule);
        }
    }
    out
}
