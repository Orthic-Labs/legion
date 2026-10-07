//! Pure, bounded Xcode build-analysis helpers.
//!
//! This module ports the useful, deterministic portions of the upstream
//! build-optimization helpers. It reads supplied text or bounded input files;
//! it never invokes xcodebuild, SwiftPM, git, a shell, or another runtime.
//! Build execution belongs to the native mobile adapter. A caller that wants
//! to claim a benchmark must supply the resulting log/artifact.

use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ROWS: usize = 10_000;

/// Invoke one pure build-analysis operation.
///
/// `operation` is read from the JSON object. Supported operations are listed
/// by [`catalog`]. Inputs may be inline text/JSON or explicit bounded file
/// paths. No operation executes a system tool.
pub fn invoke(arguments: &Value) -> Result<Value, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    let operation = object
        .get("operation")
        .or_else(|| object.get("action"))
        .and_then(Value::as_str)
        .unwrap_or("catalog")
        .to_ascii_lowercase();

    match operation.as_str() {
        "catalog" | "discover" => Ok(catalog()),
        "timing.parse" | "timing_summary.parse" | "build_timing.parse" => {
            let text = input_text(
                object,
                &["text", "build_log", "log", "input", "input_path", "path"],
            )?;
            Ok(parse_timing_value(&text))
        }
        "benchmark.stats" | "benchmark.statistics" => benchmark_stats(object),
        "benchmark.compare" | "benchmark.regression" => benchmark_compare(object),
        "compiler.parse" | "compilation.parse" | "diagnostics.parse" => {
            let text = input_text(
                object,
                &["text", "build_log", "log", "input", "input_path", "path"],
            )?;
            Ok(parse_compiler_value(&text, object)?)
        }
        "project.audit" | "project.settings" => {
            let text = input_text(
                object,
                &["pbxproj", "text", "project_path", "input_path", "path"],
            )?;
            Ok(audit_project(&text))
        }
        "spm.audit" | "spm.graph" | "spm.pins" => audit_spm(object),
        "recommendations.render" | "recommendation.render" => render_recommendations(object),
        "report.summarize" | "report.render" => render_report(object),
        other => Err(format!("unknown build-analysis operation: {other}")),
    }
}

/// Describe pure native build-analysis operations and their evidence contract.
pub fn catalog() -> Value {
    json!({
        "adapter": "legion-apple-build-analysis",
        "native": true,
        "execution": {
            "pure": true,
            "reads": "inline JSON/text or bounded explicit files",
            "executes": [],
            "benchmark_claim": "requires supplied output from a selected system tool"
        },
        "operations": [
            {"name": "timing.parse", "purpose": "Parse -showBuildTimingSummary categories, seconds, and task counts"},
            {"name": "benchmark.stats", "purpose": "Compute successful-run count, min/max/median/average/stddev/variance"},
            {"name": "benchmark.compare", "purpose": "Compare clean/cached-clean/incremental medians with cache comparability and regression decisions"},
            {"name": "compiler.parse", "purpose": "Parse type-check warnings, per-file timings, and compiler diagnostic evidence"},
            {"name": "project.audit", "purpose": "Audit Debug/Release settings and Run Script input/output metadata"},
            {"name": "spm.audit", "purpose": "Inspect package references, product linkage, pins, macros, re-exports, and graph fixtures"},
            {"name": "recommendations.render", "purpose": "Render evidence-bound recommendation records as Markdown"},
            {"name": "report.summarize", "purpose": "Render supplied benchmark, compiler, project, SPM, and recommendation evidence"}
        ],
        "ported_helpers": [
            "benchmark_builds.py statistics/status/cache comparison",
            "diagnose_compilation.py warning and file-time parsers",
            "summarize_build_timing.py timing aggregation",
            "check_spm_pins.py branch-pin extraction (tag query remains caller-owned)",
            "generate_optimization_report.py project/settings/report sections",
            "render_recommendations.py recommendation Markdown"
        ],
        "not_implemented_here": [
            "xcodebuild/swift/git execution",
            "filesystem mutation, DerivedData cleanup, touching source files",
            "remote tag availability queries"
        ]
    })
}

fn input_text(object: &Map<String, Value>, keys: &[&str]) -> Result<String, String> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };
        if *key == "text"
            || *key == "build_log"
            || *key == "log"
            || *key == "pbxproj"
            || *key == "manifest"
            || *key == "package_resolved"
        {
            return value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} must be a string"));
        }
        let path = value
            .as_str()
            .ok_or_else(|| format!("{key} must be a string path"))?;
        return read_text(path);
    }
    Err(format!("missing input; provide one of {}", keys.join(", ")))
}

fn read_text(path: &str) -> Result<String, String> {
    if path.is_empty() || path.contains('\0') {
        return Err("input path must be non-empty and NUL-free".to_string());
    }
    let metadata = fs::metadata(path).map_err(|error| format!("cannot inspect input: {error}"))?;
    if !metadata.is_file() {
        return Err("input path must be a regular file".to_string());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(format!("input exceeds {MAX_INPUT_BYTES} bytes"));
    }
    let bytes = fs::read(Path::new(path)).map_err(|error| format!("cannot read input: {error}"))?;
    String::from_utf8(bytes).map_err(|_| "input must be UTF-8".to_string())
}

fn parse_timing_value(text: &str) -> Value {
    let categories = parse_timing_summary(text);
    let category_count = categories.len();
    json!({"categories": categories, "category_count": category_count, "parser": "xcode-build-timing-v1"})
}

#[derive(Default, Debug, Clone)]
struct TimingRow {
    seconds: f64,
    tasks: Option<u64>,
}

fn parse_timing_summary(text: &str) -> Vec<Value> {
    let task_re = Regex::new(r"^(.+?)\s*\((\d+)\s+tasks?\)$").expect("valid timing task regex");
    let mut categories: BTreeMap<String, TimingRow> = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let (name_part, parsed) = match timing_suffix(line) {
            Some(value) => value,
            None => continue,
        };
        if !parsed.is_finite() || parsed < 0.0 {
            continue;
        }
        let cleaned = name_part
            .replace("  ", " ")
            .trim_matches([' ', '-', ':'])
            .trim()
            .to_string();
        if cleaned.len() < 3 {
            continue;
        }
        let (name, tasks) = if let Some(caps) = task_re.captures(&cleaned) {
            (
                caps.get(1)
                    .map(|m| m.as_str().trim().to_string())
                    .unwrap_or(cleaned.clone()),
                caps.get(2).and_then(|m| m.as_str().parse::<u64>().ok()),
            )
        } else {
            (cleaned, None)
        };
        let row = categories.entry(name).or_default();
        row.seconds += parsed;
        if let Some(tasks) = tasks {
            row.tasks = Some(row.tasks.unwrap_or(0) + tasks);
        }
    }
    let mut rows: Vec<(String, TimingRow)> = categories.into_iter().collect();
    rows.sort_by(|(left_name, left), (right_name, right)| {
        right
            .seconds
            .partial_cmp(&left.seconds)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left_name.cmp(right_name))
    });
    rows.into_iter()
        .take(MAX_ROWS)
        .map(|(name, row)| {
            let mut value = json!({"name": name, "seconds": round3(row.seconds)});
            if let Some(tasks) = row.tasks {
                value["task_count"] = json!(tasks);
            }
            value
        })
        .collect()
}

fn timing_suffix(line: &str) -> Option<(&str, f64)> {
    for suffix in [" seconds", " second", " sec"] {
        if let Some(trimmed) = line.strip_suffix(suffix) {
            let (name, number) = if let Some((name, number)) = trimmed.rsplit_once('|') {
                (name, number.trim())
            } else {
                let split = trimmed
                    .char_indices()
                    .rev()
                    .find(|(_, character)| character.is_whitespace())
                    .map(|(index, _)| index)?;
                (&trimmed[..split], trimmed[split..].trim())
            };
            return Some((name, number.parse().ok()?));
        }
    }
    None
}

fn round3(number: f64) -> f64 {
    (number * 1000.0).round() / 1000.0
}

fn benchmark_stats(object: &Map<String, Value>) -> Result<Value, String> {
    let runs = object
        .get("runs")
        .or_else(|| object.get("input"))
        .ok_or_else(|| "benchmark.stats requires runs array or input path".to_string())?;
    let input = if let Some(path) = runs.as_str() {
        let text = read_text(path)?;
        serde_json::from_str::<Value>(&text)
            .map_err(|error| format!("benchmark input is not valid JSON: {error}"))?
    } else {
        runs.clone()
    };
    let runs = input.get("runs").unwrap_or(&input);
    let runs = runs
        .as_array()
        .ok_or_else(|| "benchmark runs must be an array".to_string())?;
    Ok(stats_value(runs))
}

fn stats_value(runs: &[Value]) -> Value {
    let mut durations = Vec::new();
    let mut failed = 0_u64;
    for run in runs {
        let success = run.get("success").and_then(Value::as_bool).unwrap_or(false);
        let duration = run
            .get("duration_seconds")
            .and_then(Value::as_f64)
            .or_else(|| run.get("durationSeconds").and_then(Value::as_f64));
        if success && duration.is_some_and(|value| value.is_finite() && value >= 0.0) {
            durations.push(duration.unwrap());
        } else {
            failed += 1;
        }
    }
    durations.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let count = durations.len();
    let (min, max, median, average, variance, stddev) = if count == 0 {
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    } else {
        let min = durations[0];
        let max = durations[count - 1];
        let median = if count % 2 == 0 {
            (durations[count / 2 - 1] + durations[count / 2]) / 2.0
        } else {
            durations[count / 2]
        };
        let average = durations.iter().sum::<f64>() / count as f64;
        let variance = durations
            .iter()
            .map(|duration| (duration - average).powi(2))
            .sum::<f64>()
            / count as f64;
        (min, max, median, average, variance, variance.sqrt())
    };
    json!({
        "count": count,
        "failed_count": failed,
        "min_seconds": round3(min),
        "max_seconds": round3(max),
        "median_seconds": round3(median),
        "average_seconds": round3(average),
        "variance_seconds_squared": round3(variance),
        "stddev_seconds": round3(stddev),
        "range_seconds": round3(max - min),
        "variance_percent_of_median": if median > 0.0 { round3((max - min) / median * 100.0) } else { 0.0 },
        "high_variance": median > 0.0 && (max - min) > median * 0.20,
        "source": "successful runs only"
    })
}

fn benchmark_compare(object: &Map<String, Value>) -> Result<Value, String> {
    let baseline = object
        .get("baseline")
        .ok_or_else(|| "benchmark.compare requires baseline".to_string())?;
    let post = object
        .get("post")
        .ok_or_else(|| "benchmark.compare requires post".to_string())?;
    let baseline_mode = cache_mode(baseline, object.get("baseline_cache_mode"));
    let post_mode = cache_mode(post, object.get("post_cache_mode"));
    let cache_comparable = baseline_mode == post_mode && baseline_mode.is_some();
    let baseline_sections = benchmark_sections(baseline)?;
    let post_sections = benchmark_sections(post)?;
    let mut metrics = Map::new();
    for metric in ["clean", "cached_clean", "incremental"] {
        let Some(before) = baseline_sections.get(metric) else {
            continue;
        };
        let Some(after) = post_sections.get(metric) else {
            continue;
        };
        let before_stats = if before.is_array() {
            stats_value(before.as_array().unwrap())
        } else {
            before.clone()
        };
        let after_stats = if after.is_array() {
            stats_value(after.as_array().unwrap())
        } else {
            after.clone()
        };
        let before_median = before_stats
            .get("median_seconds")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let after_median = after_stats
            .get("median_seconds")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let before_min = before_stats
            .get("min_seconds")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let before_max = before_stats
            .get("max_seconds")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let decision = if !cache_comparable {
            "not-comparable"
        } else if after_median < before_min {
            "improved"
        } else if after_median > before_max {
            "regressed"
        } else {
            "inconclusive"
        };
        metrics.insert(metric.to_string(), json!({"baseline": before_stats, "post": after_stats, "delta_seconds": round3(after_median - before_median), "delta_percent": if before_median > 0.0 { round3((after_median - before_median) / before_median * 100.0) } else { 0.0 }, "decision": decision}));
    }
    Ok(
        json!({"cacheComparable": cache_comparable, "baselineCacheMode": baseline_mode, "postCacheMode": post_mode, "metrics": metrics, "decisionRule": "post median outside baseline min-max; cache mode must match"}),
    )
}

fn cache_mode(value: &Value, override_value: Option<&Value>) -> Option<String> {
    override_value
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            value
                .get("cache_mode")
                .or_else(|| value.get("cacheMode"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .or_else(|| {
            value
                .get("build")
                .and_then(|build| build.get("cache_mode").or_else(|| build.get("cacheMode")))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

fn benchmark_sections(value: &Value) -> Result<Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "benchmark input must be an object".to_string())?;
    if let Some(summary) = object.get("summary").and_then(Value::as_object) {
        return Ok(summary.clone());
    }
    let runs = object
        .get("runs")
        .and_then(Value::as_object)
        .ok_or_else(|| "benchmark input requires summary or runs".to_string())?;
    Ok(runs.clone())
}

fn parse_compiler_value(text: &str, object: &Map<String, Value>) -> Result<Value, String> {
    let threshold = object
        .get("threshold_ms")
        .or_else(|| object.get("thresholdMs"))
        .and_then(Value::as_u64)
        .unwrap_or(100);
    let warnings = parse_typecheck_warnings(text);
    let file_timings = parse_file_timings(text);
    let stats_dir = object
        .get("stats_dir")
        .or_else(|| object.get("statsDir"))
        .and_then(Value::as_str);
    let total_warnings = warnings.len();
    let function_body_warnings = warnings
        .iter()
        .filter(|value| value.get("kind").and_then(Value::as_str) == Some("function-body"))
        .count();
    let expression_warnings = warnings
        .iter()
        .filter(|value| value.get("kind").and_then(Value::as_str) == Some("expression"))
        .count();
    let slowest_ms = warnings
        .first()
        .and_then(|value| value.get("duration_ms"))
        .cloned()
        .unwrap_or(Value::from(0));
    Ok(json!({
        "parser": "xcode-compilation-diagnostics-v1",
        "threshold_ms": threshold,
        "warnings": warnings,
        "per_file_timings": file_timings,
        "summary": {
            "total_warnings": total_warnings,
            "function_body_warnings": function_body_warnings,
            "expression_warnings": expression_warnings,
            "slowest_ms": slowest_ms
        },
        "stats_dir": stats_dir,
        "execution": "parse supplied output only"
    }))
}

fn parse_typecheck_warnings(text: &str) -> Vec<Value> {
    let function_re = Regex::new(r"^(?P<file>.+?):(?P<line>\d+):(?P<column>\d+): warning: (?P<kind>instance method|global function|getter|type-check|expression) '?(?P<name>[^']*?)'?\s+took\s+(?P<ms>\d+)ms\s+to\s+type-check").expect("valid typecheck warning regex");
    let expression_re = Regex::new(r"^(?P<file>.+?):(?P<line>\d+):(?P<column>\d+): warning: expression took\s+(?P<ms>\d+)ms\s+to\s+type-check").expect("valid expression warning regex");
    let mut seen = HashSet::new();
    let mut warnings = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(caps) = function_re.captures(line) {
            let file = caps
                .name("file")
                .map(|m| m.as_str())
                .unwrap_or_default()
                .to_string();
            let line_number = caps
                .name("line")
                .and_then(|m| m.as_str().parse::<u64>().ok())
                .unwrap_or(0);
            let column = caps
                .name("column")
                .and_then(|m| m.as_str().parse::<u64>().ok())
                .unwrap_or(0);
            let key = format!("{file}:{line_number}:{column}:function-body");
            if !seen.insert(key) {
                continue;
            }
            warnings.push(json!({"file": file, "line": line_number, "column": column, "duration_ms": caps.name("ms").and_then(|m| m.as_str().parse::<u64>().ok()).unwrap_or(0), "kind": "function-body", "name": caps.name("name").map(|m| m.as_str()).unwrap_or_default()}));
        } else if let Some(caps) = expression_re.captures(line) {
            let file = caps
                .name("file")
                .map(|m| m.as_str())
                .unwrap_or_default()
                .to_string();
            let line_number = caps
                .name("line")
                .and_then(|m| m.as_str().parse::<u64>().ok())
                .unwrap_or(0);
            let column = caps
                .name("column")
                .and_then(|m| m.as_str().parse::<u64>().ok())
                .unwrap_or(0);
            let key = format!("{file}:{line_number}:{column}:expression");
            if !seen.insert(key) {
                continue;
            }
            warnings.push(json!({"file": file, "line": line_number, "column": column, "duration_ms": caps.name("ms").and_then(|m| m.as_str().parse::<u64>().ok()).unwrap_or(0), "kind": "expression", "name": ""}));
        }
    }
    warnings.sort_by(|left, right| {
        right
            .get("duration_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .cmp(&left.get("duration_ms").and_then(Value::as_u64).unwrap_or(0))
            .then_with(|| {
                left.get("file")
                    .and_then(Value::as_str)
                    .cmp(&right.get("file").and_then(Value::as_str))
            })
    });
    warnings.into_iter().take(MAX_ROWS).collect()
}

fn parse_file_timings(text: &str) -> Vec<Value> {
    let file_re =
        Regex::new(r"^\s*(?P<seconds>\d+(?:\.\d+)?)\s+seconds\s+.*\s+compiling\s+(?P<file>\S+)")
            .expect("valid file timing regex");
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    for raw in text.lines() {
        let Some(caps) = file_re.captures(raw.trim()) else {
            continue;
        };
        let file = caps
            .name("file")
            .map(|m| m.as_str())
            .unwrap_or_default()
            .to_string();
        if !seen.insert(file.clone()) {
            continue;
        }
        let seconds = caps
            .name("seconds")
            .and_then(|m| m.as_str().parse::<f64>().ok())
            .unwrap_or(0.0);
        if seconds.is_finite() {
            rows.push(json!({"file": file, "duration_seconds": round3(seconds)}));
        }
    }
    rows.sort_by(|left, right| {
        right
            .get("duration_seconds")
            .and_then(Value::as_f64)
            .partial_cmp(&left.get("duration_seconds").and_then(Value::as_f64))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows.into_iter().take(MAX_ROWS).collect()
}

fn audit_project(text: &str) -> Value {
    let configs = parse_build_configs(text);
    let mut checks = Vec::new();
    let debug_expectations = [
        ("SWIFT_COMPILATION_MODE", "singlefile"),
        ("SWIFT_OPTIMIZATION_LEVEL", "-Onone"),
        ("GCC_OPTIMIZATION_LEVEL", "0"),
        ("ONLY_ACTIVE_ARCH", "YES"),
        ("DEBUG_INFORMATION_FORMAT", "dwarf"),
        ("ENABLE_TESTABILITY", "YES"),
        ("EAGER_LINKING", "YES"),
    ];
    let release_expectations = [
        ("SWIFT_COMPILATION_MODE", "wholemodule"),
        ("SWIFT_OPTIMIZATION_LEVEL", "-O"),
        ("GCC_OPTIMIZATION_LEVEL", "s"),
        ("ONLY_ACTIVE_ARCH", "NO"),
        ("DEBUG_INFORMATION_FORMAT", "dwarf-with-dsym"),
        ("ENABLE_TESTABILITY", "NO"),
    ];
    let general_expectations = [("COMPILATION_CACHE_ENABLE_CACHING", "YES")];
    for (key, expected) in debug_expectations {
        checks.push(setting_check(
            "Debug",
            key,
            expected,
            configs.get("Debug").and_then(|values| values.get(key)),
        ));
    }
    for (key, expected) in release_expectations {
        checks.push(setting_check(
            "Release",
            key,
            expected,
            configs.get("Release").and_then(|values| values.get(key)),
        ));
    }
    let merged = merged_settings(&configs);
    for (key, expected) in general_expectations {
        checks.push(setting_check("General", key, expected, merged.get(key)));
    }
    let scripts = parse_script_phases(text);
    let mut issues = Vec::new();
    for script in &scripts {
        if script.get("always_out_of_date").and_then(Value::as_bool) == Some(true) {
            issues.push(json!({"phase": script["name"], "kind": "always-out-of-date"}));
        }
        let has_inputs = script
            .get("input_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0;
        let has_outputs = script
            .get("output_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0;
        if !has_inputs && !has_outputs {
            issues.push(
                json!({"phase": script["name"], "kind": "missing-input-output-declarations"}),
            );
        }
    }
    json!({
        "parser": "xcode-project-settings-v1",
        "configurations": configs,
        "settings_checks": checks,
        "script_phases": scripts,
        "script_issues": issues,
        "notes": ["Settings are evidence for review; this operation does not edit project files or claim build execution."]
    })
}

fn parse_build_configs(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let block_re = Regex::new(r"(?s)(?:[0-9A-F]{24}\s*/\*\s*)?(?P<name>Debug|Release)(?:\s*\*/)?\s*=\s*\{.*?buildSettings\s*=\s*\{(?P<body>.*?)\}\s*;?").expect("valid build config regex");
    let setting_re =
        Regex::new(r"(?m)^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*;").expect("valid setting regex");
    let mut result = BTreeMap::new();
    for caps in block_re.captures_iter(text) {
        let name = caps
            .name("name")
            .map(|m| m.as_str())
            .unwrap_or_default()
            .to_string();
        let body = caps.name("body").map(|m| m.as_str()).unwrap_or_default();
        let values = result.entry(name).or_insert_with(BTreeMap::new);
        for setting in setting_re.captures_iter(body) {
            let key = setting
                .get(1)
                .map(|m| m.as_str())
                .unwrap_or_default()
                .to_string();
            let value = setting
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or_default()
                .trim()
                .trim_matches('"')
                .to_string();
            values.insert(key, value);
        }
    }
    result
}

fn merged_settings(
    configs: &BTreeMap<String, BTreeMap<String, String>>,
) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::new();
    for values in configs.values() {
        merged.extend(values.clone());
    }
    merged
}

fn setting_check(config: &str, key: &str, expected: &str, actual: Option<&String>) -> Value {
    let actual = actual.map(String::as_str).unwrap_or("(unset)");
    let passed = if actual == "(unset)" && expected == "singlefile" {
        true
    } else if expected == "-O" {
        matches!(actual, "-O" | "-Osize")
    } else {
        actual == expected
    };
    json!({"configuration": config, "key": key, "actual": actual, "expected": expected, "passed": passed})
}

fn parse_script_phases(text: &str) -> Vec<Value> {
    let phase_re = Regex::new(r"(?s)(?:[0-9A-F]{24}\s*/\*\s*(?P<name>[^*]+?)\s*\*/\s*=\s*\{.*?isa\s*=\s*PBXShellScriptBuildPhase;(?P<body>.*?))(?=\n\s*[0-9A-F]{24}\s*/\*|\z)").expect("valid shell phase regex");
    let value_re = |key: &str| {
        Regex::new(&format!(r"(?s){}\s*=\s*\((?P<body>.*?)\);", key))
            .expect("valid script list regex")
    };
    let mut phases = Vec::new();
    for caps in phase_re.captures_iter(text) {
        let name = caps
            .name("name")
            .map(|m| m.as_str().trim())
            .unwrap_or("Run Script")
            .to_string();
        let body = caps.name("body").map(|m| m.as_str()).unwrap_or_default();
        let inputs = script_list_count(body, &value_re("inputPaths"))
            + script_list_count(body, &value_re("inputFileListPaths"));
        let outputs = script_list_count(body, &value_re("outputPaths"))
            + script_list_count(body, &value_re("outputFileListPaths"));
        let always = Regex::new(r"alwaysOutOfDate\s*=\s*1\s*;")
            .expect("valid always out-of-date regex")
            .is_match(body);
        phases.push(json!({"name": name, "input_count": inputs, "output_count": outputs, "always_out_of_date": always, "has_shell_script": body.contains("shellScript") }));
    }
    phases
}

fn script_list_count(body: &str, regex: &Regex) -> u64 {
    regex
        .captures(body)
        .and_then(|caps| caps.name("body"))
        .map(|body| body.as_str().matches('"').count() as u64 / 2)
        .unwrap_or(0)
}

fn audit_spm(object: &Map<String, Value>) -> Result<Value, String> {
    let pbxproj = optional_input_text(object, &["pbxproj", "project_path"])?;
    let manifest = optional_input_text(object, &["manifest", "package_path"])?;
    let resolved = optional_input_text(object, &["package_resolved", "resolved_path"])?;
    let pbxproj_text = pbxproj.as_deref().unwrap_or("");
    let manifest_text = manifest.as_deref().unwrap_or("");
    let remote = parse_remote_packages(pbxproj_text);
    let local = parse_local_packages(pbxproj_text);
    let products = parse_product_dependencies(pbxproj_text);
    let pins = parse_resolved_pins(resolved.as_deref().unwrap_or(""));
    let branch_pins: Vec<Value> = remote
        .iter()
        .filter(|entry| entry.get("kind").and_then(Value::as_str) == Some("branch"))
        .cloned()
        .collect();
    let exported_imports = manifest_text
        .lines()
        .filter(|line| line.trim_start().starts_with("@_exported import"))
        .count();
    let macro_evidence = manifest_text.contains("macro ")
        || manifest_text.contains("SwiftSyntax")
        || manifest_text.contains("SwiftCompilerPlugin")
        || pbxproj_text.contains("SwiftSyntax");
    let mut issues = Vec::new();
    if !branch_pins.is_empty() {
        issues.push(json!({"kind": "branch-pins", "count": branch_pins.len(), "action": "check tags or pin an explicit revision after measurement"}));
    }
    if exported_imports > 0 {
        issues.push(json!({"kind": "umbrella-reexports", "count": exported_imports, "action": "inspect downstream invalidation"}));
    }
    if macro_evidence {
        issues.push(json!({"kind": "macro-or-swift-syntax", "action": "isolate macro-heavy code and compare rebuild scope"}));
    }
    if let Some(file_count) = object
        .get("module_file_count")
        .or_else(|| object.get("file_count"))
        .and_then(Value::as_u64)
    {
        if file_count >= 200 {
            issues.push(json!({"kind": "oversized-module", "file_count": file_count, "action": "consider responsibility-based split"}));
        }
    }
    if let Some(graph) = object.get("graph") {
        for cycle in graph_cycles(graph) {
            issues.push(json!({"kind": "target-cycle", "cycle": cycle}));
        }
    }
    let remote_count = remote.len();
    let local_count = local.len();
    let product_count = products.len();
    let product_package_ids: Vec<&str> = products
        .iter()
        .filter_map(|product| product.get("package").and_then(Value::as_str))
        .collect();
    Ok(json!({
        "parser": "swift-package-project-evidence-v1",
        "remote_references": remote,
        "local_references": local,
        "product_dependencies": products,
        "resolved_pins": pins,
        "branch_pins": branch_pins,
        "exported_import_count": exported_imports,
        "macro_or_swift_syntax": macro_evidence,
        "linkage": {"remote_reference_count": remote_count, "local_reference_count": local_count, "product_dependency_count": product_count, "product_package_ids": product_package_ids},
        "issues": issues,
        "tag_query": "not executed; caller must supply read-only git evidence"
    }))
}

fn optional_input_text(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Result<Option<String>, String> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };
        if *key == "pbxproj" || *key == "manifest" || *key == "package_resolved" {
            return value
                .as_str()
                .map(|text| Some(text.to_string()))
                .ok_or_else(|| format!("{key} must be a string"));
        }
        let path = value
            .as_str()
            .ok_or_else(|| format!("{key} must be a string path"))?;
        return read_text(path).map(Some);
    }
    Ok(None)
}

fn parse_remote_packages(text: &str) -> Vec<Value> {
    let reference_re = Regex::new(r#"(?s)XCRemoteSwiftPackageReference\s+"(?P<name>[^"]+)".*?repositoryURL\s*=\s*"(?P<url>[^"]+)".*?requirement\s*=\s*\{(?P<requirement>[^}]*)\}"#).expect("valid remote package regex");
    let kind_re = Regex::new(r"kind\s*=\s*([^;]+)").expect("valid requirement kind regex");
    let branch_re = Regex::new(r"branch\s*=\s*([^;]+)").expect("valid branch regex");
    let revision_re = Regex::new(r"revision\s*=\s*([^;]+)").expect("valid revision regex");
    let version_re = Regex::new(r"(?:minimumVersion|version|exactVersion)\s*=\s*([^;]+)")
        .expect("valid version regex");
    reference_re.captures_iter(text).map(|caps| {
        let requirement = caps.name("requirement").map(|m| m.as_str()).unwrap_or_default();
        let kind = kind_re.captures(requirement).and_then(|m| m.get(1)).map(|m| clean_pbx_value(m.as_str())).unwrap_or_else(|| "unknown".to_string());
        let branch = branch_re.captures(requirement).and_then(|m| m.get(1)).map(|m| clean_pbx_value(m.as_str()));
        let revision = revision_re.captures(requirement).and_then(|m| m.get(1)).map(|m| clean_pbx_value(m.as_str()));
        let version = version_re.captures(requirement).and_then(|m| m.get(1)).map(|m| clean_pbx_value(m.as_str()));
        json!({"name": caps.name("name").map(|m| m.as_str()).unwrap_or_default(), "url": caps.name("url").map(|m| m.as_str()).unwrap_or_default(), "kind": kind, "branch": branch, "revision": revision, "version": version})
    }).take(MAX_ROWS).collect()
}

fn parse_local_packages(text: &str) -> Vec<Value> {
    let local_re = Regex::new(r#"(?s)XCLocalSwiftPackageReference\s+"(?P<name>[^"]+)".*?relativePath\s*=\s*"(?P<path>[^"]+)""#).expect("valid local package regex");
    local_re.captures_iter(text).map(|caps| json!({"name": caps.name("name").map(|m| m.as_str()).unwrap_or_default(), "relative_path": caps.name("path").map(|m| m.as_str()).unwrap_or_default()})).take(MAX_ROWS).collect()
}

fn parse_product_dependencies(text: &str) -> Vec<Value> {
    let product_re = Regex::new(r#"(?s)XCSwiftPackageProductDependency\s+"(?P<id>[^"]+)".*?productName\s*=\s*"(?P<product>[^"]+)"(?:.*?package\s*=\s*(?P<package>[A-Za-z0-9]+))?"#).expect("valid package product regex");
    product_re.captures_iter(text).map(|caps| json!({"id": caps.name("id").map(|m| m.as_str()).unwrap_or_default(), "product": caps.name("product").map(|m| m.as_str()).unwrap_or_default(), "package": caps.name("package").map(|m| m.as_str())})).take(MAX_ROWS).collect()
}

fn parse_resolved_pins(text: &str) -> Vec<Value> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let Ok(payload) = serde_json::from_str::<Value>(text) else {
        return vec![json!({"error": "Package.resolved is not valid JSON"})];
    };
    let Some(pins) = payload.get("pins").and_then(Value::as_array) else {
        return Vec::new();
    };
    pins.iter().map(|pin| json!({"identity": pin.get("identity"), "location": pin.get("location"), "state": pin.get("state")})).take(MAX_ROWS).collect()
}

fn clean_pbx_value(value: &str) -> String {
    value.trim().trim_matches('"').to_string()
}

fn graph_cycles(value: &Value) -> Vec<Vec<String>> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (node, destinations) in object {
        let values = destinations
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        edges.insert(node.clone(), values);
    }
    let mut cycles = Vec::new();
    for node in edges.keys() {
        detect_cycle(
            node,
            &edges,
            &mut Vec::new(),
            &mut HashSet::new(),
            &mut cycles,
        );
    }
    cycles
}

fn detect_cycle(
    node: &str,
    edges: &BTreeMap<String, Vec<String>>,
    stack: &mut Vec<String>,
    visiting: &mut HashSet<String>,
    cycles: &mut Vec<Vec<String>>,
) {
    if let Some(index) = stack.iter().position(|item| item == node) {
        cycles.push(
            stack[index..]
                .iter()
                .cloned()
                .chain(std::iter::once(node.to_string()))
                .collect(),
        );
        return;
    }
    if !visiting.insert(node.to_string()) {
        return;
    }
    stack.push(node.to_string());
    if let Some(destinations) = edges.get(node) {
        for destination in destinations {
            if edges.contains_key(destination) {
                detect_cycle(destination, edges, stack, visiting, cycles);
            }
        }
    }
    stack.pop();
    visiting.remove(node);
}

fn render_recommendations(object: &Map<String, Value>) -> Result<Value, String> {
    let payload = object
        .get("recommendations")
        .or_else(|| object.get("input"))
        .ok_or_else(|| "recommendations.render requires recommendations array".to_string())?;
    let recommendations = payload
        .as_array()
        .ok_or_else(|| "recommendations must be an array".to_string())?;
    let mut sections = vec!["# Xcode Build Recommendations".to_string(), String::new()];
    for (index, item) in recommendations.iter().enumerate() {
        let item = item
            .as_object()
            .ok_or_else(|| "each recommendation must be an object".to_string())?;
        sections.push(format!(
            "## {}. {}",
            index + 1,
            item.get("title")
                .and_then(Value::as_str)
                .unwrap_or("Untitled recommendation")
        ));
        for (key, label) in [
            ("category", "Category"),
            ("observed_evidence", "Observed evidence"),
            ("estimated_impact", "Estimated impact"),
            ("wait_time_impact", "Wait-time impact"),
            ("confidence", "Confidence"),
            (
                "benchmark_verification_status",
                "Benchmark verification status",
            ),
            ("scope", "Scope"),
            ("risk_level", "Risk level"),
            ("actionability", "Actionability"),
        ] {
            if let Some(value) = item.get(key) {
                append_markdown_field(&mut sections, label, value);
            }
        }
        if let Some(notes) = item.get("implementation_notes") {
            append_markdown_field(&mut sections, "Implementation notes", notes);
        }
        sections.push(String::new());
    }
    let markdown = sections.join("\n").trim_end().to_string() + "\n";
    Ok(
        json!({"markdown": markdown, "count": recommendations.len(), "execution": "rendered supplied records only"}),
    )
}

fn append_markdown_field(sections: &mut Vec<String>, label: &str, value: &Value) {
    if let Some(values) = value.as_array() {
        sections.push(format!("**{label}:**"));
        for entry in values {
            sections.push(format!("- {}", markdown_value(entry)));
        }
    } else {
        sections.push(format!("**{label}:** {}", markdown_value(value)));
    }
}

fn markdown_value(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn render_report(object: &Map<String, Value>) -> Result<Value, String> {
    let mut sections = vec!["# Xcode Build Optimization Plan".to_string()];
    if let Some(context) = object.get("context") {
        sections.push(render_context(context));
    }
    if let Some(benchmark) = object.get("benchmark") {
        sections.push(render_benchmark_section(benchmark)?);
    }
    if let Some(diagnostics) = object.get("diagnostics") {
        sections.push(render_diagnostics_section(diagnostics));
    }
    if let Some(project) = object.get("project") {
        sections.push(render_project_section(project));
    }
    if let Some(spm) = object.get("spm") {
        sections.push(render_spm_section(spm));
    }
    if let Some(recommendations) = object.get("recommendations") {
        let rendered = render_recommendations(&Map::from_iter([(
            String::from("recommendations"),
            recommendations.clone(),
        )]))?;
        if let Some(markdown) = rendered.get("markdown").and_then(Value::as_str) {
            sections.push(markdown.to_string());
        }
    }
    sections.push("## Execution boundary\nThis report interprets supplied artifacts only. It does not claim xcodebuild, SwiftPM, git, or compiler execution.".to_string());
    Ok(
        json!({"markdown": sections.join("\n\n") + "\n", "sections": sections.len() - 1, "execution": "rendered supplied artifacts only"}),
    )
}

fn render_context(value: &Value) -> String {
    let object = value.as_object();
    format!("## Project Context\n\n- Project: `{}`\n- Scheme: `{}`\n- Configuration: `{}`\n- Destination: `{}`\n- Xcode: `{}`",
        object.and_then(|map| map.get("project").or_else(|| map.get("path"))).map(markdown_value).unwrap_or_else(|| "unknown".to_string()),
        object.and_then(|map| map.get("scheme")).map(markdown_value).unwrap_or_else(|| "unknown".to_string()),
        object.and_then(|map| map.get("configuration")).map(markdown_value).unwrap_or_else(|| "unknown".to_string()),
        object.and_then(|map| map.get("destination")).map(markdown_value).unwrap_or_else(|| "unknown".to_string()),
        object.and_then(|map| map.get("xcode_version").or_else(|| map.get("xcodeVersion"))).map(markdown_value).unwrap_or_else(|| "unknown".to_string()))
}

fn render_benchmark_section(value: &Value) -> Result<String, String> {
    let sections = benchmark_sections(value)?;
    let mut lines = vec![
        "## Baseline Benchmarks".to_string(),
        String::new(),
        "| Metric | Median | Min | Max | Runs |".to_string(),
        "|---|---:|---:|---:|---:|".to_string(),
    ];
    for metric in ["clean", "cached_clean", "incremental"] {
        let Some(raw) = sections.get(metric) else {
            continue;
        };
        let stats = if raw.is_array() {
            stats_value(raw.as_array().unwrap())
        } else {
            raw.clone()
        };
        lines.push(format!(
            "| {} | {:.3}s | {:.3}s | {:.3}s | {} |",
            metric,
            stats
                .get("median_seconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0),
            stats
                .get("min_seconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0),
            stats
                .get("max_seconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0),
            stats.get("count").and_then(Value::as_u64).unwrap_or(0)
        ));
    }
    Ok(lines.join("\n"))
}

fn render_diagnostics_section(value: &Value) -> String {
    let warnings = value
        .get("warnings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let threshold = value
        .get("threshold_ms")
        .and_then(Value::as_u64)
        .unwrap_or(100);
    let mut lines = vec![
        "## Compilation Diagnostics".to_string(),
        String::new(),
        format!(
            "Threshold: {threshold}ms | Total warnings: {}",
            warnings.len()
        ),
        String::new(),
        "| Duration | Kind | File | Line |".to_string(),
        "|---:|---|---|---:|".to_string(),
    ];
    for warning in warnings.iter().take(30) {
        lines.push(format!(
            "| {}ms | {} | {} | {} |",
            warning
                .get("duration_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            warning
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            warning
                .get("file")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            warning.get("line").and_then(Value::as_u64).unwrap_or(0)
        ));
    }
    lines.join("\n")
}

fn render_project_section(value: &Value) -> String {
    let checks = value
        .get("settings_checks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let issues = value
        .get("script_issues")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut lines = vec!["## Project Audit".to_string(), String::new()];
    for check in checks {
        lines.push(format!(
            "- [{}] {}: actual `{}`, expected `{}`",
            if check
                .get("passed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                "x"
            } else {
                " "
            },
            check
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            check
                .get("actual")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            check
                .get("expected")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ));
    }
    for issue in issues {
        lines.push(format!(
            "- Script issue: {}",
            issue
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ));
    }
    lines.join("\n")
}

fn render_spm_section(value: &Value) -> String {
    let issues = value
        .get("issues")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let linkage = value
        .get("linkage")
        .map(markdown_value)
        .unwrap_or_else(|| "{}".to_string());
    let mut lines = vec![
        "## Swift Package Manager Audit".to_string(),
        String::new(),
        format!("Linkage: `{linkage}`"),
    ];
    for issue in issues {
        lines.push(format!(
            "- Issue: {}",
            issue
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_parser_aggregates_pipe_and_space_forms() {
        let value = parse_timing_value(
            "CompileSwift (2 tasks) | 1.25 seconds\nCompileSwift (3 tasks) 0.75 sec",
        );
        assert_eq!(value["categories"][0]["name"], "CompileSwift");
        assert_eq!(value["categories"][0]["task_count"], 5);
        assert_eq!(value["categories"][0]["seconds"], 2.0);
    }

    #[test]
    fn stats_exclude_failed_runs_and_mark_variance() {
        let runs = vec![
            json!({"success": true, "duration_seconds": 10.0}),
            json!({"success": true, "duration_seconds": 12.0}),
            json!({"success": false, "duration_seconds": 99.0}),
        ];
        let value = stats_value(&runs);
        assert_eq!(value["count"], 2);
        assert_eq!(value["median_seconds"], 11.0);
        assert_eq!(value["failed_count"], 1);
    }

    #[test]
    fn compiler_parser_deduplicates_locations() {
        let value = parse_compiler_value("Sources/A.swift:4:2: warning: expression took 120ms to type-check\nSources/A.swift:4:2: warning: expression took 120ms to type-check", &Map::new()).unwrap();
        assert_eq!(value["summary"]["total_warnings"], 1);
    }

    #[test]
    fn spm_parser_reads_branch_names_with_punctuation() {
        let value = audit_spm(&Map::from_iter([(String::from("pbxproj"), Value::String("/* XCRemoteSwiftPackageReference \"Pkg\" */ = { repositoryURL = \"https://example.test/pkg\"; requirement = { kind = branch; branch = feature/foo-bar; }; };".to_string()))])).unwrap();
        assert_eq!(value["branch_pins"][0]["branch"], "feature/foo-bar");
    }

    #[test]
    fn catalog_is_pure_and_reports_execution_boundary() {
        assert_eq!(catalog()["execution"]["pure"], true);
        assert!(catalog()["execution"]["executes"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
