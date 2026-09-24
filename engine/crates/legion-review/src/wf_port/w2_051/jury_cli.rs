//! Port of `src/lib/review/jury.py` (the Council CLI entry point).
//! `parse_flag` is the deterministic argv-coercion logic, ported since
//! before r60. r60 closes the remaining gap — `main()`'s
//! `Engine().run(...)` orchestration — now that `engine_run::Engine::run`
//! exists (r59): [`run`] drives it end to end (argv parse -> `Engine.run`
//! -> optional shadow-log write -> render/print), matching
//! `health_check_run::run`'s `(stdout, exit_code)` shape so a bin crate
//! can wire it identically.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use serde_json::Value;

use super::dual_review_run::run_result_to_value;
use super::engine_run::{Engine, VisionPrep};
use super::super::w2_054::synthesizer::render as render_result;

/// Port of `parse_flag`: `"k=v"` -> `(k, v)` with `v` coerced to bool
/// (`true`/`yes`/`1` / `false`/`no`/`0`, case-insensitive) then int, else
/// left as the raw string. A flag with no `=` is a bare boolean `true`
/// flag, matching `return s, True`.
pub fn parse_flag(s: &str) -> (String, Value) {
    let Some((k, v)) = s.split_once('=') else {
        return (s.to_string(), Value::Bool(true));
    };
    let lower = v.to_lowercase();
    if matches!(lower.as_str(), "true" | "yes" | "1") {
        return (k.to_string(), Value::Bool(true));
    }
    if matches!(lower.as_str(), "false" | "no" | "0") {
        return (k.to_string(), Value::Bool(false));
    }
    if let Ok(n) = v.parse::<i64>() {
        return (k.to_string(), Value::Number(n.into()));
    }
    (k.to_string(), Value::String(v.to_string()))
}

/// Port of `main()`. `args` mirrors `sys.argv[1:]`. On success, returns
/// `(stdout_text, 0)`; a bad invocation (missing `skill`/`--input`, a
/// read failure, or `Engine.run` raising) mirrors `argparse`/an uncaught
/// exception by returning a non-zero code with an `error:`-prefixed
/// message instead of printing a traceback. `shadow_dir` stands in for
/// `ROOT / "shadow_log"` (this port has no `__file__`-relative `ROOT`;
/// the caller owns where that directory lives, same treatment `RUNS_ROOT`
/// gets in `dual_review_run.rs`).
pub fn run(args: &[String], engine: &Engine, shadow_dir: Option<&Path>, vision_prep: &dyn VisionPrep) -> (String, i32) {
    let mut skill: Option<String> = None;
    let mut input: Option<String> = None;
    let mut flag_args: Vec<String> = Vec::new();
    let mut no_cache = false;
    let mut no_escalation = false;
    let mut allow_cli_escalation = false;
    let mut json_out = false;
    let mut shadow = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input = args.get(i).cloned();
            }
            "--flag" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    flag_args.push(v.clone());
                }
            }
            "--no-cache" => no_cache = true,
            "--no-escalation" => no_escalation = true,
            "--allow-cli-escalation" => allow_cli_escalation = true,
            "--json" => json_out = true,
            "--shadow" => shadow = true,
            other if !other.starts_with("--") && skill.is_none() => skill = Some(other.to_string()),
            _ => {}
        }
        i += 1;
    }

    let (Some(skill), Some(input_arg)) = (skill, input) else {
        return ("error: skill and --input are required\n".to_string(), 2);
    };

    let user_input = if input_arg == "-" {
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

    // `engine_run::Engine::run` (r59) types `flags` as `BTreeMap<String, bool>`
    // (rubric flags are consumed as booleans downstream); a non-bool
    // `--flag k=v` (int or bare string) is coerced truthy, same as Python's
    // `bool(v)` would treat any non-zero int/non-empty string.
    let mut flags: BTreeMap<String, bool> = BTreeMap::new();
    for f in &flag_args {
        let (k, v) = parse_flag(f);
        let truthy = match &v {
            Value::Bool(b) => *b,
            Value::Number(n) => n.as_i64().map(|i| i != 0).unwrap_or(true),
            Value::String(s) => !s.is_empty(),
            _ => true,
        };
        flags.insert(k, truthy);
    }

    let t0 = Instant::now();
    let run_result = engine.run(
        &skill,
        &user_input,
        &flags,
        no_cache,
        (!allow_cli_escalation) || no_escalation,
        true,
        "jury",
        None,
        vision_prep,
    );
    let run_result = match run_result {
        Ok(r) => r,
        Err(e) => return (format!("error: {e}\n"), 1),
    };
    let wall_seconds = (t0.elapsed().as_secs_f64() * 100.0).round() / 100.0;
    let mut result = run_result_to_value(&run_result);
    result["wall_seconds"] = Value::from(wall_seconds);

    if shadow {
        if let Some(dir) = shadow_dir {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let out_path = dir.join(format!("{skill}_{ts}.json"));
            if let Ok(text) = serde_json::to_string_pretty(&result) {
                let _ = std::fs::create_dir_all(dir);
                let _ = std::fs::write(out_path, text);
            }
        }
    }

    let lens_questions: BTreeMap<String, String> = engine
        .lenses
        .iter()
        .filter(|(_, cfg)| !cfg.lens_question.is_empty())
        .map(|(name, cfg)| (name.clone(), cfg.lens_question.clone()))
        .collect();

    let output = if json_out {
        serde_json::to_string_pretty(&result).unwrap_or_default()
    } else {
        format!("{}\n\n_wall: {wall_seconds}s_", render_result(&result, &lens_questions))
    };
    (output, 0)
}
