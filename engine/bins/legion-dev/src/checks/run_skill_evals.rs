// Deterministic executor for the skill-eval corpus (`skills/**/evals/*.json`).
//
// Legion has no native natural-language classifier: per `doctrine/legion.md`
// the always-on orchestration model performs semantic routing, and the
// deterministic runtime only validates selected ids and resolves explicit
// aliases. This runner therefore executes the one deterministic router that
// exists, explicit slash-alias resolution (`/name` at the start of a prompt,
// optionally namespaced `/legion:name`), against the packaged skill names.
//
// For each case in a case array:
//   * prompt starts with a slash alias -> the selection is the resolved skill
//     (or none if the alias names no packaged skill). The case passes when the
//     selection equals `expected_skill` (string), is none when `expected_skill`
//     is null, and is not in `forbidden_skills`. Cases that declare none of
//     those expectations are not routing cases and are skipped.
//   * any other prompt -> natural language: `requires-model`, never a failure.
// Exit status is nonzero on any deterministic mismatch.

use super::skill_evals::{is_eval_file, known_names};
use super::tracked_files;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CASE_ARRAYS: [&str; 7] = [
    "should_trigger",
    "should_not_trigger",
    "output_quality",
    "safety",
    "pressure",
    "compatibility",
    "human_quality",
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BundleResult {
    pub passed: usize,
    pub failed: usize,
    pub requires_model: usize,
    pub skipped: usize,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub bundles: BTreeMap<String, BundleResult>,
    pub mismatches: Vec<String>,
}

impl Summary {
    pub fn ok(&self) -> bool {
        self.mismatches.is_empty() && !self.bundles.is_empty()
    }
}

/// Explicit-alias router: the leading `/name` of a prompt, without a
/// `legion:` namespace, or `None` when the prompt is not an alias invocation.
fn alias_name(prompt: &str) -> Option<String> {
    let rest = prompt.trim_start().strip_prefix('/')?;
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':')))
        .unwrap_or(rest.len());
    let name = &rest[..end];
    if name.is_empty() {
        return None;
    }
    Some(name.strip_prefix("legion:").unwrap_or(name).to_string())
}

enum Outcome {
    Pass,
    Fail(String),
    RequiresModel,
    Skip,
}

fn evaluate_case(case: &Value, known: &BTreeSet<String>) -> Outcome {
    let Some(prompt) = case.get("prompt").and_then(Value::as_str) else {
        return Outcome::Skip;
    };
    let expected = case.get("expected_skill");
    let forbidden: Vec<&str> = case
        .get("forbidden_skills")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if expected.is_none() && forbidden.is_empty() {
        return Outcome::Skip;
    }
    let Some(name) = alias_name(prompt) else {
        return Outcome::RequiresModel;
    };
    let selected = known.contains(&name).then_some(name);
    if let Some(sel) = &selected {
        if forbidden.contains(&sel.as_str()) {
            return Outcome::Fail(format!("selected forbidden skill `{sel}`"));
        }
    }
    match expected {
        Some(Value::String(want)) if selected.as_deref() != Some(want.as_str()) => {
            Outcome::Fail(format!(
                "expected `{want}`, router selected {}",
                selected.map_or("nothing".to_string(), |s| format!("`{s}`"))
            ))
        }
        Some(Value::Null) if selected.is_some() => Outcome::Fail(format!(
            "expected no skill, router selected `{}`",
            selected.unwrap_or_default()
        )),
        _ => Outcome::Pass,
    }
}

fn bundle_of(path: &str) -> String {
    let dir = path.rsplit_once("/evals/").map(|(d, _)| d).unwrap_or("");
    dir.rsplit('/').next().unwrap_or(dir).to_string()
}

pub fn evaluate(root: &Path, files: &[String], bundles: &[String]) -> Summary {
    let known = known_names(files);
    let mut summary = Summary::default();
    for rel in files.iter().filter(|f| is_eval_file(f)) {
        let bundle = bundle_of(rel);
        if !bundles.is_empty() && !bundles.contains(&bundle) {
            continue;
        }
        let entry = summary.bundles.entry(bundle).or_default();
        let doc: Value = match std::fs::read_to_string(root.join(rel))
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
        {
            Ok(d) => d,
            Err(e) => {
                entry.failed += 1;
                summary.mismatches.push(format!("{rel}: unreadable ({e})"));
                continue;
            }
        };
        for array in CASE_ARRAYS {
            let Some(cases) = doc.get(array).and_then(Value::as_array) else {
                continue;
            };
            for case in cases {
                let id = case.get("id").and_then(Value::as_str).unwrap_or("?");
                match evaluate_case(case, &known) {
                    Outcome::Pass => entry.passed += 1,
                    Outcome::Skip => entry.skipped += 1,
                    Outcome::RequiresModel => entry.requires_model += 1,
                    Outcome::Fail(why) => {
                        entry.failed += 1;
                        summary.mismatches.push(format!("{rel}: {array}/{id}: {why}"));
                    }
                }
            }
        }
    }
    summary.mismatches.sort();
    summary
}

pub fn run(root: &Path, bundles: &[String], as_json: bool) -> bool {
    let files = tracked_files(root);
    let summary = evaluate(root, &files, bundles);
    if as_json {
        let rows: BTreeMap<_, _> = summary
            .bundles
            .iter()
            .map(|(b, r)| {
                (
                    b.clone(),
                    json!({"passed": r.passed, "failed": r.failed,
                           "requires-model": r.requires_model, "skipped": r.skipped}),
                )
            })
            .collect();
        let out = json!({"ok": summary.ok(), "bundles": rows, "mismatches": summary.mismatches});
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return summary.ok();
    }
    if summary.bundles.is_empty() {
        eprintln!("run-skill-evals: no matching skills/**/evals/*.json bundles found");
        return false;
    }
    println!(
        "{:<28} {:>6} {:>6} {:>14} {:>8}",
        "bundle", "pass", "fail", "requires-model", "skipped"
    );
    let mut total = BundleResult::default();
    for (b, r) in &summary.bundles {
        println!(
            "{:<28} {:>6} {:>6} {:>14} {:>8}",
            b, r.passed, r.failed, r.requires_model, r.skipped
        );
        total.passed += r.passed;
        total.failed += r.failed;
        total.requires_model += r.requires_model;
        total.skipped += r.skipped;
    }
    println!(
        "{:<28} {:>6} {:>6} {:>14} {:>8}",
        "TOTAL", total.passed, total.failed, total.requires_model, total.skipped
    );
    println!(
        "router: explicit slash aliases only (no native natural-language classifier); natural-language cases are requires-model and never fail the run"
    );
    for m in &summary.mismatches {
        eprintln!("{m}");
    }
    if !summary.ok() {
        eprintln!(
            "\nrun-skill-evals failed: {} deterministic mismatch(es)",
            summary.mismatches.len()
        );
    }
    summary.ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup(label: &str, cases: &str) -> (std::path::PathBuf, Vec<String>) {
        let dir =
            std::env::temp_dir().join(format!("legion-runevals-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("skills/alpha/evals")).unwrap();
        fs::write(dir.join("skills/alpha/SKILL.md"), "---\nname: alpha\n---\n").unwrap();
        fs::write(
            dir.join("skills/alpha/evals/evals.json"),
            format!(r#"{{"should_trigger":[{cases}]}}"#),
        )
        .unwrap();
        let files = vec![
            "skills/alpha/SKILL.md".to_string(),
            "skills/alpha/evals/evals.json".to_string(),
        ];
        (dir, files)
    }

    #[test]
    fn alias_case_passes() {
        let (dir, files) = setup(
            "pass",
            r#"{"id":"a","prompt":"/alpha do it","expected_skill":"alpha","forbidden_skills":[]}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(s.ok(), "{:?}", s.mismatches);
        assert_eq!(s.bundles["alpha"].passed, 1);
    }

    #[test]
    fn alias_mismatch_fails() {
        let (dir, files) = setup(
            "fail",
            r#"{"id":"a","prompt":"/alpha do it","expected_skill":"beta","forbidden_skills":[]}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(!s.ok());
        assert_eq!(s.bundles["alpha"].failed, 1);
    }

    #[test]
    fn natural_language_requires_model_and_never_fails() {
        let (dir, files) = setup(
            "nl",
            r#"{"id":"a","prompt":"please do the thing","expected_skill":"beta","forbidden_skills":[]}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(s.ok());
        assert_eq!(s.bundles["alpha"].requires_model, 1);
    }

    #[test]
    fn namespaced_alias_and_bundle_filter() {
        assert_eq!(alias_name("/legion:alpha x").as_deref(), Some("alpha"));
        assert_eq!(alias_name("no alias"), None);
        let (dir, files) = setup("filter", r#"{"id":"a","prompt":"/zzz","expected_skill":"alpha"}"#);
        let s = evaluate(&dir, &files, &["other".to_string()]);
        let _ = fs::remove_dir_all(&dir);
        assert!(s.bundles.is_empty());
    }
}
