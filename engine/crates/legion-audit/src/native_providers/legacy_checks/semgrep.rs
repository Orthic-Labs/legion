//! Offline two-rule SAST scope. Completion concerns only this packaged bundle;
//! unsupported selected languages remain coverage gaps in original denominator.
use super::*;
use std::{fs, io::Write, path::Component};

pub const RULE_SOURCE: &str = "src/registry/rules/opengrep/legion-core.yml";
pub const RULES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../src/registry/rules/opengrep/legion-core.yml"
));
pub const VERSION: &str = "1.141.0";
pub const RULE_IDS: &[&str] = &["legion-command-injection-shell", "legion-sql-interpolation"];

pub fn rules_digest() -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(RULES.as_bytes())))
}
pub fn contract() -> Value {
    json!({"version":VERSION,"rulesSource":RULE_SOURCE,"rulesDigest":rules_digest(),
        "ruleIds":RULE_IDS,"languages":["python","javascript","typescript"],
        "scope":"two packaged intrafile taint rules only; no auto-rules parity or vulnerability adjudication",
        "suppression":"disabled","exitCodes":[0]})
}
fn supported(path: &str) -> bool {
    matches!(
        Path::new(path).extension().and_then(|x| x.to_str()),
        Some("py" | "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx")
    )
}
fn selected(input: &LegacyCheckInput) -> BTreeSet<String> {
    input
        .denominator
        .entries
        .iter()
        .filter(|e| supported(&e.path))
        .map(|e| e.path.clone())
        .collect()
}
fn unchanged(input: &LegacyCheckInput, path: &str, expected: Option<&str>) -> bool {
    let relative = Path::new(path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return false;
    }
    let mut full = input.root.clone();
    for part in relative.components() {
        full.push(part);
        if full.is_symlink() {
            return false;
        }
    }
    fs::read(full).is_ok_and(|bytes| {
        expected == Some(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))).as_str())
    })
}
fn refusal(input: &LegacyCheckInput, reason: &str) -> LegacyCheckExecution {
    let mut output = empty_output(vec![reason.into()]);
    output.details.insert("semgrepContract".into(), contract());
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: 0,
        gaps: vec![reason.into()],
    });
    let mut execution = terminal_execution(
        input,
        spec(&input.provider_id)
            .expect("validated SAST contract")
            .command,
        LegacyCheckProcessState::Failed,
        None,
        vec![],
        vec![],
        output,
        vec![reason.into()],
        now_ms(),
        false,
        Some(reason),
    );
    if let Some(receipt) = execution
        .output
        .as_mut()
        .and_then(|o| o.details.get_mut("executionReceipt"))
    {
        receipt["parser"]["attempted"] = json!(false);
        receipt["processTree"]["detail"] =
            json!("Semgrep source/configuration prerequisite refused; no process started");
    }
    execution
}
/// Materialize source-bound rules outside target tree; selected paths never
/// collapse to implicit cwd, even when every selected language is unsupported.
fn prepared_args(
    input: &LegacyCheckInput,
    provider: &AuditProvider,
    scratch: &AuditScratch,
    args: &[String],
) -> Result<Vec<String>, String> {
    if provider.configuration.get("semgrepContract") != Some(&contract()) {
        return Err("semgrep-frozen-contract-mismatch".into());
    }
    let targets = selected(input);
    if targets.is_empty() {
        return Err("semgrep-no-supported-selected-targets".into());
    }
    if input
        .denominator
        .entries
        .iter()
        .any(|e| !unchanged(input, &e.path, e.digest.as_deref()))
    {
        return Err("semgrep-selected-source-changed".into());
    }
    let rules_path = scratch.reports_dir().join(format!(
        "semgrep-{}.yml",
        rules_digest().trim_start_matches("sha256:")
    ));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&rules_path)
    {
        Ok(mut file) => file
            .write_all(RULES.as_bytes())
            .map_err(|e| e.to_string())?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.to_string()),
    }
    if rules_path.is_symlink() || fs::read(&rules_path).ok().as_deref() != Some(RULES.as_bytes()) {
        return Err("semgrep-packaged-rules-changed".into());
    }
    let mut args = args.to_vec();
    if args
        .iter()
        .filter(|s| s.as_str() == "@legion-packaged-core")
        .count()
        != 1
    {
        return Err("semgrep-command-contract-mismatch".into());
    }
    for arg in &mut args {
        if arg == "@legion-packaged-core" {
            *arg = rules_path.to_string_lossy().into_owned();
        }
    }
    args.push("--".into());
    args.extend(targets.into_iter().map(|p| format!("./{p}")));
    Ok(args)
}
pub(super) fn prepare(
    input: &LegacyCheckInput,
    provider: &AuditProvider,
    scratch: &AuditScratch,
    args: &[String],
) -> Result<Vec<String>, LegacyCheckExecution> {
    prepared_args(input, provider, scratch, args).map_err(|reason| refusal(input, &reason))
}
fn path(value: &Value) -> Option<&str> {
    let value = value.as_str()?;
    let relative = value.strip_prefix("./").unwrap_or(value);
    (!relative.is_empty()
        && !relative.contains('\\')
        && Path::new(relative)
            .components()
            .all(|c| matches!(c, Component::Normal(_))))
    .then_some(relative)
}
/// `--verbose` emits skipped dispositions; `--strict` makes warning/error
/// exits fail. JSON errors are independently rejected, regardless of exit.
pub(super) fn valid_envelope(value: &Value) -> bool {
    value.get("version").and_then(Value::as_str) == Some(VERSION)
        && value
            .get("results")
            .and_then(Value::as_array)
            .is_some_and(|results| {
                results.iter().all(|r| {
                    r.get("check_id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| RULE_IDS.contains(&id))
                        && r.get("path").and_then(path).is_some()
                        && r.pointer("/start/line")
                            .and_then(Value::as_u64)
                            .is_some_and(|n| n > 0)
                })
            })
        && value
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && value
            .pointer("/paths/scanned")
            .and_then(Value::as_array)
            .is_some_and(|paths| paths.iter().all(|p| path(p).is_some()))
        && value
            .pointer("/paths/skipped")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && value
            .get("skipped_rules")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
}
pub(super) fn receipt_rules_valid(receipt: &legion_provider_sdk::ExecutionReceipt) -> bool {
    receipt.command.as_ref().is_some_and(|command| {
        let args = &command.args;
        args.iter()
            .position(|arg| arg == "--config")
            .and_then(|i| args.get(i + 1))
            .is_some_and(|path| {
                let path = Path::new(path);
                path.is_absolute()
                    && !path.is_symlink()
                    && fs::read(path).ok().as_deref() == Some(RULES.as_bytes())
            })
            && receipt.exit_code == Some(0)
    })
}
pub(super) fn parse(
    input: &LegacyCheckInput,
    value: &Value,
    output: &mut LegacyCheckOutput,
) -> bool {
    output.details.insert("semgrepContract".into(), contract());
    let mut gaps = Vec::new();
    let targets = selected(input);
    for entry in &input.denominator.entries {
        if !supported(&entry.path) {
            gaps.push(format!("semgrep-unsupported-selected-file:{}", entry.path));
        }
        if !unchanged(input, &entry.path, entry.digest.as_deref()) {
            gaps.push(format!("semgrep-selected-source-changed:{}", entry.path));
        }
    }
    let valid = valid_envelope(value);
    if !valid {
        gaps.push("semgrep-incomplete-or-invalid-envelope".into());
    }
    let raw_paths = value.pointer("/paths/scanned").and_then(Value::as_array);
    let scanned: BTreeSet<String> = raw_paths
        .into_iter()
        .flatten()
        .filter_map(path)
        .map(str::to_owned)
        .collect();
    if raw_paths.is_some_and(|p| p.len() != scanned.len())
        || scanned.iter().any(|p| !targets.contains(p))
    {
        gaps.push("semgrep-unexpected-or-duplicate-scanned-target".into());
    }
    for p in targets.difference(&scanned) {
        gaps.push(format!("semgrep-unexamined-selected-file:{p}"));
    }
    if value
        .get("results")
        .and_then(Value::as_array)
        .is_some_and(|results| {
            results.iter().any(|r| {
                r.get("path")
                    .and_then(path)
                    .is_none_or(|p| !scanned.contains(p))
            })
        })
    {
        gaps.push("semgrep-result-outside-scanned-targets".into());
    }
    let count = if valid {
        value["results"].as_array().unwrap().len() as u64
    } else {
        0
    };
    output.details.insert(
        "findingsCount".into(),
        if valid { json!(count) } else { Value::Null },
    );
    output.details.insert("semgrepReport".into(), value.clone());
    if valid {
        for row in value["results"].as_array().unwrap() {
            let file = path(&row["path"]).unwrap();
            if targets.contains(file) && scanned.contains(file) {
                push_candidate(
                    output,
                    row["check_id"].as_str().unwrap(),
                    "high",
                    file,
                    row["start"]["line"].as_u64().unwrap() as usize,
                    row.pointer("/extra/message")
                        .and_then(Value::as_str)
                        .unwrap_or("Packaged Semgrep rule matched; adjudication required"),
                );
            }
        }
    }
    output.coverage_gaps.extend(gaps);
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: if valid {
            targets.intersection(&scanned).count() as u64
        } else {
            0
        },
        gaps: output.coverage_gaps.clone(),
    });
    output.complete = output.coverage_gaps.is_empty();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn semgrep_partial_envelopes_never_prove_clean() {
        let valid = json!({"version":VERSION,"results":[],"errors":[],"paths":{"scanned":[],"skipped":[]},"skipped_rules":[]});
        assert!(valid_envelope(&valid));
        for (pointer, bad) in [
            ("/errors", json!([{"type":"Timeout"}])),
            (
                "/paths/skipped",
                json!([{"path":"x.py","reason":"parse error"}]),
            ),
            ("/skipped_rules", json!(["bad"])),
            ("/version", json!("unknown")),
            ("/paths/scanned", json!(["../escape.py"])),
        ] {
            let mut report = valid.clone();
            *report.pointer_mut(pointer).unwrap() = bad;
            assert!(!valid_envelope(&report));
        }
        assert!(!valid_envelope(&json!({"results":[]})));
    }
    #[test]
    fn semgrep_reconciliation_preserves_original_denominator() {
        let root = std::env::temp_dir().join(format!(
            "semgrep-denominator-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let mut entries = Vec::new();
        for (name, bytes) in [
            ("examined.py", "print(1)"),
            ("omitted.py", "print(2)"),
            ("unsupported.rs", "fn main() {}"),
        ] {
            fs::write(root.join(name), bytes).unwrap();
            entries.push(crate::InventoryEntry {
                path: name.into(),
                symbols: vec![],
                dependencies: vec![],
                package_scripts: vec![],
                source_file: true,
                digest: Some(format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(bytes.as_bytes()))
                )),
            });
        }
        let input = LegacyCheckInput {
            provider_id: "legacy.security.sast".into(),
            check: "sast".into(),
            root: root.clone(),
            inventory_generation: "fixture".into(),
            inventory_digest: "frozen-inventory".into(),
            denominator: crate::inventory::InventoryDenominator {
                entries,
                digest: "original-denominator".into(),
            },
            binding: None,
            projection: None,
            artifacts: Value::Null,
        };
        let report = json!({"version":VERSION,"results":[],"errors":[],"paths":{"scanned":["examined.py"],"skipped":[]},"skipped_rules":[]});
        let mut output = empty_output(vec![]);
        assert!(parse(&input, &report, &mut output));
        let coverage = output.coverage.as_ref().unwrap();
        assert_eq!((coverage.expected, coverage.examined), (3, 1));
        assert_eq!(coverage.denominator_digest, "original-denominator");
        assert!(!output.complete);
        assert!(output
            .coverage_gaps
            .iter()
            .any(|s| s == "semgrep-unexamined-selected-file:omitted.py"));
        assert!(output
            .coverage_gaps
            .iter()
            .any(|s| s == "semgrep-unsupported-selected-file:unsupported.rs"));
        fs::write(root.join("examined.py"), "changed()").unwrap();
        let mut changed = empty_output(vec![]);
        parse(&input, &report, &mut changed);
        assert!(!changed.complete);
        assert!(changed
            .coverage_gaps
            .iter()
            .any(|s| s == "semgrep-selected-source-changed:examined.py"));
        let mut failed = report;
        failed["errors"] = json!([{"type":"Timeout"}]);
        let mut output = empty_output(vec![]);
        parse(&input, &failed, &mut output);
        assert_eq!(output.coverage.as_ref().unwrap().examined, 0);
        assert_eq!(output.coverage.as_ref().unwrap().expected, 3);
        fs::remove_dir_all(root).unwrap();
    }
}
