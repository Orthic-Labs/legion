//! Native implementation of `governance.capability-ownership`.
//!
//! The trusted host declares a capability-ownership scan command through the
//! `AUDIT_OWNERSHIP_SCAN_CMD` environment variable: a JSON array of strings
//! (argv, no shell). Legion ships no ownership ruleset of its own. The plan
//! freezes whether the host declared the command and its digest; this module
//! re-reads the declaration at execution time and refuses to run on drift.
//!
//! Contract with the host command: it is run with the frozen root as its
//! working directory, must be read-only, and must print one JSON document on
//! stdout: `{"schemaVersion":1,"findings":[{"rule","path","line","message",
//! "capability"?,"owner"?}]}`. Every finding needs a repository-relative
//! `path` inside the frozen denominator. `line` is optional (1-based); a
//! finding without one is file-level: it is reported at line 1 with
//! `"lineKnown": false` in its evidence. Findings are advisory "duplicates
//! RightKit owner" notes unless the host sets `AUDIT_OWNERSHIP_SCAN_REQUIRED`.

use std::{
    collections::BTreeMap,
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use legion_contracts::{FindingRef, ProviderStatus};
use serde_json::{json, Value};

use super::common::{denominator, digest_text, finding, result, ProviderInput};
use crate::error::AuditError;

/// Environment variable carrying the host-declared scan command (JSON argv).
pub const COMMAND_ENV: &str = "AUDIT_OWNERSHIP_SCAN_CMD";
/// Set to `1`/`true` by the host to make the provider required for a clean claim.
pub const REQUIRED_ENV: &str = "AUDIT_OWNERSHIP_SCAN_REQUIRED";

const TIMEOUT: Duration = Duration::from_secs(120);
const MAX_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;

/// Parse a declared command into argv. `None` means not declared or malformed.
pub fn parse_argv(raw: &str) -> Option<Vec<String>> {
    let argv: Vec<String> = serde_json::from_str(raw).ok()?;
    if argv.is_empty() || argv[0].trim().is_empty() {
        return None;
    }
    Some(argv)
}

/// Digest bound into the frozen plan for a declared command.
pub fn command_digest(raw: &str) -> String {
    digest_text(raw)
}

fn run_scan(argv: &[String], root: &std::path::Path) -> Result<String, String> {
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(root)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command.env("AUDIT_FROZEN_ROOT", root);
    let mut child = command
        .spawn()
        .map_err(|error| format!("ownership-scan-spawn-failed:{error}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "ownership-scan-spawn-failed:no stdout".to_owned())?;
    let reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = (&mut stdout)
            .take(MAX_OUTPUT_BYTES)
            .read_to_end(&mut buffer);
        buffer
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() > TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("ownership-scan-timeout".into());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(format!("ownership-scan-wait-failed:{error}")),
        }
    };
    let bytes = reader.join().unwrap_or_default();
    if !status.success() {
        return Err(format!(
            "ownership-scan-exit-nonzero:{}",
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |c| c.to_string())
        ));
    }
    String::from_utf8(bytes).map_err(|_| "ownership-scan-output-not-utf8".to_owned())
}

fn safe_relative(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    !normalized.is_empty()
        && !normalized.starts_with('/')
        && !normalized.contains(':')
        && !normalized.split('/').any(|part| part == "..")
}

/// Message reported for a finding: the host message, always phrased as a
/// "duplicates RightKit owner" note (capability/owner appended when present).
fn finding_message(message: Option<&str>, capability: Option<&str>, owner: Option<&str>) -> String {
    const PHRASE: &str = "duplicates RightKit owner";
    let base = match message.map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => text.to_owned(),
        None => match (capability, owner) {
            (Some(capability), Some(owner)) => format!("{capability} {PHRASE} {owner}"),
            (_, Some(owner)) => format!("{PHRASE} {owner}"),
            _ => PHRASE.to_owned(),
        },
    };
    if base.contains(PHRASE) {
        base
    } else {
        match owner {
            Some(owner) => format!("{base} ({PHRASE} {owner})"),
            None => format!("{base} ({PHRASE})"),
        }
    }
}

/// ProviderExecutor-facing entrypoint.
pub fn execute(input: &ProviderInput<'_>) -> Result<legion_contracts::ProviderResult, AuditError> {
    let denominator = denominator(input)?;
    let mut gaps: Vec<String> = Vec::new();
    let mut findings: Vec<FindingRef> = Vec::new();
    let mut evidence = serde_json::Map::new();
    let mut locations = serde_json::Map::new();
    let mut messages = serde_json::Map::new();
    let mut details: BTreeMap<String, Value> = BTreeMap::new();

    let frozen_digest = input
        .provider
        .configuration
        .get("hostDeclaration")
        .and_then(|value| value.get("commandDigest"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let raw = std::env::var(COMMAND_ENV).unwrap_or_default();
    let argv = parse_argv(&raw);
    match (&argv, &frozen_digest) {
        (Some(_), Some(frozen)) if *frozen == command_digest(&raw) => {}
        _ => gaps.push("ownership-scan-declaration-drift".into()),
    }

    if gaps.is_empty() {
        let argv = argv.expect("declaration checked above");
        match run_scan(&argv, input.root).and_then(|text| {
            serde_json::from_str::<Value>(&text)
                .map_err(|error| format!("ownership-scan-output-invalid:{error}"))
        }) {
            Err(gap) => gaps.push(gap),
            Ok(document) => {
                let rows = document.get("findings").and_then(Value::as_array);
                if document.get("schemaVersion").and_then(Value::as_u64) != Some(1)
                    || rows.is_none()
                {
                    gaps.push("ownership-scan-output-invalid:schema".into());
                }
                for (index, row) in rows.into_iter().flatten().enumerate() {
                    let rule = row.get("rule").and_then(Value::as_str).unwrap_or("");
                    let path = row.get("path").and_then(Value::as_str).unwrap_or("");
                    // `line` is optional: absent means a file-level finding.
                    let (line, line_known) = match row.get("line") {
                        None | Some(Value::Null) => (1, false),
                        Some(value) => match value.as_u64() {
                            Some(line) if line > 0 => (line, true),
                            _ => (0, false),
                        },
                    };
                    if rule.is_empty() || line == 0 || !safe_relative(path) {
                        gaps.push(format!("ownership-scan-finding-invalid:{index}"));
                        continue;
                    }
                    let path = path.replace('\\', "/");
                    if !denominator.entries.iter().any(|entry| entry.path == path) {
                        gaps.push(format!("ownership-finding-outside-scope:{path}"));
                        continue;
                    }
                    let item = finding(
                        &format!("governance.capability-ownership:{rule}"),
                        "warning",
                        &path,
                        line as usize,
                    );
                    let message = finding_message(
                        row.get("message").and_then(Value::as_str),
                        row.get("capability").and_then(Value::as_str),
                        row.get("owner").and_then(Value::as_str),
                    );
                    messages.insert(item.id.to_string(), Value::String(message.clone()));
                    evidence.insert(
                        item.id.to_string(),
                        json!({
                            "path": path,
                            "line": line,
                            "lineKnown": line_known,
                            "rule": rule,
                            "message": message,
                            "capability": row.get("capability").cloned().unwrap_or(Value::Null),
                            "owner": row.get("owner").cloned().unwrap_or(Value::Null),
                        }),
                    );
                    locations.insert(item.id.to_string(), json!([format!("{path}:{line}")]));
                    findings.push(item);
                }
            }
        }
    }

    details.insert("findingEvidence".into(), Value::Object(evidence));
    details.insert("findingLocations".into(), Value::Object(locations));
    details.insert("findingMessages".into(), Value::Object(messages));
    details.insert("hostDeclared".into(), Value::Bool(true));
    let complete = gaps.is_empty();
    result(
        input,
        if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        &denominator,
        if complete {
            denominator.entries.len()
        } else {
            0
        },
        findings,
        gaps.clone(),
        gaps,
        details,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_requires_non_empty_json_array() {
        assert!(parse_argv("").is_none());
        assert!(parse_argv("[]").is_none());
        assert!(parse_argv("scan --json").is_none());
        assert_eq!(
            parse_argv("[\"scan\",\"--json\"]"),
            Some(vec!["scan".to_owned(), "--json".to_owned()])
        );
    }

    #[test]
    fn finding_message_is_a_duplicates_owner_note() {
        assert_eq!(
            finding_message(
                Some("audio duplicates RightKit owner rightkit-audio"),
                None,
                None
            ),
            "audio duplicates RightKit owner rightkit-audio"
        );
        assert_eq!(
            finding_message(None, Some("audio"), Some("rightkit-audio")),
            "audio duplicates RightKit owner rightkit-audio"
        );
        assert_eq!(
            finding_message(Some("hound dependency"), None, Some("rightkit-audio")),
            "hound dependency (duplicates RightKit owner rightkit-audio)"
        );
    }

    #[test]
    fn finding_paths_must_stay_inside_root() {
        assert!(safe_relative("src/a.rs"));
        assert!(!safe_relative("../a.rs"));
        assert!(!safe_relative("/etc/passwd"));
        assert!(!safe_relative("C:/x"));
        assert!(!safe_relative(""));
    }
}
