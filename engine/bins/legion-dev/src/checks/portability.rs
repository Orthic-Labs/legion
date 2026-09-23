// Port of `scripts/check-portability.mjs`. Scans every tracked file for
// developer-local path fragments (a workspace drive, a home directory, a
// bare username) that must either be absent or explicitly allowlisted in
// `src/config/portability-allowlist.json` with an exact occurrence count.
//
// The literal fragments are built via string concatenation, exactly as the
// Node source does, so this file's own source text does not itself trip the
// scan it implements.

use super::{read_json, read_text, tracked_files};
use regex::RegexBuilder;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct Issue {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<&'static str>,
    reason: String,
}

#[derive(Serialize)]
struct Report {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    kind: &'static str,
    status: &'static str,
    #[serde(rename = "filesScanned")]
    files_scanned: usize,
    issues: Vec<Issue>,
}

struct Pattern {
    id: &'static str,
    count: fn(&str) -> usize,
}

fn count_workspace(content: &str) -> usize {
    let d_claude = format!("{}{}", "D:[/\\\\]Clau", "de");
    let volumes_d_claude = format!("{}{}", "/Volumes/D/[Cc]lau", "de");
    let pattern = format!("{d_claude}|{volumes_d_claude}");
    let re = RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
        .expect("valid pattern");
    re.find_iter(content).count()
}

fn count_home(content: &str) -> usize {
    let name1 = format!("{}{}", "Adri", "an");
    let name2 = format!("{}{}", "AD", "RDS");
    let win = format!("C:[/\\\\]Users[/\\\\](?:{name1}|{name2})");
    let mac = format!("/Users/(?:{name1}|adri{}|{name2})", "an");
    let pattern = format!("{win}|{mac}");
    let re = RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
        .expect("valid pattern");
    re.find_iter(content).count()
}

fn count_username(content: &str) -> usize {
    // `(?<![A-Za-z0-9])ADRDS(?![A-Za-z0-9])`, case-insensitive: no lookaround
    // support in the `regex` crate, so the boundary is checked manually.
    let needle = format!("{}{}", "AD", "RDS");
    let hay = content.as_bytes();
    let needle_lower = needle.to_ascii_lowercase();
    let hay_lower = content.to_ascii_lowercase();
    let hay_lower_bytes = hay_lower.as_bytes();
    let mut count = 0usize;
    let mut start = 0usize;
    let is_alnum = |b: u8| b.is_ascii_alphanumeric();
    while let Some(pos) = find_from(hay_lower_bytes, needle_lower.as_bytes(), start) {
        let before_ok = pos == 0 || !is_alnum(hay[pos - 1]);
        let end = pos + needle.len();
        let after_ok = end >= hay.len() || !is_alnum(hay[end]);
        if before_ok && after_ok {
            count += 1;
        }
        start = pos + 1;
    }
    count
}

fn find_from(hay: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if start >= hay.len() || needle.is_empty() {
        return None;
    }
    hay[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

fn patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            id: "developer-workspace",
            count: count_workspace,
        },
        Pattern {
            id: "developer-home",
            count: count_home,
        },
        Pattern {
            id: "developer-username",
            count: count_username,
        },
    ]
}

fn pattern_by_id(id: &str) -> Option<Pattern> {
    patterns().into_iter().find(|p| p.id == id)
}

pub fn report(root: &Path) -> Report {
    let files = tracked_files(root);
    let allowlist_path = "src/config/portability-allowlist.json";
    let mut issues = Vec::new();

    let allowlist = match read_json(&root.join(allowlist_path)) {
        Ok(v) => v,
        Err(e) => {
            issues.push(Issue {
                path: allowlist_path.to_string(),
                pattern: None,
                reason: format!("invalid portability allowlist: {e}"),
            });
            serde_json::json!({})
        }
    };

    let schema_ok = allowlist.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1)
        && allowlist.get("rules").map(|v| v.is_array()).unwrap_or(false);
    if !schema_ok {
        issues.push(Issue {
            path: allowlist_path.to_string(),
            pattern: None,
            reason: "invalid portability allowlist".to_string(),
        });
    }

    let empty_rules = Vec::new();
    let rules = allowlist
        .get("rules")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_rules);

    let file_set: std::collections::HashSet<&str> = files.iter().map(|s| s.as_str()).collect();

    for rule in rules {
        let rule_path = rule.get("path").and_then(|v| v.as_str()).unwrap_or("");
        if !file_set.contains(rule_path) {
            issues.push(Issue {
                path: rule_path.to_string(),
                pattern: None,
                reason: "portability allowlist path does not exist".to_string(),
            });
            continue;
        }
        let reason = rule.get("reason").and_then(|v| v.as_str());
        let class = rule.get("class").and_then(|v| v.as_str());
        let rule_patterns = rule.get("patterns").and_then(|v| v.as_array());
        if reason.is_none()
            || class.is_none()
            || rule_patterns.map(|a| a.is_empty()).unwrap_or(true)
        {
            issues.push(Issue {
                path: rule_path.to_string(),
                pattern: None,
                reason: "portability allowlist rule lacks classification, reason, or patterns"
                    .to_string(),
            });
            continue;
        }
        let content = read_text(&root.join(rule_path));
        for pat in rule_patterns.unwrap() {
            let id = pat.as_str().unwrap_or("");
            let Some(pattern) = pattern_by_id(id) else {
                issues.push(Issue {
                    path: rule_path.to_string(),
                    pattern: Some(leak(id)),
                    reason: "unknown portability pattern in allowlist".to_string(),
                });
                continue;
            };
            let expected = rule
                .get("occurrences")
                .and_then(|o| o.get(id))
                .and_then(|v| v.as_i64());
            let observed = content
                .as_deref()
                .map(pattern.count)
                .unwrap_or(0) as i64;
            let valid_expected = expected.map(|e| e >= 1).unwrap_or(false);
            if !valid_expected || observed != expected.unwrap_or(-1) {
                issues.push(Issue {
                    path: rule_path.to_string(),
                    pattern: Some(pattern.id),
                    reason: format!(
                        "allowlisted occurrence count differs: expected {}, found {observed}",
                        expected
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "<missing>".to_string())
                    ),
                });
            }
        }
    }

    for path in &files {
        let content = match read_text(&root.join(path)) {
            Some(c) => c,
            None => continue,
        };
        for pattern in patterns() {
            let observed = (pattern.count)(&content);
            if observed == 0 {
                continue;
            }
            let has_rule = rules.iter().any(|rule| {
                rule.get("path").and_then(|v| v.as_str()) == Some(path.as_str())
                    && rule
                        .get("patterns")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().any(|p| p.as_str() == Some(pattern.id)))
                        .unwrap_or(false)
            });
            if !has_rule {
                issues.push(Issue {
                    path: path.clone(),
                    pattern: Some(pattern.id),
                    reason: format!(
                        "unclassified developer-local value ({observed} occurrence{})",
                        if observed == 1 { "" } else { "s" }
                    ),
                });
            }
        }
    }

    let status = if issues.is_empty() { "pass" } else { "fail" };
    Report {
        schema_version: 1,
        kind: "legion-portability-report",
        status,
        files_scanned: files.len(),
        issues,
    }
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

pub fn run(root: &Path, json: bool) -> bool {
    let report = report(root);
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else if report.status == "pass" {
        println!("portability: PASS ({} tracked files)", report.files_scanned);
    } else {
        for issue in &report.issues {
            eprintln!(
                "{}: {}{}",
                issue.path,
                issue.reason,
                issue
                    .pattern
                    .map(|p| format!(" [{p}]"))
                    .unwrap_or_default()
            );
        }
    }
    report.status == "pass"
}
