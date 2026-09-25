// Port of `scripts/check-blueprint-config.mjs`. `.agent/config.json` must be
// a regular file, valid JSON, and declare `ignoredPrefixes` including every
// required prefix.

use super::read_json;
use std::path::Path;

const REQUIRED_IGNORED_PREFIXES: &[&str] = &[
    ".agent/",
    ".audit/",
    ".cache/",
    ".workbuddy-ai/",
    "docs/product.md",
    "docs/architecture.md",
];

pub struct Issue {
    pub path: String,
    pub reason: String,
}

pub struct Report {
    pub status: &'static str,
    pub issues: Vec<Issue>,
}

pub fn report(root: &Path) -> Report {
    let path = root.join(".agent").join("config.json");
    let mut issues = Vec::new();

    let meta = std::fs::metadata(&path);
    match meta {
        Ok(m) if !m.is_file() => {
            issues.push(Issue {
                path: ".agent/config.json".to_string(),
                reason: "blueprint config is not a regular file".to_string(),
            });
            return Report { status: "fail", issues };
        }
        Ok(_) => {}
        Err(_) => {
            issues.push(Issue {
                path: ".agent/config.json".to_string(),
                reason: "blueprint config is missing or invalid".to_string(),
            });
            return Report { status: "fail", issues };
        }
    }

    let config = match read_json(&path) {
        Ok(v) => v,
        Err(e) => {
            issues.push(Issue {
                path: ".agent/config.json".to_string(),
                reason: format!("blueprint config is missing or invalid: {e}"),
            });
            return Report { status: "fail", issues };
        }
    };

    match config.get("ignoredPrefixes").and_then(|v| v.as_array()) {
        None => issues.push(Issue {
            path: ".agent/config.json".to_string(),
            reason: "ignoredPrefixes must be an array".to_string(),
        }),
        Some(arr) => {
            let present: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            for prefix in REQUIRED_IGNORED_PREFIXES {
                if !present.contains(prefix) {
                    issues.push(Issue {
                        path: ".agent/config.json".to_string(),
                        reason: format!("ignoredPrefixes must exclude {prefix} from Blueprint indexing"),
                    });
                }
            }
        }
    }

    let status = if issues.is_empty() { "pass" } else { "fail" };
    Report { status, issues }
}

pub fn run(root: &Path, json: bool) -> bool {
    let report = report(root);
    if json {
        let issues: Vec<_> = report
            .issues
            .iter()
            .map(|i| serde_json::json!({ "path": i.path, "reason": i.reason }))
            .collect();
        let out = serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-blueprint-config-report",
            "status": report.status,
            "issues": issues,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if report.status == "pass" {
        println!("blueprint config: PASS");
    } else {
        for issue in &report.issues {
            eprintln!("{}: {}", issue.path, issue.reason);
        }
    }
    report.status == "pass"
}
