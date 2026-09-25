// Port of `scripts/check-canonical-names.mjs` + `src/lib/naming/check.mjs` +
// `src/lib/naming/registry.mjs`. Scans every tracked file for legacy
// (`seer`/`nemesis`/`forge`/`sentinel`/`sorcerer`) tokens, plus a set of
// semantic invariants (authority sets, README/package.json/plugin-manifest
// content), against `src/config/naming-registry.json` and
// `src/config/naming-legacy-allowlist.json`.
//
// `AUTHORITY_ID` (src/packages/contracts/enums.mjs) and `ROSTER_ROLE_IDS`
// (src/lib/roster/index.mjs) are runtime JS constants with no Rust
// equivalent to import; their values are mirrored here as literals and must
// be kept in sync by hand if those modules change.

use super::{read_json, read_text, tracked_files};
use regex::RegexBuilder;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const TOKENS: &[&str] = &["seer", "nemesis", "forge", "sentinel", "sorcerer"];
const SKIP_PREFIXES: &[&str] = &[
    ".git/",
    ".agent/",
    ".audit/",
    ".cache/",
    "docs/foundation/",
    "node_modules/",
];
const AUTHORITY_ID: &[&str] = &["legion", "sage", "alchemist", "oracle", "arcane", "kernel"];
const ROSTER_ROLE_IDS: &[&str] = &["sage", "alchemist", "oracle"];

pub struct Issue {
    pub path: String,
    pub line: Option<usize>,
    pub token: Option<String>,
    pub reason: String,
}

pub struct Report {
    pub status: &'static str,
    pub canonical_authorities: Vec<String>,
    pub deprecated_aliases: Vec<String>,
    pub unclassified: Vec<Issue>,
}

fn is_active_source(path: &str) -> bool {
    let re = RegexBuilder::new(r"\.(?:cjs|js|json|jsx|md|mjs|py|sh|toml|ts|tsx|ya?ml)$")
        .case_insensitive(true)
        .build()
        .unwrap();
    re.is_match(path)
}

/// `(?<![A-Za-z0-9])token(?![A-Za-z0-9])`, case-insensitive, emulated
/// without lookaround (unsupported by the `regex` crate).
fn occurrences(content: &str, token: &str) -> Vec<usize> {
    let hay_lower = content.to_ascii_lowercase();
    let needle_lower = token.to_ascii_lowercase();
    let bytes = content.as_bytes();
    let hay_bytes = hay_lower.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_alphanumeric();
    let mut found = Vec::new();
    let mut start = 0usize;
    while start < hay_bytes.len() {
        let Some(rel) = hay_bytes[start..]
            .windows(needle_lower.len().max(1))
            .position(|w| w == needle_lower.as_bytes())
        else {
            break;
        };
        let pos = start + rel;
        let before_ok = pos == 0 || !is_alnum(bytes[pos - 1]);
        let end = pos + needle_lower.len();
        let after_ok = end >= bytes.len() || !is_alnum(bytes[end]);
        if before_ok && after_ok {
            let line = content[..pos].matches('\n').count() + 1;
            found.push(line);
        }
        start = pos + 1;
    }
    found
}

fn matching_rule<'a>(rules: &'a [Value], path: &str, token: &str) -> Option<&'a Value> {
    rules.iter().find(|rule| {
        let path_matches = rule.get("path").and_then(|v| v.as_str()) == Some(path)
            || rule
                .get("pathPrefix")
                .and_then(|v| v.as_str())
                .map(|p| path.starts_with(p))
                .unwrap_or(false);
        let tokens_match = rule
            .get("tokens")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().any(|t| t.as_str() == Some(token)))
            .unwrap_or(false);
        path_matches && tokens_match
    })
}

fn allowlist_issues(root: &Path, rules: &[Value], files: &[String]) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let rule_path = format!("src/config/naming-legacy-allowlist.json#rules[{index}]");
        let has_target = rule.get("path").and_then(|v| v.as_str()).is_some()
            || rule.get("pathPrefix").and_then(|v| v.as_str()).is_some();
        let tokens = rule.get("tokens").and_then(|v| v.as_array());
        let valid_shape = has_target
            && tokens.map(|a| !a.is_empty()).unwrap_or(false)
            && rule.get("class").and_then(|v| v.as_str()).is_some()
            && rule.get("reason").and_then(|v| v.as_str()).is_some();
        if !valid_shape {
            issues.push(Issue {
                path: rule_path,
                line: None,
                token: None,
                reason: "legacy allowlist rule lacks target, tokens, class, or reason".to_string(),
            });
            continue;
        }
        let rule_target_path = rule.get("path").and_then(|v| v.as_str());
        let rule_prefix = rule.get("pathPrefix").and_then(|v| v.as_str());
        let candidates: Vec<&String> = files
            .iter()
            .filter(|p| {
                Some(p.as_str()) == rule_target_path
                    || rule_prefix.map(|pre| p.starts_with(pre)).unwrap_or(false)
            })
            .collect();
        let target_label = rule_target_path.or(rule_prefix).unwrap_or("").to_string();
        if candidates.is_empty() {
            issues.push(Issue {
                path: target_label,
                line: None,
                token: None,
                reason: "legacy allowlist target does not exist or matches no files".to_string(),
            });
            continue;
        }
        for token in tokens.unwrap() {
            let token = match token.as_str() {
                Some(t) => t,
                None => continue,
            };
            if !TOKENS.contains(&token) {
                issues.push(Issue {
                    path: rule_path.clone(),
                    line: None,
                    token: Some(token.to_string()),
                    reason: "legacy allowlist names unknown token".to_string(),
                });
                continue;
            }
            let mut observed = 0usize;
            for path in &candidates {
                observed += occurrences(path, token).len();
                if let Some(content) = read_text(&root.join(path.as_str())) {
                    observed += occurrences(&content, token).len();
                }
            }
            if observed == 0 {
                issues.push(Issue {
                    path: target_label.clone(),
                    line: None,
                    token: Some(token.to_string()),
                    reason: "legacy allowlist token exemption is unused".to_string(),
                });
            }
        }
    }
    issues
}

fn canonical_authority_ids(registry: &Value) -> Vec<String> {
    let mut ids: Vec<String> = registry
        .get("authorities")
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    ids.sort();
    ids
}

fn semantic_issues(root: &Path, registry: &Value) -> Vec<Issue> {
    let mut issues = Vec::new();
    let expected = vec!["alchemist", "arcane", "oracle", "sage"];
    let canonical = canonical_authority_ids(registry);
    if canonical != expected {
        issues.push(mk("src/config/naming-registry.json", "canonical authority set mismatch"));
    }
    let product_id = registry
        .pointer("/product/id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut runtime_expected: BTreeSet<String> = BTreeSet::new();
    runtime_expected.insert(product_id.to_string());
    for e in &expected {
        runtime_expected.insert(e.to_string());
    }
    if let Some(actors) = registry.get("actors").and_then(|v| v.as_object()) {
        for k in actors.keys() {
            runtime_expected.insert(k.clone());
        }
    }
    let mut runtime_expected: Vec<String> = runtime_expected.into_iter().collect();
    runtime_expected.sort();
    let mut authority_sorted: Vec<String> = AUTHORITY_ID.iter().map(|s| s.to_string()).collect();
    authority_sorted.sort();
    if authority_sorted != runtime_expected {
        issues.push(mk(
            "src/packages/contracts/enums.mjs",
            "runtime authority set differs from naming registry",
        ));
    }
    if let Some(seats) = registry.get("seats").and_then(|v| v.as_object()) {
        for (id, seat) in seats {
            let authority_false = seat.get("authority").and_then(|v| v.as_bool()) == Some(false);
            if !authority_false || AUTHORITY_ID.contains(&id.as_str()) {
                issues.push(mk(
                    "src/config/naming-registry.json",
                    &format!("advisory seat '{id}' must not be an authority"),
                ));
            }
        }
    }
    let mut roster_sorted: Vec<String> = ROSTER_ROLE_IDS.iter().map(|s| s.to_string()).collect();
    roster_sorted.sort();
    if roster_sorted != vec!["alchemist", "oracle", "sage"] {
        issues.push(mk(
            "src/lib/roster/index.mjs",
            "runtime roster differs from naming registry",
        ));
    }
    if let Ok(readme) = std::fs::read_to_string(root.join("README.md")) {
        for display in ["Legion", "Sage", "Alchemist", "Oracle", "Arcane", "Covenant"] {
            if !readme.contains(&format!("| **{display}** |")) {
                issues.push(mk("README.md", &format!("authority table missing {display}")));
            }
        }
    }
    if let Ok(pkg) = read_json(&root.join("package.json")) {
        let keywords: Vec<&str> = pkg
            .get("keywords")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        for id in ["legion", "alchemist", "arcane", "sage", "covenant"] {
            if !keywords.contains(&id) {
                issues.push(mk("package.json", &format!("missing canonical keyword {id}")));
            }
        }
        let files: Vec<&str> = pkg
            .get("files")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if files.contains(&"packages/seer/") {
            issues.push(mk("package.json", "published files retain legacy assurance package"));
        }
    }
    if let Ok(manifest) = read_json(&root.join("MANIFEST.package.json")) {
        let allowlisted: Vec<&str> = manifest
            .get("allowlistedTopLevel")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if allowlisted.contains(&"packages/seer/") {
            issues.push(mk(
                "MANIFEST.package.json",
                "package manifest retains legacy assurance package",
            ));
        }
    }
    for path in [".claude-plugin/plugin.json", ".codex-plugin/plugin.json"] {
        if let Ok(manifest) = read_json(&root.join(path)) {
            let description = manifest.get("description").and_then(|v| v.as_str()).unwrap_or("");
            for display in ["Legion", "Sage", "Alchemist", "Oracle", "Arcane"] {
                if !description.contains(display) {
                    issues.push(mk(path, &format!("description missing {display}")));
                }
            }
        }
    }
    if root.join("packages/seer").exists() {
        issues.push(mk("packages/seer", "legacy assurance package still exists"));
    }
    if root.join("registry/rules/opengrep/nemesis-core.yml").exists() {
        issues.push(mk(
            "registry/rules/opengrep/nemesis-core.yml",
            "legacy product filename still exists",
        ));
    }
    // Runtime authority registry literal check (authority-binding-store.mjs).
    let abs_path = "src/lib/contracts/arcane/authority-binding-store.mjs";
    if let Ok(source) = std::fs::read_to_string(root.join(abs_path)) {
        let decl_re = RegexBuilder::new(r"const MAP\s*=\s*(\{[^}]+\})").build().unwrap();
        let literal = decl_re
            .captures(&source)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let value_re = RegexBuilder::new(r#":\s*['"]([^'"]+)['"]"#).build().unwrap();
        let mut observed: BTreeSet<String> = BTreeSet::new();
        for cap in value_re.captures_iter(&literal) {
            observed.insert(cap[1].to_string());
        }
        let observed: Vec<String> = observed.into_iter().collect();
        let mut expected_sorted = vec!["alchemist", "legion", "oracle", "sage"];
        expected_sorted.sort();
        if observed != expected_sorted {
            issues.push(mk(abs_path, "runtime authority registry differs from canonical set"));
        }
    }
    issues
}

fn mk(path: &str, reason: &str) -> Issue {
    Issue {
        path: path.to_string(),
        line: None,
        token: None,
        reason: reason.to_string(),
    }
}

pub fn check_canonical_names(root: &Path) -> Result<Report, String> {
    let registry = read_json(&root.join("src/config/naming-registry.json"))?;
    let allowlist = read_json(&root.join("src/config/naming-legacy-allowlist.json"))?;
    let empty_rules = Vec::new();
    let rules: &[Value] = allowlist
        .get("rules")
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&empty_rules);
    let files = tracked_files_naming(root);

    let mut issues = semantic_issues(root, &registry);
    issues.extend(allowlist_issues(root, rules, &files));

    for path in &files {
        for token in TOKENS {
            let path_hit = !occurrences(path, token).is_empty();
            if path_hit && matching_rule(rules, path, token).is_none() {
                issues.push(Issue {
                    path: path.clone(),
                    line: None,
                    token: Some(token.to_string()),
                    reason: "unclassified legacy filename".to_string(),
                });
            }
        }
        let content = match read_text(&root.join(path.as_str())) {
            Some(c) => c,
            None => {
                if is_active_source(path) {
                    issues.push(Issue {
                        path: path.clone(),
                        line: None,
                        token: None,
                        reason: "active source cannot be decoded for naming scan".to_string(),
                    });
                }
                continue;
            }
        };
        for token in TOKENS {
            let lines = occurrences(&content, token);
            let rule = matching_rule(rules, path, token);
            let exact_count = rule
                .and_then(|r| r.get("occurrences"))
                .and_then(|o| o.get(token))
                .and_then(|v| v.as_i64());
            if !lines.is_empty() && rule.is_none() {
                issues.push(Issue {
                    path: path.clone(),
                    line: Some(lines[0]),
                    token: Some(token.to_string()),
                    reason: "unclassified legacy token".to_string(),
                });
            } else if !lines.is_empty()
                && rule.map(|r| r.get("path").is_some()).unwrap_or(false)
                && rule.and_then(|r| r.get("class")).and_then(|v| v.as_str()) != Some("R5")
                && exact_count.is_none()
            {
                issues.push(Issue {
                    path: path.clone(),
                    line: Some(lines[0]),
                    token: Some(token.to_string()),
                    reason: "active exact-path allowlist lacks occurrence count".to_string(),
                });
            } else if let Some(expected) = exact_count {
                if lines.len() as i64 != expected {
                    issues.push(Issue {
                        path: path.clone(),
                        line: Some(lines[0]),
                        token: Some(token.to_string()),
                        reason: format!(
                            "legacy token occurrence count differs: expected {expected}, found {}",
                            lines.len()
                        ),
                    });
                }
            }
        }
    }

    let deprecated_aliases: BTreeSet<String> = registry
        .get("authorities")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.values()
                .flat_map(|entry| {
                    entry
                        .get("aliases")
                        .and_then(|a| a.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|alias| alias.get("id").and_then(|v| v.as_str()))
                                .map(String::from)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default();

    let status = if issues.is_empty() { "pass" } else { "fail" };
    Ok(Report {
        status,
        canonical_authorities: canonical_authority_ids(&registry),
        deprecated_aliases: deprecated_aliases.into_iter().collect(),
        unclassified: issues,
    })
}

/// Repository files, skipping the naming scan's own extra prefixes on top
/// of the shared `SKIP_DIRS`.
fn tracked_files_naming(root: &Path) -> Vec<String> {
    tracked_files(root)
        .into_iter()
        .filter(|p| !SKIP_PREFIXES.iter().any(|prefix| format!("{p}/").starts_with(prefix)))
        .collect()
}

pub fn run(root: &Path, json: bool) -> bool {
    let report = match check_canonical_names(root) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("canonical naming: {e}");
            return false;
        }
    };
    if json {
        let unclassified: Vec<_> = report
            .unclassified
            .iter()
            .map(|i| {
                serde_json::json!({
                    "path": i.path,
                    "line": i.line,
                    "token": i.token,
                    "reason": i.reason,
                })
            })
            .collect();
        let out = serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-naming-contract-report",
            "status": report.status,
            "canonicalAuthorities": report.canonical_authorities,
            "deprecatedAliases": report.deprecated_aliases,
            "unclassified": unclassified,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if report.status == "pass" {
        println!("canonical naming: PASS");
    } else {
        for issue in &report.unclassified {
            let line = issue.line.map(|l| format!(":{l}")).unwrap_or_default();
            let token = issue
                .token
                .as_ref()
                .map(|t| format!(" ({t})"))
                .unwrap_or_default();
            eprintln!("{}{line}: {}{token}", issue.path, issue.reason);
        }
    }
    report.status == "pass"
}
