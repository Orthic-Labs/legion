//! Packet P11d — the provider suite orchestrators that have a production
//! caller: `data_suite` and `infrastructure_suite` (dispatched by
//! `legacy::candidate_suites`) and `security_suite` (its five heuristic packs
//! are dispatched by `native_providers::security::packs`). Provider modules
//! with no production caller (ai-quality, accessibility, generic-source,
//! framework suites) were removed in the native-provider sweep.

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn digest_id(parts: &[&str]) -> String {
    format!("sha256:{}", sha256_hex(parts.join("\0").as_bytes()))
}

/// Largest char boundary at or below `index` (clamped to the text length), so
/// byte-window slices never split a multi-byte character.
fn char_floor(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn line_at(text: &str, index: usize) -> usize {
    text.get(..index.min(text.len()))
        .unwrap_or("")
        .matches('\n')
        .count()
        + 1
}

// =====================================================================
// providers/data-suite.mjs :: runDataSuite
// =====================================================================
pub mod data_suite {
    use super::*;

    const DATA_EXTENSIONS: &[&str] = &[
        "sql", "ts", "tsx", "js", "mjs", "cjs", "py", "php", "rb", "go", "rs", "java", "kt", "cs",
    ];

    /// Whether the data suite inspects this path (by extension).
    pub fn inspects(file: &str) -> bool {
        let ext = std::path::Path::new(file)
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        DATA_EXTENSIONS.contains(&ext.as_str())
    }

    fn severity_hint(level: &str) -> &'static str {
        match level {
            "error" => "high",
            "warning" => "medium",
            _ => "low",
        }
    }

    fn candidate(rule_id: &str, level: &str, message: &str, file: &str, line: usize) -> Value {
        json!({
            "id": digest_id(&[rule_id, file, &line.to_string()]),
            "ruleId": rule_id, "severityHint": severity_hint(level), "claim": message, "file": file, "line": line,
        })
    }

    struct Rule {
        id: &'static str,
        level: &'static str,
        message: &'static str,
        patterns: &'static [&'static str],
    }

    // Lookahead-free rules stay data-driven. Three JS rules use `(?!...)`
    // (unsupported by the `regex` crate) and are reimplemented below as
    // explicit scans with identical semantics.
    const RULES: &[Rule] = &[
        Rule { id: "data.sql-interpolation", level: "error", message: "SQL text appears to interpolate or concatenate variable input.", patterns: &[r#"(?is)(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP)[^\n;]*(?:\$\{|\+\s*(?:req|request|input|user|params|query)|format\s*\(|f['"])"#] },
        Rule { id: "data.destructive-migration", level: "warning", message: "Migration contains a destructive DROP operation; require backup, rollback, and compatibility evidence.", patterns: &[r#"(?i)\bDROP\s+(?:TABLE|COLUMN|DATABASE|INDEX)\b"#] },
        Rule { id: "data.sqlite-foreign-keys-off", level: "error", message: "SQLite foreign-key enforcement is disabled.", patterns: &[r#"(?i)PRAGMA\s+foreign_keys\s*=\s*(?:OFF|0)"#] },
        Rule { id: "data.redis-keys", level: "warning", message: "Redis KEYS can block the server; use bounded SCAN for production paths.", patterns: &[r#"\.(?:keys|KEYS)\s*\(\s*['"][^'"]*['"]\s*\)"#] },
        Rule { id: "data.mongo-javascript", level: "error", message: "MongoDB server-side JavaScript evaluation is used.", patterns: &[r#"(?i)\$(?:where|function)\b|mapReduce\s*\("#] },
    ];

    /// JS: `/\bADD\s+(?:COLUMN\s+)?[A-Za-z0-9_"\`]+[^;\n]*\bNOT\s+NULL\b(?![^;\n]*\bDEFAULT\b)/i`
    /// — `NOT NULL` not followed by `DEFAULT` before the next `;`/newline.
    fn collect_not_null_migration(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r#"(?i)\bADD\s+(?:COLUMN\s+)?[A-Za-z0-9_"`]+[^;\n]*\bNOT\s+NULL\b"#).unwrap()
        });
        for m in re.find_iter(text) {
            let rest_end = text[m.end()..]
                .find(|c| c == ';' || c == '\n')
                .map(|i| m.end() + i)
                .unwrap_or(text.len());
            let rest = &text[m.end()..rest_end];
            if !rest.to_lowercase().contains("default") {
                candidates.push(candidate(
                    "data.not-null-migration",
                    "warning",
                    "Migration adds NOT NULL without a visible default/backfill sequence.",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    /// JS: `/sqlite(?:3)?[\s\S]{0,200}(?:connect|open)\s*\((?![\s\S]{0,300}(?:busy_timeout|timeout))/is`
    /// — an sqlite connect/open call not followed within 300 chars by a busy-timeout mention.
    fn collect_sqlite_no_busy_timeout(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r"(?is)sqlite(?:3)?[\s\S]{0,200}(?:connect|open)\s*\(").unwrap()
        });
        for m in re.find_iter(text) {
            let end = char_floor(text, m.end() + 300);
            let window = &text[m.end()..end];
            if !Regex::new(r"(?i)busy_timeout|timeout")
                .unwrap()
                .is_match(window)
            {
                candidates.push(candidate("data.sqlite-no-busy-timeout", "note", "SQLite connection is configured without a visible busy timeout; assess lock contention.", file, line_at(text, m.start())));
            }
        }
    }

    /// JS: `/\.(?:set|hset)\s*\([^\n;]+\)(?![^\n;]*(?:expire|ttl|ex\s*:|px\s*:))/i`
    /// — a redis set/hset call with no expiration keyword before the next `;`/newline.
    fn collect_redis_unbounded_value(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| Regex::new(r"(?i)\.(?:set|hset)\s*\([^\n;]+\)").unwrap());
        for m in re.find_iter(text) {
            let rest_end = text[m.end()..]
                .find(|c| c == ';' || c == '\n')
                .map(|i| m.end() + i)
                .unwrap_or(text.len());
            let rest = &text[m.end()..rest_end];
            if !Regex::new(r"(?i)expire|ttl|ex\s*:|px\s*:")
                .unwrap()
                .is_match(rest)
            {
                candidates.push(candidate(
                    "data.redis-unbounded-value",
                    "note",
                    "Redis write has no visible expiration; verify retention and invalidation.",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    /// JS: `/(?:insert|update|delete|save)\s*\([\s\S]{0,500}(?:insert|update|delete|save)\s*\((?![\s\S]{0,700}(?:transaction|beginTransaction|BEGIN\b))/is`
    /// — two adjacent write calls within 500 chars, with no transaction keyword within 700 chars after the second.
    fn collect_transaction_missing(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static FIRST: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let first_re =
            FIRST.get_or_init(|| Regex::new(r"(?i)(?:insert|update|delete|save)\s*\(").unwrap());
        static TXN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let txn_re =
            TXN.get_or_init(|| Regex::new(r"(?i)transaction|beginTransaction|BEGIN\b").unwrap());
        for m in first_re.find_iter(text) {
            let window_end = char_floor(text, m.end() + 500);
            let window = &text[m.end()..window_end];
            let second = match first_re.find(window) {
                Some(s) => s,
                None => continue,
            };
            let second_abs_end = m.end() + second.end();
            let tail_end = char_floor(text, second_abs_end + 700);
            let tail = &text[second_abs_end..tail_end];
            if !txn_re.is_match(tail) {
                candidates.push(candidate(
                    "data.transaction-missing",
                    "note",
                    "Multiple adjacent write operations have no visible transaction boundary.",
                    file,
                    line_at(text, m.start()),
                ));
                break; // one candidate per file is sufficient to mirror the JS regex's single global scan cursor behavior closely enough
            }
        }
    }

    pub fn run_data_suite(root: &std::path::Path, files: &[String]) -> Value {
        let mut candidates = Vec::new();
        for file in files {
            let ext = std::path::Path::new(file)
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            if !DATA_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
            for rule in RULES {
                for pattern in rule.patterns {
                    let re = Regex::new(pattern).unwrap();
                    for m in re.find_iter(&text) {
                        candidates.push(candidate(
                            rule.id,
                            rule.level,
                            rule.message,
                            file,
                            line_at(&text, m.start()),
                        ));
                    }
                }
            }
            collect_not_null_migration(&text, file, &mut candidates);
            collect_sqlite_no_busy_timeout(&text, file, &mut candidates);
            collect_redis_unbounded_value(&text, file, &mut candidates);
            collect_transaction_missing(&text, file, &mut candidates);
        }
        json!({
            "schemaVersion": 1, "provider": "data.internal-suite", "providerVersion": "1.0.0",
            "ownerProvider": "data.internal-suite", "phase": "runtime", "role": "candidate-generator",
            "status": if candidates.is_empty() { "pass" } else { "candidates" },
            "complete": true, "applicable": true, "required": true,
            "coverage": { "pathCount": files.len(), "rules": RULES.len() + 4 },
            "candidates": candidates, "findings": [], "receipts": [], "coverageGaps": [], "degradation": [],
        })
    }
}

// =====================================================================
// providers/infrastructure-suite.mjs :: runInfrastructureSuite
// =====================================================================
pub mod infrastructure_suite {
    use super::*;

    fn severity_hint(level: &str) -> &'static str {
        match level {
            "critical" | "error" => "high",
            "warning" => "medium",
            _ => "low",
        }
    }

    fn candidate(rule_id: &str, level: &str, message: &str, file: &str, line: usize) -> Value {
        json!({
            "id": digest_id(&[rule_id, file, &line.to_string()]),
            "ruleId": rule_id, "severityHint": severity_hint(level), "claim": message, "file": file, "line": line,
        })
    }

    type Applies = fn(&str, &str) -> bool;

    struct Rule {
        id: &'static str,
        level: &'static str,
        message: &'static str,
        pattern: &'static str,
        applies: Applies,
    }

    fn is_dockerfile(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)^Dockerfile").unwrap().is_match(
            std::path::Path::new(file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(""),
        )
    }
    fn is_dockerfile_no_user(file: &str, text: &str) -> bool {
        is_dockerfile(file, text) && !Regex::new(r"(?im)^\s*USER\s+").unwrap().is_match(text)
    }
    fn is_yaml(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)\.ya?ml$").unwrap().is_match(file)
    }
    fn is_workflow(file: &str, _text: &str) -> bool {
        file.starts_with(".github/workflows/")
    }
    fn is_workflow_pr_target(file: &str, text: &str) -> bool {
        is_workflow(file, text) && text.contains("pull_request_target")
    }
    fn is_tf(file: &str, _text: &str) -> bool {
        file.ends_with(".tf")
    }
    fn is_release_script(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)\.(?:sh|ps1|mjs|cjs|js|py|rb|yml|yaml|toml|json)$")
            .unwrap()
            .is_match(file)
    }
    fn is_release_script_narrow(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)\.(?:sh|ps1|mjs|cjs|js|py|rb)$")
            .unwrap()
            .is_match(file)
    }
    fn is_tauri_conf(file: &str, _text: &str) -> bool {
        Regex::new(r"(?:tauri\.conf\.(?:json|json5)|Tauri\.toml)$")
            .unwrap()
            .is_match(file)
    }

    const RULES: &[Rule] = &[
        Rule { id: "container.latest-tag", level: "warning", message: "Container base image is unpinned or uses latest.", pattern: r"(?im)^\s*FROM\s+[^\s:@]+(?::latest)?\s*$", applies: is_dockerfile },
        Rule { id: "container.remote-add", level: "warning", message: "Docker ADD fetches a mutable remote resource without explicit integrity verification.", pattern: r"(?im)^\s*ADD\s+https?://", applies: is_dockerfile },
        Rule { id: "container.curl-pipe-shell", level: "error", message: "Container build pipes remote content directly to a shell.", pattern: r"(?i)(?:curl|wget)[^\n|]*\|\s*(?:sh|bash|zsh)", applies: is_dockerfile },
        Rule { id: "container-root-user", level: "warning", message: "Container has no explicit non-root USER.", pattern: r"(?im)^\s*FROM\s+", applies: is_dockerfile_no_user },
        Rule { id: "k8s-privileged", level: "error", message: "Kubernetes workload enables privileged mode.", pattern: r"(?i)privileged:\s*true", applies: is_yaml },
        Rule { id: "k8s-host-namespace", level: "error", message: "Kubernetes workload joins a host namespace.", pattern: r"(?i)(?:hostNetwork|hostPID|hostIPC):\s*true", applies: is_yaml },
        Rule { id: "k8s-unpinned-image", level: "warning", message: "Kubernetes image is not digest-pinned.", pattern: r"(?im)image:\s*[^\s@]+(?::latest)?\s*$", applies: is_yaml },
        Rule { id: "k8s-secret-literal", level: "error", message: "Secret-like value appears inline in deployment YAML.", pattern: r#"(?i)(?:password|secret|token|api[_-]?key):\s*['"]?[^\s${][^\n]{5,}"#, applies: is_yaml },
        Rule { id: "actions-write-all", level: "error", message: "GitHub Actions grants write-all permissions.", pattern: r"(?i)permissions:\s*write-all", applies: is_workflow },
        Rule { id: "actions-unpinned", level: "warning", message: "GitHub Action is not pinned to an immutable commit.", pattern: r"(?im)uses:\s*[^\s@]+@(?:main|master|latest|v?\d+(?:\.\d+)?)\s*$", applies: is_workflow },
        Rule { id: "actions-expression-in-shell", level: "error", message: "Attacker-controlled event data is interpolated directly into a shell command.", pattern: r"(?i)run:\s*[^\n]*\$\{\{\s*github\.event\.", applies: is_workflow },
        Rule { id: "actions-pr-target-checkout", level: "critical", message: "Privileged pull_request_target workflow checks out attacker-controlled head code.", pattern: r"(?i)ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}", applies: is_workflow_pr_target },
        Rule { id: "terraform-open-ingress", level: "error", message: "Terraform security rule allows global IPv4 access.", pattern: r#"(?i)cidr_blocks\s*=\s*\[[^\]]*['"]0\.0\.0\.0/0['"][^\]]*\]"#, applies: is_tf },
        Rule { id: "terraform-public-storage", level: "error", message: "Infrastructure configuration enables public storage access.", pattern: r"(?i)(?:acl\s*=\s*['\x22]public|public_access\s*=\s*true|block_public_acls\s*=\s*false)", applies: is_tf },
        Rule { id: "release-mutable-download", level: "warning", message: "Release tooling downloads from a mutable latest URL.", pattern: r#"(?i)https?://[^\s'"]+/(?:latest|releases/latest|download/latest)[^\s'"]*"#, applies: is_release_script },
        Rule { id: "tauri-updater-insecure", level: "error", message: "Tauri updater permits insecure transport.", pattern: r"(?i)dangerousInsecureTransportProtocol\s*[:=]\s*true", applies: is_tauri_conf },
    ];

    /// JS: `/(?:curl|wget|Invoke-WebRequest|fetch\s*\()[\s\S]{0,300}https?:\/\/(?![\s\S]{0,500}(?:sha256|checksum|digest|integrity))/is`
    /// (unsupported lookahead) — a download call whose URL has no integrity
    /// keyword within 500 chars after it.
    fn collect_release_download_no_hash(file: &str, text: &str, candidates: &mut Vec<Value>) {
        if !is_release_script_narrow(file, text) {
            return;
        }
        static PREFIX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let prefix_re = PREFIX.get_or_init(|| {
            Regex::new(r"(?is)(?:curl|wget|Invoke-WebRequest|fetch\s*\()[\s\S]{0,300}https?://")
                .unwrap()
        });
        static INTEGRITY: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let integrity_re =
            INTEGRITY.get_or_init(|| Regex::new(r"(?i)sha256|checksum|digest|integrity").unwrap());
        for m in prefix_re.find_iter(text) {
            let end = char_floor(text, m.end() + 500);
            if !integrity_re.is_match(&text[m.end()..end]) {
                candidates.push(candidate(
                    "release-download-no-hash",
                    "warning",
                    "Downloaded release artifact has no nearby integrity verification.",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    pub fn run_infrastructure_suite(root: &std::path::Path, files: &[String]) -> Value {
        let mut candidates = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
            for rule in RULES {
                if !(rule.applies)(file, &text) {
                    continue;
                }
                let re = Regex::new(rule.pattern).unwrap();
                for m in re.find_iter(&text) {
                    candidates.push(candidate(
                        rule.id,
                        rule.level,
                        rule.message,
                        file,
                        line_at(&text, m.start()),
                    ));
                }
            }
            collect_release_download_no_hash(file, &text, &mut candidates);
        }
        json!({
            "schemaVersion": 1, "provider": "infrastructure.internal-suite", "providerVersion": "1.0.0",
            "ownerProvider": "infrastructure.internal-suite", "phase": "runtime", "role": "candidate-generator",
            "status": if candidates.is_empty() { "pass" } else { "candidates" },
            "complete": true, "applicable": true, "required": true,
            "coverage": { "pathCount": files.len(), "rules": RULES.len() + 1 },
            "candidates": candidates, "findings": [], "receipts": [], "coverageGaps": [], "degradation": [],
        })
    }
}

// =====================================================================
// providers/security-suite.mjs
//
// Lives in `security_suite.rs`. Production dispatch of its five packs is
// `native_providers::security::packs` (provider ids `security.credentials`,
// `security.insecure-defaults`, `security.misuse-resistance`,
// `security.agentic-ci`, `security.agent-skill-mcp`).
// =====================================================================
pub mod security_suite;
