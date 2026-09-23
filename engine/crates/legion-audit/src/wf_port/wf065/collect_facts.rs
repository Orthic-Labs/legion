//! Port of the pure, filesystem/process-free helpers from
//! `tools/audit/collect-facts.mjs`.
//!
//! `collect-facts.mjs` is overwhelmingly a process-spawning check runner: it
//! shells out to `git`, `tsc`, `eslint`, `cargo clippy`, `gitleaks`, `npm
//! audit`, `pip-audit`, etc. and normalizes each tool's own output. None of
//! that external-tool orchestration is ported here — `engine/`'s own
//! `native_providers` module is this crate's native-tool integration layer,
//! and re-implementing every third-party CLI's output parser as a "port" of
//! this file would not be a faithful behavioral port (it would be a fresh
//! reimplementation of `tsc`/`eslint`/`clippy`/`gitleaks` themselves).
//!
//! What *is* pure logic, independent of any spawned process, is ported
//! faithfully here:
//!
//! - `clean_path` / `git_ref` / `in_scope` — path/ref normalization and the
//!   git-ref shell-injection guard used before any `git diff <ref>` spawn.
//! - `redact` — the secret-redaction regex chain applied to every captured
//!   tool log before it is written to disk.
//! - `gitleaks_candidates` — converts a raw `gitleaks --report-format json`
//!   array into secret-free candidate records (digest/rule/file/line only).
//! - `looks_missing` / `has_dep` — the ENOENT/stderr sniffing used to tell a
//!   genuinely-absent tool from a real lint failure.
//! - `is_generated_or_vendored_path` / `classify_file` — the file
//!   classification used by the `decomposition` check's review triggers.
//! - `decomposition_review_loc` — the `CORTEX_DECOMPOSITION_REVIEW_LOC` /
//!   `.agent/config.json` / workspace-default threshold resolution, with its
//!   "invalid config is surfaced as `ignored`, never silently dropped" rule.
//! - `resolve_root_positional` — the `--flag value` vs. bare-positional
//!   argv scan that finds the repo root among `collect-facts.mjs`'s CLI args
//!   (a real bug fixed upstream: a value-taking flag's argument must never be
//!   mistaken for the positional root).
//! - `oversized_files` / `mechanical_splits` — the LOC-threshold and
//!   include!/mod-stitch "logical unit reconstruction" grouping the
//!   `decomposition` check runs over a caller-supplied per-file LOC map (the
//!   check itself still has to read every tracked file to build that map;
//!   only the grouping/threshold math is pure).

use std::collections::BTreeMap;

use regex::Regex;

/// `cleanPath`: backslash-to-forward-slash, strip a leading `./` (a single
/// literal `.` followed by a *run* of one or more `/` — matching the JS
/// non-global `/^\.\/+/ `, which fires once, not repeatedly: `"././x"`
/// becomes `"./x"`, not `"x"`), strip trailing slashes. `None` in, `None`
/// out (mirrors the JS `p ? ... : null`).
pub fn clean_path(p: Option<&str>) -> Option<String> {
    let p = p?;
    if p.is_empty() {
        return None;
    }
    let normalized = p.replace('\\', "/");
    let stripped_leading = strip_leading_dot_slash_run(&normalized);
    let stripped = stripped_leading.trim_end_matches('/');
    Some(stripped.to_string())
}

fn strip_leading_dot_slash_run(s: &str) -> &str {
    let Some(after_dot) = s.strip_prefix('.') else {
        return s;
    };
    let run_end = after_dot
        .char_indices()
        .find(|(_, c)| *c != '/')
        .map(|(i, _)| i)
        .unwrap_or(after_dot.len());
    if run_end == 0 {
        // "." not followed by any "/": no match, string unchanged.
        s
    } else {
        &after_dot[run_end..]
    }
}

/// `gitRef`: validates a ref is safe to pass to `git` outside a shell.
/// `None` in (no `--base`/`--base-commit`) returns `Ok(None)`; an unsafe ref
/// is an error, matching the JS `throw new Error(...)`.
pub fn git_ref(ref_value: Option<&str>) -> Result<Option<String>, String> {
    let Some(s) = ref_value else { return Ok(None) };
    if s.is_empty() {
        return Ok(None);
    }
    let valid = {
        let mut chars = s.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        first_ok
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '@' | '-'))
    };
    if !valid {
        return Err(format!("Unsafe git ref: {s}"));
    }
    Ok(Some(s.to_string()))
}

/// `inScope`: `file` is in scope for `dir` iff `dir` is unset, or `file`
/// equals `dir`, or `file` starts with `dir/`. Both are `clean_path`d first.
pub fn in_scope(file: &str, dir: Option<&str>) -> bool {
    let f = clean_path(Some(file)).unwrap_or_default();
    match clean_path(dir) {
        None => true,
        Some(d) => f == d || f.starts_with(&format!("{d}/")),
    }
}

struct RedactRule {
    regex: Regex,
    replacement: &'static str,
}

fn redact_rules() -> Vec<RedactRule> {
    vec![
        RedactRule {
            regex: Regex::new(r"\bsk-[A-Za-z0-9]{16,}\b").unwrap(),
            replacement: "<REDACTED:openai>",
        },
        RedactRule {
            regex: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            replacement: "<REDACTED:aws>",
        },
        RedactRule {
            regex: Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b").unwrap(),
            replacement: "<REDACTED:github>",
        },
        RedactRule {
            regex: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
            replacement: "<REDACTED:slack>",
        },
        RedactRule {
            regex: Regex::new(
                r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            )
            .unwrap(),
            replacement: "<REDACTED:privkey>",
        },
        RedactRule {
            regex: Regex::new(r"\b[A-Za-z0-9+/]{60,}={0,2}\b").unwrap(),
            replacement: "<REDACTED:b64>",
        },
    ]
}

/// `redact`: apply the secret-redaction chain, in source order, to captured
/// tool output before it is written to a log or facts payload.
pub fn redact(text: Option<&str>) -> Option<String> {
    let text = text?;
    let mut out = text.to_string();
    for rule in redact_rules() {
        out = rule.regex.replace_all(&out, rule.replacement).into_owned();
    }
    Some(out)
}

/// `looksMissing`: post-hoc ENOENT/"command not found" sniffing for
/// shell-invoked commands.
pub fn looks_missing(stdout: &str, stderr: &str) -> bool {
    let re = Regex::new(
        r"(?i)is not recognized|command not found|ENOENT|could not determine executable|npm error code ENOENT|npx canceled|missing packages|no YES option",
    )
    .unwrap();
    re.is_match(&format!("{stderr}{stdout}"))
}

/// `hasDep`: a `package.json`-shaped value declares `name` in
/// `dependencies` or `devDependencies`.
pub fn has_dep(pkg: &serde_json::Value, name: &str) -> bool {
    let has = |key: &str| {
        pkg.get(key)
            .and_then(|deps| deps.as_object())
            .is_some_and(|deps| deps.contains_key(name))
    };
    has("dependencies") || has("devDependencies")
}

/// `isGeneratedOrVendoredPath`: swept out of `changedFiles` and the
/// decomposition scan.
pub fn is_generated_or_vendored_path(file: &str) -> bool {
    let Some(f) = clean_path(Some(file)) else {
        return false;
    };
    f.starts_with("vendor/")
        || f.starts_with("qwik/")
        || f.starts_with("dist/")
        || f.starts_with("src-tauri/gen/")
        || f.starts_with("src/generated/")
        || f.contains("/src/generated/")
        || f.contains("/drizzle/")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    Test,
    Tooling,
    Runtime,
}

impl FileClass {
    pub fn as_str(self) -> &'static str {
        match self {
            FileClass::Test => "test",
            FileClass::Tooling => "tooling",
            FileClass::Runtime => "runtime",
        }
    }
}

/// `classifyFile`: test > tooling > runtime, conservative (anything
/// ambiguous stays `runtime`).
pub fn classify_file(file: &str) -> FileClass {
    let cleaned = clean_path(Some(file)).unwrap_or_default().to_lowercase();
    let p = format!("/{cleaned}");
    let base = p.rsplit('/').next().unwrap_or("").to_string();

    let test_dir = Regex::new(
        r"(?:^|/)(?:tests?|specs?|__tests__|__mocks__|e2e|fixtures?|__fixtures__|cypress|playwright|\.storybook)/",
    )
    .unwrap();
    let test_suffix = Regex::new(r"\.(test|spec|stories|bench|e2e|cy)\.[a-z0-9]+$").unwrap();
    let test_file_suffix = Regex::new(r"_test\.[a-z0-9]+$").unwrap();
    let test_file_prefix = Regex::new(r"^test_.*\.py$").unwrap();
    if test_dir.is_match(&p)
        || test_suffix.is_match(&base)
        || test_file_suffix.is_match(&base)
        || test_file_prefix.is_match(&base)
        || base == "conftest.py"
    {
        return FileClass::Test;
    }

    let github_dir = Regex::new(r"(?:^|/)\.github/").unwrap();
    let config_suffix = Regex::new(r"\.config\.[a-z0-9]+$").unwrap();
    let setup_teardown = Regex::new(r"\.(setup|teardown)\.[a-z0-9]+$").unwrap();
    if github_dir.is_match(&p)
        || config_suffix.is_match(&base)
        || setup_teardown.is_match(&base)
        || base == "dockerfile"
        || base == "makefile"
    {
        return FileClass::Tooling;
    }

    FileClass::Runtime
}

#[derive(Debug, Clone, PartialEq)]
pub struct IgnoredThreshold {
    pub source: String,
    pub value: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecompositionReviewLoc {
    pub value: i64,
    pub source: String,
    pub ignored: Vec<IgnoredThreshold>,
}

/// `decompositionReviewLoc`: resolve the decomposition check's per-file LOC
/// review threshold from (in priority order) `CORTEX_DECOMPOSITION_REVIEW_LOC`,
/// `.agent/config.json`'s `hygiene.decompositionReviewLoc`, then the
/// workspace default of 400. An invalid configured value is never silently
/// dropped — it is returned in `ignored` so the caller can log it exactly as
/// `collect-facts.mjs` does (`console.error` per ignored item), and
/// resolution falls through to the next source.
///
/// `env_value` is `CORTEX_DECOMPOSITION_REVIEW_LOC` (unset ⇒ `None`, matching
/// `rawEnv !== undefined && rawEnv !== ''`); `config_value` is the JSON value
/// at `.agent/config.json` → `hygiene.decompositionReviewLoc` (absent or
/// `null` ⇒ `None`, matching `configured !== undefined && configured !== null`).
pub fn decomposition_review_loc(
    env_value: Option<&str>,
    config_value: Option<&serde_json::Value>,
) -> DecompositionReviewLoc {
    let mut ignored = Vec::new();

    if let Some(raw) = env_value {
        if !raw.is_empty() {
            // `Number(rawEnv)` then `Number.isInteger(...)`: parse as f64 (JS's
            // only numeric type), then require an integral value >= 100.
            match raw.trim().parse::<f64>() {
                Ok(f) if f.fract() == 0.0 && f >= 100.0 => {
                    return DecompositionReviewLoc {
                        value: f as i64,
                        source: "blueprint-config".to_string(),
                        ignored,
                    };
                }
                _ => ignored.push(IgnoredThreshold {
                    source: "CORTEX_DECOMPOSITION_REVIEW_LOC".to_string(),
                    value: raw.to_string(),
                    reason: "must be an integer >= 100".to_string(),
                }),
            }
        }
    }

    if let Some(configured) = config_value {
        if !configured.is_null() {
            // `Number(configured)` then `Number.isInteger(...)`: accept any
            // JSON number (int- or float-stored) that is integral and >= 100.
            let integral = configured.as_f64().filter(|f| f.fract() == 0.0 && *f >= 100.0);
            match integral {
                Some(f) => {
                    return DecompositionReviewLoc {
                        value: f as i64,
                        source: ".agent/config.json".to_string(),
                        ignored,
                    };
                }
                None => ignored.push(IgnoredThreshold {
                    source: ".agent/config.json hygiene.decompositionReviewLoc".to_string(),
                    value: configured.to_string(),
                    reason: "must be an integer >= 100".to_string(),
                }),
            }
        }
    }

    DecompositionReviewLoc {
        value: 400,
        source: "workspace-default".to_string(),
        ignored,
    }
}

/// `VALUE_FLAGS` scan: the first bare positional (a token not starting with
/// `--`, and not the argument consumed by a value-taking flag) is the repo
/// root. Mirrors the closure at the top of `collect-facts.mjs` that fixed a
/// real bug (`--only apple_platform` used to be misread as the root).
pub fn resolve_root_positional(args: &[String]) -> Option<String> {
    const VALUE_FLAGS: &[&str] = &["--base", "--base-commit", "--dir", "--only", "--out", "--skip", "--type"];
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(stripped) = arg.strip_prefix("--") {
            let flag = format!("--{stripped}");
            if VALUE_FLAGS.contains(&flag.as_str()) {
                i += 1;
            }
            i += 1;
            continue;
        }
        return Some(arg.clone());
    }
    None
}

/// A gitleaks `--report-format json` finding, secret-free by construction —
/// mirrors `gitleaksCandidates`' output shape (`digest`/`rule`/`file`/`line`
/// only; the raw `Secret`/`Match`/commit fields are never carried forward).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct GitleaksCandidate {
    pub digest: String,
    pub rule: Option<String>,
    pub file: Option<String>,
    pub line: Option<i64>,
}

/// `gitleaksCandidates`: parse a raw gitleaks JSON report and redact it down
/// to identity-only candidates. Errors (not a JSON array) mirror the JS
/// `throw`.
pub fn gitleaks_candidates(json_text: &str) -> Result<Vec<GitleaksCandidate>, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(json_text).map_err(|_| "gitleaks report is not valid JSON".to_string())?;
    let items = parsed
        .as_array()
        .ok_or_else(|| "gitleaks report is not a JSON array".to_string())?;
    Ok(items
        .iter()
        .map(|f| {
            let fingerprint = f.get("Fingerprint").and_then(|v| v.as_str());
            let digest = match fingerprint {
                Some(fp) if !fp.is_empty() => fp.to_string(),
                _ => {
                    let rule = f.get("RuleID").and_then(|v| v.as_str()).unwrap_or("");
                    let file = f.get("File").and_then(|v| v.as_str()).unwrap_or("");
                    let line = f
                        .get("StartLine")
                        .map(|v| {
                            if let Some(s) = v.as_str() {
                                s.to_string()
                            } else {
                                v.to_string()
                            }
                        })
                        .unwrap_or_default();
                    let key = format!("{rule}\0{file}\0{line}");
                    use sha2::{Digest as _, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(key.as_bytes());
                    format!("sha256:{}", hex::encode(hasher.finalize()))
                }
            };
            GitleaksCandidate {
                digest,
                rule: f.get("RuleID").and_then(|v| v.as_str()).map(str::to_string),
                file: f.get("File").and_then(|v| v.as_str()).map(str::to_string),
                line: f.get("StartLine").and_then(|v| v.as_i64()),
            }
        })
        .collect())
}

/// One tracked file's classification input for the decomposition grouping
/// math (`oversized_files` / `mechanical_splits`) — the caller has already
/// done the filesystem read that produces `loc`/`bytes`.
#[derive(Debug, Clone)]
pub struct FileLoc {
    pub path: String,
    pub loc: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct OversizedFile {
    pub file: String,
    pub loc: u64,
    pub bytes: u64,
    pub class: &'static str,
}

/// Per-file review trigger: any tracked, non-generated code file over
/// `threshold` LOC, sorted largest-first.
pub fn oversized_files(files: &[FileLoc], threshold: u64) -> Vec<OversizedFile> {
    let mut out: Vec<OversizedFile> = files
        .iter()
        .filter(|f| f.loc > threshold)
        .map(|f| OversizedFile {
            file: f.path.clone(),
            loc: f.loc,
            bytes: f.bytes,
            class: classify_file(&f.path).as_str(),
        })
        .collect();
    out.sort_by(|a, b| b.loc.cmp(&a.loc));
    out
}

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct MechanicalSplit {
    pub dir: String,
    pub parts: usize,
    pub logical_loc: u64,
    pub files: Vec<String>,
    pub part_files: Vec<String>,
    pub class: &'static str,
}

/// Reconstructs "mechanically split" logical modules: files grouped either
/// by a `*_parts/`/`parts/` containing directory, or a `partNN.ext`
/// filename, whose combined LOC exceeds `threshold`. Conservative — never
/// flags an ordinary barrel/mod file. `files` must be tracked, non-generated
/// paths (the caller applies `is_generated_or_vendored_path` beforehand, as
/// `collect-facts.mjs`'s `git ls-files` + `CODE` regex filter does).
pub fn mechanical_splits(files: &[FileLoc], threshold: u64) -> Vec<MechanicalSplit> {
    let is_parts_dir = Regex::new(r"(?i)(?:_parts|^parts)$").unwrap();
    let is_part_file = Regex::new(r"(?i)^part[._-]?\d+\.[a-z0-9]+$").unwrap();

    let loc_by_file: BTreeMap<&str, u64> = files.iter().map(|f| (f.path.as_str(), f.loc)).collect();
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in files {
        let segs: Vec<&str> = f.path.split(['\\', '/']).collect();
        if segs.is_empty() {
            continue;
        }
        let base = segs.last().copied().unwrap_or("");
        let parent = if segs.len() >= 2 { segs[segs.len() - 2] } else { "" };
        let is_dir_split = is_parts_dir.is_match(parent);
        let is_file_split = is_part_file.is_match(base);
        if !is_dir_split && !is_file_split {
            continue;
        }
        let dir = segs[..segs.len() - 1].join("/");
        groups.entry(dir).or_default().push(f.path.clone());
    }

    let mut out = Vec::new();
    for (dir, gfiles) in groups {
        if gfiles.len() < 2 {
            continue;
        }
        let logical_loc: u64 = gfiles.iter().map(|f| *loc_by_file.get(f.as_str()).unwrap_or(&0)).sum();
        if logical_loc <= threshold {
            continue;
        }
        let any_runtime = gfiles.iter().any(|f| classify_file(f) == FileClass::Runtime);
        let any_test = gfiles.iter().any(|f| classify_file(f) == FileClass::Test);
        let class = if any_runtime {
            FileClass::Runtime
        } else if any_test {
            FileClass::Test
        } else {
            FileClass::Tooling
        };
        out.push(MechanicalSplit {
            dir,
            parts: gfiles.len(),
            logical_loc,
            files: gfiles.iter().take(6).cloned().collect(),
            part_files: gfiles.clone(),
            class: class.as_str(),
        });
    }
    out.sort_by(|a, b| b.logical_loc.cmp(&a.logical_loc));
    out
}
