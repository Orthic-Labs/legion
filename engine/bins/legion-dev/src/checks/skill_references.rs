// Dead-reference gate for packaged skills. Every `skills/**/*.md` (excluding
// `skills/manifests/`) must satisfy:
//   1. every relative markdown link resolves on disk;
//   2. every `legion script <name>` names an entry in the dispatch table
//      (`TABLE` in `engine/bins/legion/src/commands/script.rs`);
//   3. every `scripts/<x>.(py|mjs|sh|js)` mention, `node <path>.mjs|js` and
//      `python3 <path>.py` command points at a file that exists in the bundle;
//   4. every `hostRequirements` id in SKILL.md frontmatter is declared in
//      `src/registry/capabilities.json`.
// Failures print as `file:line: message`.

use super::{read_json, read_text, tracked_files};
use crate::shared::skill_frontmatter::parse_skill_frontmatter;
use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const SCRIPT_DISPATCH_SOURCE: &str = "engine/bins/legion/src/commands/script.rs";
const CAPABILITY_REGISTRY: &str = "src/registry/capabilities.json";

#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub file: String,
    pub line: usize,
    pub message: String,
}

fn fail(file: &str, line: usize, message: String) -> Failure {
    Failure {
        file: file.to_string(),
        line,
        message,
    }
}

/// Names registered in the `TABLE` of the `legion script` dispatcher.
pub fn parse_script_table(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Some(start) = source.find("pub const TABLE") else {
        return names;
    };
    let body = &source[start..];
    let end = body.find("];").unwrap_or(body.len());
    let entry = Regex::new(r#"\(\s*"([^"]+)"\s*,"#).unwrap();
    for cap in entry.captures_iter(&body[..end]) {
        names.insert(cap[1].to_string());
    }
    names
}

fn is_skill_markdown(path: &str) -> bool {
    path.starts_with("skills/") && path.ends_with(".md") && !path.starts_with("skills/manifests/")
}

/// First path segment under `skills/`, i.e. the bundle directory.
fn bundle_root(root: &Path, rel: &str) -> PathBuf {
    let bundle = rel.split('/').nth(1).unwrap_or("");
    root.join("skills").join(bundle)
}

fn strip_inline_code(line: &str) -> String {
    Regex::new(r"`[^`]*`")
        .unwrap()
        .replace_all(line, "")
        .into_owned()
}

fn link_target_is_checkable(target: &str) -> bool {
    if target.is_empty() || target.starts_with('#') {
        return false;
    }
    if target.contains(['{', '}', '$', '*', '<', '>']) {
        return false;
    }
    // Any URI scheme (`https:`, `mailto:`, `tel:` ...) is external.
    let scheme = Regex::new(r"^[A-Za-z][A-Za-z0-9+.\-]*:").unwrap();
    !scheme.is_match(target)
}

fn script_file_exists(root: &Path, rel: &str, mention: &str) -> bool {
    let file_dir = root.join(rel);
    let file_dir = file_dir.parent().unwrap_or(root);
    let bundle = bundle_root(root, rel);
    let mut candidates = vec![file_dir.join(mention), bundle.join(mention)];
    if mention.starts_with("skills/") {
        candidates.push(root.join(mention));
    }
    if let Some(idx) = mention.find("scripts/") {
        candidates.push(bundle.join(&mention[idx..]));
    }
    candidates.iter().any(|p| p.is_file())
}

/// Scans one markdown file. `rel` is root-relative with forward slashes.
pub fn scan_file(
    root: &Path,
    rel: &str,
    text: &str,
    script_table: &BTreeSet<String>,
) -> Vec<Failure> {
    let mut failures = Vec::new();
    let link_re = Regex::new(r#"\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)"#).unwrap();
    let script_cmd_re = Regex::new(r"legion script\s+([A-Za-z0-9_./<>-]+)").unwrap();
    let script_path_re =
        Regex::new(r"[A-Za-z0-9_.\-/]*scripts/[A-Za-z0-9_.\-/]*[A-Za-z0-9_\-]\.(?:py|mjs|sh|js)\b")
            .unwrap();
    let interp_re = Regex::new(
        r"\b(?:node|python3?)\s+((?:\./|\.\./)?[A-Za-z0-9_.\-/]*[A-Za-z0-9_\-]\.(?:mjs|js|py))\b",
    )
    .unwrap();
    let file_dir = root.join(rel);
    let file_dir = file_dir.parent().unwrap_or(root).to_path_buf();

    let mut in_fence = false;
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
        }

        if !in_fence {
            let visible = strip_inline_code(line);
            for cap in link_re.captures_iter(&visible) {
                let raw = cap[1].trim_matches(|c| c == '<' || c == '>');
                if !link_target_is_checkable(raw) {
                    continue;
                }
                let path_part = raw
                    .split(['#', '?'])
                    .next()
                    .unwrap_or("")
                    .replace("%20", " ");
                if path_part.is_empty() {
                    continue;
                }
                let resolved = if let Some(stripped) = path_part.strip_prefix('/') {
                    root.join(stripped)
                } else {
                    file_dir.join(&path_part)
                };
                if !resolved.exists() {
                    failures.push(fail(rel, line_no, format!("broken link target `{raw}`")));
                }
            }
        }

        for cap in script_cmd_re.captures_iter(line) {
            let name = cap[1].trim_end_matches(['.', ',', ':', ';']);
            if name.is_empty() || name.starts_with('-') || name.contains('<') || name.contains('>')
            {
                continue;
            }
            if !script_table.contains(name) {
                failures.push(fail(
                    rel,
                    line_no,
                    format!("`legion script {name}` is not in the dispatch table"),
                ));
            }
        }

        let mut mentions: BTreeSet<String> = BTreeSet::new();
        for m in script_path_re.find_iter(line) {
            mentions.insert(m.as_str().to_string());
        }
        for cap in interp_re.captures_iter(line) {
            mentions.insert(cap[1].to_string());
        }
        for mention in mentions {
            if !script_file_exists(root, rel, &mention) {
                failures.push(fail(
                    rel,
                    line_no,
                    format!("script reference `{mention}` does not exist in the bundle"),
                ));
            }
        }
    }

    if rel.ends_with("/SKILL.md") {
        failures.extend(check_host_requirements(root, rel, text));
    }
    failures
}

fn declared_capabilities(root: &Path) -> Result<BTreeSet<String>, String> {
    let registry = read_json(&root.join(CAPABILITY_REGISTRY))?;
    Ok(registry
        .get("capabilities")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default())
}

fn check_host_requirements(root: &Path, rel: &str, text: &str) -> Vec<Failure> {
    let mut failures = Vec::new();
    let Ok(frontmatter) = parse_skill_frontmatter(text, rel) else {
        // Malformed frontmatter is reported by check-dependency-closure.
        return failures;
    };
    if frontmatter.host_requirements.is_empty() {
        return failures;
    }
    let declared = match declared_capabilities(root) {
        Ok(d) => d,
        Err(e) => {
            failures.push(fail(
                rel,
                1,
                format!("cannot read capability registry: {e}"),
            ));
            return failures;
        }
    };
    let line_no = text
        .lines()
        .position(|l| l.trim_start().starts_with("hostRequirements"))
        .map(|i| i + 1)
        .unwrap_or(1);
    for id in &frontmatter.host_requirements {
        if !declared.contains(id) {
            failures.push(fail(
                rel,
                line_no,
                format!("hostRequirements id `{id}` is not declared in {CAPABILITY_REGISTRY}"),
            ));
        }
    }
    failures
}

/// Scans the given root-relative files.
pub fn check_files(root: &Path, files: &[String], script_table: &BTreeSet<String>) -> Vec<Failure> {
    let mut failures = Vec::new();
    for rel in files.iter().filter(|f| is_skill_markdown(f)) {
        // A markdown file sealed by a sibling `<stem>.receipt.json` is
        // HISTORICAL_EVIDENCE: its bytes are digest-bound, so it records what
        // ran then and cannot be rewritten to current commands.
        if root.join(rel).with_extension("receipt.json").is_file() {
            continue;
        }
        if let Some(text) = read_text(&root.join(rel)) {
            failures.extend(scan_file(root, rel, &text, script_table));
        }
    }
    failures
}

pub fn run(root: &Path) -> bool {
    let source = match std::fs::read_to_string(root.join(SCRIPT_DISPATCH_SOURCE)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("check-skill-references: cannot read {SCRIPT_DISPATCH_SOURCE}: {e}");
            return false;
        }
    };
    let table = parse_script_table(&source);
    if table.is_empty() {
        eprintln!("check-skill-references: no entries parsed from {SCRIPT_DISPATCH_SOURCE}");
        return false;
    }
    let files = tracked_files(root);
    let checked = files.iter().filter(|f| is_skill_markdown(f)).count();
    let failures = check_files(root, &files, &table);
    if failures.is_empty() {
        println!(
            "skill references ok: {checked} markdown files, {} dispatch entries",
            table.len()
        );
        return true;
    }
    for f in &failures {
        eprintln!("{}:{}: {}", f.file, f.line, f.message);
    }
    eprintln!(
        "\ncheck-skill-references failed: {} reference(s) across {checked} files",
        failures.len()
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "legion-skillrefs-{label}-{}-{nonce}-{}",
                std::process::id(),
                { static NEXT: ::std::sync::atomic::AtomicU64 = ::std::sync::atomic::AtomicU64::new(0); NEXT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed) }
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn write(&self, rel: &str, body: &str) {
            let path = self.0.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn table() -> BTreeSet<String> {
        parse_script_table(
            r#"pub const TABLE: &[(&str, Entry)] = &[
    ("seo/google_report", seo_google_report),
    ("qa/qa-shot", qa_shot),
];"#,
        )
    }

    fn scan(fx: &Fixture, rel: &str) -> Vec<Failure> {
        check_files(&fx.0, &[rel.to_string()], &table())
    }

    #[test]
    fn parses_dispatch_table() {
        let t = table();
        assert!(t.contains("seo/google_report"));
        assert!(t.contains("qa/qa-shot"));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn broken_relative_link_reports_line() {
        let fx = Fixture::new("link");
        fx.write("skills/a/references/real.md", "ok\n");
        fx.write(
            "skills/a/SKILL.md-less.md",
            "[good](references/real.md)\n[bad](references/gone.md#x)\n[web](https://x.test)\n`[code](nope.md)`\n```\n[fenced](nope.md)\n```\n",
        );
        let failures = scan(&fx, "skills/a/SKILL.md-less.md");
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].line, 2);
        assert!(failures[0].message.contains("references/gone.md"));
    }

    #[test]
    fn script_commands_must_be_in_table() {
        let fx = Fixture::new("cmd");
        fx.write(
            "skills/a/doc.md",
            "run `legion script seo/google_report`\nrun `legion script seo/seo_closure`\nlist: `legion script --list` or `legion script <skill>/<stem>`\n",
        );
        let failures = scan(&fx, "skills/a/doc.md");
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].line, 2);
        assert!(failures[0].message.contains("seo/seo_closure"));
    }

    #[test]
    fn deleted_script_mentions_are_leaks_unless_present() {
        let fx = Fixture::new("leak");
        fx.write("skills/a/scripts/kept.py", "print()\n");
        fx.write(
            "skills/a/doc.md",
            "see scripts/kept.py\nsee scripts/gone.py\nnode ../../qa/scripts/qa-shot.mjs --x\npython3 tools/run.py\n",
        );
        let failures = scan(&fx, "skills/a/doc.md");
        let lines: Vec<usize> = failures.iter().map(|f| f.line).collect();
        assert_eq!(lines, vec![2, 3, 4], "{failures:?}");
    }

    #[test]
    fn host_requirements_must_be_declared() {
        let fx = Fixture::new("host");
        fx.write(
            "src/registry/capabilities.json",
            r#"{"capabilities":{"banana":{}}}"#,
        );
        fx.write(
            "skills/a/SKILL.md",
            "---\nname: a\ndescription: \"d\"\nkind: capability\ncapabilityClass: domain\ndiscoverability: public\ndomain: commercial\noperations:\n  - analyze\neffects:\n  - source-read\nhostRequirements:\n  - banana\n  - python-runtime\n---\nbody\n",
        );
        let failures = scan(&fx, "skills/a/SKILL.md");
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].message.contains("python-runtime"));
        assert_eq!(failures[0].line, 12);
    }

    #[test]
    fn manifests_are_excluded() {
        assert!(!is_skill_markdown("skills/manifests/x.md"));
        assert!(is_skill_markdown("skills/a/b.md"));
        assert!(!is_skill_markdown("docs/a.md"));
    }
}
