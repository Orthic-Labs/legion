//! Port of the output-formatting logic in
//! `skills/designer/engine/scripts/detector/cli/main.mjs`: `formatFindingSummary`,
//! `formatFindings`, and `printUsage`. The rest of `main.mjs` (`detectCli`,
//! `handleStdin`, `confirm`, framework-dev-server sniffing, browser/URL
//! scanning, `fs`/`process` interaction) is CLI orchestration wired directly
//! to filesystem, stdin, process-exit and other detector engines not owned
//! by this chunk, and is not ported.

use std::collections::BTreeMap;

/// Mirrors the JS finding object's fields actually read by `formatFindings`:
/// `file`, `line`, `antipattern`, `snippet`, `description`, `importedBy`.
/// Other fields (`name`, `severity`, `ignoreValue`, ...) are not read by
/// this formatter and are therefore not modeled here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub file: String,
    /// `0` means "no line" (JS: `item.line ? ... : ''`), matching the
    /// falsy-zero check in `formatFindings`.
    pub line: u32,
    pub antipattern: String,
    pub snippet: String,
    pub description: String,
    pub imported_by: Vec<String>,
}

/// Port of `formatFindingSummary(count)`:
/// `` `${count} anti-pattern${count === 1 ? '' : 's'} found.` ``
pub fn format_finding_summary(count: usize) -> String {
    format!(
        "{count} anti-pattern{} found.",
        if count == 1 { "" } else { "s" }
    )
}

/// Port of `formatFindings(findings, jsonMode)`.
///
/// `json_mode = true` returns a JSON array via `serde_json` (mirrors
/// `JSON.stringify(findings, null, 2)` field-for-field, built explicitly
/// per finding by [`finding_to_json`], 2-space indented). Text mode groups
/// findings by `file`
/// (JS uses `Object.entries` on an object keyed by insertion order, which
/// V8 preserves for string keys — reproduced here with an explicit
/// insertion-order `Vec` of groups rather than a sorted map, since sorting
/// by file name would silently reorder output relative to the JS).
pub fn format_findings(findings: &[Finding], json_mode: bool) -> String {
    if json_mode {
        return serde_json::to_string_pretty(
            &findings
                .iter()
                .map(finding_to_json)
                .collect::<Vec<_>>(),
        )
        .expect("Finding -> JSON is infallible for these field types");
    }

    // Group by `file`, preserving first-seen order (matches JS `Object`
    // insertion-order iteration for string keys).
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        if !groups.contains_key(&f.file) {
            order.push(f.file.clone());
        }
        groups.entry(f.file.clone()).or_default().push(f);
    }

    let mut out: Vec<String> = Vec::new();
    for file in &order {
        let items = &groups[file];
        let import_note = match items.first().map(|f| &f.imported_by) {
            Some(imported) if !imported.is_empty() => {
                format!(" (imported by {})", imported.join(", "))
            }
            _ => String::new(),
        };
        out.push(format!("\n{file}{import_note}"));
        for item in items {
            let line_prefix = if item.line != 0 {
                format!("line {}: ", item.line)
            } else {
                String::new()
            };
            out.push(format!(
                "  {line_prefix}[{}] {}",
                item.antipattern, item.snippet
            ));
            out.push(format!("    \u{2192} {}", item.description));
        }
    }
    out.push(format!("\n{}", format_finding_summary(findings.len())));
    out.join("\n")
}

fn finding_to_json(f: &Finding) -> serde_json::Value {
    serde_json::json!({
        "file": f.file,
        "line": f.line,
        "antipattern": f.antipattern,
        "snippet": f.snippet,
        "description": f.description,
        "importedBy": f.imported_by,
    })
}

/// Port of `printUsage()`'s message body (the exact text written to
/// stdout). The caller is responsible for the `console.log` / process-exit
/// side effects `printUsage()` itself does not perform (it only logs; the
/// caller in `detectCli` calls `process.exit(0)` separately).
pub fn usage_text() -> &'static str {
    "Usage: impeccable detect [options] [file-or-dir-or-url...]\n\
\n\
Scan files or URLs for UI anti-patterns and design quality issues.\n\
\n\
Options:\n\
  --json              Output results as JSON\n\
  --quiet             In text mode, only print the final findings count\n\
  --gpt               Also report GPT-specific provider tells (off by default)\n\
  --gemini            Also report Gemini-specific provider tells (off by default)\n\
  --no-config         Do not apply project config, detector ignores, or DESIGN.md\n\
  --no-design-system  Do not load local DESIGN.md / .impeccable/design.json context\n\
  --viewport=WxH      Rendered viewport for URL scans (default 1280x800)\n\
  --mobile            Shorthand for --viewport=390x844\n\
  --tablet            Shorthand for --viewport=768x1024\n\
  --site              Also sweep same-origin links from the scanned page:\n\
                      broken internal links + required-page presence\n\
  --site-type=T       Required-page profile for --site: app | ecommerce | content\n\
  --help              Show this help message\n\
\n\
Project config:\n\
  Respects .impeccable/config.json and .impeccable/config.local.json detector\n\
  settings: detector.ignoreRules, detector.ignoreFiles, detector.ignoreValues,\n\
  and detector.designSystem.enabled.\n\
\n\
Detection modes:\n\
  HTML files     Static HTML/CSS analysis (default, catches linked CSS)\n\
  Non-HTML files Regex pattern matching (CSS, JSX, TSX, etc.)\n\
  URLs           Full browser rendering: puppeteer when installed, otherwise\n\
                 an installed Chrome/Edge over raw CDP (auto-detected)\n\
\n\
Examples:\n\
  impeccable detect src/\n\
  impeccable detect index.html\n\
  impeccable detect https://example.com\n\
  impeccable detect --json .\n\
  impeccable detect --no-config src/"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(file: &str, line: u32, antipattern: &str, snippet: &str, description: &str) -> Finding {
        Finding {
            file: file.to_string(),
            line,
            antipattern: antipattern.to_string(),
            snippet: snippet.to_string(),
            description: description.to_string(),
            imported_by: Vec::new(),
        }
    }

    #[test]
    fn summary_pluralizes_correctly() {
        assert_eq!(format_finding_summary(0), "0 anti-patterns found.");
        assert_eq!(format_finding_summary(1), "1 anti-pattern found.");
        assert_eq!(format_finding_summary(2), "2 anti-patterns found.");
    }

    #[test]
    fn text_mode_groups_by_file_and_appends_summary() {
        let findings = vec![
            f("a.html", 3, "shadow-spam", "box-shadow: ...", "too many shadows"),
            f("a.html", 0, "gradient-overuse", "background: linear-gradient", "gradient overuse"),
            f("b.html", 10, "border-glow", "border: 1px solid", "glow border"),
        ];
        let out = format_findings(&findings, false);
        assert!(out.contains("\na.html"));
        assert!(out.contains("  line 3: [shadow-spam] box-shadow: ...\n    \u{2192} too many shadows"));
        // line == 0 must omit the "line N: " prefix (JS falsy check).
        assert!(out.contains("  [gradient-overuse] background: linear-gradient"));
        assert!(out.contains("\nb.html"));
        assert!(out.ends_with("\n3 anti-patterns found."));
    }

    #[test]
    fn text_mode_notes_importers_from_first_item_only() {
        let mut first = f("a.html", 1, "x", "s", "d");
        first.imported_by = vec!["main.js".to_string(), "app.js".to_string()];
        let findings = vec![first];
        let out = format_findings(&findings, false);
        assert!(out.contains("a.html (imported by main.js, app.js)"));
    }

    #[test]
    fn json_mode_round_trips_fields() {
        let findings = vec![f("a.html", 3, "x", "snip", "desc")];
        let out = format_findings(&findings, true);
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value[0]["file"], "a.html");
        assert_eq!(value[0]["line"], 3);
        assert_eq!(value[0]["antipattern"], "x");
        assert_eq!(value[0]["importedBy"], serde_json::json!([]));
    }

    #[test]
    fn usage_text_matches_known_flags() {
        let text = usage_text();
        assert!(text.starts_with("Usage: impeccable detect"));
        assert!(text.contains("--json"));
        assert!(text.contains("--viewport=WxH"));
        assert!(text.contains("--site-type=T"));
        assert!(text.ends_with("impeccable detect --no-config src/"));
    }
}
