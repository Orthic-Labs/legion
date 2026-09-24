//! Port of `main.mjs`'s CLI: `printUsage`, `detectCli`'s argv parsing,
//! target dispatch (stdin / files / dirs / URLs), the framework-dev-server
//! hint, the >50-file confirm prompt, and exit codes.
//!
//! JS's async, side-effecting shape (`process.stdin`, `console.log`,
//! `process.exit`, an interactive `readline` confirm) is threaded through
//! the [`Io`] trait here so [`run`] is a plain, testable function — per
//! this port's "I/O behind a trait, tested with fakes" rule. [`Detectors`]
//! is the equivalent seam for the four engine calls (`detectText`,
//! `detectHtml`, `detectUrl`, `sweepSite`); [`super::real_detectors`] wires
//! it to the production implementations.

use std::path::{Path, PathBuf};

use super::super::w2_011::design_system::DesignSystem;
use super::super::w2_013::file_system::{
    build_import_graph, detect_framework_config, html_extensions, is_port_listening_http,
    is_port_listening_tcp, walk_dir,
};
use super::super::w2_016::impeccable_config::{
    filter_detection_findings, read_detection_config, should_ignore_detection_file, DetectionConfig,
    Finding as ConfigFinding,
};
use super::output::{format_findings, format_finding_summary, CliFinding};

/// Everything `main.mjs` does through `process.std{in,out,err}`, TTY
/// detection, and the interactive `readline` confirm prompt.
pub trait Io {
    fn stdout(&mut self, s: &str);
    fn stderr(&mut self, s: &str);
    /// Port of `!process.stdin.isTTY`.
    fn stdin_is_tty(&self) -> bool;
    /// Port of `handleStdin`'s `for await (const chunk of process.stdin)`.
    fn read_stdin(&mut self) -> String;
    /// Port of `confirm(question)`: prints `"{question} [Y/n] "` and reads
    /// one line, defaulting to `true` on empty/`y`/`yes` input (case
    /// insensitive), matching `!answer || /^y(es)?$/i.test(answer.trim())`.
    fn confirm(&mut self, question: &str) -> bool;
}

/// Port of `confirm(question)`'s answer parse, given the raw line already
/// read (without the trailing newline). Exposed so [`Io`] implementations
/// don't have to re-derive the JS regex.
pub fn parse_confirm_answer(answer: &str) -> bool {
    let trimmed = answer.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower == "y" || lower == "yes"
}

/// The four engine calls `main.mjs` imports and invokes directly. See the
/// [`super`] module doc for exactly which JS behaviour each of these does
/// and doesn't reproduce; [`super::real_detectors`] is the production
/// wiring.
pub trait Detectors {
    fn detect_text(&mut self, content: &str, file_path: &str, design_system: Option<&DesignSystem>) -> Vec<CliFinding>;
    fn detect_html(&mut self, file_path: &str, design_system: Option<&DesignSystem>) -> Result<Vec<CliFinding>, String>;
    fn detect_url(&mut self, url: &str, options: &UrlScanOptions) -> Result<Vec<CliFinding>, String>;
    fn sweep_site(&mut self, url: &str, site_type: Option<&str>) -> Vec<CliFinding>;
}

/// Port of the subset of `detectUrl`'s `options` the CLI itself builds
/// (viewport + providers + design system); `settleMs`/`quiet`/
/// `visualContrast` stay at [`super::super::r07::detect_url::DetectUrlOptions`]'s
/// defaults since `main.mjs` never overrides them.
#[derive(Debug, Clone, Default)]
pub struct UrlScanOptions {
    pub viewport: Option<(u32, u32)>,
    pub providers: Vec<String>,
}

/// Port of `--site-type`'s allowed values (`app | ecommerce | content`).
fn is_valid_site_type(s: &str) -> bool {
    matches!(s, "app" | "ecommerce" | "content")
}

/// Port of `printUsage()`'s help text, verbatim.
pub const USAGE: &str = "Usage: impeccable detect [options] [file-or-dir-or-url...]

Scan files or URLs for UI anti-patterns and design quality issues.

Options:
  --json              Output results as JSON
  --quiet             In text mode, only print the final findings count
  --gpt               Also report GPT-specific provider tells (off by default)
  --gemini            Also report Gemini-specific provider tells (off by default)
  --no-config         Do not apply project config, detector ignores, or DESIGN.md
  --no-design-system  Do not load local DESIGN.md / .impeccable/design.json context
  --viewport=WxH      Rendered viewport for URL scans (default 1280x800)
  --mobile            Shorthand for --viewport=390x844
  --tablet            Shorthand for --viewport=768x1024
  --site              Also sweep same-origin links from the scanned page:
                      broken internal links + required-page presence
  --site-type=T       Required-page profile for --site: app | ecommerce | content
  --help              Show this help message

Project config:
  Respects .impeccable/config.json and .impeccable/config.local.json detector
  settings: detector.ignoreRules, detector.ignoreFiles, detector.ignoreValues,
  and detector.designSystem.enabled.

Detection modes:
  HTML files     Static HTML/CSS analysis (default, catches linked CSS)
  Non-HTML files Regex pattern matching (CSS, JSX, TSX, etc.)
  URLs           Full browser rendering: puppeteer when installed, otherwise
                 an installed Chrome/Edge over raw CDP (auto-detected)

Examples:
  impeccable detect src/
  impeccable detect index.html
  impeccable detect https://example.com
  impeccable detect --json .
  impeccable detect --no-config src/";

fn is_url(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn to_config_finding(f: &CliFinding) -> ConfigFinding {
    ConfigFinding {
        antipattern: Some(f.antipattern.clone()),
        file: Some(f.file.clone()),
        ignore_value: f.ignore_value.clone(),
        value: None,
        detail: None,
        snippet: Some(f.snippet.clone()),
    }
}

/// Applies `filterDetectionFindings` to a `Vec<CliFinding>`, round-tripping
/// through `wf_port::w2_016::impeccable_config::Finding` (the shape that
/// function operates on) and reattaching each survivor's original record
/// (so `name`/`description`/`severity`/`importedBy`, which the config
/// `Finding` shape doesn't carry, aren't lost).
fn filter_findings(findings: Vec<CliFinding>, config: &DetectionConfig) -> Vec<CliFinding> {
    if findings.is_empty() {
        return findings;
    }
    let config_findings: Vec<ConfigFinding> = findings.iter().map(to_config_finding).collect();
    let kept = filter_detection_findings(&config_findings, config);
    // `filter_detection_findings` preserves order and drops entries; walk
    // both in lockstep by index rather than re-matching on content (a
    // finding's fields aren't necessarily unique).
    let mut kept_iter = kept.into_iter().peekable();
    let mut out = Vec::new();
    for (f, cf) in findings.into_iter().zip(config_findings.into_iter()) {
        if kept_iter.peek().map(|k| findings_match(k, &cf)) == Some(true) {
            kept_iter.next();
            out.push(f);
        }
    }
    out
}

fn findings_match(a: &ConfigFinding, b: &ConfigFinding) -> bool {
    a.antipattern == b.antipattern && a.file == b.file && a.snippet == b.snippet && a.ignore_value == b.ignore_value
}

/// Parsed argv, port of `detectCli`'s option/target extraction (excluding
/// `--fast`'s deprecation note, handled separately in [`run`] since it
/// writes to stderr).
struct ParsedArgs {
    json_mode: bool,
    quiet_mode: bool,
    help_mode: bool,
    fast_deprecated: bool,
    no_config: bool,
    no_design_system: bool,
    gpt: bool,
    gemini: bool,
    viewport: Option<(u32, u32)>,
    site_sweep: bool,
    site_type: Option<String>,
    site_type_invalid: bool,
    viewport_invalid: bool,
    targets: Vec<String>,
}

fn parse_args(argv: &[String]) -> ParsedArgs {
    // Port of the `-json`/`-fast` -> `--json`/`--fast` normalization and
    // the optional leading `detect` subcommand strip.
    let mut args: Vec<String> = argv
        .iter()
        .map(|a| match a.as_str() {
            "-json" => "--json".to_string(),
            "-fast" => "--fast".to_string(),
            other => other.to_string(),
        })
        .collect();
    if args.first().map(String::as_str) == Some("detect") {
        args.remove(0);
    }

    let json_mode = args.iter().any(|a| a == "--json");
    let quiet_mode = args.iter().any(|a| a == "--quiet");
    let help_mode = args.iter().any(|a| a == "--help");
    let fast_deprecated = args.iter().any(|a| a == "--fast");
    let no_config = args.iter().any(|a| a == "--no-config");
    let no_design_system = args.iter().any(|a| a == "--no-design-system");
    let gpt = args.iter().any(|a| a == "--gpt");
    let gemini = args.iter().any(|a| a == "--gemini");
    let site_sweep = args.iter().any(|a| a == "--site");

    let mut viewport = None;
    let mut viewport_invalid = false;
    if let Some(vp) = args.iter().find(|a| a.starts_with("--viewport=")) {
        let re = regex::Regex::new(r"^--viewport=(\d+)x(\d+)$").unwrap();
        match re.captures(vp) {
            Some(caps) => {
                let w: u32 = caps[1].parse().unwrap_or(0);
                let h: u32 = caps[2].parse().unwrap_or(0);
                viewport = Some((w, h));
            }
            None => viewport_invalid = true,
        }
    } else if args.iter().any(|a| a == "--mobile") {
        viewport = Some((390, 844));
    } else if args.iter().any(|a| a == "--tablet") {
        viewport = Some((768, 1024));
    }

    let mut site_type = None;
    let mut site_type_invalid = false;
    if let Some(st) = args.iter().find(|a| a.starts_with("--site-type=")) {
        let value = st.splitn(2, '=').nth(1).unwrap_or("");
        if is_valid_site_type(value) {
            site_type = Some(value.to_string());
        } else {
            site_type_invalid = true;
        }
    }

    let targets: Vec<String> = args.iter().filter(|a| !a.starts_with("--")).cloned().collect();

    ParsedArgs {
        json_mode,
        quiet_mode,
        help_mode,
        fast_deprecated,
        no_config,
        no_design_system,
        gpt,
        gemini,
        viewport,
        site_sweep,
        site_type,
        site_type_invalid,
        viewport_invalid,
        targets,
    }
}

/// Port of `detectCli()`. `cwd` stands in for `process.cwd()`;
/// `design_system` for `loadDesignSystemForCwd` already resolved by the
/// caller when `--no-design-system`/config disables it, this is `None`
/// regardless of what's passed (mirroring the JS gating), otherwise the
/// caller-supplied value is used as-is (the CLI itself doesn't decide
/// *how* to load it — see [`super::design_system_loader`] for that).
///
/// Returns the process exit code (0 clean, 1 usage error, 2 findings).
pub fn run<I: Io, D: Detectors>(
    argv: &[String],
    cwd: &Path,
    io: &mut I,
    detectors: &mut D,
    design_system: Option<&DesignSystem>,
) -> i32 {
    let parsed = parse_args(argv);

    if parsed.fast_deprecated {
        io.stderr("Note: --fast is deprecated and ignored. The full scan is fast now and runs every rule.\n");
    }

    if parsed.viewport_invalid {
        io.stderr("Error: --viewport expects WxH, e.g. --viewport=1440x900\n");
        return 1;
    }
    if parsed.site_type_invalid {
        io.stderr("Error: --site-type must be app, ecommerce, or content\n");
        return 1;
    }

    if parsed.help_mode {
        io.stdout(USAGE);
        io.stdout("\n");
        return 0;
    }

    let detection_config = if parsed.no_config {
        DetectionConfig::default_disabled()
    } else {
        read_detection_config(cwd)
    };

    let design_system_enabled = !parsed.no_config && !parsed.no_design_system && detection_config.design_system_enabled;
    let effective_design_system = if design_system_enabled { design_system } else { None };

    let url_options = UrlScanOptions {
        viewport: parsed.viewport,
        providers: {
            let mut p = Vec::new();
            if parsed.gpt {
                p.push("gpt".to_string());
            }
            if parsed.gemini {
                p.push("gemini".to_string());
            }
            p
        },
    };

    let site_type = parsed.site_type.clone();

    let mut all_findings: Vec<CliFinding> = Vec::new();

    if !io.stdin_is_tty() && parsed.targets.is_empty() {
        let input = io.read_stdin();
        all_findings.extend(handle_stdin(&input, detectors, effective_design_system));
    } else {
        let paths: Vec<String> = if parsed.targets.is_empty() {
            vec![cwd.to_string_lossy().into_owned()]
        } else {
            parsed.targets.clone()
        };

        for target in &paths {
            if is_url(target) {
                match detectors.detect_url(target, &url_options) {
                    Ok(findings) => {
                        all_findings.extend(findings);
                        if parsed.site_sweep {
                            all_findings.extend(detectors.sweep_site(target, site_type.as_deref()));
                        }
                    }
                    Err(e) => io.stderr(&format!("Error: {e}\n")),
                }
                continue;
            }

            let resolved = if Path::new(target).is_absolute() {
                PathBuf::from(target)
            } else {
                cwd.join(target)
            };
            let metadata = match std::fs::metadata(&resolved) {
                Ok(m) => m,
                Err(_) => {
                    io.stderr(&format!("Warning: cannot access {target}\n"));
                    continue;
                }
            };

            if metadata.is_dir() {
                if !parsed.json_mode && !parsed.quiet_mode {
                    emit_framework_hint(&resolved, io);
                }

                let files: Vec<PathBuf> = walk_dir(&resolved)
                    .into_iter()
                    .filter(|f| {
                        !should_ignore_detection_file(&f.to_string_lossy(), cwd, &detection_config)
                    })
                    .collect();

                if files.len() > 50 && io.stdin_is_tty() && !parsed.json_mode && !parsed.quiet_mode {
                    let html_exts = html_extensions();
                    let html_count = files
                        .iter()
                        .filter(|f| {
                            f.extension()
                                .map(|e| html_exts.contains(format!(".{}", e.to_string_lossy().to_lowercase()).as_str()))
                                .unwrap_or(false)
                        })
                        .count();
                    io.stderr(&format!(
                        "\nFound {} files ({} HTML) in {}.\nScanning may take a while{}.\nTarget a specific subdirectory to narrow scope.\n",
                        files.len(),
                        html_count,
                        target,
                        if html_count > 10 {
                            " (static HTML/CSS processes each HTML file individually)"
                        } else {
                            ""
                        }
                    ));
                    if !io.confirm("Continue?") {
                        io.stderr("Aborted.\n");
                        return 0;
                    }
                }

                let graph = build_import_graph(&files);
                let mut imported_by: std::collections::HashMap<PathBuf, Vec<String>> = std::collections::HashMap::new();
                for (importer, imports) in &graph {
                    let importer_name = importer
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    for imported in imports {
                        imported_by.entry(imported.clone()).or_default().push(importer_name.clone());
                    }
                }

                let html_exts = html_extensions();
                for file in &files {
                    let ext = file
                        .extension()
                        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
                        .unwrap_or_default();
                    let mut file_findings = if html_exts.contains(ext.as_str()) {
                        match detectors.detect_html(&file.to_string_lossy(), effective_design_system) {
                            Ok(f) => f,
                            Err(e) => {
                                io.stderr(&format!("Error: {e}\n"));
                                Vec::new()
                            }
                        }
                    } else {
                        match std::fs::read_to_string(file) {
                            Ok(content) => detectors.detect_text(&content, &file.to_string_lossy(), effective_design_system),
                            Err(_) => Vec::new(),
                        }
                    };
                    if let Some(names) = imported_by.get(file) {
                        if !names.is_empty() {
                            for f in file_findings.iter_mut() {
                                f.imported_by = names.clone();
                            }
                        }
                    }
                    all_findings.append(&mut file_findings);
                }
            } else if metadata.is_file() {
                if should_ignore_detection_file(&resolved.to_string_lossy(), cwd, &detection_config) {
                    continue;
                }
                let ext = resolved
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
                    .unwrap_or_default();
                if html_extensions().contains(ext.as_str()) {
                    match detectors.detect_html(&resolved.to_string_lossy(), effective_design_system) {
                        Ok(f) => all_findings.extend(f),
                        Err(e) => io.stderr(&format!("Error: {e}\n")),
                    }
                } else if let Ok(content) = std::fs::read_to_string(&resolved) {
                    all_findings.extend(detectors.detect_text(&content, &resolved.to_string_lossy(), effective_design_system));
                }
            }
        }
    }

    all_findings = filter_findings(all_findings, &detection_config);

    if !all_findings.is_empty() {
        if parsed.json_mode {
            io.stdout(&format_findings(&all_findings, true));
            io.stdout("\n");
        } else if parsed.quiet_mode {
            io.stderr(&format_finding_summary(all_findings.len()));
            io.stderr("\n");
        } else {
            io.stderr(&format_findings(&all_findings, false));
            io.stderr("\n");
        }
        return 2;
    }
    if parsed.json_mode {
        io.stdout("[]\n");
    }
    0
}

/// Port of `handleStdin(options)`: tries to parse stdin as the
/// `{ tool_input: { file_path } }` hook payload and read that file
/// (dispatching HTML vs text the same way the directory loop does), else
/// falls back to treating the raw input as `<stdin>` text content.
fn handle_stdin<D: Detectors>(input: &str, detectors: &mut D, design_system: Option<&DesignSystem>) -> Vec<CliFinding> {
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(input) {
        if let Some(fp) = parsed.get("tool_input").and_then(|t| t.get("file_path")).and_then(|v| v.as_str()) {
            if Path::new(fp).exists() {
                let ext = Path::new(fp)
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
                    .unwrap_or_default();
                if html_extensions().contains(ext.as_str()) {
                    return match detectors.detect_html(fp, design_system) {
                        Ok(f) => f,
                        Err(_) => Vec::new(),
                    };
                }
                if let Ok(content) = std::fs::read_to_string(fp) {
                    return detectors.detect_text(&content, fp, design_system);
                }
            }
        }
    }
    detectors.detect_text(input, "<stdin>", design_system)
}

/// Port of `detectCli`'s framework-dev-server hint block for a directory
/// target. Every `FRAMEWORK_CONFIGS` entry declares a header and/or body
/// fingerprint, so this always probes via
/// [`is_port_listening_http`] with that framework's own fingerprint
/// (mirroring `isPortListening(fwConfig.port, fwConfig.fingerprint)`); the
/// plain-TCP probe ([`is_port_listening_tcp`]) is `isPortListening`'s
/// no-fingerprint branch, unreachable for any config in the table today but
/// kept as the fallback if that ever changes.
fn emit_framework_hint<I: Io>(dir: &Path, io: &mut I) {
    let Some(fw) = detect_framework_config(dir) else {
        return;
    };
    let cfg = super::super::w2_013::file_system::framework_configs()
        .into_iter()
        .find(|c| c.name == fw.name);
    let probe = match cfg {
        Some(cfg) => {
            let header_re = cfg
                .fingerprint_header
                .and_then(|(_, pat)| pat)
                .map(|p| regex::Regex::new(p).expect("static fingerprint regex"));
            let header = cfg
                .fingerprint_header
                .map(|(name, _)| (name, header_re.as_ref()));
            let body_re = cfg
                .fingerprint_body
                .map(|p| regex::Regex::new(p).expect("static fingerprint regex"));
            if header.is_some() || body_re.is_some() {
                is_port_listening_http(fw.port, header, body_re.as_ref())
            } else {
                is_port_listening_tcp(fw.port)
            }
        }
        None => is_port_listening_tcp(fw.port),
    };
    let config_name = fw
        .config_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if probe.listening && probe.matched == Some(true) {
        io.stderr(&format!(
            "\n{} dev server detected on localhost:{}.\nFor more accurate results, scan the running site:\n  npx impeccable detect http://localhost:{}\n\n",
            fw.name, fw.port, fw.port
        ));
    } else if probe.listening && probe.matched != Some(true) {
        io.stderr(&format!(
            "\n{} project detected ({}).\nPort {} is in use by another service. Start the {} dev server and scan via URL for best results.\n\n",
            fw.name, config_name, fw.port, fw.name
        ));
    } else {
        io.stderr(&format!(
            "\n{} project detected ({}).\nStart the dev server and scan via URL for best results:\n  npx impeccable detect http://localhost:{}\n\n",
            fw.name, config_name, fw.port
        ));
    }
}

impl DetectionConfig {
    /// Port of `detectCli`'s `--no-config` branch: `{ ignoreRules: [],
    /// ignoreFiles: [], ignoreValues: [] }` (no `designSystem` field, so
    /// the CLI treats it as "not explicitly disabled" — but `--no-config`
    /// also unconditionally turns off design-system loading itself, see
    /// [`run`]).
    fn default_disabled() -> Self {
        DetectionConfig {
            ignore_rules: Vec::new(),
            ignore_files: Vec::new(),
            ignore_values: Vec::new(),
            design_system_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeIo {
        out: String,
        err: String,
        tty: bool,
        stdin: String,
        confirm_answer: bool,
    }
    impl Io for FakeIo {
        fn stdout(&mut self, s: &str) {
            self.out.push_str(s);
        }
        fn stderr(&mut self, s: &str) {
            self.err.push_str(s);
        }
        fn stdin_is_tty(&self) -> bool {
            self.tty
        }
        fn read_stdin(&mut self) -> String {
            self.stdin.clone()
        }
        fn confirm(&mut self, _q: &str) -> bool {
            self.confirm_answer
        }
    }

    struct FakeDetectors {
        text_findings: RefCell<Vec<CliFinding>>,
    }
    impl Detectors for FakeDetectors {
        fn detect_text(&mut self, _c: &str, file_path: &str, _ds: Option<&DesignSystem>) -> Vec<CliFinding> {
            let mut v = self.text_findings.borrow().clone();
            for f in v.iter_mut() {
                f.file = file_path.to_string();
            }
            v
        }
        fn detect_html(&mut self, _f: &str, _ds: Option<&DesignSystem>) -> Result<Vec<CliFinding>, String> {
            Ok(Vec::new())
        }
        fn detect_url(&mut self, _u: &str, _o: &UrlScanOptions) -> Result<Vec<CliFinding>, String> {
            Ok(Vec::new())
        }
        fn sweep_site(&mut self, _u: &str, _t: Option<&str>) -> Vec<CliFinding> {
            Vec::new()
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "r05-cli-{tag}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn help_prints_usage_and_exits_zero() {
        let mut io = FakeIo { out: String::new(), err: String::new(), tty: true, stdin: String::new(), confirm_answer: true };
        let mut d = FakeDetectors { text_findings: RefCell::new(Vec::new()) };
        let code = run(&["--help".to_string()], Path::new("."), &mut io, &mut d, None);
        assert_eq!(code, 0);
        assert!(io.out.contains("Usage: impeccable detect"));
    }

    #[test]
    fn invalid_viewport_is_a_usage_error() {
        let mut io = FakeIo { out: String::new(), err: String::new(), tty: true, stdin: String::new(), confirm_answer: true };
        let mut d = FakeDetectors { text_findings: RefCell::new(Vec::new()) };
        let code = run(&["--viewport=bad".to_string()], Path::new("."), &mut io, &mut d, None);
        assert_eq!(code, 1);
        assert!(io.err.contains("--viewport expects WxH"));
    }

    #[test]
    fn invalid_site_type_is_a_usage_error() {
        let mut io = FakeIo { out: String::new(), err: String::new(), tty: true, stdin: String::new(), confirm_answer: true };
        let mut d = FakeDetectors { text_findings: RefCell::new(Vec::new()) };
        let code = run(&["--site-type=bogus".to_string()], Path::new("."), &mut io, &mut d, None);
        assert_eq!(code, 1);
        assert!(io.err.contains("--site-type must be"));
    }

    #[test]
    fn single_file_scan_with_findings_exits_two_and_prints_summary() {
        let dir = tmp_dir("file");
        let path = dir.join("a.css");
        std::fs::write(&path, "a{}").unwrap();
        let mut io = FakeIo { out: String::new(), err: String::new(), tty: true, stdin: String::new(), confirm_answer: true };
        let mut d = FakeDetectors {
            text_findings: RefCell::new(vec![CliFinding::new("side-tab", "x", 1, "s")]),
        };
        let code = run(&[path.to_string_lossy().into_owned()], &dir, &mut io, &mut d, None);
        assert_eq!(code, 2);
        assert!(io.err.contains("1 anti-pattern found."));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clean_scan_exits_zero() {
        let dir = tmp_dir("clean");
        let path = dir.join("a.css");
        std::fs::write(&path, "a{}").unwrap();
        let mut io = FakeIo { out: String::new(), err: String::new(), tty: true, stdin: String::new(), confirm_answer: true };
        let mut d = FakeDetectors { text_findings: RefCell::new(Vec::new()) };
        let code = run(&[path.to_string_lossy().into_owned()], &dir, &mut io, &mut d, None);
        assert_eq!(code, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_mode_prints_empty_array_when_clean() {
        let dir = tmp_dir("json-clean");
        let path = dir.join("a.css");
        std::fs::write(&path, "a{}").unwrap();
        let mut io = FakeIo { out: String::new(), err: String::new(), tty: true, stdin: String::new(), confirm_answer: true };
        let mut d = FakeDetectors { text_findings: RefCell::new(Vec::new()) };
        let code = run(&["--json".to_string(), path.to_string_lossy().into_owned()], &dir, &mut io, &mut d, None);
        assert_eq!(code, 0);
        assert_eq!(io.out, "[]\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stdin_mode_used_when_no_targets_and_not_a_tty() {
        let mut io = FakeIo {
            out: String::new(),
            err: String::new(),
            tty: false,
            stdin: "border-l-4: 1;".to_string(),
            confirm_answer: true,
        };
        let mut d = FakeDetectors {
            text_findings: RefCell::new(vec![CliFinding::new("side-tab", "<stdin>", 1, "s")]),
        };
        let code = run(&[], Path::new("."), &mut io, &mut d, None);
        assert_eq!(code, 2);
    }

    #[test]
    fn confirm_answer_parsing_matches_js_regex() {
        assert!(parse_confirm_answer(""));
        assert!(parse_confirm_answer("y"));
        assert!(parse_confirm_answer("Y"));
        assert!(parse_confirm_answer("yes"));
        assert!(parse_confirm_answer("YES"));
        assert!(!parse_confirm_answer("n"));
        assert!(!parse_confirm_answer("no"));
        assert!(!parse_confirm_answer("nope"));
    }

    #[test]
    fn detect_cli_normalizes_dash_json_and_dash_fast() {
        let dir = tmp_dir("norm");
        let path = dir.join("a.css");
        std::fs::write(&path, "a{}").unwrap();
        let mut io = FakeIo { out: String::new(), err: String::new(), tty: true, stdin: String::new(), confirm_answer: true };
        let mut d = FakeDetectors { text_findings: RefCell::new(Vec::new()) };
        let code = run(&["-json".to_string(), "-fast".to_string(), path.to_string_lossy().into_owned()], &dir, &mut io, &mut d, None);
        assert_eq!(code, 0);
        assert!(io.err.contains("--fast is deprecated"));
        assert_eq!(io.out, "[]\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
