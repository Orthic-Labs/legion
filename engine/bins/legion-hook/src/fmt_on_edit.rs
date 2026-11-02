//! Format Rust at edit time, not at push (fix plan B1). Check id
//! `fmt-on-edit`, PostToolUse of `Write`, `Edit` or `MultiEdit` on a `.rs`
//! file.
//!
//! The edited file's text is piped through standalone
//! `rustfmt --edition <edition> --emit stdout` and written back only when the
//! output differs and the file has not changed since it was read. Piping the
//! text, instead of passing the path, keeps rustfmt from following `mod x;`
//! into sibling files that another agent may be editing right now. The
//! edition comes from the nearest `Cargo.toml` (`[package] edition`, or
//! `edition.workspace = true` resolved from `[workspace.package]`), default
//! 2021. rustfmt runs with the file's folder as its working directory, so a
//! `rustfmt.toml` and `rust-toolchain.toml` above the file apply.
//!
//! Skipped: other extensions, `tests/fixtures` and `scripts/ci/fixtures`
//! paths, files listed in the nearest `.rightkit/fixture-files.json`, symlinks
//! (a rename would replace the link) and files over 2 MB.
//!
//! The check never fails the hook and never denies: a missing rustfmt, a
//! parse error or the 5 second timeout leaves the file as it was and returns a
//! one-line note for the model. It does not run cargo and does not compile.

use std::{
    ffi::OsStr,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

use crate::protocol::HookRequest;
use crate::skills_gate::{check_disabled, str_field, tool_input, tool_name, write_atomic};

pub const CHECK: &str = "fmt-on-edit";

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_EDITION: &str = "2021";
const MAX_WALK: usize = 24;
const MAX_ERROR_CHARS: usize = 160;
const FIXTURE_DIRS: [&str; 2] = ["/tests/fixtures/", "/scripts/ci/fixtures/"];

/// What one rustfmt run produced.
#[derive(Debug, PartialEq, Eq)]
enum FmtOutcome {
    /// rustfmt succeeded; the formatted text.
    Formatted(String),
    /// rustfmt exited non-zero; its first error line.
    ParseError(String),
    /// rustfmt could not be started.
    Missing,
    /// rustfmt ran past the timeout and was killed.
    TimedOut,
}

/// `(source text, edition, working directory) -> outcome`.
type Formatter<'a> = &'a dyn Fn(&str, &str, &Path) -> FmtOutcome;

// ---------------------------------------------------------------------------
// Edition from Cargo.toml (no toml crate in this binary)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Edition {
    #[default]
    Absent,
    Value(String),
    Workspace,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Manifest {
    has_package: bool,
    package_edition: Edition,
    workspace_edition: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Package,
    WorkspacePackage,
    Other,
}

/// The line without a trailing `# comment` (a `#` inside quotes stays).
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (index, c) in line.char_indices() {
        match quote {
            Some(open) => {
                if c == open {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '#' => return &line[..index],
                _ => {}
            },
        }
    }
    line
}

/// The text of a TOML string value (`"2021"` or `'2021'`).
fn quoted(value: &str) -> Option<String> {
    let value = value.trim();
    let quote = value.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &value[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_owned())
}

fn valid_edition(text: &str) -> bool {
    text.len() == 4 && text.chars().all(|c| c.is_ascii_digit())
}

/// Just enough TOML to read `edition` from `[package]` and
/// `[workspace.package]`.
fn parse_manifest(text: &str) -> Manifest {
    let mut manifest = Manifest::default();
    let mut section = Section::Other;
    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let name = line.trim_start_matches('[').trim_end_matches(']').trim();
            section = if line.starts_with("[[") {
                Section::Other
            } else if name == "package" {
                manifest.has_package = true;
                Section::Package
            } else if name == "workspace.package" {
                Section::WorkspacePackage
            } else {
                Section::Other
            };
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match section {
            Section::Package => {
                if key == "edition" {
                    if let Some(edition) = quoted(value).filter(|text| valid_edition(text)) {
                        manifest.package_edition = Edition::Value(edition);
                    } else if value.starts_with('{')
                        && value.contains("workspace")
                        && value.contains("true")
                    {
                        manifest.package_edition = Edition::Workspace;
                    }
                } else if key == "edition.workspace" && value == "true" {
                    manifest.package_edition = Edition::Workspace;
                }
            }
            Section::WorkspacePackage => {
                if key == "edition" {
                    if let Some(edition) = quoted(value).filter(|text| valid_edition(text)) {
                        manifest.workspace_edition = Some(edition);
                    }
                }
            }
            Section::Other => {}
        }
    }
    manifest
}

/// The edition for `path`: the nearest `[package]` decides, inherited from the
/// nearest `[workspace.package]` above it when it says `workspace = true`;
/// 2021 when nothing says.
fn edition_for(path: &Path) -> String {
    let mut found_package = false;
    let mut dir = path.parent();
    for _ in 0..MAX_WALK {
        let Some(current) = dir else {
            break;
        };
        if let Ok(text) = fs::read_to_string(current.join("Cargo.toml")) {
            let manifest = parse_manifest(&text);
            if !found_package && manifest.has_package {
                found_package = true;
                match manifest.package_edition {
                    Edition::Value(edition) => return edition,
                    Edition::Absent => return DEFAULT_EDITION.to_owned(),
                    Edition::Workspace => {}
                }
            }
            if let Some(edition) = manifest.workspace_edition {
                return edition;
            }
        }
        dir = current.parent();
    }
    DEFAULT_EDITION.to_owned()
}

// ---------------------------------------------------------------------------
// Which files are left alone
// ---------------------------------------------------------------------------

fn is_rust_file(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
}

fn is_fixture_path(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    FIXTURE_DIRS
        .iter()
        .any(|dir| text.contains(dir) || text.starts_with(&dir[1..]))
}

/// Is `path` a key of `files` in the fixture list found at `root`?
fn fixture_listed(json_text: &str, path: &Path, root: &Path) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(json_text) else {
        return false;
    };
    let Some(files) = value.get("files").and_then(Value::as_object) else {
        return false;
    };
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    files.contains_key(&relative.to_string_lossy().replace('\\', "/"))
}

/// Is `path` listed in the nearest `.rightkit/fixture-files.json`?
fn listed_fixture(path: &Path) -> bool {
    let mut dir = path.parent();
    for _ in 0..MAX_WALK {
        let Some(current) = dir else {
            return false;
        };
        let list = current.join(".rightkit").join("fixture-files.json");
        if let Ok(text) = fs::read_to_string(&list) {
            return fixture_listed(&text, path, current);
        }
        dir = current.parent();
    }
    false
}

// ---------------------------------------------------------------------------
// Running rustfmt
// ---------------------------------------------------------------------------

fn truncate_chars(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

/// The 1-based line number in rustfmt's `--> <stdin>:12:5` location line.
fn error_line_number(stderr: &str) -> Option<u32> {
    for line in stderr.lines() {
        if let Some(index) = line.find("stdin") {
            let rest = line[index + 5..].trim_start_matches('>');
            if let Some(rest) = rest.strip_prefix(':') {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(number) = digits.parse() {
                    return Some(number);
                }
            }
        }
    }
    None
}

/// The first `error...` line of rustfmt's stderr (else its first line), with
/// the line number appended when rustfmt gave one.
fn first_error_line(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let first = lines
        .iter()
        .find(|line| line.starts_with("error"))
        .or_else(|| lines.first())
        .copied()
        .unwrap_or("unknown error");
    let mut text = truncate_chars(first, MAX_ERROR_CHARS).to_owned();
    if let Some(line) = error_line_number(stderr) {
        text.push_str(&format!(" (line {line})"));
    }
    text
}

/// Pipe `source` through `rustfmt` and wait at most `TIMEOUT`.
fn run_rustfmt(source: &str, edition: &str, dir: &Path) -> FmtOutcome {
    let mut command = Command::new("rustfmt");
    command
        .args(["--edition", edition, "--emit", "stdout"])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return FmtOutcome::Missing,
    };
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let input = source.as_bytes().to_vec();
    let writer = thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(&input);
        }
    });
    let out_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut stdout) = stdout {
            let _ = stdout.read_to_end(&mut buffer);
        }
        buffer
    });
    let err_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut stderr) = stderr {
            let _ = stderr.read_to_end(&mut buffer);
        }
        buffer
    });
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let out = out_reader.join().unwrap_or_default();
    let err = err_reader.join().unwrap_or_default();
    let _ = writer.join();
    let Some(status) = status else {
        return FmtOutcome::TimedOut;
    };
    if status.success() {
        return match String::from_utf8(out) {
            Ok(text) => FmtOutcome::Formatted(text),
            Err(_) => FmtOutcome::ParseError("rustfmt output was not UTF-8".to_owned()),
        };
    }
    FmtOutcome::ParseError(first_error_line(&String::from_utf8_lossy(&err)))
}

/// Replace the file's text, but only when it still holds `original` (another
/// writer may have changed it while rustfmt ran), keeping its permissions.
fn write_back(path: &Path, original: &[u8], formatted: &str) -> bool {
    match fs::read(path) {
        Ok(current) if current == original => {}
        _ => return false,
    }
    let permissions = fs::metadata(path).ok().map(|meta| meta.permissions());
    if write_atomic(path, formatted.as_bytes()).is_err() {
        return false;
    }
    if let Some(permissions) = permissions {
        let _ = fs::set_permissions(path, permissions);
    }
    true
}

fn format_file(path: &Path, shown: &str, format: Formatter<'_>) -> Option<String> {
    if !is_rust_file(path) || is_fixture_path(path) || listed_fixture(path) {
        return None;
    }
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let original = fs::read(path).ok()?;
    let source = std::str::from_utf8(&original).ok()?.to_owned();
    let dir = path.parent()?;
    let edition = edition_for(path);
    match format(&source, &edition, dir) {
        FmtOutcome::Formatted(formatted) => {
            if formatted == source || (formatted.trim().is_empty() && !source.trim().is_empty()) {
                return None;
            }
            if write_back(path, &original, &formatted) {
                Some(format!("rustfmt formatted {shown}"))
            } else {
                None
            }
        }
        FmtOutcome::ParseError(line) => Some(format!("rustfmt could not parse {shown}: {line}")),
        FmtOutcome::Missing => Some(format!(
            "rustfmt is not installed; {shown} was left unformatted"
        )),
        FmtOutcome::TimedOut => Some(format!("rustfmt timed out on {shown}; left unformatted")),
    }
}

fn observe_edit_with(request: &HookRequest, format: Formatter<'_>) -> Option<String> {
    if !matches!(request.event_type.as_str(), "PostToolUse" | "post-effect") {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = tool_name(payload)?;
    if !matches!(tool.as_str(), "Write" | "Edit" | "MultiEdit") {
        return None;
    }
    let shown = str_field(tool_input(payload)?, &["file_path", "filePath", "path"])?;
    let mut path = PathBuf::from(&shown);
    if path.is_relative() {
        path = PathBuf::from(str_field(payload, &["cwd", "workdir"])?).join(path);
    }
    format_file(&path, &shown, format)
}

/// PostToolUse of `Write`, `Edit` or `MultiEdit` on a `.rs` file: format that
/// one file with standalone rustfmt. Returns a one-line note for the model's
/// context (formatted, could not parse, rustfmt missing or timed out), or
/// `None` when nothing changed or the file is out of scope. Never denies and
/// never fails the hook.
pub fn observe_edit(request: &HookRequest) -> Option<String> {
    if check_disabled(CHECK) {
        return None;
    }
    observe_edit_with(request, &run_rustfmt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        cell::RefCell,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "legion-hook-fmt-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("create test dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, text: &str) -> PathBuf {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(&path, text).expect("write file");
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn edit_request(event: &str, tool: &str, path: &Path) -> HookRequest {
        HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: event.to_owned(),
            payload: json!({
                "tool_name": tool,
                "tool_input": {"file_path": path.to_string_lossy()},
            }),
        }
    }

    fn shout(source: &str, _edition: &str, _dir: &Path) -> FmtOutcome {
        FmtOutcome::Formatted(source.to_uppercase())
    }

    fn never(_: &str, _: &str, _: &Path) -> FmtOutcome {
        panic!("the formatter must not run");
    }

    // --- Cargo.toml ---

    #[test]
    fn manifest_reads_package_and_workspace_editions() {
        let package = parse_manifest(
            "[package]\nname = \"x\"\nedition = \"2018\" # old\n\n[dependencies]\nedition = \"1999\"\n",
        );
        assert!(package.has_package);
        assert_eq!(package.package_edition, Edition::Value("2018".into()));
        assert_eq!(package.workspace_edition, None);

        let inherited = parse_manifest("[package]\nname = \"x\"\nedition.workspace = true\n");
        assert_eq!(inherited.package_edition, Edition::Workspace);
        let inline = parse_manifest("[package]\nedition = { workspace = true }\n");
        assert_eq!(inline.package_edition, Edition::Workspace);

        let root = parse_manifest(
            "[workspace]\nmembers = [\"a\"]\n\n[workspace.package]\nversion = \"1\"\nedition = '2024'\n",
        );
        assert!(!root.has_package);
        assert_eq!(root.workspace_edition, Some("2024".into()));

        let bin = parse_manifest("[[bin]]\nname = \"x\"\n[package]\nname = \"y\"\n");
        assert!(bin.has_package);
        assert_eq!(bin.package_edition, Edition::Absent);
        assert_eq!(
            parse_manifest("[package]\nedition = \"20x1\"\n").package_edition,
            Edition::Absent
        );
    }

    #[test]
    fn edition_comes_from_the_nearest_package_then_the_workspace() {
        let dir = TestDir::new("edition");
        dir.write(
            "ws/Cargo.toml",
            "[workspace]\nmembers = [\"inherit\", \"direct\", \"bare\"]\n[workspace.package]\nedition = \"2024\"\n",
        );
        let inherit = dir.write("ws/inherit/src/lib.rs", "");
        dir.write(
            "ws/inherit/Cargo.toml",
            "[package]\nname = \"a\"\nedition.workspace = true\n",
        );
        let direct = dir.write("ws/direct/src/a/b.rs", "");
        dir.write(
            "ws/direct/Cargo.toml",
            "[package]\nname = \"b\"\nedition = \"2018\"\n",
        );
        let bare = dir.write("ws/bare/src/lib.rs", "");
        dir.write("ws/bare/Cargo.toml", "[package]\nname = \"c\"\n");
        assert_eq!(edition_for(&inherit), "2024");
        assert_eq!(edition_for(&direct), "2018");
        assert_eq!(edition_for(&bare), "2021");
        let loose = dir.write("loose/x.rs", "");
        assert_eq!(edition_for(&loose), "2021");
    }

    // --- scope ---

    #[test]
    fn fixture_paths_and_listed_files_are_skipped() {
        assert!(is_fixture_path(Path::new("/r/crate/tests/fixtures/a.rs")));
        assert!(is_fixture_path(Path::new("/r/scripts/ci/fixtures/a.rs")));
        assert!(is_fixture_path(Path::new("tests/fixtures/a.rs")));
        assert!(!is_fixture_path(Path::new("/r/crate/src/fixtures_not.rs")));
        assert!(!is_fixture_path(Path::new("/r/crate/tests/other/a.rs")));

        let dir = TestDir::new("listed");
        dir.write(
            ".rightkit/fixture-files.json",
            r#"{"files":{"engine/x/y.rs":{"note":"n","sha256":"0"}}}"#,
        );
        let listed = dir.write("engine/x/y.rs", "fn  a(){}");
        let other = dir.write("engine/x/z.rs", "fn  a(){}");
        assert!(listed_fixture(&listed));
        assert!(!listed_fixture(&other));
        let note = observe_edit_with(&edit_request("PostToolUse", "Edit", &listed), &never);
        assert_eq!(note, None);
    }

    #[test]
    fn only_post_tool_use_of_edit_tools_on_rust_files_runs() {
        let dir = TestDir::new("scope");
        let rust = dir.write("a.rs", "fn  a(){}");
        let text = dir.write("a.txt", "fn  a(){}");
        assert_eq!(
            observe_edit_with(&edit_request("PostToolUse", "Edit", &text), &never),
            None
        );
        assert_eq!(
            observe_edit_with(&edit_request("PostToolUse", "Read", &rust), &never),
            None
        );
        assert_eq!(
            observe_edit_with(&edit_request("PostToolUseFailure", "Edit", &rust), &never),
            None
        );
        assert_eq!(
            observe_edit_with(&edit_request("PreToolUse", "Edit", &rust), &never),
            None
        );
        let missing = dir.path().join("gone.rs");
        assert_eq!(
            observe_edit_with(&edit_request("PostToolUse", "Write", &missing), &never),
            None
        );
    }

    // --- behaviour with a fake formatter ---

    #[test]
    fn changed_output_is_written_and_noted() {
        let dir = TestDir::new("changed");
        let path = dir.write("a.rs", "fn  a(){}");
        let note = observe_edit_with(&edit_request("PostToolUse", "Edit", &path), &shout);
        let shown = path.to_string_lossy();
        assert_eq!(note, Some(format!("rustfmt formatted {shown}")));
        assert_eq!(fs::read_to_string(&path).expect("read"), "FN  A(){}");
        for tool in ["Write", "MultiEdit"] {
            let again = dir.write("b.rs", "x");
            let note = observe_edit_with(&edit_request("PostToolUse", tool, &again), &shout);
            assert!(note.is_some(), "{tool}");
        }
    }

    #[test]
    fn unchanged_output_is_silent() {
        let dir = TestDir::new("same");
        let path = dir.write("a.rs", "FN A(){}");
        let note = observe_edit_with(&edit_request("PostToolUse", "Edit", &path), &shout);
        assert_eq!(note, None);
        assert_eq!(fs::read_to_string(&path).expect("read"), "FN A(){}");
    }

    #[test]
    fn a_parse_error_leaves_the_file_and_says_so() {
        let dir = TestDir::new("parse");
        let path = dir.write("a.rs", "fn main( {");
        let fail =
            |_: &str, _: &str, _: &Path| FmtOutcome::ParseError("error: bad (line 1)".into());
        let note = observe_edit_with(&edit_request("PostToolUse", "Edit", &path), &fail);
        let shown = path.to_string_lossy();
        assert_eq!(
            note,
            Some(format!(
                "rustfmt could not parse {shown}: error: bad (line 1)"
            ))
        );
        assert_eq!(fs::read_to_string(&path).expect("read"), "fn main( {");
    }

    #[test]
    fn missing_rustfmt_and_timeouts_add_a_note_and_leave_the_file() {
        let dir = TestDir::new("missing");
        let path = dir.write("a.rs", "fn  a(){}");
        let missing = |_: &str, _: &str, _: &Path| FmtOutcome::Missing;
        let note =
            observe_edit_with(&edit_request("PostToolUse", "Edit", &path), &missing).expect("note");
        assert!(note.contains("rustfmt is not installed"));
        let slow = |_: &str, _: &str, _: &Path| FmtOutcome::TimedOut;
        let note =
            observe_edit_with(&edit_request("PostToolUse", "Edit", &path), &slow).expect("note");
        assert!(note.contains("timed out"));
        assert_eq!(fs::read_to_string(&path).expect("read"), "fn  a(){}");
    }

    #[test]
    fn an_empty_result_never_wipes_a_file() {
        let dir = TestDir::new("empty");
        let path = dir.write("a.rs", "fn a() {}\n");
        let wipe = |_: &str, _: &str, _: &Path| FmtOutcome::Formatted(String::new());
        assert_eq!(
            observe_edit_with(&edit_request("PostToolUse", "Edit", &path), &wipe),
            None
        );
        assert_eq!(fs::read_to_string(&path).expect("read"), "fn a() {}\n");
    }

    #[test]
    fn a_file_changed_while_formatting_is_not_overwritten() {
        let dir = TestDir::new("race");
        let path = dir.write("a.rs", "fn  a(){}");
        let racing = {
            let path = path.clone();
            move |source: &str, _: &str, _: &Path| {
                fs::write(&path, "fn  other(){}").expect("concurrent write");
                FmtOutcome::Formatted(source.to_uppercase())
            }
        };
        let note = observe_edit_with(&edit_request("PostToolUse", "Edit", &path), &racing);
        assert_eq!(note, None);
        assert_eq!(fs::read_to_string(&path).expect("read"), "fn  other(){}");
    }

    #[test]
    fn the_formatter_gets_the_crate_edition_and_the_file_folder() {
        let dir = TestDir::new("args");
        dir.write(
            "Cargo.toml",
            "[package]\nname = \"a\"\nedition = \"2018\"\n",
        );
        let path = dir.write("src/a.rs", "fn  a(){}");
        let seen: RefCell<Vec<(String, PathBuf)>> = RefCell::new(Vec::new());
        let spy = |source: &str, edition: &str, folder: &Path| {
            seen.borrow_mut()
                .push((edition.to_owned(), folder.to_path_buf()));
            FmtOutcome::Formatted(source.to_owned())
        };
        let _ = observe_edit_with(&edit_request("PostToolUse", "Edit", &path), &spy);
        let calls = seen.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "2018");
        assert_eq!(calls[0].1, dir.path().join("src"));
    }

    #[test]
    fn a_relative_path_joins_the_working_folder() {
        let dir = TestDir::new("relative");
        dir.write("a.rs", "fn  a(){}");
        let request = HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: "PostToolUse".to_owned(),
            payload: json!({
                "tool_name": "Edit",
                "cwd": dir.path().to_string_lossy(),
                "tool_input": {"file_path": "a.rs"},
            }),
        };
        let note = observe_edit_with(&request, &shout);
        assert_eq!(note, Some("rustfmt formatted a.rs".to_owned()));
    }

    #[test]
    fn symlinked_files_are_left_alone() {
        #[cfg(unix)]
        {
            let dir = TestDir::new("symlink");
            let target = dir.write("real.rs", "fn  a(){}");
            let link = dir.path().join("link.rs");
            std::os::unix::fs::symlink(&target, &link).expect("symlink");
            assert_eq!(
                observe_edit_with(&edit_request("PostToolUse", "Edit", &link), &never),
                None
            );
        }
    }

    // --- rustfmt's own error text ---

    #[test]
    fn the_first_error_line_carries_the_line_number() {
        let stderr = "Warning: can't set `x`\nerror: this file contains an unclosed delimiter\n --> <stdin>:1:21\n  |\n1 | fn main( {\n";
        assert_eq!(
            first_error_line(stderr),
            "error: this file contains an unclosed delimiter (line 1)"
        );
        assert_eq!(first_error_line("boom\nmore"), "boom");
        assert_eq!(first_error_line(""), "unknown error");
        assert_eq!(error_line_number("--> stdin:12"), Some(12));
        assert_eq!(error_line_number("no location"), None);
    }

    // --- the real rustfmt, when it is installed ---

    fn rustfmt_installed() -> bool {
        Command::new("rustfmt")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    #[test]
    fn real_rustfmt_formats_an_unformatted_file_and_leaves_a_broken_one() {
        if !rustfmt_installed() {
            return;
        }
        let dir = TestDir::new("real");
        let good = dir.write(
            "good.rs",
            "mod missing;\nfn  main( ){let x=1;println!(\"{}\",x)}\n",
        );
        let note = observe_edit_with(&edit_request("PostToolUse", "Edit", &good), &run_rustfmt);
        assert_eq!(
            note,
            Some(format!("rustfmt formatted {}", good.to_string_lossy()))
        );
        assert_eq!(
            fs::read_to_string(&good).expect("read"),
            "mod missing;\nfn main() {\n    let x = 1;\n    println!(\"{}\", x)\n}\n"
        );
        let broken = dir.write("broken.rs", "fn main( { let = ;}\n");
        let note = observe_edit_with(&edit_request("PostToolUse", "Edit", &broken), &run_rustfmt)
            .expect("note");
        assert!(note.starts_with("rustfmt could not parse"), "{note}");
        assert_eq!(
            fs::read_to_string(&broken).expect("read"),
            "fn main( { let = ;}\n"
        );
    }
}
