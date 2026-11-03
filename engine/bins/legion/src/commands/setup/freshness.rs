//! Is the installed Legion behind? `legion setup status` compares the
//! installed release with the newest published release, with the version in
//! the development checkout, and with the checkout's HEAD commit distance from
//! the installed source commit, so an install that stopped moving cannot read
//! as "complete" (Orthic-Labs/legion#137).
//!
//! The check fails open: a version, tag, commit or checkout that cannot be read
//! leaves `behind` unknown and the setup status exactly as it was. An installed
//! commit that is not recorded yields `commitState` `unknown`, never `current`.
use rightkit_evidence_effects::{PlatformProcess, ProcessLaunch};
use serde_json::Value;
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

/// Where releases are published.
const RELEASE_REPOSITORY: &str = "Orthic-Labs/legion";
/// Each lookup (git tag listing, `gh release view`) gets this long.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// `LEGION_RELEASE_CHECK=off` skips every lookup (tests, offline hosts).
/// `LEGION_DEV_CHECKOUT=<path>` names the development checkout when the
/// command is not run from inside it. Both are environment seams: they exist
/// only in builds with debug assertions and are compiled out of release builds
/// (Orthic-Labs/legion#127), where lookups always run and the checkout is the
/// nearest Legion git checkout above the working directory.
#[cfg(debug_assertions)]
const SWITCH_ENV: &str = "LEGION_RELEASE_CHECK";
#[cfg(debug_assertions)]
const CHECKOUT_ENV: &str = "LEGION_DEV_CHECKOUT";
const CHECKOUT_MANIFESTS: [&str; 2] = [".claude-plugin/plugin.json", ".codex-plugin/plugin.json"];

/// What was observed about the installed release and what is newer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct Freshness {
    pub(super) installed_version: Option<String>,
    pub(super) latest_release: Option<String>,
    /// `git-tag` (newest `v*` tag in the checkout) or `github-release`.
    pub(super) latest_release_source: Option<&'static str>,
    /// `version` in the development checkout's plugin manifest.
    pub(super) checkout_version: Option<String>,
    /// The source commit the installed generation was built from, when its
    /// release manifest records one (`sourceRevision`).
    pub(super) installed_commit: Option<String>,
    /// Commits on checkout HEAD that the installed commit does not include.
    /// `None` when either commit is unknown or git could not count them.
    pub(super) commits_behind: Option<u64>,
    /// `current`, `behind` or `unknown`, judged from the installed commit and
    /// the commit distance alone.
    pub(super) commit_state: Option<&'static str>,
    /// `None` when installed or newer versions could not be determined.
    pub(super) behind: Option<bool>,
    /// The line `setup status` adds when `behind` is true.
    pub(super) remediation: Option<String>,
}

impl Freshness {
    /// A `behind` install is not `complete`. An install that is already
    /// `incomplete` keeps that status; the versions are still reported.
    pub(super) fn apply_to_health(
        &self,
        status: &'static str,
        remediation: &mut Vec<String>,
    ) -> &'static str {
        let Some(line) = &self.remediation else {
            return status;
        };
        remediation.insert(0, line.clone());
        if status == "complete" {
            "behind"
        } else {
            status
        }
    }

    /// Add `installedVersion`, `latestRelease`, `behind` and the evidence
    /// behind them to a `legion-setup-status` object.
    pub(super) fn merge_into(&self, target: &mut Value) {
        let Some(object) = target.as_object_mut() else {
            return;
        };
        let fields: [(&str, Value); 8] = [
            ("installedVersion", string_or_null(&self.installed_version)),
            ("latestRelease", string_or_null(&self.latest_release)),
            (
                "latestReleaseSource",
                self.latest_release_source
                    .map_or(Value::Null, |source| Value::String(source.into())),
            ),
            ("checkoutVersion", string_or_null(&self.checkout_version)),
            ("installedCommit", string_or_null(&self.installed_commit)),
            (
                "commitsBehind",
                self.commits_behind.map_or(Value::Null, Value::from),
            ),
            (
                "commitState",
                self.commit_state
                    .map_or(Value::Null, |state| Value::String(state.into())),
            ),
            ("behind", self.behind.map_or(Value::Null, Value::Bool)),
        ];
        for (key, value) in fields {
            object.insert(key.into(), value);
        }
    }
}

fn string_or_null(value: &Option<String>) -> Value {
    value.clone().map_or(Value::Null, Value::String)
}

/// `1.2.3`, `v1.2.3`, one to four numeric parts. A pre-release or build suffix
/// is not a release version and parses as unknown.
fn parse_version(text: &str) -> Option<Vec<u64>> {
    let text = text.trim();
    let text = text.strip_prefix('v').unwrap_or(text);
    let parts = text
        .split('.')
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                None
            } else {
                part.parse::<u64>().ok()
            }
        })
        .collect::<Option<Vec<_>>>()?;
    (1..=4).contains(&parts.len()).then_some(parts)
}

fn compare(left: &[u64], right: &[u64]) -> Ordering {
    for index in 0..left.len().max(right.len()) {
        let order = left
            .get(index)
            .copied()
            .unwrap_or(0)
            .cmp(&right.get(index).copied().unwrap_or(0));
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}

/// The newest release tag in `git tag --list v*` output.
fn newest_tag(listing: &str) -> Option<String> {
    listing
        .lines()
        .map(str::trim)
        .filter(|tag| tag.starts_with('v'))
        .filter_map(|tag| parse_version(tag).map(|parsed| (parsed, tag)))
        .max_by(|left, right| compare(&left.0, &right.0))
        .map(|(_, tag)| tag.to_owned())
}

/// `tagName` from `gh release view --json tagName`.
fn release_tag(output: &str) -> Option<String> {
    let value: Value = serde_json::from_str(output).ok()?;
    let tag = value.get("tagName")?.as_str()?.trim();
    parse_version(tag).map(|_| tag.to_owned())
}

/// A source commit as recorded in a release manifest or passed to git: 7 to 40
/// hexadecimal digits. Anything else is never handed to git as an argument.
fn is_commit_id(text: &str) -> bool {
    (7..=40).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// `sourceRevision` from an installed release manifest. Releases that do not
/// record their source commit yield `None`.
fn installed_commit_from_manifest(value: &Value) -> Option<String> {
    value
        .get("sourceRevision")?
        .as_str()
        .map(str::trim)
        .filter(|commit| is_commit_id(commit))
        .map(str::to_owned)
}

/// `git rev-list --count` output: one non-negative integer.
fn parse_commit_count(output: &str) -> Option<u64> {
    output.trim().parse().ok()
}

/// Compare the installed version and commit with every newer version and commit
/// known. Pure. Without a known installed commit the commit distance is ignored
/// and `commit_state` is `unknown`; a version-current install is then not
/// reported `behind: false`, because the commit that decides it is unknown.
fn assess(
    installed: &str,
    latest: Option<(String, &'static str)>,
    checkout_version: Option<String>,
    installed_commit: Option<String>,
    commits_behind: Option<u64>,
) -> Freshness {
    let mut targets: Vec<(Vec<u64>, String)> = Vec::new();
    if let Some((tag, _)) = &latest {
        if let Some(parsed) = parse_version(tag) {
            targets.push((parsed, format!("latest release {tag}")));
        }
    }
    if let Some(version) = &checkout_version {
        if let Some(parsed) = parse_version(version) {
            targets.push((parsed, format!("dev checkout {version}")));
        }
    }
    let commits_behind = if installed_commit.is_some() {
        commits_behind
    } else {
        None
    };
    // `None` when the installed version or every version target is unknown.
    let newer = parse_version(installed)
        .filter(|_| !targets.is_empty())
        .map(|parsed| {
            targets
                .iter()
                .filter(|(target, _)| compare(&parsed, target) == Ordering::Less)
                .map(|(_, label)| label.as_str())
                .collect::<Vec<_>>()
        });
    let mut reasons = Vec::new();
    if let Some(newer) = newer.as_ref().filter(|newer| !newer.is_empty()) {
        reasons.push(format!("behind {}", newer.join(" and ")));
    }
    if let Some(count) = commits_behind.filter(|count| *count > 0) {
        reasons.push(format!("behind: {count} commits to checkout HEAD"));
    }
    let (behind, remediation) = if reasons.is_empty() {
        let current = newer.is_some() && commits_behind == Some(0);
        (current.then_some(false), None)
    } else {
        (
            Some(true),
            Some(format!(
                "installed Legion {installed} is {}; reinstall from the newest release (rerun bootstrap), then run legion setup repair --confirm",
                reasons.join("; ")
            )),
        )
    };
    let commit_state = match (installed_commit.is_some(), commits_behind) {
        (true, Some(0)) => "current",
        (true, Some(_)) => "behind",
        _ => "unknown",
    };
    Freshness {
        installed_version: Some(installed.to_owned()),
        latest_release: latest.as_ref().map(|(tag, _)| tag.clone()),
        latest_release_source: latest.map(|(_, source)| source),
        checkout_version,
        installed_commit,
        commits_behind,
        commit_state: Some(commit_state),
        behind,
        remediation,
    }
}

fn is_checkout(root: &Path) -> bool {
    root.join(".git").exists()
        && CHECKOUT_MANIFESTS.iter().any(|manifest| {
            std::fs::read(root.join(manifest))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|value| value.get("name").and_then(Value::as_str) == Some("legion"))
        })
}

/// The development checkout: the explicit path when given, else the nearest
/// ancestor of the working directory that is a Legion git checkout.
fn find_checkout(explicit: Option<&Path>, cwd: Option<&Path>) -> Option<PathBuf> {
    if let Some(root) = explicit {
        return is_checkout(root).then(|| root.to_path_buf());
    }
    cwd?.ancestors()
        .take(12)
        .find(|candidate| is_checkout(candidate))
        .map(Path::to_path_buf)
}

fn read_checkout_version(root: &Path) -> Option<String> {
    CHECKOUT_MANIFESTS.iter().find_map(|manifest| {
        let bytes = std::fs::read(root.join(manifest)).ok()?;
        let value: Value = serde_json::from_slice(&bytes).ok()?;
        value
            .get("version")
            .and_then(Value::as_str)
            .map(|version| version.trim().to_owned())
            .filter(|version| !version.is_empty())
    })
}

#[cfg(any(debug_assertions, test))]
fn release_check_disabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "no"
        )
    })
}

/// Run `git` or `gh` once with a short timeout and no console. `None` on any
/// failure: a missing tool, a timeout, a non-zero exit or unreadable output.
async fn run_tool(command: &str, args: Vec<String>, cwd: &Path) -> Option<String> {
    let executable = super::resolve_command(command).ok()?;
    let mut environment = std::env::vars().collect::<BTreeMap<_, _>>();
    environment.insert("GH_PROMPT_DISABLED".into(), "1".into());
    environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    let launch = ProcessLaunch {
        executable: executable.to_string_lossy().into_owned(),
        args,
        cwd: cwd.to_string_lossy().into_owned(),
        environment,
        stdout_limit: 256 * 1024,
        stderr_limit: 64 * 1024,
        timeout_ms: LOOKUP_TIMEOUT.as_millis() as u64,
        termination_grace_ms: 500,
        cancellation: CancellationToken::new(),
    };
    #[cfg(unix)]
    let output = rightkit_evidence_effects::platform::unix::UnixProcess
        .run(launch)
        .await;
    #[cfg(windows)]
    let output = rightkit_evidence_effects::platform::windows::WindowsProcess
        .run(launch)
        .await;
    let output = output.ok()?;
    if output.timed_out || output.cancelled || output.output_limited || output.exit_code != Some(0)
    {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// Which sources `observe` may consult.
#[derive(Clone, Debug)]
pub(super) struct Lookup {
    pub(super) enabled: bool,
    pub(super) checkout: Option<PathBuf>,
    pub(super) cwd: Option<PathBuf>,
    pub(super) use_git: bool,
    pub(super) use_gh: bool,
    /// The installed generation's recorded source commit, when known.
    pub(super) installed_commit: Option<String>,
}

impl Lookup {
    pub(super) fn from_environment() -> Self {
        let (enabled, checkout) = environment_seams();
        Self {
            enabled,
            checkout,
            cwd: std::env::current_dir().ok(),
            use_git: true,
            use_gh: true,
            installed_commit: enabled.then(installed_source_commit).flatten(),
        }
    }
}

/// The source commit recorded in the installed generation's release manifest.
/// The manifest is re-read raw so a value the typed `source_revision` field
/// rejects or lacks (an older release, a short id) stays "unknown" instead of
/// failing the whole status.
fn installed_source_commit() -> Option<String> {
    let installed = legion_runtime::release_binding::load_installed_release().ok()?;
    let bytes = std::fs::read(&installed.manifest_path).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    installed_commit_from_manifest(&value)
}

/// `git -C <checkout> rev-list --count <installed>..HEAD`. `None` when the
/// installed commit is unknown, git is not allowed, or git cannot count it
/// (for example the installed commit is not in this checkout).
async fn commits_behind(lookup: &Lookup, checkout: Option<&Path>) -> Option<u64> {
    let installed = lookup.installed_commit.as_deref()?;
    if !lookup.use_git || !is_commit_id(installed) {
        return None;
    }
    let root = checkout?;
    let args = vec![
        "-C".to_owned(),
        root.to_string_lossy().into_owned(),
        "rev-list".to_owned(),
        "--count".to_owned(),
        format!("{installed}..HEAD"),
    ];
    run_tool("git", args, root)
        .await
        .and_then(|output| parse_commit_count(&output))
}

#[cfg(debug_assertions)]
fn environment_seams() -> (bool, Option<PathBuf>) {
    (
        !release_check_disabled(std::env::var(SWITCH_ENV).ok().as_deref()),
        std::env::var_os(CHECKOUT_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
    )
}

#[cfg(not(debug_assertions))]
fn environment_seams() -> (bool, Option<PathBuf>) {
    (true, None)
}

/// Observe the installed version against the newest release and the checkout.
pub(super) async fn observe(installed_version: &str) -> Freshness {
    observe_with(installed_version, &Lookup::from_environment()).await
}

async fn observe_with(installed_version: &str, lookup: &Lookup) -> Freshness {
    if !lookup.enabled {
        return Freshness {
            installed_version: Some(installed_version.to_owned()),
            ..Freshness::default()
        };
    }
    let checkout = find_checkout(lookup.checkout.as_deref(), lookup.cwd.as_deref());
    let checkout_version = checkout.as_deref().and_then(read_checkout_version);
    let mut latest: Option<(String, &'static str)> = None;
    if lookup.use_git {
        if let Some(root) = checkout.as_deref() {
            let args = vec![
                "-C".to_owned(),
                root.to_string_lossy().into_owned(),
                "tag".to_owned(),
                "--list".to_owned(),
                "v*".to_owned(),
            ];
            latest = run_tool("git", args, root)
                .await
                .and_then(|listing| newest_tag(&listing))
                .map(|tag| (tag, "git-tag"));
        }
    }
    if latest.is_none() && lookup.use_gh {
        let args = [
            "release",
            "view",
            "--repo",
            RELEASE_REPOSITORY,
            "--json",
            "tagName",
        ]
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
        let cwd = lookup.cwd.clone().unwrap_or_else(std::env::temp_dir);
        latest = run_tool("gh", args, &cwd)
            .await
            .and_then(|output| release_tag(&output))
            .map(|tag| (tag, "github-release"));
    }
    let commits = commits_behind(lookup, checkout.as_deref()).await;
    assess(
        installed_version,
        latest,
        checkout_version,
        lookup.installed_commit.clone(),
        commits,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    fn temp_dir(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "legion-freshness-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn checkout(version: &str) -> PathBuf {
        let root = temp_dir("checkout");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join(".claude-plugin")).unwrap();
        std::fs::write(
            root.join(".claude-plugin/plugin.json"),
            json!({"name": "legion", "version": version}).to_string(),
        )
        .unwrap();
        root
    }

    #[test]
    fn versions_parse_strictly_and_compare_numerically() {
        assert_eq!(parse_version("v0.3.22"), Some(vec![0, 3, 22]));
        assert_eq!(parse_version(" 1.10 "), Some(vec![1, 10]));
        for unknown in [
            "",
            "v",
            "1..2",
            "1.2.3-rc1",
            "1.2.3+build",
            "latest",
            "1.2.3.4.5",
        ] {
            assert_eq!(parse_version(unknown), None, "{unknown}");
        }
        assert_eq!(compare(&[0, 3, 9], &[0, 3, 10]), Ordering::Less);
        assert_eq!(compare(&[0, 3], &[0, 3, 0]), Ordering::Equal);
        assert_eq!(compare(&[1], &[0, 99, 99]), Ordering::Greater);
    }

    #[test]
    fn newest_tag_ignores_prereleases_and_other_tags() {
        let listing = "v0.3.9\nv0.3.22\nv0.3.23-rc1\nnightly\n  v0.3.10  \n";
        assert_eq!(newest_tag(listing).as_deref(), Some("v0.3.22"));
        assert_eq!(newest_tag(""), None);
        assert_eq!(newest_tag("nightly\n"), None);
    }

    #[test]
    fn release_tag_reads_gh_json_or_nothing() {
        assert_eq!(
            release_tag(r#"{"tagName":"v0.3.22"}"#).as_deref(),
            Some("v0.3.22")
        );
        for bad in [
            "",
            "not json",
            r#"{"tagName":"nightly"}"#,
            r#"{"name":"x"}"#,
        ] {
            assert_eq!(release_tag(bad), None, "{bad}");
        }
    }

    #[test]
    fn older_than_the_latest_release_is_behind_and_names_both_versions() {
        let freshness = assess(
            "0.3.23",
            Some(("v0.3.24".into(), "github-release")),
            None,
            None,
            None,
        );
        assert_eq!(freshness.behind, Some(true));
        let line = freshness.remediation.as_deref().unwrap();
        assert!(
            line.contains("0.3.23") && line.contains("v0.3.24"),
            "{line}"
        );
        assert_eq!(freshness.latest_release_source, Some("github-release"));
    }

    #[test]
    fn older_than_the_checkout_version_is_behind() {
        let freshness = assess(
            "0.3.23",
            Some(("v0.3.22".into(), "git-tag")),
            Some("0.3.25".into()),
            None,
            None,
        );
        assert_eq!(freshness.behind, Some(true));
        let line = freshness.remediation.as_deref().unwrap();
        assert!(line.contains("dev checkout 0.3.25"), "{line}");
        assert!(
            !line.contains("v0.3.22"),
            "an older release is not a reason: {line}"
        );
    }

    #[test]
    fn current_or_ahead_is_not_behind_only_when_the_commit_is_current() {
        let equal = assess(
            "0.3.22",
            Some(("v0.3.22".into(), "git-tag")),
            Some("0.3.22".into()),
            Some("14b630ca".into()),
            Some(0),
        );
        assert_eq!((equal.behind, equal.remediation), (Some(false), None));
        assert_eq!(equal.commit_state, Some("current"));
        let ahead = assess(
            "0.3.23",
            Some(("v0.3.22".into(), "git-tag")),
            None,
            Some("14b630ca".into()),
            Some(0),
        );
        assert_eq!(ahead.behind, Some(false));
    }

    #[test]
    fn version_current_with_commit_behind_is_behind_not_complete() {
        let freshness = assess(
            "0.3.23",
            Some(("v0.3.23".into(), "git-tag")),
            Some("0.3.23".into()),
            Some("14b630ca".into()),
            Some(486),
        );
        assert_eq!(freshness.behind, Some(true));
        assert_eq!(freshness.commit_state, Some("behind"));
        assert_eq!(freshness.commits_behind, Some(486));
        let line = freshness.remediation.as_deref().unwrap();
        assert!(line.contains("behind: 486 commits"), "{line}");
        assert!(line.contains("0.3.23"), "{line}");
        let mut remediation = Vec::new();
        assert_eq!(
            freshness.apply_to_health("complete", &mut remediation),
            "behind"
        );
    }

    #[test]
    fn unknown_commit_or_distance_never_reports_current() {
        let no_commit = assess(
            "0.3.23",
            Some(("v0.3.23".into(), "git-tag")),
            Some("0.3.23".into()),
            None,
            Some(486),
        );
        assert_eq!(
            no_commit.behind, None,
            "a commit distance without an installed commit is ignored"
        );
        assert_eq!(no_commit.commits_behind, None);
        assert_eq!(no_commit.commit_state, Some("unknown"));
        let no_distance = assess(
            "0.3.23",
            Some(("v0.3.23".into(), "git-tag")),
            Some("0.3.23".into()),
            Some("14b630ca".into()),
            None,
        );
        assert_eq!(no_distance.behind, None);
        assert_eq!(no_distance.installed_commit.as_deref(), Some("14b630ca"));
        assert_eq!(no_distance.commit_state, Some("unknown"));
        assert_eq!(no_distance.remediation, None);
    }

    #[test]
    fn commit_distance_counts_even_when_the_version_is_unknown() {
        let freshness = assess("dev-build", None, None, Some("14b630ca".into()), Some(3));
        assert_eq!(freshness.behind, Some(true));
        assert_eq!(freshness.commit_state, Some("behind"));
        assert!(freshness
            .remediation
            .unwrap()
            .contains("behind: 3 commits to checkout HEAD"));
    }

    #[test]
    fn installed_commit_must_be_a_plain_hex_revision() {
        let manifest =
            |revision: Value| json!({"releaseVersion": "0.3.23", "sourceRevision": revision});
        let full = "4c1a414269d8ffdb95b4b1e685440bd34784b41b";
        assert_eq!(
            installed_commit_from_manifest(&manifest(json!(" 14b630ca9f1e "))),
            Some("14b630ca9f1e".to_owned())
        );
        assert_eq!(
            installed_commit_from_manifest(&manifest(json!(full))),
            Some(full.to_owned())
        );
        assert_eq!(
            installed_commit_from_manifest(&manifest(json!("14b630c"))),
            Some("14b630c".to_owned()),
            "seven digits is the shortest commit id"
        );
        for unknown in [
            json!(""),
            json!("14b630"),
            json!("14b630ca9f1e-dirty"),
            json!("--output=/tmp/x"),
            json!("HEAD~1"),
            json!("main"),
            json!(42),
            Value::Null,
        ] {
            let shown = unknown.to_string();
            assert_eq!(
                installed_commit_from_manifest(&manifest(unknown)),
                None,
                "{shown}"
            );
        }
        assert_eq!(
            installed_commit_from_manifest(&json!({"releaseVersion": "0.3.23"})),
            None
        );
        assert_eq!(
            installed_commit_from_manifest(&json!({"rightkitAx": {"sourceCommit": full}})),
            None,
            "the RightKit commit is not the Legion commit"
        );
    }

    #[test]
    fn commit_count_output_is_one_integer() {
        assert_eq!(parse_commit_count("486\n"), Some(486));
        assert_eq!(parse_commit_count("0"), Some(0));
        for bad in ["", "fatal: bad revision", "-3", "1 2"] {
            assert_eq!(parse_commit_count(bad), None, "{bad}");
        }
    }

    #[test]
    fn unknown_inputs_leave_behind_unknown() {
        for freshness in [
            assess("0.3.23", None, None, None, None),
            assess("0.3.23", None, Some("garbage".into()), None, None),
            assess(
                "dev-build",
                Some(("v9.9.9".into(), "git-tag")),
                None,
                None,
                None,
            ),
        ] {
            assert_eq!(freshness.behind, None);
            assert_eq!(freshness.remediation, None);
            assert_eq!(freshness.commit_state, Some("unknown"));
        }
    }

    #[test]
    fn behind_replaces_complete_and_keeps_stronger_statuses() {
        let behind = assess(
            "0.3.23",
            Some(("v0.3.24".into(), "git-tag")),
            None,
            None,
            None,
        );
        let mut remediation = vec!["something else".to_owned()];
        assert_eq!(
            behind.apply_to_health("complete", &mut remediation),
            "behind"
        );
        assert!(remediation[0].contains("0.3.24"));
        assert_eq!(remediation.len(), 2);

        let mut remediation = Vec::new();
        assert_eq!(
            behind.apply_to_health("incomplete", &mut remediation),
            "incomplete"
        );
        assert_eq!(remediation.len(), 1);

        let unknown = assess("0.3.23", None, None, None, None);
        let mut remediation = Vec::new();
        assert_eq!(
            unknown.apply_to_health("complete", &mut remediation),
            "complete"
        );
        assert!(remediation.is_empty());
    }

    #[test]
    fn fields_merge_into_the_status_object() {
        let mut status = json!({"kind": "legion-setup-status", "status": "complete"});
        assess(
            "0.3.23",
            Some(("v0.3.24".into(), "git-tag")),
            Some("0.3.25".into()),
            Some("14b630ca".into()),
            Some(486),
        )
        .merge_into(&mut status);
        assert_eq!(status["installedVersion"], "0.3.23");
        assert_eq!(status["latestRelease"], "v0.3.24");
        assert_eq!(status["latestReleaseSource"], "git-tag");
        assert_eq!(status["checkoutVersion"], "0.3.25");
        assert_eq!(status["installedCommit"], "14b630ca");
        assert_eq!(status["commitsBehind"], 486);
        assert_eq!(status["commitState"], "behind");
        assert_eq!(status["behind"], true);
        assert_eq!(
            status["status"], "complete",
            "merge never changes the status"
        );

        let mut failed = json!({"kind": "legion-setup-status", "status": "failed"});
        Freshness::default().merge_into(&mut failed);
        assert_eq!(failed["behind"], Value::Null);
        assert_eq!(failed["latestRelease"], Value::Null);
        assert_eq!(failed["installedVersion"], Value::Null);
        assert_eq!(failed["commitState"], Value::Null);
        assert_eq!(failed["commitsBehind"], Value::Null);
    }

    #[test]
    fn checkout_is_found_from_a_subdirectory_or_an_explicit_path() {
        let root = checkout("0.3.30");
        let nested = root.join("engine/bins");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            find_checkout(None, Some(nested.as_path())),
            Some(root.clone())
        );
        assert_eq!(
            find_checkout(Some(root.as_path()), None),
            Some(root.clone())
        );
        assert_eq!(read_checkout_version(&root).as_deref(), Some("0.3.30"));
        let elsewhere = temp_dir("elsewhere");
        assert_eq!(
            find_checkout(Some(elsewhere.as_path()), Some(nested.as_path())),
            None
        );
        assert_eq!(read_checkout_version(&elsewhere), None);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn switch_values_that_disable_the_check() {
        for off in ["off", "OFF", "0", "false", " no "] {
            assert!(release_check_disabled(Some(off)), "{off}");
        }
        for on in ["", "on", "1", "true"] {
            assert!(!release_check_disabled(Some(on)), "{on}");
        }
        assert!(!release_check_disabled(None));
    }

    #[tokio::test]
    async fn observe_uses_the_checkout_version_without_touching_git_or_the_network() {
        let root = checkout("9.9.9");
        let lookup = Lookup {
            enabled: true,
            checkout: Some(root.clone()),
            cwd: None,
            use_git: false,
            use_gh: false,
            installed_commit: Some("14b630ca".into()),
        };
        let freshness = observe_with("0.3.23", &lookup).await;
        assert_eq!(freshness.checkout_version.as_deref(), Some("9.9.9"));
        assert_eq!(freshness.latest_release, None);
        assert_eq!(freshness.behind, Some(true));
        assert_eq!(freshness.commits_behind, None, "git is not allowed");
        assert_eq!(freshness.commit_state, Some("unknown"));

        let disabled = Lookup {
            enabled: false,
            ..lookup
        };
        let freshness = observe_with("0.3.23", &disabled).await;
        assert_eq!(freshness.installed_version.as_deref(), Some("0.3.23"));
        assert_eq!(freshness.behind, None);
        assert_eq!(freshness.commit_state, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn observe_without_a_known_installed_commit_never_counts_commits() {
        let root = checkout("0.3.23");
        let lookup = Lookup {
            enabled: true,
            checkout: Some(root.clone()),
            cwd: None,
            use_git: true,
            use_gh: false,
            installed_commit: None,
        };
        let freshness = observe_with("0.3.23", &lookup).await;
        assert_eq!(freshness.commits_behind, None);
        assert_eq!(freshness.installed_commit, None);
        assert_eq!(freshness.commit_state, Some("unknown"));
        assert_eq!(freshness.behind, None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
