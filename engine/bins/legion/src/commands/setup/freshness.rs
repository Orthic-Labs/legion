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
        Self {
            enabled: true,
            checkout: None,
            cwd: std::env::current_dir().ok(),
            use_git: true,
            use_gh: true,
            installed_commit: installed_source_commit(),
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
