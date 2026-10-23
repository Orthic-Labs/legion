//! Audit-specific scope identity. Original Git state stays read-only. PR objects
//! enter an isolated bare store; no checkout, temporary index or project execution.
use crate::AuditError;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::mpsc,
    time::{Duration, Instant},
};

pub const SCOPE_SCHEMA_VERSION: u32 = 1;
pub const GIT_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;
fn invalid(message: impl Into<String>) -> AuditError {
    AuditError::Invalid(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum ScopeSpec {
    Repo,
    Local,
    Uncommitted,
    Staged,
    Committed,
    Revision(String),
    PullRequest(String),
    Branch(String),
    Range { base: String, head: String },
    SinceLast,
}
impl ScopeSpec {
    /// Legacy `uncommitted` deliberately retains unstaged-only semantics. Use
    /// `local` to include staged, unstaged & untracked bytes.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        Ok(match value {
            "all" | "repo" => Self::Repo,
            "local" => Self::Local,
            "uncommitted" => Self::Uncommitted,
            "staged" => Self::Staged,
            "committed" => Self::Committed,
            "since-last" => Self::SinceLast,
            "branch" => Self::Branch("@{upstream}".into()),
            _ if value.starts_with("commit:") => Self::Revision(reference(&value[7..])?),
            _ if value.starts_with("branch:") => Self::Branch(reference(&value[7..])?),
            _ if value.starts_with("range:") => {
                let (base, head) = value[6..]
                    .split_once("..")
                    .ok_or_else(|| invalid("range requires A..B"))?;
                if head.starts_with('.') {
                    return Err(invalid("three-dot ranges require branch:<base>"));
                }
                Self::Range {
                    base: reference(base)?,
                    head: if head == "WORKTREE" {
                        head.into()
                    } else {
                        reference(head)?
                    },
                }
            }
            _ if value.starts_with("pr:") => Self::PullRequest(pr_selector(&value[3..])?),
            _ => return Err(invalid(format!("unsupported Audit scope: {value}"))),
        })
    }
    pub fn label(&self) -> String {
        match self {
            Self::Repo => "repo".into(),
            Self::Local => "local".into(),
            Self::Uncommitted => "uncommitted".into(),
            Self::Staged => "staged".into(),
            Self::Committed => "committed".into(),
            Self::Revision(rev) => format!("commit:{rev}"),
            Self::PullRequest(pr) => format!("pr:{pr}"),
            Self::Branch(base) => format!("branch:{base}"),
            Self::Range { base, head } => format!("range:{base}..{head}"),
            Self::SinceLast => "since-last".into(),
        }
    }
    pub fn is_diff(&self) -> bool {
        !matches!(self, Self::Repo)
    }
}
fn reference(value: &str) -> Result<String, AuditError> {
    if value.is_empty()
        || value.starts_with('-')
        || value.contains('\0')
        || value.chars().any(char::is_whitespace)
        || value.contains(':')
    {
        return Err(invalid("invalid Git revision"));
    }
    Ok(value.into())
}

/// Read-only Git command owner. Every invocation has a deadline & bounded pipes;
/// RightKit owns process groups/jobs & terminates descendants on drop.
pub struct GitRunner {
    root: PathBuf,
    pub timeout: Duration,
    pub output_limit: usize,
}
impl GitRunner {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.into(),
            timeout: Duration::from_secs(30),
            output_limit: GIT_OUTPUT_LIMIT,
        }
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn run(&self, args: &[&str]) -> Result<Vec<u8>, AuditError> {
        if !matches!(
            args.first().copied(),
            Some(
                "rev-parse"
                    | "for-each-ref"
                    | "ls-tree"
                    | "ls-files"
                    | "cat-file"
                    | "diff"
                    | "merge-base"
                    | "status"
                    | "version"
                    | "check-ignore"
            )
        ) {
            return Err(invalid("Git scope command is not read-only allowlisted"));
        }
        if args.first().copied() == Some("diff") {
            let mut safe_args = vec![
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=all",
            ];
            safe_args.extend_from_slice(&args[1..]);
            self.invoke("git", &safe_args)
        } else {
            self.invoke("git", args)
        }
    }
    fn invoke(&self, executable: &str, args: &[&str]) -> Result<Vec<u8>, AuditError> {
        let mut command = if executable == "git" {
            // Trusted absolute git outside the audited root, scrubbed env and
            // config-execution denial; unavailable trusted git fails closed.
            crate::trusted_git::owned_command(&self.root)
                .ok_or_else(|| invalid("scope Git unavailable: no trusted git binary"))?
        } else {
            // Trusted absolute helper (never PATH/repo-local), scrubbed env that
            // admits only OS essentials, gh config location and gh token names.
            crate::trusted_git::owned_tool_command(
                &self.root,
                executable,
                &[
                    "SystemRoot",
                    "WINDIR",
                    "TMP",
                    "TEMP",
                    "HOME",
                    "USERPROFILE",
                    "APPDATA",
                    "LOCALAPPDATA",
                    "GH_CONFIG_DIR",
                    "GH_TOKEN",
                    "GITHUB_TOKEN",
                ],
            )
            .ok_or_else(|| invalid(format!("scope {executable} unavailable: no trusted binary")))?
        };
        command
            .command_mut()
            .current_dir(&self.root)
            .args(args)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| invalid(format!("scope Git spawn failed: {e}")))?;
        let (tx, rx) = mpsc::channel();
        for (stream, pipe) in [
            (
                0,
                child
                    .take_stdout()
                    .map(|p| Box::new(p) as Box<dyn Read + Send>),
            ),
            (
                1,
                child
                    .take_stderr()
                    .map(|p| Box::new(p) as Box<dyn Read + Send>),
            ),
        ] {
            let tx = tx.clone();
            let cap = self.output_limit;
            std::thread::spawn(move || {
                let result = match pipe {
                    Some(pipe) => {
                        let mut bytes = Vec::new();
                        pipe.take(cap as u64 + 1)
                            .read_to_end(&mut bytes)
                            .map(|_| bytes)
                    }
                    None => Ok(Vec::new()),
                };
                let _ = tx.send((stream, result));
            });
        }
        drop(tx);
        let deadline = Instant::now() + self.timeout;
        let mut streams = BTreeMap::new();
        for _ in 0..2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (stream, result) = rx
                .recv_timeout(remaining)
                .map_err(|_| invalid("scope Git deadline exceeded"))?;
            let bytes = result.map_err(|e| invalid(format!("scope Git read failed: {e}")))?;
            if bytes.len() > self.output_limit
                || streams.values().map(Vec::len).sum::<usize>() + bytes.len() > self.output_limit
            {
                return Err(invalid("scope Git output cap exceeded"));
            }
            streams.insert(stream, bytes);
        }
        let status = child
            .wait_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|e| invalid(format!("scope Git wait failed: {e}")))?
            .ok_or_else(|| invalid("scope Git deadline exceeded"))?;
        if !status.success() {
            return Err(invalid(format!(
                "scope Git {} failed ({}): {}",
                args[0],
                status,
                String::from_utf8_lossy(&streams[&1])
            )));
        }
        Ok(streams.remove(&0).unwrap_or_default())
    }
    pub fn text(&self, args: &[&str]) -> Result<String, AuditError> {
        String::from_utf8(self.run(args)?)
            .map_err(|_| invalid("non-UTF-8 Git metadata is unsupported"))
    }
    pub fn oid(&self, revision: &str) -> Result<String, AuditError> {
        reference(revision)?;
        let oid = self
            .text(&[
                "rev-parse",
                "--verify",
                "--end-of-options",
                &format!("{revision}^{{commit}}"),
            ])?
            .trim()
            .to_owned();
        if !valid_oid(&oid) {
            return Err(invalid("Git returned malformed commit OID"));
        }
        Ok(oid)
    }
    pub fn merge_base(&self, base: &str, head: &str) -> Result<String, AuditError> {
        let result = self.text(&["merge-base", "--all", base, head])?;
        let values: Vec<_> = result.lines().collect();
        if values.len() != 1 || !valid_oid(values[0]) {
            return Err(invalid("incomplete:ambiguous-or-missing-merge-base"));
        }
        Ok(values[0].into())
    }
}
pub fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn pr_selector(value: &str) -> Result<String, AuditError> {
    if value.parse::<u64>().is_ok_and(|n| n > 0) {
        return Ok(value.into());
    }
    let _ = github_pr_parts(value)?;
    Ok(value.into())
}
fn github_pr_parts(url: &str) -> Result<(String, String, String), AuditError> {
    let path = url
        .strip_prefix("https://github.com/")
        .ok_or_else(|| invalid("PR URL must use https://github.com/owner/repo/pull/number"))?;
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() != 4
        || parts[2] != "pull"
        || !parts[3].parse::<u64>().is_ok_and(|n| n > 0)
        || parts[..2].iter().any(|p| {
            p.is_empty()
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    {
        return Err(invalid("invalid canonical GitHub PR URL"));
    }
    Ok((parts[0].into(), parts[1].into(), parts[3].into()))
}
struct AcquiredPr {
    head_oid: String,
    base_oid: String,
    object_root: PathBuf,
}
fn acquire_pr(git: &GitRunner, selector: &str) -> Result<AcquiredPr, AuditError> {
    pr_selector(selector)?;
    let bytes = git
        .invoke(
            "gh",
            &[
                "pr",
                "view",
                selector,
                "--json",
                "baseRefOid,headRefOid,baseRefName,isCrossRepository,url",
            ],
        )
        .map_err(|e| invalid(format!("blocked:pr-acquisition:{e}")))?;
    let metadata: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| invalid("blocked:invalid-PR-metadata"))?;
    let field = |name: &str| {
        metadata
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid(format!("blocked:missing-PR-{name}")))
    };
    let head = field("headRefOid")?.to_owned();
    let base = field("baseRefOid")?.to_owned();
    if !valid_oid(&head) || !valid_oid(&base) {
        return Err(invalid("blocked:invalid-PR-OIDs"));
    }
    let (owner, repo, _) = github_pr_parts(field("url")?)?;
    let cache_root =
        crate::source_cache::audit_cache_root(&git.root).map_err(|e| invalid(e.to_string()))?;
    let cache = rightkit_fs::state::StateDir::create(&cache_root.join("audit-pr"))
        .map_err(|e| invalid(e.to_string()))?;
    let name = format!("{base}-{head}");
    let dir =
        crate::source_cache::cache_child(&cache, &name).map_err(|e| invalid(e.to_string()))?;
    // Construct a minimal bare store ourselves: an existing cache config may
    // contain credential helpers, URL rewrites or includes. Never let Git read
    // such repository-controlled configuration during network acquisition.
    const CONFIG: &[u8] = b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n";
    const HEAD: &[u8] = b"ref: refs/heads/audit-unborn\n";
    for (name, expected) in [("config", CONFIG), ("HEAD", HEAD)] {
        match dir
            .read_opt(name, 4096)
            .map_err(|e| invalid(e.to_string()))?
        {
            Some(bytes) if bytes != expected => {
                return Err(invalid("blocked:PR-object-store-configuration-changed"));
            }
            Some(_) => {}
            None => dir
                .write_new(name, expected)
                .map_err(|e| invalid(e.to_string()))?,
        }
    }
    // Git reopens these paths; use RightKit's identity-checked reopen rather than
    // retaining Windows child-creation DELETE handles across that boundary.
    let object_dir =
        crate::source_cache::cache_child(&dir, "objects").map_err(|e| invalid(e.to_string()))?;
    crate::source_cache::cache_child(&object_dir, "pack").map_err(|e| invalid(e.to_string()))?;
    let info = crate::source_cache::cache_child(&object_dir, "info")
        .map_err(|e| invalid(e.to_string()))?;
    crate::source_cache::cache_child(&dir, "refs").map_err(|e| invalid(e.to_string()))?;
    for name in ["alternates", "http-alternates"] {
        if info
            .read_opt(name, 4096)
            .map_err(|e| invalid(e.to_string()))?
            .is_some()
        {
            return Err(invalid("blocked:PR-object-store-alternates-forbidden"));
        }
    }
    let objects = GitRunner::new(dir.path());
    if objects.oid(&head).is_err() || objects.oid(&base).is_err() {
        // No destination refspec or FETCH_HEAD, even in isolated object storage.
        let url = format!("https://github.com/{owner}/{repo}.git");
        objects
            .invoke(
                "git",
                // The hardened launcher denies every transport; this one fetch,
                // into a store the audit built itself with global/system
                // config nulled, may use https to github.com only.
                &[
                    "-c",
                    "protocol.https.allow=always",
                    "fetch",
                    "--no-tags",
                    "--no-write-fetch-head",
                    "--refmap=",
                    "--no-recurse-submodules",
                    "--no-auto-maintenance",
                    "--",
                    &url,
                    &base,
                    &head,
                ],
            )
            .map_err(|e| invalid(format!("blocked:PR-objects-unavailable:{e}")))?;
    }
    if objects.oid(&head)? != head || objects.oid(&base)? != base {
        return Err(invalid("blocked:PR-object-identity-mismatch"));
    }
    Ok(AcquiredPr {
        head_oid: head,
        base_oid: base,
        object_root: dir.path().into(),
    })
}
pub fn safe_path(value: &str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains(':')
        || value.contains('\0')
        || Path::new(value)
            .components()
            .any(|p| !matches!(p, Component::Normal(_)))
        || value.split('/').any(|c| {
            c.eq_ignore_ascii_case(".git") || c.is_empty() || c.ends_with('.') || c.ends_with(' ')
        })
    {
        return Err(invalid(format!("unsafe snapshot path: {value:?}")));
    }
    Ok(())
}
pub fn excluded(path: &str) -> bool {
    path.split('/').any(|c| {
        matches!(
            c.to_ascii_lowercase().as_str(),
            ".git"
                | ".audit"
                | ".legion-cache"
                | "node_modules"
                | "target"
                | ".next"
                | "dist"
                | "build"
                | ".venv"
                | "__pycache__"
        )
    })
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitEntry {
    pub mode: String,
    pub oid: String,
}
pub fn tree_entries(
    git: &GitRunner,
    revision: &str,
) -> Result<BTreeMap<String, GitEntry>, AuditError> {
    let bytes = git.run(&["ls-tree", "-rz", "--full-tree", revision])?;
    parse_entries(&bytes, false)
}
pub fn index_entries(git: &GitRunner) -> Result<BTreeMap<String, GitEntry>, AuditError> {
    parse_entries(&git.run(&["ls-files", "--stage", "-z"])?, true)
}
fn parse_entries(bytes: &[u8], index: bool) -> Result<BTreeMap<String, GitEntry>, AuditError> {
    let mut result = BTreeMap::new();
    for row in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let row =
            std::str::from_utf8(row).map_err(|_| invalid("non-UTF-8 paths are unsupported"))?;
        let (meta, path) = row
            .split_once('\t')
            .ok_or_else(|| invalid("malformed Git entry"))?;
        safe_path(path)?;
        if excluded(path) {
            continue;
        }
        let parts: Vec<_> = meta.split(' ').collect();
        if parts.len() != 3 {
            return Err(invalid("malformed Git entry metadata"));
        }
        if index && parts[2] != "0" {
            return Err(invalid("incomplete:unmerged-index"));
        }
        let oid = parts[if index { 1 } else { 2 }];
        if !valid_oid(oid) {
            return Err(invalid("malformed blob OID"));
        }
        if result
            .insert(
                path.into(),
                GitEntry {
                    mode: parts[0].into(),
                    oid: oid.into(),
                },
            )
            .is_some()
        {
            return Err(invalid("duplicate Git path"));
        }
    }
    Ok(result)
}
pub fn names(bytes: &[u8]) -> Result<BTreeSet<String>, AuditError> {
    let mut result = BTreeSet::new();
    for path in bytes.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let path = std::str::from_utf8(path).map_err(|_| invalid("non-UTF-8 paths unsupported"))?;
        safe_path(path)?;
        if !excluded(path) {
            result.insert(path.into());
        }
    }
    Ok(result)
}
fn filtered_status(bytes: &[u8]) -> Result<Vec<String>, AuditError> {
    let mut result = Vec::new();
    let mut rows = bytes.split(|b| *b == 0);
    while let Some(row) = rows.next().filter(|r| !r.is_empty()) {
        let text =
            std::str::from_utf8(row).map_err(|_| invalid("non-UTF-8 status path unsupported"))?;
        let fields = match row[0] {
            b'1' => 8,
            b'2' => 9,
            b'u' => return Err(invalid("incomplete:unmerged-index")),
            b'?' | b'!' => 1,
            _ => return Err(invalid("malformed porcelain-v2 status")),
        };
        let path = text
            .splitn(fields + 1, ' ')
            .nth(fields)
            .ok_or_else(|| invalid("malformed status entry"))?;
        safe_path(path)?;
        if row[0] == b'2' {
            let original = rows
                .next()
                .ok_or_else(|| invalid("missing rename source"))?;
            let original = std::str::from_utf8(original).map_err(io_status)?;
            safe_path(original)?;
            if !excluded(original) {
                result.push(format!("rename-source:{original}"));
            }
        }
        if !excluded(path) {
            result.push(text.into());
        }
    }
    result.sort();
    Ok(result)
}
fn io_status(error: std::str::Utf8Error) -> AuditError {
    invalid(error.to_string())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedScope {
    pub schema_version: u32,
    pub spec: ScopeSpec,
    pub source_root: PathBuf,
    pub object_root: Option<PathBuf>,
    pub head_oid: String,
    pub head_kind: String,
    pub selected_oid: String,
    pub base_ref_oid: Option<String>,
    pub merge_base_oid: Option<String>,
    pub baseline_oid: Option<String>,
    pub changed_paths: BTreeSet<String>,
    pub path_prefix: Option<String>,
    pub notices: Vec<String>,
    pub selected_entries: BTreeMap<String, GitEntry>,
    pub baseline_entries: BTreeMap<String, GitEntry>,
    pub index_digest: String,
    pub status_digest: String,
    pub git_version: String,
    pub untracked_paths: BTreeSet<String>,
}
impl ResolvedScope {
    pub fn resolve(
        root: &Path,
        spec: ScopeSpec,
        prefix: Option<String>,
    ) -> Result<Self, AuditError> {
        if let Some(path) = &prefix {
            safe_path(path)?;
        }
        let root = std::fs::canonicalize(root).map_err(|e| invalid(format!("scope root: {e}")))?;
        let git = GitRunner::new(&root);
        let top = PathBuf::from(git.text(&["rev-parse", "--show-toplevel"])?.trim());
        if std::fs::canonicalize(top).map_err(|e| invalid(e.to_string()))? != root {
            return Err(invalid(
                "Audit snapshot root must be repository top-level; use --dir for path scope",
            ));
        }
        let head = git.oid("HEAD")?;
        let index = index_entries(&git)?;
        let index_digest = crate::digest(&index)?;
        // `--ignore-submodules=all`: git never runs status inside a submodule
        // (whose own filter config is not neutralized); the gitlink itself is
        // covered by the index digest above.
        let status_digest = crate::digest(&filtered_status(&git.run(&[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
        ])?)?)?;
        let untracked_paths =
            names(&git.run(&["ls-files", "--others", "--exclude-standard", "-z"])?)?;
        let mut selected = head.clone();
        let mut kind = "worktree";
        let mut base_ref = None;
        let mut merge = None;
        let mut baseline = None;
        let mut notices = Vec::new();
        let mut object_root = None;
        match &spec {
            ScopeSpec::Repo => {}
            ScopeSpec::Local => {
                if let Ok(upstream) = git.oid("@{upstream}") {
                    let mb = git.merge_base(&upstream, &head)?;
                    base_ref = Some(upstream);
                    merge = Some(mb.clone());
                    baseline = Some(mb);
                } else {
                    baseline = Some(head.clone());
                    notices.push("local has no upstream; baseline is pinned HEAD".into());
                }
            }
            ScopeSpec::Uncommitted => {
                notices.push("uncommitted retains worktree-only unstaged semantics; local includes index & untracked changes".into());
            }
            ScopeSpec::Staged => {
                kind = "index";
                baseline = Some(head.clone());
            }
            ScopeSpec::Committed | ScopeSpec::Revision(_) => {
                kind = "commit";
                if let ScopeSpec::Revision(rev) = &spec {
                    selected = git.oid(rev)?;
                }
                // A root commit has no parent. Distinguish that fact from a
                // failed object read: only an actual parentless commit selects
                // the empty baseline.
                let commit = git.run(&["cat-file", "commit", &selected])?;
                for header in commit
                    .split(|byte| *byte == b'\n')
                    .take_while(|line| !line.is_empty())
                {
                    if let Some(parent) = header.strip_prefix(b"parent ") {
                        let parent = std::str::from_utf8(parent)
                            .map_err(|_| invalid("malformed commit parent OID"))?;
                        if !valid_oid(parent) {
                            return Err(invalid("malformed commit parent OID"));
                        }
                        baseline = Some(git.oid(parent)?);
                        break;
                    }
                }
            }
            ScopeSpec::Branch(base) => {
                // Branch review means committed HEAD against merge-base.
                // Dirty bytes require local or explicit range:A..WORKTREE.
                kind = "commit";
                let oid = git.oid(base)?;
                let mb = git.merge_base(&oid, &head)?;
                base_ref = Some(oid);
                merge = Some(mb.clone());
                baseline = Some(mb);
            }
            ScopeSpec::Range { base, head: target } => {
                baseline = Some(git.oid(base)?);
                if target != "WORKTREE" {
                    selected = git.oid(target)?;
                    kind = "commit";
                }
            }
            ScopeSpec::PullRequest(selector) => {
                let acquired = acquire_pr(&git, selector)?;
                selected = acquired.head_oid;
                kind = "commit";
                let objects = GitRunner::new(&acquired.object_root);
                let mb = objects.merge_base(&acquired.base_oid, &selected)?;
                base_ref = Some(acquired.base_oid);
                merge = Some(mb.clone());
                baseline = Some(mb);
                object_root = Some(acquired.object_root);
                notices.push(format!(
                    "PR head pinned once:{selected}; no original refs/index/FETCH_HEAD mutated"
                ));
            }
            ScopeSpec::SinceLast => {
                let last = crate::snapshot::read_last_completed(&root)?
                    .ok_or_else(|| invalid("since-last has no validated completed report"))?;
                let old = git.oid(&last.head_oid)?;
                let mb = git.merge_base(&old, &head)?;
                if mb != old {
                    notices.push(
                        "since-last head is not ancestor; using explicit merge-base fallback"
                            .into(),
                    );
                    merge = Some(mb.clone());
                }
                base_ref = Some(old);
                baseline = Some(mb);
            }
        }
        let object_git = GitRunner::new(object_root.as_deref().unwrap_or(&root));
        let mut entries = if kind == "index" {
            index.clone()
        } else {
            tree_entries(&object_git, &selected)?
        };
        // Stage-0 additions are tracked & therefore absent from `--others`,
        // while not yet present in HEAD. Worktree context must include both.
        if kind == "worktree" {
            entries.extend(index.clone());
        }
        let baseline_entries = if matches!(spec, ScopeSpec::Uncommitted) {
            index
        } else if let Some(oid) = &baseline {
            tree_entries(&object_git, oid)?
        } else {
            BTreeMap::new()
        };
        let mut changed = if !spec.is_diff() {
            BTreeSet::new()
        } else if matches!(spec, ScopeSpec::Staged) {
            names(&git.run(&[
                "diff",
                "--cached",
                "--name-only",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                &head,
                "--",
            ])?)?
        } else if matches!(spec, ScopeSpec::Uncommitted) {
            names(&git.run(&[
                "diff",
                "--name-only",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                "--",
            ])?)?
        } else if kind == "commit" && baseline.is_none() {
            entries.keys().cloned().collect()
        } else {
            let base = baseline
                .as_deref()
                .ok_or_else(|| invalid("diff baseline missing"))?;
            let mut args = vec![
                "diff",
                "--name-only",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                base,
            ];
            if kind == "commit" {
                args.push(&selected);
            }
            args.push("--");
            names(&object_git.run(&args)?)?
        };
        if matches!(
            spec,
            ScopeSpec::Local | ScopeSpec::SinceLast | ScopeSpec::Range { .. }
        ) && kind == "worktree"
        {
            changed.extend(names(&git.run(&[
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
            ])?)?);
        }
        if let Some(prefix) = &prefix {
            changed.retain(|p| p == prefix || p.starts_with(&format!("{prefix}/")));
        }
        Ok(Self {
            schema_version: SCOPE_SCHEMA_VERSION,
            spec,
            source_root: root,
            object_root,
            head_oid: head,
            head_kind: kind.into(),
            selected_oid: selected,
            base_ref_oid: base_ref,
            merge_base_oid: merge,
            baseline_oid: baseline,
            changed_paths: changed,
            path_prefix: prefix,
            notices,
            selected_entries: entries,
            baseline_entries,
            index_digest,
            status_digest,
            untracked_paths,
            git_version: git.text(&["version"])?.trim().into(),
        })
    }
    pub fn inventory_filter(&self) -> Option<BTreeSet<String>> {
        if self.spec.is_diff() {
            Some(self.changed_paths.clone())
        } else {
            self.path_prefix.as_ref().map(|prefix| {
                self.selected_entries
                    .keys()
                    .chain(self.untracked_paths.iter())
                    .filter(|p| *p == prefix || p.starts_with(&format!("{prefix}/")))
                    .cloned()
                    .collect()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grammar_rejects_ambiguous_or_unsafe_inputs() {
        assert!(ScopeSpec::parse("range:main...HEAD").is_err());
        assert!(ScopeSpec::parse("commit:--output=/tmp/x").is_err());
        assert!(ScopeSpec::parse("pr:42").is_ok());
        assert!(ScopeSpec::parse("pr:https://evil.test/a/b/pull/42").is_err());
        for path in [
            "../escape",
            "/tmp/x",
            "a/../../x",
            "a/.git/config",
            "C:/x",
            "a//x",
            "a\\x",
        ] {
            assert!(safe_path(path).is_err(), "{path}");
        }
    }
    #[test]
    fn unmerged_entries_are_never_silently_selected() {
        let oid = "1".repeat(40);
        assert!(parse_entries(format!("100644 {oid} 2\ta.rs\0").as_bytes(), true).is_err());
    }
    #[test]
    fn output_dirs_never_perturb_source_status_identity() {
        let rows = b"? .audit/report.json\0? .legion-cache/audit-snapshots/file\0? src/new.rs\0";
        assert_eq!(filtered_status(rows).unwrap(), vec!["? src/new.rs"]);
    }
    #[test]
    fn nul_names_preserve_spaces_newlines_and_deletions() {
        assert_eq!(
            names(b"removed.rs\0with space.rs\0with\nnewline.rs\0.audit/report.json\0")
                .unwrap()
                .len(),
            3
        );
    }
}
