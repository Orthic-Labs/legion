//! Object-only closure snapshots. Expected result trees must be computed from the
//! exact baseline + patch separately before admission; a worktree is never a source.
use rightkit_child_process::OwnedCommand;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const STREAM_CAP: usize = 16 * 1024 * 1024;
const CONTEXT_CAP: usize = 256 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "path", rename_all = "snake_case")]
pub enum Selector {
    Path(String),
    Tree(String),
}

impl Selector {
    fn path(&self) -> &str {
        match self {
            Self::Path(p) | Self::Tree(p) => p,
        }
    }
    fn kind(&self) -> &str {
        match self {
            Self::Path(_) => "path",
            Self::Tree(_) => "tree",
        }
    }
    fn selects(&self, path: &str) -> bool {
        path == self.path() || matches!(self, Self::Tree(_)) && descendant(path, self.path())
    }
}

fn descendant(path: &str, parent: &str) -> bool {
    path.strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.eq_ignore_ascii_case(".git"))
    {
        return Err(format!("noncanonical closure path: {path:?}"));
    }
    Ok(())
}

pub fn canonical_selectors(selectors: &[Selector]) -> Result<Vec<Selector>, String> {
    if selectors.is_empty() {
        return Err("closure needs at least one selector".into());
    }
    for selector in selectors {
        validate_path(selector.path())?;
    }
    let mut result = selectors.to_vec();
    result.sort();
    result.dedup();
    Ok(result)
}

fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
fn finish(hash: Sha256) -> String {
    hex::encode(hash.finalize())
}

pub fn exact_patch_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn definition_digest(selectors: &[Selector]) -> Result<String, String> {
    let mut hash = Sha256::new();
    frame(&mut hash, b"legion-closure-definition-v1");
    for selector in canonical_selectors(selectors)? {
        frame(&mut hash, selector.kind().as_bytes());
        frame(&mut hash, selector.path().as_bytes());
    }
    Ok(finish(hash))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub source_oid: String,
    pub tree_oid: String,
    pub closure_digest: String,
    pub definition_digest: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ReviewFile {
    pub path: String,
    pub mode: String,
    pub content: String,
}

pub struct GitRepository {
    pub root: PathBuf,
    binary: PathBuf,
    object_directory: Option<PathBuf>,
    primary_objects: PathBuf,
    /// Native consume supplies one absolute budget for open + every blob read.
    absolute_deadline: Option<Instant>,
}

fn command_deadline(absolute: Option<Instant>, now: Instant) -> Result<Instant, String> {
    let deadline = absolute.map_or(now + GIT_TIMEOUT, |end| end.min(now + GIT_TIMEOUT));
    if deadline <= now {
        return Err("Git shared authorization deadline exhausted".into());
    }
    Ok(deadline)
}

fn full_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn zero_oid(value: &str) -> bool {
    full_oid(value) && value.bytes().all(|b| b == b'0')
}

fn bounded_reader<R: Read + Send + 'static>(
    input: R,
    cap: usize,
) -> mpsc::Receiver<Result<Vec<u8>, String>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = input
            .take(cap as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())
            .and_then(|_| {
                if bytes.len() > cap {
                    Err(format!("Git stream exceeded {cap} byte cap"))
                } else {
                    Ok(bytes)
                }
            });
        let _ = tx.send(result);
    });
    rx
}

fn receive<T>(
    rx: mpsc::Receiver<Result<T, String>>,
    deadline: Instant,
    stream: &str,
) -> Result<T, String> {
    rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| format!("Git {stream} did not complete before operation deadline"))?
        .map_err(|e| format!("Git {stream}: {e}"))
}

impl GitRepository {
    /// Canonical enrolled repository objects, never candidate scratch objects.
    pub fn object_directory(&self) -> &Path {
        &self.primary_objects
    }

    pub fn open(path: &Path) -> Result<Self, String> {
        Self::open_with_binary(path, Path::new("/usr/bin/git"))
    }

    pub fn open_with_binary(path: &Path, binary: &Path) -> Result<Self, String> {
        Self::open_with_deadline(path, binary, None)
    }

    pub fn open_with_binary_before(
        path: &Path,
        binary: &Path,
        deadline: Instant,
    ) -> Result<Self, String> {
        Self::open_with_deadline(path, binary, Some(deadline))
    }

    fn open_with_deadline(
        path: &Path,
        binary: &Path,
        absolute_deadline: Option<Instant>,
    ) -> Result<Self, String> {
        command_deadline(absolute_deadline, Instant::now())?;
        if !binary.is_absolute() || !binary.is_file() {
            return Err("Git binary must be pinned absolute file".into());
        }
        let root = path.canonicalize().map_err(|e| e.to_string())?;
        let binary = binary.canonicalize().map_err(|e| e.to_string())?;
        let mut repo = Self {
            root,
            binary,
            object_directory: None,
            primary_objects: PathBuf::new(),
            absolute_deadline,
        };
        let top = repo.git(&["rev-parse", "--show-toplevel"])?;
        let top = line(&top)?;
        if top.chars().any(char::is_control) {
            return Err("invalid repository root".into());
        }
        let top = Path::new(top).canonicalize().map_err(|e| e.to_string())?;
        if repo.root != top {
            return Err("source path must be repository root".into());
        }
        let objects = repo.git(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ])?;
        repo.primary_objects = Path::new(line(&objects)?)
            .canonicalize()
            .map_err(|e| e.to_string())?;
        repo.ensure_remaining()?;
        Ok(repo)
    }

    fn ensure_remaining(&self) -> Result<(), String> {
        command_deadline(self.absolute_deadline, Instant::now()).map(|_| ())
    }

    /// Use an existing, root-owned scratch object store; inherit primary objects
    /// only as alternates. Caller computes candidate tree from exact patch first.
    pub fn with_object_directory(mut self, path: &Path) -> Result<Self, String> {
        let canonical = path.canonicalize().map_err(|e| e.to_string())?;
        if !path.is_absolute()
            || canonical != path
            || !canonical.is_dir()
            || canonical.starts_with(&self.root)
            || canonical == self.primary_objects
        {
            return Err(
                "scratch object directory must be canonical, absolute & outside repository".into(),
            );
        }
        for p in [&canonical, &self.primary_objects] {
            let text = p.to_str().ok_or("non-UTF8 object directory")?;
            if text.chars().any(char::is_control) || (!cfg!(windows) && text.contains(':')) {
                return Err("unsafe object directory".into());
            }
        }
        self.object_directory = Some(canonical);
        Ok(self)
    }

    fn git(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        self.git_with_input(args, None, None)
    }

    /// Internal broker data operations only; never expose this as a generic RPC.
    pub(crate) fn git_with_input(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
        index: Option<&Path>,
    ) -> Result<Vec<u8>, String> {
        let deadline = command_deadline(self.absolute_deadline, Instant::now())?;
        let allowed = match args {
            ["rev-parse", "--show-toplevel"]
            | ["rev-parse", "--path-format=absolute", "--git-path", "objects"] => true,
            ["rev-parse", "--verify", "--end-of-options", value] => {
                full_oid(value) || value.strip_suffix("^{tree}").is_some_and(full_oid)
            }
            ["cat-file", "-t" | "-s" | "blob", oid] => full_oid(oid),
            ["ls-tree", "-r", "-t", "-z", "--full-tree", oid] => full_oid(oid),
            ["read-tree", oid] => full_oid(oid) && index.is_some(),
            ["write-tree"] => index.is_some(),
            ["apply", "--cached", "--check", "--binary", "-"]
            | ["apply", "--cached", "--binary", "-"] => index.is_some() && input.is_some(),
            _ => false,
        };
        if !allowed || input.is_some_and(|b| b.len() > STREAM_CAP) {
            return Err("unsupported or oversized Git data operation".into());
        }
        let mut owned = OwnedCommand::new(&self.binary);
        owned.env_allowlist(["SystemRoot", "WINDIR"]);
        owned.windows_hide();
        let command = owned.command_mut();
        if let Some(index) = index {
            let objects = self
                .object_directory
                .as_ref()
                .ok_or("scratch index requires scratch object directory")?;
            let parent = index.parent().ok_or("scratch index needs parent")?;
            if !index.is_absolute()
                || parent.canonicalize().map_err(|e| e.to_string())? != parent
                || objects.parent() != Some(parent)
                || index.file_name().is_none()
                || index
                    .symlink_metadata()
                    .is_ok_and(|m| !m.file_type().is_file())
            {
                return Err(
                    "index must be regular file in configured scratch object sibling".into(),
                );
            }
            command.env("GIT_INDEX_FILE", index);
        }
        let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
        if let Some(objects) = &self.object_directory {
            command
                .env("GIT_OBJECT_DIRECTORY", objects)
                .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", &self.primary_objects);
        }
        command
            .current_dir(&self.root)
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .args([
                "--no-replace-objects",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "protocol.allow=never",
                "-c",
                "core.splitIndex=false",
                "-c",
                "core.sparseCheckout=false",
                "-c",
                "index.sparse=false",
                "-c",
                "gc.auto=0",
                "-c",
                "core.filemode=true",
                "-c",
                "apply.ignoreWhitespace=false",
                "-c",
                "apply.whitespace=nowarn",
                "-c",
            ])
            .arg(format!(
                "safe.directory={}",
                self.root.to_str().ok_or("non-UTF8 repository root")?
            ))
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if Instant::now() >= deadline {
            return Err("Git authorization deadline exhausted before spawn".into());
        }
        let mut child = owned
            .spawn()
            .map_err(|e| format!("Git data spawn failed: {e}"))?;
        let stdout = bounded_reader(
            child.take_stdout().ok_or("Git stdout unavailable")?,
            STREAM_CAP,
        );
        let stderr = bounded_reader(
            child.take_stderr().ok_or("Git stderr unavailable")?,
            STREAM_CAP,
        );
        let writer = if let Some(bytes) = input {
            let mut stdin = child.take_stdin().ok_or("Git stdin unavailable")?;
            let bytes = bytes.to_vec();
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let _ = tx.send(stdin.write_all(&bytes).map_err(|e| e.to_string()));
            });
            Some(rx)
        } else {
            None
        };
        let status = child
            .wait_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|e| format!("Git wait failed: {e}"))?
            .ok_or("Git data operation timed out before bounded deadline")?;
        let out = receive(stdout, deadline, "stdout")?;
        let err = receive(stderr, deadline, "stderr")?;
        if let Some(writer) = writer {
            receive(writer, deadline, "stdin")?;
        }
        if !status.success() {
            return Err(format!(
                "Git {} failed: {}",
                args[0],
                String::from_utf8_lossy(&err).trim()
            ));
        }
        self.ensure_remaining()?;
        Ok(out)
    }

    fn source_entries(
        &self,
        source: &str,
    ) -> Result<(String, String, BTreeMap<String, Entry>), String> {
        if !full_oid(source) || zero_oid(source) {
            return Err("source needs full nonzero object ID".into());
        }
        let source = source.to_ascii_lowercase();
        let resolved = self.git(&["rev-parse", "--verify", "--end-of-options", &source])?;
        if line(&resolved)? != source {
            return Err("source object ID is abbreviated or ambiguous".into());
        }
        let source_type = self.git(&["cat-file", "-t", &source])?;
        if !matches!(line(&source_type)?, "commit" | "tree" | "tag") {
            return Err("source is not a tree-ish object".into());
        }
        let tree = self.git(&[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{source}^{{tree}}"),
        ])?;
        let tree = line(&tree)?.to_owned();
        if !full_oid(&tree) || zero_oid(&tree) {
            return Err("invalid resolved tree ID".into());
        }
        let listing = self.git(&["ls-tree", "-r", "-t", "-z", "--full-tree", &tree])?;
        let entries = parse_listing(&listing)?;
        self.ensure_remaining()?;
        Ok((source, tree, entries))
    }

    /// Accept only full immutable IDs, avoiding ref ambiguity, rev syntax & races.
    pub fn snapshot(&self, source: &str, selectors: &[Selector]) -> Result<Snapshot, String> {
        let (source, tree, entries) = self.source_entries(source)?;
        let selectors = canonical_selectors(selectors)?;
        validate_selection(&entries, &selectors)?;
        let definition_digest = definition_digest(&selectors)?;
        let mut hash = Sha256::new();
        frame(&mut hash, b"legion-closure-snapshot-v1");
        frame(&mut hash, definition_digest.as_bytes());
        for selector in &selectors {
            let exists = entries.contains_key(selector.path());
            frame(&mut hash, if exists { b"present" } else { b"missing" });
            frame(&mut hash, selector.kind().as_bytes());
            frame(&mut hash, selector.path().as_bytes());
        }
        for (path, entry) in &entries {
            self.ensure_remaining()?;
            if !selectors.iter().any(|s| s.selects(path)) {
                continue;
            }
            frame(&mut hash, path.as_bytes());
            frame(&mut hash, entry.mode.as_bytes());
            frame(&mut hash, entry.kind.as_bytes());
            if entry.kind == "blob" {
                frame(&mut hash, entry.oid.as_bytes());
                frame(&mut hash, &self.git(&["cat-file", "blob", &entry.oid])?);
            }
        }
        self.ensure_remaining()?;
        Ok(Snapshot {
            source_oid: source,
            tree_oid: tree,
            closure_digest: finish(hash),
            definition_digest,
        })
    }

    /// Full selected source context, including unchanged files. Binary content
    /// cannot enter a text reviewer packet; each side is bounded to 256 KiB.
    pub fn review_files(
        &self,
        source: &str,
        selectors: &[Selector],
    ) -> Result<Vec<ReviewFile>, String> {
        let (_, _, entries) = self.source_entries(source)?;
        let selectors = canonical_selectors(selectors)?;
        validate_selection(&entries, &selectors)?;
        let mut result = Vec::new();
        let mut total = 0usize;
        for (path, entry) in entries {
            self.ensure_remaining()?;
            if entry.kind != "blob" || !selectors.iter().any(|s| s.selects(&path)) {
                continue;
            }
            let size = self.git(&["cat-file", "-s", &entry.oid])?;
            let size: usize = line(&size)?.parse().map_err(|_| "invalid Git blob size")?;
            total = total
                .checked_add(size)
                .and_then(|n| n.checked_add(path.len() + entry.mode.len()))
                .ok_or("review context size overflow")?;
            if total > CONTEXT_CAP {
                return Err("frozen review source exceeds 256 KiB per side".into());
            }
            let bytes = self.git(&["cat-file", "blob", &entry.oid])?;
            if bytes.len() != size || bytes.contains(&0) {
                return Err(format!("unsupported binary or changing Git blob: {path}"));
            }
            let content =
                String::from_utf8(bytes).map_err(|_| format!("non-UTF8 review source: {path}"))?;
            result.push(ReviewFile {
                path,
                mode: entry.mode,
                content,
            });
        }
        self.ensure_remaining()?;
        Ok(result)
    }
}

fn line(bytes: &[u8]) -> Result<&str, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "non-UTF8 git output")?;
    let value = text.strip_suffix('\n').unwrap_or(text);
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err("invalid git output line".into());
    }
    Ok(value)
}

struct Entry {
    mode: String,
    kind: String,
    oid: String,
}
fn validate_selection(
    entries: &BTreeMap<String, Entry>,
    selectors: &[Selector],
) -> Result<(), String> {
    for (path, entry) in entries {
        if selectors.iter().any(|s| descendant(s.path(), path))
            && (entry.mode != "040000" || entry.kind != "tree")
        {
            return Err(format!("closure ancestor is not a tree: {path}"));
        }
        if selectors.iter().any(|s| s.selects(path)) {
            validate_entry(path, entry, selectors)?;
        }
    }
    Ok(())
}
fn validate_entry(path: &str, entry: &Entry, selectors: &[Selector]) -> Result<(), String> {
    match (entry.mode.as_str(), entry.kind.as_str()) {
        ("040000", "tree")
            if !selectors
                .iter()
                .any(|s| matches!(s, Selector::Path(p) if p == path)) =>
        {
            Ok(())
        }
        ("100644" | "100755", "blob")
            if !selectors
                .iter()
                .any(|s| matches!(s, Selector::Tree(p) if p == path)) =>
        {
            Ok(())
        }
        _ => Err(format!(
            "unsupported closure entry or selector type (symlink/gitlink/tree/blob): {path}"
        )),
    }
}
fn parse_listing(bytes: &[u8]) -> Result<BTreeMap<String, Entry>, String> {
    if !bytes.is_empty() && !bytes.ends_with(&[0]) {
        return Err("unterminated tree listing".into());
    }
    let mut entries = BTreeMap::new();
    for record in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let record = std::str::from_utf8(record).map_err(|_| "non-UTF8 tree path")?;
        let (header, path) = record.split_once('\t').ok_or("invalid tree record")?;
        validate_path(path)?;
        let fields: Vec<_> = header.split(' ').collect();
        if fields.len() != 3 || !full_oid(fields[2]) || zero_oid(fields[2]) {
            return Err("invalid tree entry header".into());
        }
        if entries
            .insert(
                path.to_owned(),
                Entry {
                    mode: fields[0].into(),
                    kind: fields[1].into(),
                    oid: fields[2].into(),
                },
            )
            .is_some()
        {
            return Err("duplicate tree path".into());
        }
    }
    Ok(entries)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushUpdate {
    pub local_ref: String,
    pub local_oid: String,
    pub remote_ref: String,
    pub remote_oid: String,
}

fn valid_ref(value: &str) -> bool {
    value.starts_with("refs/")
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("@{")
        && !value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "~^:?*[\\".contains(c))
        && value
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

pub fn parse_pre_push(bytes: &[u8]) -> Result<Vec<PushUpdate>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "non-UTF8 pre-push input")?;
    let mut updates = Vec::new();
    let mut remotes = BTreeSet::new();
    for record in text.lines() {
        let fields: Vec<_> = record.split(' ').collect();
        if fields.len() != 4
            || !full_oid(fields[1])
            || !full_oid(fields[3])
            || fields[1].len() != fields[3].len()
            || !valid_ref(fields[2])
            || !remotes.insert(fields[2].to_owned())
            || !(valid_ref(fields[0]) || fields[0] == "(delete)" && zero_oid(fields[1]))
            || zero_oid(fields[1]) && fields[0] != "(delete)"
            || zero_oid(fields[1]) && zero_oid(fields[3])
        {
            return Err("invalid or duplicate pre-push update".into());
        }
        updates.push(PushUpdate {
            local_ref: fields[0].into(),
            local_oid: fields[1].to_ascii_lowercase(),
            remote_ref: fields[2].into(),
            remote_oid: fields[3].to_ascii_lowercase(),
        });
    }
    Ok(updates)
}

/// Frozen pushes deny deletions until caller provides a separate explicit policy.
pub fn outgoing_tips(updates: &[PushUpdate]) -> Result<Vec<String>, String> {
    if updates.is_empty() {
        return Err("frozen push needs at least one outgoing tip".into());
    }
    if updates.iter().any(|u| zero_oid(&u.local_oid)) {
        return Err("frozen push deletion requires explicit disposition".into());
    }
    Ok(updates
        .iter()
        .map(|u| u.local_oid.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn git_operations_share_absolute_budget_without_renewing_per_blob() {
        let start = Instant::now();
        let end = start + Duration::from_secs(1);
        assert_eq!(command_deadline(Some(end), start).unwrap(), end);
        assert_eq!(
            command_deadline(Some(end), start + Duration::from_millis(900)).unwrap(),
            end
        );
        assert!(command_deadline(Some(end), end).is_err());
        assert!(command_deadline(Some(end), end + Duration::from_secs(1)).is_err());
        assert_eq!(command_deadline(None, start).unwrap(), start + GIT_TIMEOUT);
        assert_eq!(
            command_deadline(Some(start + GIT_TIMEOUT * 2), start).unwrap(),
            start + GIT_TIMEOUT
        );
    }
    #[test]
    fn expired_open_is_rejected_before_paths_or_git_can_be_accessed() {
        let expired = Instant::now() - Duration::from_secs(1);
        let result = GitRepository::open_with_binary_before(
            Path::new("/nonexistent-legion-deadline-repository"),
            Path::new("/nonexistent-legion-deadline-git"),
            expired,
        );
        assert!(
            matches!(result, Err(error) if error.contains("shared authorization deadline exhausted"))
        );
    }
    #[test]
    fn canonical_paths_and_definitions() {
        for p in [
            "", "/x", "x/", ".", "a/../b", "a/.git/b", "C:/x", "a\\b", "a\tb",
        ] {
            assert!(
                canonical_selectors(&[Selector::Path(p.into())]).is_err(),
                "{p:?}"
            );
        }
        let a = Selector::Path("a b".into());
        assert_eq!(
            definition_digest(&[a.clone(), a.clone()]).unwrap(),
            definition_digest(&[a.clone()]).unwrap()
        );
        assert_ne!(
            definition_digest(&[a]).unwrap(),
            definition_digest(&[Selector::Tree("a b".into())]).unwrap()
        );
        assert!(!Selector::Tree("dir".into()).selects("directory/a"));
        assert_ne!(exact_patch_digest(b"x\n"), exact_patch_digest(b"x"));
        assert_eq!(
            exact_patch_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn records_preserve_spaces_and_rename_paths() {
        let oid = "1".repeat(40);
        let entries = parse_listing(format!("100644 blob {oid}\told name\0").as_bytes()).unwrap();
        assert!(entries.contains_key("old name"));
        assert!(!entries.contains_key("new name"));
        assert!(parse_listing(b"100644 blob bad\tx\0").is_err());
        for (mode, kind) in [("120000", "blob"), ("160000", "commit")] {
            let entries = parse_listing(format!("{mode} {kind} {oid}\tlink\0").as_bytes()).unwrap();
            assert!(
                validate_entry("link", &entries["link"], &[Selector::Path("link".into())]).is_err()
            );
        }
        assert!(parse_listing(&[255, 0]).is_err());
    }
    #[test]
    fn outgoing_records_and_deletions() {
        let oid = "1".repeat(40);
        let zero = "0".repeat(40);
        let input = format!("refs/heads/main {oid} refs/heads/main {zero}\nrefs/heads/main {oid} refs/heads/other {zero}\n");
        assert_eq!(
            outgoing_tips(&parse_pre_push(input.as_bytes()).unwrap()).unwrap(),
            vec![oid.clone()]
        );
        let deletion =
            parse_pre_push(format!("(delete) {zero} refs/heads/main {oid}\n").as_bytes()).unwrap();
        assert!(outgoing_tips(&deletion).is_err());
        for input in [
            format!("main {oid} refs/heads/main {zero}"),
            format!("refs/heads/main\t{oid} refs/heads/main {zero}"),
            format!("refs/heads/main {oid} refs/heads/main abc"),
            "\n".into(),
        ] {
            assert!(parse_pre_push(input.as_bytes()).is_err());
        }
    }
    #[test]
    fn streams_fail_closed_at_cap() {
        let deadline = Instant::now() + GIT_TIMEOUT;
        assert_eq!(
            receive(
                bounded_reader(std::io::Cursor::new(b"abc"), 3),
                deadline,
                "test"
            )
            .unwrap(),
            b"abc"
        );
        assert!(receive(
            bounded_reader(std::io::Cursor::new(b"abcd"), 3),
            deadline,
            "test"
        )
        .is_err());
    }
}
