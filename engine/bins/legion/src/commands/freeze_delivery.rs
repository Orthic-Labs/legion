//! Delivery reads objects from source, never its refs, configuration or worktree.
//! Protected enrollment owns destination, hooks & delivery storage. Failed or
//! uncertain delivery returns an error; caller retains its pending-push journal.
#[cfg(not(unix))]
use std::path::Path;

#[cfg(unix)]
mod unix {
    use rightkit_child_process::OwnedCommand;
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::Stdio,
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    const CAP: usize = 256 * 1024;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn failure(e: impl std::fmt::Display) -> String {
        format!("managed delivery held: {e}")
    }

    fn canonical(path: &Path) -> Result<(), String> {
        if !path.is_absolute() || path.canonicalize().map_err(failure)? != path || !path.is_dir() {
            return Err(failure("directory must be canonical, absolute & existing"));
        }
        Ok(())
    }

    fn protected(path: &Path) -> Result<(), String> {
        canonical(path)?;
        for ancestor in path.ancestors() {
            let meta = fs::symlink_metadata(ancestor).map_err(failure)?;
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || meta.mode() & 0o005 != 0o005
            {
                return Err(failure(
                    "delivery/hook ancestry must be root-owned, immutable & traversable",
                ));
            }
        }
        Ok(())
    }

    // Never inherit client Git/config/transport variables, including GIT_CONFIG_COUNT.
    fn command(program: &str) -> OwnedCommand {
        let mut owned = OwnedCommand::new(program);
        owned.env_allowlist(std::iter::empty::<&str>());
        owned
            .command_mut()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        owned
    }

    fn drain<R: Read + Send + 'static>(mut input: R) -> mpsc::Receiver<Result<Vec<u8>, String>> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = (|| {
                let mut bytes = Vec::new();
                let mut block = [0u8; 8192];
                let mut overflow = false;
                loop {
                    let n = input.read(&mut block).map_err(failure)?;
                    if n == 0 {
                        break;
                    }
                    let keep = n.min(CAP.saturating_sub(bytes.len()));
                    bytes.extend_from_slice(&block[..keep]);
                    overflow |= keep != n;
                }
                if overflow {
                    Err(failure("Git output exceeded bounded capture"))
                } else {
                    Ok(bytes)
                }
            })();
            let _ = tx.send(result);
        });
        rx
    }

    fn run(mut owned: OwnedCommand, deadline: Instant) -> Result<Vec<u8>, String> {
        if Instant::now() >= deadline {
            return Err(failure("120-second delivery deadline exhausted"));
        }
        let mut child = owned.spawn().map_err(failure)?;
        let out = drain(
            child
                .take_stdout()
                .ok_or_else(|| failure("stdout unavailable"))?,
        );
        let err = drain(
            child
                .take_stderr()
                .ok_or_else(|| failure("stderr unavailable"))?,
        );
        let status = match child.wait_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Some(status)) => status,
            other => {
                let _ = child.terminate_tree_bounded(Duration::from_secs(3));
                return Err(failure(format!("Git deadline/wait failed: {other:?}")));
            }
        };
        let receive = |rx: mpsc::Receiver<Result<Vec<u8>, String>>| {
            rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| failure("Git streams incomplete; delivery outcome uncertain"))?
        };
        let stdout = receive(out)?;
        let stderr = receive(err)?;
        if !status.success() {
            return Err(failure(format!(
                "Git failed; outcome may be uncertain: {}",
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        Ok(stdout)
    }

    fn walk(path: &Path, seal: bool, count: &mut usize) -> Result<(), String> {
        *count += 1;
        if *count > 1024 {
            return Err(failure("protected delivery/hook tree exceeds cap"));
        }
        let meta = fs::symlink_metadata(path).map_err(failure)?;
        if meta.file_type().is_symlink()
            || meta.uid() != 0
            || (!meta.is_dir() && !meta.is_file())
            || (!seal && meta.mode() & 0o022 != 0)
        {
            return Err(failure(
                "delivery/hook tree must contain only protected root-owned files & directories",
            ));
        }
        if seal {
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(if meta.is_dir() { 0o755 } else { 0o644 }),
            )
            .map_err(failure)?;
        }
        if meta.is_dir() {
            for entry in fs::read_dir(path).map_err(failure)? {
                walk(&entry.map_err(failure)?.path(), seal, count)?;
            }
        }
        Ok(())
    }

    pub fn push(
        objects: &Path,
        source: &str,
        remote: &str,
        remote_ref: &str,
        uid: &str,
        hooks: &Path,
        delivery_root: &Path,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let number: u32 = uid.parse().map_err(|_| failure("invalid delivery UID"))?;
        if number == 0
            || number.to_string() != uid
            || !matches!(source.len(), 40 | 64)
            || !source.bytes().all(|b| b.is_ascii_hexdigit())
            || source.bytes().all(|b| b == b'0')
            || remote.is_empty()
            || remote.starts_with('-')
            || remote.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(failure(
                "invalid immutable source, destination or nonroot UID",
            ));
        }
        super::super::freeze_git::parse_pre_push(
            format!(
                "{remote_ref} {source} {remote_ref} {}\n",
                "0".repeat(source.len())
            )
            .as_bytes(),
        )
        .map_err(failure)?;
        canonical(objects)?;
        let object_text = objects
            .to_str()
            .ok_or_else(|| failure("non-UTF8 objects path"))?;
        if object_text.chars().any(char::is_control) {
            return Err(failure("unsafe alternate object path"));
        }
        protected(delivery_root)?;
        protected(hooks)?;
        walk(hooks, false, &mut 0)?;
        let mut identity = command("/usr/bin/id");
        identity.command_mut().arg("-u");
        if run(identity, deadline)? != b"0\n" {
            return Err(failure("root delivery broker required"));
        }
        let unique = format!(
            "delivery-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(failure)?
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let isolated: PathBuf = delivery_root.join(unique);
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&isolated)
            .map_err(failure)?;
        fs::set_permissions(&isolated, fs::Permissions::from_mode(0o755)).map_err(failure)?;
        let mut init = command("/usr/bin/git");
        init.command_mut()
            .args(["init", "--bare", "--quiet", "--template="])
            .arg(if source.len() == 64 {
                "--object-format=sha256"
            } else {
                "--object-format=sha1"
            })
            .arg("--")
            .arg(&isolated);
        run(init, deadline)?;
        let mut alternate = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(isolated.join("objects/info/alternates"))
            .map_err(failure)?;
        writeln!(alternate, "{object_text}").map_err(failure)?;
        alternate.sync_all().map_err(failure)?;
        walk(&isolated, true, &mut 0)?;
        let mut delivery = command("/usr/bin/sudo");
        delivery
            .command_mut()
            .args([
                "-n",
                "-H",
                "-u",
                &format!("#{uid}"),
                "--",
                "/usr/bin/env",
                "PATH=/usr/bin:/bin",
                "LC_ALL=C",
                "GIT_CONFIG_NOSYSTEM=1",
                "GIT_CONFIG_GLOBAL=/dev/null",
                "GIT_NO_REPLACE_OBJECTS=1",
                "GIT_TERMINAL_PROMPT=0",
                "/usr/bin/git",
                "--no-replace-objects",
            ])
            .arg(format!("--git-dir={}", isolated.display()))
            .arg("-c")
            .arg(format!("safe.directory={}", isolated.display()))
            .arg("-c")
            .arg(format!("core.hooksPath={}", hooks.display()))
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "push.followTags=false",
                "push",
                "--porcelain",
                "--",
            ])
            .arg(remote)
            .arg(format!("{source}:{remote_ref}"));
        run(delivery, deadline)?;
        Ok(())
    }
}

#[cfg(unix)]
pub use unix::push;

#[cfg(not(unix))]
pub fn push(
    _: &Path,
    _: &str,
    _: &str,
    _: &str,
    _: &str,
    _: &Path,
    _: &Path,
) -> Result<(), String> {
    Err("native isolated delivery unavailable; use authenticated Unix broker".into())
}
