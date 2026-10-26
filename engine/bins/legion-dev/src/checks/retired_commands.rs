//! The RustRight client was called `rightkit` until it was renamed. A skill,
//! registry entry or agent rule that still tells a host to run `rightkit owns`,
//! `rightkit cargo` and the like probes for a command that is no longer
//! installed, so the ownership index silently goes unused. This test keeps the
//! retired spelling out of the files an agent reads.
//!
//! Dated evidence under `docs/` (verification logs, dispatch records) is
//! history and is not scanned.

use regex::Regex;
use std::fs;
use std::path::Path;

const SCOPES: &[&str] = &["skills", "src/registry", "docs/agent-rules.md", "scripts"];
const TEXT_EXTENSIONS: &[&str] = &["md", "json", "mjs", "js", "sh", "ps1", "yaml", "yml", "py"];
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

pub(super) fn violations(root: &Path) -> Vec<String> {
    let pattern =
        Regex::new(r"\brightkit(\.cmd)?\s+(owns|cargo|rustc|rustdoc|list|status|attach)\b")
            .unwrap();
    let mut found = Vec::new();
    for scope in SCOPES {
        let base = root.join(scope);
        let entries: Vec<_> = if base.is_file() {
            vec![base.clone()]
        } else {
            walkdir::WalkDir::new(&base)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_file())
                .map(|entry| entry.into_path())
                .collect()
        };
        for path in entries {
            let supported = path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| TEXT_EXTENSIONS.contains(&extension));
            let small = fs::metadata(&path).is_ok_and(|meta| meta.len() <= MAX_FILE_BYTES);
            if !supported || !small {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            for (index, line) in text.lines().enumerate() {
                if let Some(hit) = pattern.find(line) {
                    found.push(format!(
                        "{}:{}: `{}` is the retired name of the RustRight client; use rustright",
                        path.strip_prefix(root).unwrap_or(&path).display(),
                        index + 1,
                        hit.as_str()
                    ));
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    #[test]
    fn the_packaged_files_name_no_retired_client_command() {
        let found = violations(&repo_root());
        assert!(found.is_empty(), "{}", found.join("\n"));
    }

    #[test]
    fn the_scan_finds_the_retired_spellings_it_exists_to_catch() {
        let root = std::env::temp_dir().join(format!(
            "legion-retired-commands-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("skills/x")).unwrap();
        fs::create_dir_all(root.join("src/registry")).unwrap();
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::create_dir_all(root.join("scripts")).unwrap();
        fs::write(
            root.join("skills/x/SKILL.md"),
            "run `rightkit owns --compact` first\n",
        )
        .unwrap();
        fs::write(
            root.join("src/registry/c.json"),
            "{\"c\": \"rightkit cargo test\"}\n",
        )
        .unwrap();
        fs::write(
            root.join("docs/agent-rules.md"),
            "use rightkit list once\nand `rustright owns` too\n",
        )
        .unwrap();
        fs::write(root.join("scripts/a.sh"), "exec rightkit cargo \"$@\"\n").unwrap();
        fs::write(
            root.join("skills/x/ok.md"),
            "run `rustright owns --compact`; RightKit packages\n",
        )
        .unwrap();
        let found = violations(&root);
        let _ = fs::remove_dir_all(&root);
        assert_eq!(found.len(), 4, "{found:?}");
        assert!(
            found.iter().all(|line| !line.contains("ok.md")),
            "{found:?}"
        );
    }
}
