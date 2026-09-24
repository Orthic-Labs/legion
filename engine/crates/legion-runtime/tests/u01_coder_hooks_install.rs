//! Packet U01: tests for `p9_skills::coder_hooks_install`, the Rust port of
//! `skills/coder/hooks/install.py`. Uses an in-memory fake `InstallIo` — no
//! real `~/.claude` directory is touched.

use legion_runtime::p9_skills::coder_hooks_install::{install, ClaudeLayout, InstallIo};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct FakeFs {
    files: RefCell<BTreeMap<PathBuf, String>>,
}

impl FakeFs {
    fn with(files: &[(&str, Value)]) -> Self {
        let fs = FakeFs::default();
        for (path, value) in files {
            fs.files
                .borrow_mut()
                .insert(PathBuf::from(path), serde_json::to_string_pretty(value).unwrap());
        }
        fs
    }

    fn get(&self, path: &str) -> Value {
        serde_json::from_str(self.files.borrow().get(&PathBuf::from(path)).unwrap()).unwrap()
    }
}

impl InstallIo for FakeFs {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        self.files
            .borrow()
            .get(path)
            .cloned()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, path.display().to_string()))
    }
    fn write_string(&self, path: &Path, contents: &str) -> std::io::Result<()> {
        self.files.borrow_mut().insert(path.to_path_buf(), contents.to_string());
        Ok(())
    }
    fn exists(&self, path: &Path) -> bool {
        self.files.borrow().contains_key(path)
    }
    fn copy_file(&self, src: &Path, dst: &Path) -> std::io::Result<()> {
        let contents = self.read_to_string(src)?;
        self.write_string(dst, &contents)
    }
    fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
}

fn hooks_json() -> Value {
    json!([
        {
            "file": "enforce_cheap_review_routing.py",
            "event": "PreToolUse",
            "matcher": "Bash",
            "manifest": {"id": "coder.enforce-cheap-review-routing", "description": "routes cheap review"}
        }
    ])
}

#[test]
fn install_registers_hook_in_settings_and_manifest() {
    let fs = FakeFs::with(&[
        ("/repo/skills/coder/hooks/hooks.json", hooks_json()),
        ("/home/u/.claude/settings.json", json!({})),
    ]);
    let layout = ClaudeLayout::for_home(Path::new("/home/u"));
    let summary = install(Path::new("/repo/skills/coder/hooks"), &layout, &fs).unwrap();

    assert_eq!(summary.registered.len(), 1);
    assert_eq!(summary.registered[0].id, "coder.enforce-cheap-review-routing");
    assert!(summary.registered[0].command.ends_with("enforce_cheap_review_routing.py"));

    let settings = fs.get("/home/u/.claude/settings.json");
    let entry = &settings["hooks"]["PreToolUse"][0];
    assert_eq!(entry["matcher"], "Bash");
    assert_eq!(entry["hooks"][0]["type"], "command");
    assert!(entry["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .ends_with("enforce_cheap_review_routing.py"));

    let manifest = fs.get("/home/u/.claude/hooks/hooks-manifest.json");
    assert_eq!(manifest["hooks"].as_array().unwrap().len(), 1);
    assert_eq!(manifest["hooks"][0]["id"], "coder.enforce-cheap-review-routing");

    // Backup was written before mutation.
    assert!(fs.files.borrow().contains_key(Path::new("/home/u/.claude/settings.json.pre-synced-hooks.bak")));
}

#[test]
fn install_is_idempotent_and_dedupes_by_basename_and_id() {
    let fs = FakeFs::with(&[
        ("/repo/skills/coder/hooks/hooks.json", hooks_json()),
        ("/home/u/.claude/settings.json", json!({})),
    ]);
    let layout = ClaudeLayout::for_home(Path::new("/home/u"));
    install(Path::new("/repo/skills/coder/hooks"), &layout, &fs).unwrap();
    install(Path::new("/repo/skills/coder/hooks"), &layout, &fs).unwrap();

    let settings = fs.get("/home/u/.claude/settings.json");
    assert_eq!(settings["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap().len(), 1);
    let manifest = fs.get("/home/u/.claude/hooks/hooks-manifest.json");
    assert_eq!(manifest["hooks"].as_array().unwrap().len(), 1);
}

#[test]
fn install_preserves_other_hooks_in_the_same_event_matcher() {
    let fs = FakeFs::with(&[
        ("/repo/skills/coder/hooks/hooks.json", hooks_json()),
        (
            "/home/u/.claude/settings.json",
            json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 /other/hook.py"}]}]}}),
        ),
    ]);
    let layout = ClaudeLayout::for_home(Path::new("/home/u"));
    install(Path::new("/repo/skills/coder/hooks"), &layout, &fs).unwrap();

    let settings = fs.get("/home/u/.claude/settings.json");
    let commands: Vec<String> = settings["hooks"]["PreToolUse"][0]["hooks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["command"].as_str().unwrap().to_string())
        .collect();
    assert!(commands.iter().any(|c| c == "python3 /other/hook.py"));
    assert!(commands.iter().any(|c| c.ends_with("enforce_cheap_review_routing.py")));
}
