//! Port of `design-system.mjs`'s `loadDesignSystemForCwd` (plus its
//! `resolveDesignMdPath` helper), the one piece of that file `wf_port::w2_011`
//! didn't already port (it ports the pure `parseFrontmatter`/
//! `normalizeDesignSystem`/`checkSourceDesignSystem` logic; this is the
//! filesystem-resolution glue `main.mjs` calls directly).
//!
//! The sidecar-JSON (`DESIGN.json`/`.impeccable/design.json`) merge that
//! `normalizeDesignSystem` accepts in JS is not read here: `wf_port::w2_011::
//! normalize_design_system`'s Rust signature takes only the parsed
//! frontmatter (see its doc comment — the sidecar/mtime-comparison inputs
//! aren't part of its ported surface), so `md_newer_than_json` is passed as
//! `false` and no sidecar content flows into the returned `DesignSystem`.
//! This is a real, narrower-than-JS behaviour, not a silent gap: a project
//! whose design tokens live only in `DESIGN.json` (no `DESIGN.md`) gets no
//! design-system context via this loader, matching upstream only for the
//! common DESIGN.md-primary case.

use std::path::{Path, PathBuf};

use super::super::w2_011::design_system::{normalize_design_system, parse_frontmatter, DesignSystem};

const DESIGN_NAMES: [&str; 3] = ["DESIGN.md", "Design.md", "design.md"];
const FALLBACK_DIRS: [&str; 2] = [".agents/context", "docs"];

fn first_existing(dir: &Path, names: &[&str]) -> Option<PathBuf> {
    for name in names {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Port of `resolveDesignMdPath(cwd)`.
fn resolve_design_md_path(cwd: &Path) -> Option<PathBuf> {
    if let Some(root) = first_existing(cwd, &DESIGN_NAMES) {
        return Some(root);
    }
    for rel in FALLBACK_DIRS {
        let dir = cwd.join(rel);
        if let Some(found) = first_existing(&dir, &DESIGN_NAMES) {
            return Some(found);
        }
    }
    None
}

/// Port of `loadDesignSystemForCwd(cwd)`. Returns `None` wherever JS
/// returns `null`: no `DESIGN.md` found, unreadable, or frontmatter absent.
pub fn load_design_system_for_cwd(cwd: &Path) -> Option<DesignSystem> {
    let md_path = resolve_design_md_path(cwd)?;
    let content = std::fs::read_to_string(&md_path).ok()?;
    let frontmatter = parse_frontmatter(&content)?;
    Some(normalize_design_system(
        &frontmatter,
        Some(md_path.to_string_lossy().into_owned()),
        None,
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_with_no_design_md() {
        let dir = std::env::temp_dir().join(format!(
            "r05-design-none-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load_design_system_for_cwd(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loads_design_md_frontmatter() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "r05-design-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("DESIGN.md"),
            "---\ntypography:\n  fonts:\n    - Inter\n---\n# Design\n",
        )
        .unwrap();
        let ds = load_design_system_for_cwd(&dir).expect("design system loads");
        assert!(ds.present);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
