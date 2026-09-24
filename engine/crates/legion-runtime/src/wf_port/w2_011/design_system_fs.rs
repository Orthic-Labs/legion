//! Port of `resolveDesignMdPath` / `resolveDesignSidecarPath` /
//! `safeReadJson` / `loadDesignSystemForCwd` from `design-system.mjs`
//! (packet r06). These are the `fs`/`path` wrapper this chunk's header
//! previously left for an integrator; extended here to close that gap.
//!
//! Filesystem access is behind [`DesignFs`] so the resolution/loading
//! orchestration can be unit-tested with an in-memory fake instead of a
//! real filesystem.

use std::collections::HashMap;

use super::design_system::{
    color_key, normalize_design_system, parse_design_color, parse_frontmatter, resolve_length_px,
    ColorEntry, DesignSystem, RadiusEntry,
};

const DESIGN_NAMES: [&str; 3] = ["DESIGN.md", "Design.md", "design.md"];
const FALLBACK_DIRS: [&str; 2] = [".agents/context", "docs"];

/// Minimal filesystem surface `design-system.mjs`'s loader needs:
/// existence checks, reading file contents, and reading mtimes (used for
/// `mdNewerThanJson`). Mirrors `fs.existsSync` / `fs.readFileSync` /
/// `fs.statSync(...).mtimeMs`.
pub trait DesignFs {
    fn exists(&self, path: &str) -> bool;
    /// Returns `None` on any read error (mirrors the JS `try {} catch {}`
    /// swallow in `loadDesignSystemForCwd` / `safeReadJson`).
    fn read_to_string(&self, path: &str) -> Option<String>;
    /// Milliseconds since epoch, mirroring `Stats.mtimeMs`. `None` on any
    /// stat error.
    fn mtime_ms(&self, path: &str) -> Option<f64>;
}

/// Real-filesystem [`DesignFs`], joining paths with `/` like the JS
/// `path.join` does on POSIX (the rest of this detector's `fs`/`path`
/// usage is Node/POSIX-oriented too; no Windows-path handling is ported
/// here).
pub struct RealDesignFs;

impl DesignFs for RealDesignFs {
    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    fn read_to_string(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn mtime_ms(&self, path: &str) -> Option<f64> {
        let meta = std::fs::metadata(path).ok()?;
        let modified = meta.modified().ok()?;
        let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
        Some(dur.as_secs_f64() * 1000.0)
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        return name.to_string();
    }
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn first_existing(fs: &dyn DesignFs, dir: &str, names: &[&str]) -> Option<String> {
    for name in names {
        let abs = join(dir, name);
        if fs.exists(&abs) {
            return Some(abs);
        }
    }
    None
}

/// Result of [`resolve_design_md_path`]: the resolved `DESIGN.md` path and
/// the directory it (or its fallback) was found in — sidecar resolution
/// uses this `context_dir`, mirroring the JS `{ path, contextDir }` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDesignMd {
    pub path: String,
    pub context_dir: String,
}

/// Port of `resolveDesignMdPath(cwd)`.
pub fn resolve_design_md_path(fs: &dyn DesignFs, cwd: &str) -> Option<ResolvedDesignMd> {
    if let Some(root) = first_existing(fs, cwd, &DESIGN_NAMES) {
        return Some(ResolvedDesignMd {
            path: root,
            context_dir: cwd.to_string(),
        });
    }

    for rel in FALLBACK_DIRS {
        // Mirrors `path.resolve(cwd, rel)`: `rel` is always a relative
        // fallback-dir literal here, so a plain join is equivalent.
        let dir = join(cwd, rel);
        if let Some(found) = first_existing(fs, &dir, &DESIGN_NAMES) {
            return Some(ResolvedDesignMd {
                path: found,
                context_dir: dir,
            });
        }
    }

    None
}

/// Port of `resolveDesignSidecarPath(cwd, contextDir)`.
pub fn resolve_design_sidecar_path(fs: &dyn DesignFs, cwd: &str, context_dir: &str) -> Option<String> {
    // JS dedupes candidates by first occurrence
    // (`candidates.indexOf(candidate) === index`) before existence-checking;
    // an ordered dedupe mirrors that.
    let raw_candidates = [
        join(cwd, ".impeccable/design.json"),
        join(cwd, "DESIGN.json"),
        join(context_dir, "DESIGN.json"),
    ];
    let mut seen: Vec<String> = Vec::new();
    for candidate in raw_candidates {
        if !seen.contains(&candidate) {
            seen.push(candidate);
        }
    }
    seen.into_iter().find(|c| fs.exists(c))
}

/// Port of `safeReadJson(filePath)`.
pub fn safe_read_json(fs: &dyn DesignFs, path: Option<&str>) -> Option<serde_json::Value> {
    let path = path?;
    let text = fs.read_to_string(path)?;
    serde_json::from_str(&text).ok()
}

/// Port of `loadDesignSystemForCwd(cwd)`.
///
/// Returns `None` where the JS returns `null`: no `DESIGN.md` found, or it
/// failed to read/stat, or its frontmatter did not parse to an object.
pub fn load_design_system_for_cwd(fs: &dyn DesignFs, cwd: &str) -> Option<DesignSystem> {
    let md = resolve_design_md_path(fs, cwd)?;

    let md_mtime = fs.mtime_ms(&md.path)?;
    let md_text = fs.read_to_string(&md.path)?;
    let frontmatter: HashMap<_, _> = parse_frontmatter(&md_text)?;

    let sidecar_path = resolve_design_sidecar_path(fs, cwd, &md.context_dir);
    let sidecar_json = safe_read_json(fs, sidecar_path.as_deref());
    let sidecar_mtime = sidecar_path.as_deref().and_then(|p| fs.mtime_ms(p));

    let md_newer_than_json = matches!(sidecar_mtime, Some(s) if md_mtime > s + 1000.0);

    let mut ds = normalize_design_system(&frontmatter, Some(md.path), sidecar_path, md_newer_than_json);
    apply_sidecar_extensions(&mut ds, sidecar_json.as_ref());
    Some(ds)
}

/// `normalize_design_system` (already ported) only reads
/// `frontmatter.typography` / `.colors` / `.rounded`; the sidecar's
/// `extensions.colorMeta` / `extensions.roundedMeta` augmentation
/// (`addSidecarColors` / `addSidecarRadii` in JS) is applied here against
/// the already-normalized [`DesignSystem`], mirroring JS's field-by-field
/// mutation (same tolerance/allow-list rules, same `hasPillRadius`
/// triggers).
fn apply_sidecar_extensions(ds: &mut DesignSystem, sidecar: Option<&serde_json::Value>) {
    let Some(sidecar) = sidecar else { return };

    if let Some(color_meta) = sidecar
        .get("extensions")
        .and_then(|e| e.get("colorMeta"))
        .and_then(|v| v.as_object())
    {
        for (name, meta) in color_meta {
            let Some(meta) = meta.as_object() else { continue };
            if let Some(canonical) = meta.get("canonical").and_then(|v| v.as_str()) {
                add_sidecar_color(ds, canonical, &format!("sidecar.{name}"));
            }
            if let Some(ramp) = meta.get("tonalRamp").and_then(|v| v.as_array()) {
                for (i, value) in ramp.iter().enumerate() {
                    if let Some(value) = value.as_str() {
                        add_sidecar_color(ds, value, &format!("sidecar.{name}.tonalRamp[{i}]"));
                    }
                }
            }
        }
    }

    add_sidecar_radii(ds, sidecar);
}

fn add_sidecar_color(ds: &mut DesignSystem, value: &str, label: &str) {
    let Some(parsed) = parse_design_color(value) else { return };
    let key = color_key(&parsed);
    let entry = ds.allowed_color_keys.entry(key).or_insert_with(|| ColorEntry {
        color: parsed,
        labels: Vec::new(),
    });
    entry.labels.push(label.to_string());
    ds.has_colors = true;
}

fn add_sidecar_radii(ds: &mut DesignSystem, sidecar: &serde_json::Value) {
    let Some(rounded_meta) = sidecar
        .get("extensions")
        .and_then(|e| e.get("roundedMeta"))
        .and_then(|v| v.as_object())
    else {
        return;
    };
    for (raw_name, meta) in rounded_meta {
        let name = raw_name.trim_matches(|c| c == '"' || c == '\'').to_lowercase();
        if let Some(s) = meta.as_str() {
            add_sidecar_radius_token(ds, &name, &format!("sidecar.{name}"), s);
            continue;
        }
        if let Some(n) = meta.as_f64() {
            add_sidecar_radius_token(ds, &name, &format!("sidecar.{name}"), &format_num(n));
            continue;
        }
        let Some(obj) = meta.as_object() else { continue };
        for key in ["canonical", "value"] {
            if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
                add_sidecar_radius_token(ds, &name, &format!("sidecar.{name}.{key}"), s);
            } else if let Some(n) = obj.get(key).and_then(|v| v.as_f64()) {
                add_sidecar_radius_token(ds, &name, &format!("sidecar.{name}.{key}"), &format_num(n));
            }
        }
        for key in ["values", "aliases"] {
            if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
                for (i, value) in arr.iter().enumerate() {
                    if let Some(s) = value.as_str() {
                        add_sidecar_radius_token(ds, &name, &format!("sidecar.{name}.{key}[{i}]"), s);
                    } else if let Some(n) = value.as_f64() {
                        add_sidecar_radius_token(ds, &name, &format!("sidecar.{name}.{key}[{i}]"), &format_num(n));
                    }
                }
            }
        }
        let role = obj.get("role").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        if matches!(name.as_str(), "full" | "pill" | "round" | "rounded-full")
            || matches!(role.as_str(), "full" | "pill" | "round")
        {
            ds.has_pill_radius = true;
        }
    }
}

fn add_sidecar_radius_token(ds: &mut DesignSystem, name: &str, entry_name: &str, value: &str) {
    let raw = value.trim();
    if raw.is_empty() || raw.to_lowercase().contains("var(") || raw.contains('%') {
        return;
    }
    let Some(px) = resolve_length_px(raw, 16.0) else { return };
    if !px.is_finite() {
        return;
    }
    ds.allowed_radii.push(RadiusEntry {
        name: entry_name.to_string(),
        value: raw.to_string(),
        px,
    });
    ds.has_radii = true;
    if matches!(name, "full" | "pill" | "round" | "rounded-full") {
        ds.has_pill_radius = true;
    }
}

fn format_num(n: f64) -> String {
    if n.fract() == 0.0 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap as Map;

    #[derive(Default)]
    struct FakeFs {
        files: RefCell<Map<String, (String, f64)>>,
    }

    impl FakeFs {
        fn put(&self, path: &str, content: &str, mtime_ms: f64) {
            self.files
                .borrow_mut()
                .insert(path.to_string(), (content.to_string(), mtime_ms));
        }
    }

    impl DesignFs for FakeFs {
        fn exists(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path)
        }
        fn read_to_string(&self, path: &str) -> Option<String> {
            self.files.borrow().get(path).map(|(c, _)| c.clone())
        }
        fn mtime_ms(&self, path: &str) -> Option<f64> {
            self.files.borrow().get(path).map(|(_, m)| *m)
        }
    }

    #[test]
    fn resolve_design_md_path_prefers_root_over_fallback() {
        let fs = FakeFs::default();
        fs.put("/repo/DESIGN.md", "---\n---\n", 1.0);
        fs.put("/repo/docs/design.md", "---\n---\n", 1.0);
        let resolved = resolve_design_md_path(&fs, "/repo").unwrap();
        assert_eq!(resolved.path, "/repo/DESIGN.md");
        assert_eq!(resolved.context_dir, "/repo");
    }

    #[test]
    fn resolve_design_md_path_falls_back_to_docs_dir() {
        let fs = FakeFs::default();
        fs.put("/repo/docs/design.md", "---\n---\n", 1.0);
        let resolved = resolve_design_md_path(&fs, "/repo").unwrap();
        assert_eq!(resolved.path, "/repo/docs/design.md");
        assert_eq!(resolved.context_dir, "/repo/docs");
    }

    #[test]
    fn resolve_design_md_path_none_when_missing() {
        let fs = FakeFs::default();
        assert!(resolve_design_md_path(&fs, "/repo").is_none());
    }

    #[test]
    fn resolve_design_sidecar_path_prefers_impeccable_dir() {
        let fs = FakeFs::default();
        fs.put("/repo/.impeccable/design.json", "{}", 1.0);
        fs.put("/repo/DESIGN.json", "{}", 1.0);
        let sidecar = resolve_design_sidecar_path(&fs, "/repo", "/repo").unwrap();
        assert_eq!(sidecar, "/repo/.impeccable/design.json");
    }

    #[test]
    fn safe_read_json_returns_none_on_bad_json() {
        let fs = FakeFs::default();
        fs.put("/repo/DESIGN.json", "not json", 1.0);
        assert!(safe_read_json(&fs, Some("/repo/DESIGN.json")).is_none());
    }

    #[test]
    fn load_design_system_for_cwd_parses_frontmatter_and_flags_stale_sidecar() {
        let fs = FakeFs::default();
        fs.put("/repo/DESIGN.md", "---\ncolors:\n  brand: \"#336699\"\n---\n", 5000.0);
        fs.put("/repo/DESIGN.json", "{}", 1000.0);
        let ds = load_design_system_for_cwd(&fs, "/repo").unwrap();
        assert!(ds.present);
        assert!(ds.has_colors);
        assert!(ds.md_newer_than_json);
        assert_eq!(ds.source_path.as_deref(), Some("/repo/DESIGN.md"));
    }

    #[test]
    fn load_design_system_for_cwd_none_without_design_md() {
        let fs = FakeFs::default();
        assert!(load_design_system_for_cwd(&fs, "/repo").is_none());
    }

    #[test]
    fn load_design_system_for_cwd_applies_sidecar_color_and_radius_meta() {
        let fs = FakeFs::default();
        fs.put("/repo/DESIGN.md", "---\n---\n", 1.0);
        fs.put(
            "/repo/DESIGN.json",
            r##"{"extensions":{"colorMeta":{"brand":{"canonical":"#112233"}},"roundedMeta":{"full":"999px"}}}"##,
            1.0,
        );
        let ds = load_design_system_for_cwd(&fs, "/repo").unwrap();
        assert!(ds.has_colors);
        assert!(ds.has_radii);
        assert!(ds.has_pill_radius);
    }
}
