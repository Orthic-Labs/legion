//! Port of `skills/designer/engine/scripts/live/sveltekit-adapter.mjs`.
//!
//! Ports the pure string transforms (`patchSvelteLayout`,
//! `unpatchSvelteLayout`, `buildSvelteLiveRootComponent`) AND the
//! filesystem project-detection/orchestration layer: `detectSvelteKitProject`
//! -> [`detect_sveltekit_project`], `applySvelteKitLiveAdapter` ->
//! [`apply_sveltekit_live_adapter`], `removeSvelteKitLiveAdapter` ->
//! [`remove_sveltekit_live_adapter`], `ensureSvelteLiveRootComponent` ->
//! [`ensure_sveltekit_live_root_component`], plus their private helpers
//! `findSvelteKitAppHtml`, `findSvelteKitLayout`, `packageHasSvelteKit`,
//! `fileIncludes`, `pruneEmptyDir` (ported as private fns of the same
//! shape). Wired as chunk r21's caller: `w2_018::inject::run`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const SVELTE_LIVE_ROOT_COMPONENT: &str = "src/lib/designer/ImpeccableLiveRoot.svelte";
pub const SVELTE_LAYOUT_MARKER_OPEN: &str = "<!-- impeccable-live-svelte-start -->";
pub const SVELTE_LAYOUT_MARKER_CLOSE: &str = "<!-- impeccable-live-svelte-end -->";
pub const SVELTE_ROOT_IMPORT: &str =
    "import ImpeccableLiveRoot from '$lib/designer/ImpeccableLiveRoot.svelte';";

fn escape_regexp(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Port of `patchSvelteLayout`.
pub fn patch_svelte_layout(content: &str) -> String {
    let mut out = content.to_string();

    if !out.contains(SVELTE_ROOT_IMPORT) {
        let script_re = regex::RegexBuilder::new(r"<script(?:\s[^>]*)?>")
            .case_insensitive(true)
            .build()
            .unwrap();
        if let Some(m) = script_re.find(&out) {
            let insert_at = m.end();
            out = format!("{}\n  {}{}", &out[..insert_at], SVELTE_ROOT_IMPORT, &out[insert_at..]);
        } else {
            out = format!("<script>\n  {}\n</script>\n\n{}", SVELTE_ROOT_IMPORT, out);
        }
    }

    if !out.contains(SVELTE_LAYOUT_MARKER_OPEN) {
        let block = format!(
            "{}\n<ImpeccableLiveRoot />\n{}\n",
            SVELTE_LAYOUT_MARKER_OPEN, SVELTE_LAYOUT_MARKER_CLOSE
        );
        let render_re = regex::Regex::new(r"\{@render\s+children(?:\?\.)?\(\)\s*\}").unwrap();
        let slot_re = regex::Regex::new(r"<slot\s*/?>").unwrap();
        let insert_pos = render_re.find(&out).or_else(|| slot_re.find(&out));
        match insert_pos {
            Some(m) => {
                out = format!("{}{}{}", &out[..m.start()], block, &out[m.start()..]);
            }
            None => {
                let trailing_ws_re = regex::Regex::new(r"\s*$").unwrap();
                out = trailing_ws_re.replace(&out, format!("\n\n{}", block).as_str()).into_owned();
            }
        }
    }

    out
}

/// Port of `unpatchSvelteLayout`.
pub fn unpatch_svelte_layout(content: &str) -> String {
    let mut out = content.to_string();

    let block_pat = format!(
        r"([ \t]*){}\n<ImpeccableLiveRoot\s*/>\n{}\n?",
        escape_regexp(SVELTE_LAYOUT_MARKER_OPEN),
        escape_regexp(SVELTE_LAYOUT_MARKER_CLOSE)
    );
    let block_re = regex::Regex::new(&block_pat).unwrap();
    out = block_re.replace_all(&out, "$1").into_owned();

    let import_pat = format!(r"(?m)^\s*{}\s*\n?", escape_regexp(SVELTE_ROOT_IMPORT));
    let import_re = regex::Regex::new(&import_pat).unwrap();
    out = import_re.replace_all(&out, "").into_owned();

    let empty_script_re = regex::Regex::new(r"<script>\s*</script>\s*\n?").unwrap();
    out = empty_script_re.replace_all(&out, "").into_owned();

    let blank_lines_re = regex::Regex::new(r"\n{3,}").unwrap();
    blank_lines_re.replace_all(&out, "\n\n").into_owned()
}

/// Port of `buildSvelteLiveRootComponent`.
pub fn build_svelte_live_root_component(port: i64) -> String {
    format!(
        r#"<script>
  import {{ onMount }} from 'svelte';

  const LIVE_URL = 'http://localhost:{port}/live.js';
  const HOST_ID = 'impeccable-live-root';

  onMount(() => {{
    let host = document.querySelector('impeccable-live-root#' + HOST_ID) || document.getElementById(HOST_ID);
    if (!host) {{
      host = document.createElement('impeccable-live-root');
      host.id = HOST_ID;
      document.body.appendChild(host);
    }}

    host.dataset.impeccableLiveAdapter = 'sveltekit';
    host.style.setProperty('all', 'initial', 'important');
    host.style.setProperty('display', 'block', 'important');
    host.style.setProperty('position', 'fixed', 'important');
    host.style.setProperty('top', '0', 'important');
    host.style.setProperty('left', '0', 'important');
    host.style.setProperty('width', '0', 'important');
    host.style.setProperty('height', '0', 'important');
    host.style.setProperty('overflow', 'visible', 'important');
    host.style.setProperty('z-index', '2147483000', 'important');
    host.style.setProperty('pointer-events', 'none', 'important');

    const root = host.shadowRoot || host.attachShadow({{ mode: 'open' }});
    if (!root.querySelector('style[data-impeccable-live-reset]')) {{
      const reset = document.createElement('style');
      reset.dataset.impeccableLiveReset = 'true';
      reset.textContent = ':host, :host *, * {{ box-sizing: border-box; }}';
      root.appendChild(reset);
    }}

    window.__IMPECCABLE_LIVE_ADAPTER__ = 'sveltekit';
    window.__IMPECCABLE_LIVE_UI_ROOT__ = root;
    window.__IMPECCABLE_LIVE_CHROME_MOUNT__ = {{
      adapter: 'sveltekit',
      version: 1,
      host,
      root,
    }};

    const script = document.createElement('script');
    script.src = LIVE_URL;
    script.async = true;
    script.dataset.impeccableLiveScript = 'true';
    document.head.appendChild(script);

    return () => {{
      script.remove();
      if (window.__IMPECCABLE_LIVE_UI_ROOT__ === root) delete window.__IMPECCABLE_LIVE_UI_ROOT__;
      if (window.__IMPECCABLE_LIVE_CHROME_MOUNT__?.root === root) delete window.__IMPECCABLE_LIVE_CHROME_MOUNT__;
      if (window.__IMPECCABLE_LIVE_ADAPTER__ === 'sveltekit') delete window.__IMPECCABLE_LIVE_ADAPTER__;
    }};
  }});
</script>
"#,
        port = port
    )
}

/// Mirrors `findSvelteKitAppHtml(cwd, config)`. `config_files` mirrors
/// `config?.files` (an empty/`None` slice falls back to `['src/app.html']`,
/// matching the JS default).
fn find_sveltekit_app_html(cwd: &Path, config_files: Option<&[String]>) -> Option<String> {
    let default_files = ["src/app.html".to_string()];
    let files: &[String] = config_files.filter(|f| !f.is_empty()).unwrap_or(&default_files);
    for rel in files {
        if rel.contains('*') {
            continue;
        }
        let normalized = rel.replace(std::path::MAIN_SEPARATOR, "/");
        if !normalized.ends_with("app.html") {
            continue;
        }
        if cwd.join(&normalized).exists() {
            return Some(normalized);
        }
    }
    let fallback = "src/app.html";
    if cwd.join(fallback).exists() {
        Some(fallback.to_string())
    } else {
        None
    }
}

/// Mirrors `findSvelteKitLayout(cwd)`.
fn find_sveltekit_layout(cwd: &Path) -> String {
    let candidates = ["src/routes/+layout.svelte", "src/routes/(app)/+layout.svelte"];
    for rel in candidates {
        if cwd.join(rel).exists() {
            return rel.to_string();
        }
    }
    "src/routes/+layout.svelte".to_string()
}

/// Mirrors `defaultSvelteLayout()`.
fn default_svelte_layout() -> &'static str {
    "<script>\n  let { children } = $props();\n</script>\n\n{@render children?.()}\n"
}

/// Mirrors `packageHasSvelteKit(cwd)`.
fn package_has_sveltekit(cwd: &Path) -> bool {
    let file = cwd.join("package.json");
    let Ok(raw) = fs::read_to_string(&file) else {
        return false;
    };
    let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    for section in ["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(obj) = pkg.get(section).and_then(|v| v.as_object()) {
            if obj.contains_key("@sveltejs/kit")
                || obj.contains_key("@sveltejs/vite-plugin-svelte")
                || obj.contains_key("svelte")
            {
                return true;
            }
        }
    }
    false
}

/// Mirrors `fileIncludes(file, text)`.
fn file_includes(file: &Path, text: &str) -> bool {
    fs::read_to_string(file).map(|s| s.contains(text)).unwrap_or(false)
}

/// Mirrors `pruneEmptyDir(dir, stopDir)`.
fn prune_empty_dir(dir: &Path, stop_dir: &Path) {
    let mut current = dir.to_path_buf();
    loop {
        if !current.starts_with(stop_dir) || current == stop_dir {
            return;
        }
        match fs::read_dir(&current) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return;
                }
            }
            Err(_) => return,
        }
        if fs::remove_dir(&current).is_err() {
            return;
        }
        match current.parent() {
            Some(p) => current = p.to_path_buf(),
            None => return,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SvelteKitDetection {
    pub app_html: String,
    pub layout_file: String,
    pub root_component: &'static str,
}

/// Mirrors `detectSvelteKitProject(cwd, config)`.
pub fn detect_sveltekit_project(cwd: &Path, config_files: Option<&[String]>) -> Option<SvelteKitDetection> {
    let app_html = find_sveltekit_app_html(cwd, config_files)?;
    let has_template_markers = file_includes(&cwd.join(&app_html), "%sveltekit.body%")
        && file_includes(&cwd.join(&app_html), "%sveltekit.head%");
    if !has_template_markers {
        return None;
    }
    let has_svelte_config = ["svelte.config.js", "svelte.config.mjs", "svelte.config.cjs", "svelte.config.ts"]
        .iter()
        .any(|f| cwd.join(f).exists());
    let has_kit_package = package_has_sveltekit(cwd);
    if !has_svelte_config && !has_kit_package {
        return None;
    }
    Some(SvelteKitDetection {
        app_html,
        layout_file: find_sveltekit_layout(cwd),
        root_component: SVELTE_LIVE_ROOT_COMPONENT,
    })
}

#[derive(Debug, Clone)]
pub struct SvelteKitApplyResult {
    pub file: String,
    pub inserted: bool,
    pub app_html_untouched: bool,
    pub root_component: &'static str,
}

/// Mirrors `ensureSvelteLiveRootComponent(cwd, port)`.
pub fn ensure_sveltekit_live_root_component(cwd: &Path, port: i64) -> io::Result<PathBuf> {
    let file = cwd.join(SVELTE_LIVE_ROOT_COMPONENT);
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&file, build_svelte_live_root_component(port))?;
    Ok(file)
}

/// Mirrors `applySvelteKitLiveAdapter({ cwd, port, config })`. Returns
/// `Ok(None)` when the project isn't detected as SvelteKit (mirrors the JS
/// returning `null`).
pub fn apply_sveltekit_live_adapter(
    cwd: &Path,
    port: i64,
    config_files: Option<&[String]>,
) -> io::Result<Option<SvelteKitApplyResult>> {
    let Some(detected) = detect_sveltekit_project(cwd, config_files) else {
        return Ok(None);
    };
    ensure_sveltekit_live_root_component(cwd, port)?;

    let layout_abs = cwd.join(&detected.layout_file);
    if let Some(parent) = layout_abs.parent() {
        fs::create_dir_all(parent)?;
    }
    let layout_existed = layout_abs.exists();
    let before = if layout_existed {
        fs::read_to_string(&layout_abs)?
    } else {
        default_svelte_layout().to_string()
    };
    let after = patch_svelte_layout(&before);
    fs::write(&layout_abs, &after)?;

    Ok(Some(SvelteKitApplyResult {
        file: detected.layout_file,
        inserted: after != before || !layout_existed,
        app_html_untouched: true,
        root_component: SVELTE_LIVE_ROOT_COMPONENT,
    }))
}

#[derive(Debug, Clone)]
pub struct SvelteKitRemoveResult {
    pub file: String,
    pub removed: bool,
    pub app_html_untouched: bool,
    pub root_component: &'static str,
}

/// Mirrors `removeSvelteKitLiveAdapter({ cwd, config })`. Returns `Ok(None)`
/// when the project isn't detected as SvelteKit.
pub fn remove_sveltekit_live_adapter(
    cwd: &Path,
    config_files: Option<&[String]>,
) -> io::Result<Option<SvelteKitRemoveResult>> {
    let Some(detected) = detect_sveltekit_project(cwd, config_files) else {
        return Ok(None);
    };

    let layout_abs = cwd.join(&detected.layout_file);
    let mut removed = false;
    if layout_abs.exists() {
        let before = fs::read_to_string(&layout_abs)?;
        let after = unpatch_svelte_layout(&before);
        if after != before {
            fs::write(&layout_abs, &after)?;
            removed = true;
        }
    }

    let root_abs = cwd.join(SVELTE_LIVE_ROOT_COMPONENT);
    if root_abs.exists() {
        fs::remove_file(&root_abs)?;
        removed = true;
    }

    if let Some(parent) = root_abs.parent() {
        prune_empty_dir(parent, &cwd.join("src"));
    }

    Ok(Some(SvelteKitRemoveResult {
        file: detected.layout_file,
        removed,
        app_html_untouched: true,
        root_component: SVELTE_LIVE_ROOT_COMPONENT,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_js_source() {
        assert_eq!(SVELTE_LIVE_ROOT_COMPONENT, "src/lib/designer/ImpeccableLiveRoot.svelte");
        assert_eq!(SVELTE_LAYOUT_MARKER_OPEN, "<!-- impeccable-live-svelte-start -->");
        assert_eq!(SVELTE_LAYOUT_MARKER_CLOSE, "<!-- impeccable-live-svelte-end -->");
    }

    #[test]
    fn patches_layout_with_render_children() {
        let before = "<script>\n  let { children } = $props();\n</script>\n\n{@render children?.()}\n";
        let after = patch_svelte_layout(before);
        assert!(after.contains(SVELTE_ROOT_IMPORT));
        assert!(after.contains(SVELTE_LAYOUT_MARKER_OPEN));
        assert!(after.contains("<ImpeccableLiveRoot />"));
        // Marker block must be inserted before the render call.
        let render_pos = after.find("{@render").unwrap();
        let marker_pos = after.find(SVELTE_LAYOUT_MARKER_OPEN).unwrap();
        assert!(marker_pos < render_pos);
    }

    #[test]
    fn patches_layout_with_slot_tag() {
        let before = "<slot />\n";
        let after = patch_svelte_layout(before);
        assert!(after.contains("<script>\n  import ImpeccableLiveRoot"));
        let slot_pos = after.find("<slot").unwrap();
        let marker_pos = after.find(SVELTE_LAYOUT_MARKER_OPEN).unwrap();
        assert!(marker_pos < slot_pos);
    }

    #[test]
    fn patches_layout_with_no_slot_or_render_appends_at_end() {
        let before = "<div>static</div>\n";
        let after = patch_svelte_layout(before);
        assert!(after.trim_end().ends_with(SVELTE_LAYOUT_MARKER_CLOSE.trim_start_matches("").trim()) || after.contains(SVELTE_LAYOUT_MARKER_CLOSE));
        assert!(after.contains("<ImpeccableLiveRoot />"));
    }

    #[test]
    fn patch_is_idempotent() {
        let before = "<script>\n  let { children } = $props();\n</script>\n\n{@render children?.()}\n";
        let once = patch_svelte_layout(before);
        let twice = patch_svelte_layout(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn unpatch_removes_block_and_import() {
        let before = "<script>\n  let { children } = $props();\n</script>\n\n{@render children?.()}\n";
        let patched = patch_svelte_layout(before);
        let unpatched = unpatch_svelte_layout(&patched);
        assert!(!unpatched.contains(SVELTE_ROOT_IMPORT));
        assert!(!unpatched.contains(SVELTE_LAYOUT_MARKER_OPEN));
        assert!(!unpatched.contains("<ImpeccableLiveRoot"));
        assert!(unpatched.contains("{@render children?.()}"));
    }

    #[test]
    fn unpatch_collapses_extra_blank_lines() {
        let messy = "a\n\n\n\n\nb\n";
        assert_eq!(unpatch_svelte_layout(messy), "a\n\nb\n");
    }

    #[test]
    fn builds_root_component_with_port_substituted() {
        let out = build_svelte_live_root_component(4173);
        assert!(out.contains("http://localhost:4173/live.js"));
        assert!(out.contains("HOST_ID = 'impeccable-live-root'"));
        assert!(out.trim_end().ends_with("</script>"));
    }

    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "w2-022-sveltekit-adapter-{}-{}",
                std::process::id(),
                n
            ));
            fs::create_dir_all(&path).unwrap();
            TmpDir(path)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    fn seed_sveltekit_project(cwd: &Path) {
        write(
            cwd,
            "src/app.html",
            "<!doctype html>\n<html>%sveltekit.head%<body>%sveltekit.body%</body></html>\n",
        );
        write(cwd, "svelte.config.js", "export default {};\n");
    }

    #[test]
    fn detect_sveltekit_project_requires_template_markers_and_config() {
        let dir = TmpDir::new();
        assert!(detect_sveltekit_project(&dir.0, None).is_none());
        seed_sveltekit_project(&dir.0);
        let detected = detect_sveltekit_project(&dir.0, None).unwrap();
        assert_eq!(detected.app_html, "src/app.html");
        assert_eq!(detected.layout_file, "src/routes/+layout.svelte");
        assert_eq!(detected.root_component, SVELTE_LIVE_ROOT_COMPONENT);
    }

    #[test]
    fn detect_sveltekit_project_none_without_template_markers() {
        let dir = TmpDir::new();
        write(&dir.0, "src/app.html", "<html><body>no markers</body></html>");
        write(&dir.0, "svelte.config.js", "export default {};\n");
        assert!(detect_sveltekit_project(&dir.0, None).is_none());
    }

    #[test]
    fn apply_and_remove_sveltekit_adapter_round_trip() {
        let dir = TmpDir::new();
        seed_sveltekit_project(&dir.0);
        write(&dir.0, "src/routes/+layout.svelte", default_svelte_layout());

        let applied = apply_sveltekit_live_adapter(&dir.0, 4173, None).unwrap().unwrap();
        assert_eq!(applied.file, "src/routes/+layout.svelte");
        assert!(applied.inserted);
        assert!(applied.app_html_untouched);
        // app.html itself must be untouched.
        let app_html = fs::read_to_string(dir.0.join("src/app.html")).unwrap();
        assert!(!app_html.contains("live.js"));
        // Root component was written with the port baked in.
        let root_component = fs::read_to_string(dir.0.join(SVELTE_LIVE_ROOT_COMPONENT)).unwrap();
        assert!(root_component.contains("http://localhost:4173/live.js"));
        // Layout was patched.
        let layout = fs::read_to_string(dir.0.join("src/routes/+layout.svelte")).unwrap();
        assert!(layout.contains(SVELTE_LAYOUT_MARKER_OPEN));

        let removed = remove_sveltekit_live_adapter(&dir.0, None).unwrap().unwrap();
        assert!(removed.removed);
        assert!(!dir.0.join(SVELTE_LIVE_ROOT_COMPONENT).exists());
        let layout_after = fs::read_to_string(dir.0.join("src/routes/+layout.svelte")).unwrap();
        assert!(!layout_after.contains(SVELTE_LAYOUT_MARKER_OPEN));
        assert!(!layout_after.contains(SVELTE_ROOT_IMPORT));
    }

    #[test]
    fn apply_sveltekit_adapter_is_none_for_non_sveltekit_project() {
        let dir = TmpDir::new();
        assert!(apply_sveltekit_live_adapter(&dir.0, 4173, None).unwrap().is_none());
        assert!(remove_sveltekit_live_adapter(&dir.0, None).unwrap().is_none());
    }
}
