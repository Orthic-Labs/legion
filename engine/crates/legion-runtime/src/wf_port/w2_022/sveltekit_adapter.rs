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

/// Resolve a project-relative mutation target without following a symlink
/// outside the project. For paths that do not exist yet, validate the nearest
/// existing ancestor before returning a path rooted at its canonical location.
pub fn project_mutation_target(cwd: &Path, relative: &Path) -> io::Result<PathBuf> {
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mutation target is outside project",
        ));
    }

    let root = cwd.canonicalize()?;
    let mut has_name = false;
    let mut probe = root.clone();
    for component in relative.components() {
        match component {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => {
                has_name = true;
                probe.push(name);
                match probe.canonicalize() {
                    Ok(resolved) if resolved.starts_with(&root) => {}
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "mutation target is outside project",
                        ));
                    }
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        match fs::symlink_metadata(&probe) {
                            Ok(metadata) if metadata.file_type().is_symlink() => {
                                return Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "mutation target contains a dangling symlink",
                                ));
                            }
                            Ok(_) => return Err(err),
                            Err(metadata_err) if metadata_err.kind() == io::ErrorKind::NotFound => {
                                // Nothing below a genuinely missing component can
                                // exist; the nearest existing ancestor was validated.
                                return Ok(root.join(relative));
                            }
                            Err(metadata_err) => return Err(metadata_err),
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
            _ => unreachable!("absolute and parent components were rejected"),
        }
    }
    if !has_name {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mutation target is project root",
        ));
    }
    Ok(root.join(relative))
}

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
            out = format!(
                "{}\n  {}{}",
                &out[..insert_at],
                SVELTE_ROOT_IMPORT,
                &out[insert_at..]
            );
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
                out = trailing_ws_re
                    .replace(&out, format!("\n\n{}", block).as_str())
                    .into_owned();
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
    let files: &[String] = config_files
        .filter(|f| !f.is_empty())
        .unwrap_or(&default_files);
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
    let candidates = [
        "src/routes/+layout.svelte",
        "src/routes/(app)/+layout.svelte",
    ];
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
    fs::read_to_string(file)
        .map(|s| s.contains(text))
        .unwrap_or(false)
}

/// Mirrors `pruneEmptyDir(dir, stopDir)`.
fn prune_empty_dir(dir: &Path, stop_relative: &Path, project_root: &Path) {
    let Ok(root) = project_root.canonicalize() else {
        return;
    };
    let stop_dir = root.join(stop_relative);
    if project_mutation_target(&root, stop_relative).is_err() {
        return;
    }
    let mut current = dir.to_path_buf();
    loop {
        if !current.starts_with(&stop_dir) || current == stop_dir {
            return;
        }
        let Ok(relative) = current.strip_prefix(&root) else {
            return;
        };
        if project_mutation_target(&root, relative).is_err() {
            return;
        }
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            return;
        };
        if metadata.file_type().is_symlink() {
            return;
        }
        match current.canonicalize() {
            Ok(real) if real == current => {}
            _ => return,
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
pub fn detect_sveltekit_project(
    cwd: &Path,
    config_files: Option<&[String]>,
) -> Option<SvelteKitDetection> {
    let app_html = find_sveltekit_app_html(cwd, config_files)?;
    let has_template_markers = file_includes(&cwd.join(&app_html), "%sveltekit.body%")
        && file_includes(&cwd.join(&app_html), "%sveltekit.head%");
    if !has_template_markers {
        return None;
    }
    let has_svelte_config = [
        "svelte.config.js",
        "svelte.config.mjs",
        "svelte.config.cjs",
        "svelte.config.ts",
    ]
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
    let file = project_mutation_target(cwd, Path::new(SVELTE_LIVE_ROOT_COMPONENT))?;
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
    let layout_abs = project_mutation_target(cwd, Path::new(&detected.layout_file))?;
    let _root_abs = project_mutation_target(cwd, Path::new(SVELTE_LIVE_ROOT_COMPONENT))?;
    ensure_sveltekit_live_root_component(cwd, port)?;
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

    let layout_abs = project_mutation_target(cwd, Path::new(&detected.layout_file))?;
    let root_abs = project_mutation_target(cwd, Path::new(SVELTE_LIVE_ROOT_COMPONENT))?;
    let mut removed = false;
    if layout_abs.exists() {
        let before = fs::read_to_string(&layout_abs)?;
        let after = unpatch_svelte_layout(&before);
        if after != before {
            fs::write(&layout_abs, &after)?;
            removed = true;
        }
    }

    if root_abs.exists() {
        fs::remove_file(&root_abs)?;
        removed = true;
    }

    if let Some(parent) = root_abs.parent() {
        prune_empty_dir(parent, Path::new("src"), cwd);
    }

    Ok(Some(SvelteKitRemoveResult {
        file: detected.layout_file,
        removed,
        app_html_untouched: true,
        root_component: SVELTE_LIVE_ROOT_COMPONENT,
    }))
}
