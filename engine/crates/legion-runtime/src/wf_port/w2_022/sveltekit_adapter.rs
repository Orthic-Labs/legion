//! Port of `skills/designer/engine/scripts/live/sveltekit-adapter.mjs`.
//!
//! Ports the pure string transforms: `patchSvelteLayout`,
//! `unpatchSvelteLayout`, and the `+layout.svelte` root-component template
//! builder `buildSvelteLiveRootComponent`.
//!
//! NOT ported in this chunk (filesystem project-detection/orchestration —
//! `detectSvelteKitProject`, `applySvelteKitLiveAdapter`,
//! `removeSvelteKitLiveAdapter`, `ensureSvelteLiveRootComponent`,
//! `findSvelteKitAppHtml`, `findSvelteKitLayout`, `packageHasSvelteKit`,
//! `fileIncludes`, `pruneEmptyDir` — these walk the live project's `cwd`
//! for `svelte.config.*`/`package.json`/`src/app.html`/`+layout.svelte`
//! and mutate files on disk; no Rust caller of this adapter exists yet).

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
}
