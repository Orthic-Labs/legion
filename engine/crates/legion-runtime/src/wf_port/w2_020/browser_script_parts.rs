//! Port of `skills/designer/engine/scripts/live/browser-script-parts.mjs`.
//!
//! Filesystem access (`fs.existsSync`, `fs.readFileSync`) is modeled through
//! injectable closures, same shape as the JS's default-parameter overrides
//! (`exists = fs.existsSync`, `readFile = ...readFileSync`), so callers can
//! wire real I/O while tests stay hermetic.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptPart {
    pub name: &'static str,
    pub file: &'static str,
}

/// Mirrors `LIVE_BROWSER_SCRIPT_PARTS`.
pub const LIVE_BROWSER_SCRIPT_PARTS: &[ScriptPart] = &[
    ScriptPart { name: "session-state", file: "live-browser-session.js" },
    ScriptPart { name: "dom-helpers", file: "live-browser-dom.js" },
    ScriptPart { name: "browser-ui", file: "live-browser.js" },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedScriptPart {
    pub name: &'static str,
    pub file: &'static str,
    pub index: usize,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptPartSource {
    pub name: &'static str,
    pub file: &'static str,
    pub index: usize,
    pub path: PathBuf,
    pub source: String,
}

/// Mirrors `resolveLiveBrowserScriptParts(scriptsDir, parts)`.
///
/// The JS throws `Error('scriptsDir is required')` for a falsy `scriptsDir`;
/// modeled here as `Err(&str)` since `scripts_dir` is a required, non-optional
/// argument at the type level and callers who need the "was it empty" check
/// pass `""`.
pub fn resolve_live_browser_script_parts(
    scripts_dir: &str,
    parts: &[ScriptPart],
) -> Result<Vec<ResolvedScriptPart>, &'static str> {
    if scripts_dir.is_empty() {
        return Err("scriptsDir is required");
    }
    let dir = Path::new(scripts_dir);
    Ok(parts
        .iter()
        .enumerate()
        .map(|(index, part)| ResolvedScriptPart {
            name: part.name,
            file: part.file,
            index,
            path: dir.join(part.file),
        })
        .collect())
}

/// Mirrors `assertLiveBrowserScriptParts(parts, exists)`.
pub fn assert_live_browser_script_parts(
    parts: &[ResolvedScriptPart],
    exists: impl Fn(&Path) -> bool,
) -> Result<(), String> {
    for part in parts {
        if !exists(&part.path) {
            return Err(format!(
                "Live browser script part missing: {} ({})",
                part.name,
                part.path.display()
            ));
        }
    }
    Ok(())
}

/// Mirrors `readLiveBrowserScriptParts(parts, readFile)`.
pub fn read_live_browser_script_parts(
    parts: &[ResolvedScriptPart],
    read_file: impl Fn(&Path) -> std::io::Result<String>,
) -> std::io::Result<Vec<ScriptPartSource>> {
    parts
        .iter()
        .map(|part| {
            read_file(&part.path).map(|source| ScriptPartSource {
                name: part.name,
                file: part.file,
                index: part.index,
                path: part.path.clone(),
                source,
            })
        })
        .collect()
}

/// Mirrors `assembleLiveBrowserScript({ token, port, vocabulary, parts })`.
///
/// `vocabulary` is passed through as a pre-serialized JSON string (the JS
/// does `JSON.stringify(vocabulary)`); callers own building that value with
/// `serde_json::to_string`.
pub fn assemble_live_browser_script(
    token: &str,
    port: u16,
    vocabulary_json: &str,
    parts: &[ScriptPartSource],
) -> String {
    let prelude = format!(
        "window.__IMPECCABLE_TOKEN__ = '{token}';\nwindow.__IMPECCABLE_PORT__ = {port};\nwindow.__IMPECCABLE_VOCAB__ = {vocabulary_json};\n"
    );
    let body = parts
        .iter()
        .map(|part| {
            let file = if part.file.is_empty() {
                part.path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default()
            } else {
                part.file.to_string()
            };
            format!(
                "// --- impeccable live script part: {} ({}) ---\n{}",
                part.name, file, part.source
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    prelude + &body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_requires_scripts_dir() {
        assert_eq!(
            resolve_live_browser_script_parts("", LIVE_BROWSER_SCRIPT_PARTS),
            Err("scriptsDir is required")
        );
    }

    #[test]
    fn resolve_builds_indexed_paths() {
        let resolved = resolve_live_browser_script_parts("/scripts", LIVE_BROWSER_SCRIPT_PARTS).unwrap();
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0].name, "session-state");
        assert_eq!(resolved[0].index, 0);
        assert_eq!(resolved[0].path, PathBuf::from("/scripts/live-browser-session.js"));
        assert_eq!(resolved[2].path, PathBuf::from("/scripts/live-browser.js"));
    }

    #[test]
    fn assert_reports_first_missing_part() {
        let resolved = resolve_live_browser_script_parts("/scripts", LIVE_BROWSER_SCRIPT_PARTS).unwrap();
        let err = assert_live_browser_script_parts(&resolved, |p| p.to_string_lossy() != "/scripts/live-browser-dom.js")
            .unwrap_err();
        assert_eq!(err, "Live browser script part missing: dom-helpers (/scripts/live-browser-dom.js)");
    }

    #[test]
    fn assert_ok_when_all_exist() {
        let resolved = resolve_live_browser_script_parts("/scripts", LIVE_BROWSER_SCRIPT_PARTS).unwrap();
        assert!(assert_live_browser_script_parts(&resolved, |_| true).is_ok());
    }

    #[test]
    fn assemble_builds_prelude_and_concatenated_body() {
        let parts = vec![
            ScriptPartSource {
                name: "a",
                file: "a.js",
                index: 0,
                path: PathBuf::from("/scripts/a.js"),
                source: "console.log('a')".to_string(),
            },
            ScriptPartSource {
                name: "b",
                file: "b.js",
                index: 1,
                path: PathBuf::from("/scripts/b.js"),
                source: "console.log('b')".to_string(),
            },
        ];
        let script = assemble_live_browser_script("tok123", 4321, "{\"x\":1}", &parts);
        assert!(script.starts_with(
            "window.__IMPECCABLE_TOKEN__ = 'tok123';\nwindow.__IMPECCABLE_PORT__ = 4321;\nwindow.__IMPECCABLE_VOCAB__ = {\"x\":1};\n"
        ));
        assert!(script.contains("// --- impeccable live script part: a (a.js) ---\nconsole.log('a')"));
        assert!(script.contains("// --- impeccable live script part: b (b.js) ---\nconsole.log('b')"));
    }
}
