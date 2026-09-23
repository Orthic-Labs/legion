//! Port of `skills/designer/engine/scripts/detect-csp.mjs`: scan a project
//! tree for Content-Security-Policy signals and classify the shape so the
//! agent knows which patch template to propose. Mechanical (regex over file
//! contents) — no network, no dev server, no JS evaluation.
//!
//! Shapes are named by patch mechanism, not framework origin; see the
//! module-level doc comment in the source `.mjs` file for the full
//! rationale. Priority on multiple hits: append-arrays > append-string >
//! middleware > meta-tag.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use regex::Regex;

const MAX_DEPTH: u32 = 6;
const MAX_READ_BYTES: usize = 64 * 1024;

fn skip_dirs() -> &'static [&'static str] {
    &[
        "node_modules",
        ".git",
        ".next",
        ".turbo",
        ".svelte-kit",
        ".nuxt",
        ".astro",
        "dist",
        "build",
        "out",
        ".vercel",
    ]
}

fn scan_exts() -> &'static [&'static str] {
    &["js", "mjs", "cjs", "ts", "mts", "cts", "tsx", "jsx"]
}

fn layout_exts() -> &'static [&'static str] {
    &["tsx", "jsx", "astro", "vue", "svelte", "html"]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspShape {
    AppendArrays,
    AppendString,
    Middleware,
    MetaTag,
}

impl CspShape {
    pub fn as_str(&self) -> &'static str {
        match self {
            CspShape::AppendArrays => "append-arrays",
            CspShape::AppendString => "append-string",
            CspShape::Middleware => "middleware",
            CspShape::MetaTag => "meta-tag",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CspDetection {
    pub shape: Option<CspShape>,
    pub signals: Vec<String>,
}

struct Hits {
    append_arrays: Vec<String>,
    append_string: Vec<String>,
    middleware: Vec<String>,
    meta_tag: Vec<String>,
}

pub fn detect_csp(cwd: &Path) -> CspDetection {
    let monorepo_helper_signals: Vec<Regex> = [
        r"\bbuildCSPConfig\b",
        r"\bbuildSecurityHeaders\b",
        r"\badditionalScriptSrc\b",
        r"\badditionalConnectSrc\b",
        r"\bcreateBaseNextConfig\b",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect();
    let sveltekit_csp_signals: Vec<Regex> = [r"\bkit\s*:", r"\bcsp\s*:", r"\bdirectives\s*:"]
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect();
    let nuxt_security_signals: Vec<Regex> = [r#"['"]nuxt-security['"]"#, r"\bcontentSecurityPolicy\b"]
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect();
    let inline_header_signals: Vec<Regex> = [
        r#"(?i)["']Content-Security-Policy["']"#,
        r"\bscript-src\b",
        r"\bconnect-src\b",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect();
    let monorepo_path_re = Regex::new(r"packages/[^/]+/src/.*(config|next-config|security)").unwrap();
    let config_ext_re = Regex::new(r"(^|/)(next|nuxt|vite|astro|svelte)\.config\.").unwrap();
    let middleware_hint = Regex::new(r#"(?i)headers\.set\(\s*["']Content-Security-Policy["']"#).unwrap();
    let meta_tag_hint = Regex::new(r#"(?i)http-equiv\s*=\s*["']Content-Security-Policy["']"#).unwrap();

    let mut hits = Hits {
        append_arrays: vec![],
        append_string: vec![],
        middleware: vec![],
        meta_tag: vec![],
    };

    walk(cwd, cwd, 0, &mut |abs_path: &Path, rel_path: &str, body: &str| {
        let ext = abs_path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let base = abs_path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let is_config = |name: &str| {
            Regex::new(&format!(r"(^|/){}\.config\.", regex::escape(name)))
                .unwrap()
                .is_match(rel_path)
        };

        // === append-arrays candidates ===
        if scan_exts().contains(&ext.as_str())
            && monorepo_path_re.is_match(rel_path)
            && monorepo_helper_signals.iter().any(|re| re.is_match(body))
        {
            hits.append_arrays.push(rel_path.to_string());
            return;
        }

        if scan_exts().contains(&ext.as_str())
            && is_config("svelte")
            && sveltekit_csp_signals.iter().all(|re| re.is_match(body))
        {
            hits.append_arrays.push(rel_path.to_string());
            return;
        }

        if scan_exts().contains(&ext.as_str())
            && is_config("nuxt")
            && nuxt_security_signals.iter().all(|re| re.is_match(body))
        {
            hits.append_arrays.push(rel_path.to_string());
            return;
        }

        // === append-string candidates ===
        if scan_exts().contains(&ext.as_str())
            && config_ext_re.is_match(rel_path)
            && inline_header_signals.iter().all(|re| re.is_match(body))
        {
            hits.append_string.push(rel_path.to_string());
            return;
        }

        // === detect-only shapes ===
        if (base == "middleware.ts" || base == "middleware.js" || base == "middleware.mjs")
            && middleware_hint.is_match(body)
        {
            hits.middleware.push(rel_path.to_string());
        }

        if layout_exts().contains(&ext.as_str()) && meta_tag_hint.is_match(body) {
            hits.meta_tag.push(rel_path.to_string());
        }
    });

    if !hits.append_arrays.is_empty() {
        return CspDetection {
            shape: Some(CspShape::AppendArrays),
            signals: hits.append_arrays,
        };
    }
    if !hits.append_string.is_empty() {
        return CspDetection {
            shape: Some(CspShape::AppendString),
            signals: hits.append_string,
        };
    }
    if !hits.middleware.is_empty() {
        return CspDetection {
            shape: Some(CspShape::Middleware),
            signals: hits.middleware,
        };
    }
    if !hits.meta_tag.is_empty() {
        return CspDetection {
            shape: Some(CspShape::MetaTag),
            signals: hits.meta_tag,
        };
    }
    CspDetection {
        shape: None,
        signals: vec![],
    }
}

fn walk(root: &Path, dir: &Path, depth: u32, visit: &mut dyn FnMut(&Path, &str, &str)) {
    if depth > MAX_DEPTH {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut entries: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for abs in entries {
        let file_name = abs
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if abs.is_dir() {
            if skip_dirs().contains(&file_name.as_str()) {
                continue;
            }
            walk(root, &abs, depth + 1, visit);
            continue;
        }
        if !abs.is_file() {
            continue;
        }
        let ext = abs
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if !scan_exts().contains(&ext.as_str()) && !layout_exts().contains(&ext.as_str()) {
            continue;
        }
        let body = match read_head(&abs, MAX_READ_BYTES) {
            Some(b) => b,
            None => continue,
        };
        let rel_path = pathdiff_posix(root, &abs);
        visit(&abs, &rel_path, &body);
    }
}

fn read_head(path: &Path, max_bytes: usize) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut buf = vec![0u8; max_bytes];
    let mut total = 0usize;
    loop {
        let n = file.read(&mut buf[total..]).ok()?;
        if n == 0 {
            break;
        }
        total += n;
        if total >= max_bytes {
            break;
        }
    }
    buf.truncate(total);
    Some(String::from_utf8_lossy(&buf).to_string())
}

fn pathdiff_posix(root: &Path, abs: &Path) -> String {
    let rel = abs.strip_prefix(root).unwrap_or(abs);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion_w2010_detectcsp_{name}_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detects_append_arrays_via_sveltekit_config() {
        let root = tmp_dir("sveltekit");
        fs::write(
            root.join("svelte.config.js"),
            "export default {\n  kit: {\n    csp: {\n      directives: {\n        'script-src': ['self']\n      }\n    }\n  }\n};\n",
        )
        .unwrap();
        let result = detect_csp(&root);
        assert_eq!(result.shape, Some(CspShape::AppendArrays));
        assert_eq!(result.signals, vec!["svelte.config.js".to_string()]);
    }

    #[test]
    fn detects_append_string_via_next_headers() {
        let root = tmp_dir("next_headers");
        fs::write(
            root.join("next.config.js"),
            "module.exports = { headers: () => [{ headers: [{ key: 'Content-Security-Policy', value: \"script-src 'self'; connect-src 'self'\" }] }] };\n",
        )
        .unwrap();
        let result = detect_csp(&root);
        assert_eq!(result.shape, Some(CspShape::AppendString));
    }

    #[test]
    fn detects_middleware_shape() {
        let root = tmp_dir("middleware");
        fs::write(
            root.join("middleware.ts"),
            "export function middleware(req) { const res = NextResponse.next(); res.headers.set('Content-Security-Policy', \"default-src 'self'\"); return res; }\n",
        )
        .unwrap();
        let result = detect_csp(&root);
        assert_eq!(result.shape, Some(CspShape::Middleware));
    }

    #[test]
    fn detects_meta_tag_shape() {
        let root = tmp_dir("meta");
        fs::write(
            root.join("layout.tsx"),
            "export default function Layout() { return <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\" />; }\n",
        )
        .unwrap();
        let result = detect_csp(&root);
        assert_eq!(result.shape, Some(CspShape::MetaTag));
    }

    #[test]
    fn returns_null_shape_when_no_signals() {
        let root = tmp_dir("none");
        fs::write(root.join("index.js"), "console.log('hi');\n").unwrap();
        let result = detect_csp(&root);
        assert_eq!(result.shape, None);
        assert!(result.signals.is_empty());
    }

    #[test]
    fn skips_node_modules() {
        let root = tmp_dir("skip_nm");
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::write(
            root.join("node_modules/pkg/middleware.ts"),
            "headers.set('Content-Security-Policy', 'x')",
        )
        .unwrap();
        let result = detect_csp(&root);
        assert_eq!(result.shape, None);
    }

    #[test]
    fn priority_prefers_append_arrays_over_middleware() {
        let root = tmp_dir("priority");
        fs::create_dir_all(root.join("packages/web/src/config")).unwrap();
        fs::write(
            root.join("packages/web/src/config/security.ts"),
            "export const buildCSPConfig = () => ({ additionalScriptSrc: [] });\n",
        )
        .unwrap();
        fs::write(
            root.join("middleware.ts"),
            "headers.set('Content-Security-Policy', 'default-src self')",
        )
        .unwrap();
        let result = detect_csp(&root);
        assert_eq!(result.shape, Some(CspShape::AppendArrays));
    }
}
