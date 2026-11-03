//! Port of `skills/designer/engine/scripts/detector/node/file-system.mjs`.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Port of `SKIP_DIRS`.
pub fn skip_dirs() -> HashSet<&'static str> {
    [
        "node_modules",
        ".git",
        "dist",
        "build",
        ".next",
        ".nuxt",
        ".output",
        ".svelte-kit",
        "__pycache__",
        ".turbo",
        ".vercel",
    ]
    .into_iter()
    .collect()
}

/// Port of `SCANNABLE_EXTENSIONS`.
pub fn scannable_extensions() -> HashSet<&'static str> {
    [
        ".html", ".htm", ".css", ".scss", ".sass", ".less", ".jsx", ".tsx", ".js", ".ts", ".vue",
        ".svelte", ".astro",
    ]
    .into_iter()
    .collect()
}

/// Port of `HTML_EXTENSIONS`.
pub fn html_extensions() -> HashSet<&'static str> {
    [".html", ".htm"].into_iter().collect()
}

fn ext_of(path: &Path) -> String {
    path.extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default()
}

/// Port of `walkDir(dir)`: recursively lists scannable files, skipping
/// `SKIP_DIRS` directories. Unreadable directories are silently skipped
/// (matching the JS `try { ... } catch { return files; }`).
pub fn walk_dir(dir: &Path) -> Vec<PathBuf> {
    let skip = skip_dirs();
    let scannable = scannable_extensions();
    let mut files = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return files,
    };
    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    // Preserve a deterministic, directory-read order like Node's readdirSync
    // does not guarantee either; sort for test stability.
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        if skip.contains(name_str.as_str()) {
            continue;
        }
        let full = dir.join(&name);
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            files.extend(walk_dir(&full));
        } else if scannable.contains(ext_of(&full).as_str()) {
            files.push(full);
        }
    }
    files
}

/// Port of `resolveImport(specifier, fromDir, fileSet)`.
pub fn resolve_import(
    specifier: &str,
    from_dir: &Path,
    file_set: &HashSet<PathBuf>,
) -> Option<PathBuf> {
    if !(specifier.starts_with('.') || specifier.starts_with('/')) {
        return None; // skip bare specifiers
    }
    let base = normalize_path(&from_dir.join(specifier));
    if file_set.contains(&base) {
        return Some(base);
    }
    for ext in scannable_extensions() {
        let mut with_ext = base.clone().into_os_string();
        with_ext.push(ext);
        let with_ext = PathBuf::from(with_ext);
        if file_set.contains(&with_ext) {
            return Some(with_ext);
        }
    }
    for ext in scannable_extensions() {
        let index_file = base.join(format!("index{ext}"));
        if file_set.contains(&index_file) {
            return Some(index_file);
        }
    }
    None
}

/// `path.resolve` collapses `.`/`..` segments without requiring the path to
/// exist; this is a lexical equivalent used to mirror that behaviour for
/// `resolveImport`'s `path.resolve(fromDir, specifier)` call.
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Port of `buildImportGraph(files)`. Files that fail to read (matching
/// JS's unhandled `fs.readFileSync` throw not being a concern in this
/// synchronous helper's contract) are skipped with an empty import set
/// rather than propagating an error, since callers pass an already
/// `walk_dir`-produced file list.
pub fn build_import_graph(files: &[PathBuf]) -> HashMap<PathBuf, HashSet<PathBuf>> {
    let file_set: HashSet<PathBuf> = files.iter().cloned().collect();
    let mut graph = HashMap::new();

    let es_re = regex::Regex::new(r#"import\s+(?:[\s\S]*?from\s+)?['"]([^'"]+)['"]"#).unwrap();
    let css_re =
        regex::Regex::new(r#"@import\s+(?:url\(\s*)?['"]?([^'");\s]+)['"]?\s*\)?"#).unwrap();
    let scss_re = regex::Regex::new(r#"@(?:use|forward)\s+['"]([^'"]+)['"]"#).unwrap();

    for file in files {
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => {
                graph.insert(file.clone(), HashSet::new());
                continue;
            }
        };
        let dir = file.parent().unwrap_or_else(|| Path::new(""));
        let mut imports = HashSet::new();

        for cap in es_re.captures_iter(&content) {
            if let Some(resolved) = resolve_import(&cap[1], dir, &file_set) {
                imports.insert(resolved);
            }
        }
        for cap in css_re.captures_iter(&content) {
            if let Some(resolved) = resolve_import(&cap[1], dir, &file_set) {
                imports.insert(resolved);
            }
        }
        for cap in scss_re.captures_iter(&content) {
            if let Some(resolved) = resolve_import(&cap[1], dir, &file_set) {
                imports.insert(resolved);
            }
        }

        graph.insert(file.clone(), imports);
    }
    graph
}

/// Port of one entry in `FRAMEWORK_CONFIGS`.
#[derive(Clone, Debug)]
pub struct FrameworkConfig {
    pub name: &'static str,
    pub files: &'static [&'static str],
    pub default_port: u16,
    /// Header-name / value-regex fingerprint, when present.
    pub fingerprint_header: Option<(&'static str, Option<&'static str>)>,
    /// Body-content regex fingerprint, when present.
    pub fingerprint_body: Option<&'static str>,
}

/// Port of `FRAMEWORK_CONFIGS`.
pub fn framework_configs() -> Vec<FrameworkConfig> {
    vec![
        FrameworkConfig {
            name: "Next.js",
            files: &["next.config.js", "next.config.mjs", "next.config.ts"],
            default_port: 3000,
            fingerprint_header: Some(("x-powered-by", Some("(?i)next"))),
            fingerprint_body: None,
        },
        FrameworkConfig {
            name: "SvelteKit",
            files: &["svelte.config.js", "svelte.config.ts"],
            default_port: 5173,
            fingerprint_header: Some(("x-sveltekit-page", None)),
            fingerprint_body: None,
        },
        FrameworkConfig {
            name: "Nuxt",
            files: &["nuxt.config.js", "nuxt.config.ts"],
            default_port: 3000,
            fingerprint_header: Some(("x-powered-by", Some("(?i)nuxt"))),
            fingerprint_body: None,
        },
        FrameworkConfig {
            name: "Vite",
            files: &["vite.config.js", "vite.config.ts", "vite.config.mjs"],
            default_port: 5173,
            fingerprint_header: None,
            fingerprint_body: Some(r"@vite/client"),
        },
        FrameworkConfig {
            name: "Astro",
            files: &["astro.config.js", "astro.config.ts", "astro.config.mjs"],
            default_port: 4321,
            fingerprint_header: None,
            fingerprint_body: Some(r"(?i)astro"),
        },
        FrameworkConfig {
            name: "Angular",
            files: &["angular.json"],
            default_port: 4200,
            fingerprint_header: None,
            fingerprint_body: Some(r"(?i)ng-version"),
        },
        FrameworkConfig {
            name: "Remix",
            files: &["remix.config.js", "remix.config.ts"],
            default_port: 3000,
            fingerprint_header: Some(("x-powered-by", Some("(?i)remix"))),
            fingerprint_body: None,
        },
    ]
}

/// Port of `detectFrameworkConfig(dir)`'s result shape.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectedFramework {
    pub name: String,
    pub port: u16,
    pub config_path: PathBuf,
}

/// Port of `detectFrameworkConfig(dir)`. The `portRe` capture
/// (`/port\s*[:=]\s*(\d+)/`) is applied to the config file's content; on
/// parse failure or missing match, `default_port` is kept (matching JS's
/// `catch { /* use default */ }`).
pub fn detect_framework_config(dir: &Path) -> Option<DetectedFramework> {
    let entries: HashSet<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    let port_re = regex::Regex::new(r"port\s*[:=]\s*(\d+)").unwrap();

    for cfg in framework_configs() {
        let Some(matched) = cfg.files.iter().find(|f| entries.contains(**f)) else {
            continue;
        };
        let config_path = dir.join(matched);
        let mut port = cfg.default_port;
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Some(m) = port_re.captures(&content) {
                if let Ok(p) = m[1].parse::<u16>() {
                    port = p;
                }
            }
        }
        return Some(DetectedFramework {
            name: cfg.name.to_string(),
            port,
            config_path,
        });
    }
    None
}

/// Port of `isPortListening(port, fingerprint)`'s result shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortListenStatus {
    pub listening: bool,
    /// `None` when `listening` is false (matching JS, which omits
    /// `matched` on the `{ listening: false }` result).
    pub matched: Option<bool>,
}

/// Port of `isPortListening(port, fingerprint = null)`'s plain-TCP-probe
/// fallback branch (`fingerprint` is `None`): connects with a 500ms
/// timeout, matching the JS `sock.setTimeout(500)`.
pub fn is_port_listening_tcp(port: u16) -> PortListenStatus {
    let addr = format!("127.0.0.1:{port}");
    match addr.parse::<std::net::SocketAddr>() {
        Ok(sock_addr) => match TcpStream::connect_timeout(&sock_addr, Duration::from_millis(500)) {
            Ok(_) => PortListenStatus {
                listening: true,
                matched: Some(true),
            },
            Err(_) => PortListenStatus {
                listening: false,
                matched: None,
            },
        },
        Err(_) => PortListenStatus {
            listening: false,
            matched: None,
        },
    }
}

/// Port of `isPortListening(port, fingerprint)`'s HTTP-fingerprint branch:
/// issues a plain `GET / HTTP/1.1` to `127.0.0.1:port`, with a 2s overall
/// timeout (matching the JS `AbortController` timeout of 2000ms), and
/// checks the header/body fingerprint the same way the JS does (header
/// checked first; body checked only if the header check didn't match).
/// `legion-runtime` has no async HTTP client dependency available to this
/// chunk, so this is a minimal hand-rolled HTTP/1.1 client rather than a
/// `reqwest`/`hyper` call — faithful to the JS's single unauthenticated
/// GET-and-read-headers-or-body behaviour, not a general HTTP client.
pub fn is_port_listening_http(
    port: u16,
    fingerprint_header: Option<(&str, Option<&regex::Regex>)>,
    fingerprint_body: Option<&regex::Regex>,
) -> PortListenStatus {
    let addr = format!("127.0.0.1:{port}");
    let sock_addr = match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            return PortListenStatus {
                listening: false,
                matched: None,
            }
        }
    };
    let mut stream = match TcpStream::connect_timeout(&sock_addr, Duration::from_millis(2000)) {
        Ok(s) => s,
        Err(_) => {
            return PortListenStatus {
                listening: false,
                matched: None,
            }
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));

    let request = format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return PortListenStatus {
            listening: false,
            matched: None,
        };
    }

    let mut raw = Vec::new();
    if stream.read_to_end(&mut raw).is_err() && raw.is_empty() {
        return PortListenStatus {
            listening: false,
            matched: None,
        };
    }
    let response = String::from_utf8_lossy(&raw);
    let (headers_part, body_part) = response
        .split_once("\r\n\r\n")
        .unwrap_or((response.as_ref(), ""));

    if let Some((header_name, value_re)) = fingerprint_header {
        let wanted = header_name.to_lowercase();
        for line in headers_part.lines().skip(1) {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().to_lowercase() == wanted {
                    let value = value.trim();
                    let ok = match value_re {
                        Some(re) => re.is_match(value),
                        None => true,
                    };
                    if !value.is_empty() && ok {
                        return PortListenStatus {
                            listening: true,
                            matched: Some(true),
                        };
                    }
                }
            }
        }
    }

    if let Some(body_re) = fingerprint_body {
        if body_re.is_match(body_part) {
            return PortListenStatus {
                listening: true,
                matched: Some(true),
            };
        }
    }

    PortListenStatus {
        listening: true,
        matched: Some(false),
    }
}
