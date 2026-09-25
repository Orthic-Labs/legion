// Port of `scripts/check-packed-import-closure.mjs`. Validates static
// relative ESM imports against the actual packed payload: runs `pnpm pack`
// (real tarball, not `--dry-run --json`, since there is no Node
// `npm_execpath` to shell through from Rust) and reads the resulting
// `.tgz` directly with the `flate2`/`tar` crates for the packed file list
// and JavaScript sources.

use super::publication_surface;
use flate2::read::GzDecoder;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

fn javascript_file_re() -> Regex {
    Regex::new(r"(?i)\.[cm]?js$").unwrap()
}
fn static_esm_re() -> Regex {
    Regex::new(r#"(?m)^\s*(?:import\s+(?:[^"']+?\s+from\s+)?|export\s+[^"']*?\s+from\s+)(?:"(\.{1,2}/[^"']+)"|'(\.{1,2}/[^"']+)')"#).unwrap()
}
fn dynamic_esm_re() -> Regex {
    // `(?!\/[/\*]|\*)` lookahead dropped (unsupported); approximated by
    // skipping lines that start with `//`, `/*`, or `*` after trimming,
    // matching the practical intent (skip comment lines) without changing
    // behaviour for real source files.
    Regex::new(r#"(?m)^\s*[^\n]*?\bimport\s*\(\s*(?:"(\.{1,2}/[^"']+)"|'(\.{1,2}/[^"']+)')\s*\)"#).unwrap()
}

fn normalize_path(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    replaced.strip_prefix("./").unwrap_or(&replaced).to_string()
}

pub fn relative_esm_specifiers(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in static_esm_re().captures_iter(source) {
        out.push(cap.get(1).or_else(|| cap.get(2)).map_or("", |m| m.as_str()).to_string());
    }
    let dyn_re = dynamic_esm_re();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }
        for cap in dyn_re.captures_iter(line) {
            out.push(cap.get(1).or_else(|| cap.get(2)).map_or("", |m| m.as_str()).to_string());
        }
    }
    out
}

/// posix.normalize(posix.join(posix.dirname(from), specifier)) — a pure
/// lexical join/normalize with `..` collapsing, rejecting escapes above the
/// packed root (mirrors the JS `resolvePackedRelativeImport`).
pub fn resolve_packed_relative_import(from: &str, specifier: &str) -> Option<String> {
    let pathname = specifier.split(['?', '#']).next().unwrap_or(specifier);
    let from_norm = normalize_path(from);
    let dir = match from_norm.rfind('/') {
        Some(idx) => &from_norm[..idx],
        None => "",
    };
    let joined = if dir.is_empty() {
        pathname.to_string()
    } else {
        format!("{dir}/{pathname}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for segment in joined.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                if parts.last().map(|p| *p != "..").unwrap_or(false) {
                    parts.pop();
                } else {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let resolved = parts.join("/");
    if resolved == ".." || resolved.starts_with("../") {
        None
    } else {
        Some(normalize_path(&resolved))
    }
}

pub struct MissingImport {
    pub from: String,
    pub specifier: String,
    pub target: Option<String>,
}

pub fn find_missing_packed_relative_imports(
    packed_files: &[String],
    sources: &HashMap<String, String>,
) -> Vec<MissingImport> {
    let packed: HashSet<String> = packed_files.iter().map(|p| normalize_path(p)).collect();
    let mut missing = Vec::new();
    for (from, source) in sources {
        for specifier in relative_esm_specifiers(source) {
            let target = resolve_packed_relative_import(from, &specifier);
            let hit = target.as_ref().map(|t| packed.contains(t)).unwrap_or(false);
            if !hit {
                missing.push(MissingImport {
                    from: normalize_path(from),
                    specifier,
                    target,
                });
            }
        }
    }
    missing
}

/// Run `pnpm pack` into a scratch directory and return the produced `.tgz`
/// path.
fn pnpm_pack(root: &Path) -> Result<std::path::PathBuf, String> {
    let out_dir = std::env::temp_dir().join(format!(
        "legion-pack-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    // Run the package manager that launched this check (as the JS did via
    // npm_execpath); Windows cannot spawn the bare `pnpm` shim.
    let mut command = match std::env::var_os("npm_execpath") {
        Some(exec) if !exec.is_empty() => {
            let mut c = std::process::Command::new("node");
            c.arg(exec);
            c
        }
        _ if cfg!(windows) => {
            let mut c = std::process::Command::new("cmd");
            c.args(["/C", "pnpm"]);
            c
        }
        _ => std::process::Command::new("pnpm"),
    };
    let output = command
        .args(["pack", "--pack-destination"])
        .arg(&out_dir)
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed to run pnpm pack: {e}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pnpm pack failed: {}", detail.trim()));
    }
    let entry = std::fs::read_dir(&out_dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .find(|e| e.path().extension().and_then(|x| x.to_str()) == Some("tgz"))
        .ok_or_else(|| "pnpm pack produced no .tgz".to_string())?;
    Ok(entry.path())
}

/// Read a packed tarball's file list and UTF-8 JavaScript sources. Package
/// tarballs nest content under a `package/` prefix, which is stripped to
/// match the packed-path convention used by `package.json#files`.
fn read_tarball(tgz_path: &Path) -> Result<(Vec<String>, HashMap<String, String>), String> {
    let file = std::fs::File::open(tgz_path).map_err(|e| e.to_string())?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let js_re = javascript_file_re();
    let mut files = Vec::new();
    let mut sources = HashMap::new();
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let raw_path = entry.path().map_err(|e| e.to_string())?.to_string_lossy().to_string();
        let path = raw_path.strip_prefix("package/").unwrap_or(&raw_path).to_string();
        let path = normalize_path(&path);
        files.push(path.clone());
        if js_re.is_match(&path) {
            let mut buf = String::new();
            if std::io::Read::read_to_string(&mut entry, &mut buf).is_ok() {
                sources.insert(path, buf);
            }
        }
    }
    files.sort();
    files.dedup();
    Ok((files, sources))
}

pub struct Outcome {
    pub status: &'static str,
    pub message: String,
}

pub fn check(root: &Path) -> Outcome {
    let surface = publication_surface::check(root);
    if !surface.ok {
        return Outcome {
            status: "error",
            message: format!("packed import closure skipped: {}", surface.message),
        };
    }
    let tgz = match pnpm_pack(root) {
        Ok(p) => p,
        Err(e) => {
            return Outcome {
                status: "error",
                message: format!("packed import closure failed: {e}"),
            }
        }
    };
    let result = read_tarball(&tgz);
    let _ = std::fs::remove_file(&tgz);
    if let Some(parent) = tgz.parent() {
        let _ = std::fs::remove_dir(parent);
    }
    let (packed_files, sources) = match result {
        Ok(v) => v,
        Err(e) => {
            return Outcome {
                status: "error",
                message: format!("packed import closure failed: {e}"),
            }
        }
    };
    let missing = find_missing_packed_relative_imports(&packed_files, &sources);
    if missing.is_empty() {
        Outcome {
            status: "pass",
            message: format!("packed import closure passes ({} JavaScript files)", sources.len()),
        }
    } else {
        let detail = missing
            .iter()
            .map(|m| {
                format!(
                    "{} imports {} -> {}",
                    m.from,
                    m.specifier,
                    m.target.as_deref().unwrap_or("outside packed root")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Outcome {
            status: "error",
            message: format!("packed import closure failed: {detail}"),
        }
    }
}

pub fn run(root: &Path) -> bool {
    let result = check(root);
    if result.status == "pass" {
        println!("{}", result.message);
    } else {
        eprintln!("{}", result.message);
    }
    result.status == "pass"
}
