//! Port of `skills/designer/engine/scripts/critique-storage.mjs`'s
//! deterministic core: slug derivation, frontmatter (de)serialization, and
//! snapshot read/write against `.impeccable/critique/`.
//!
//! Not ported: the CLI dispatcher (`main()`), since it is I/O plumbing
//! (argv parsing, stdout/stderr, `process.exit`) over the functions below,
//! not algorithm. The `IMPECCABLE_CRITIQUE_META` env-var passthrough used
//! only by the `write` CLI subcommand is likewise not carried over —
//! callers of `write_snapshot` pass `meta` directly.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::context::{resolve_project_root, TargetOptions};

const SLUG_MAX: usize = 50;
const IMPECCABLE_DIR: &str = ".impeccable";
const CRITIQUE_DIR: &str = "critique";

/// Port of `lib/impeccable-paths.mjs`'s `getCritiqueDir`.
pub fn get_critique_dir(cwd: &Path, options: &TargetOptions) -> PathBuf {
    resolve_project_root(cwd, options)
        .join(IMPECCABLE_DIR)
        .join(CRITIQUE_DIR)
}

/// Mechanically derive a slug from a resolved target. Returns `None` if the
/// input doesn't look like a stable identifier (empty, project root, etc).
pub fn slug_from_target(resolved: &str, cwd: &Path) -> Option<String> {
    let trimmed = resolved.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("http://")
        || trimmed.len() >= 8 && trimmed[..8].eq_ignore_ascii_case("https://")
    {
        let (scheme_len, rest) = if trimmed[..7].eq_ignore_ascii_case("http://") {
            (7, &trimmed[7..])
        } else {
            (8, &trimmed[8..])
        };
        let _ = scheme_len;
        // hostname = up to next '/', '?' or '#'; pathname = the rest up to '?'/'#'.
        let end_authority = rest
            .find(|c: char| c == '/' || c == '?' || c == '#')
            .unwrap_or(rest.len());
        let hostname = &rest[..end_authority];
        // strip userinfo@ and :port from hostname, matching URL's .hostname
        let hostname = hostname.rsplit('@').next().unwrap_or(hostname);
        let hostname = hostname.split(':').next().unwrap_or(hostname);
        if hostname.is_empty() {
            return None;
        }
        let path_and_after = &rest[end_authority..];
        let pathname_end = path_and_after
            .find(|c: char| c == '?' || c == '#')
            .unwrap_or(path_and_after.len());
        let pathname = &path_and_after[..pathname_end];
        let pathname = if pathname.is_empty() { "" } else { pathname };
        return kebab(&format!("{hostname}{pathname}"));
    }

    let abs = if Path::new(trimmed).is_absolute() {
        PathBuf::from(trimmed)
    } else {
        cwd.join(trimmed)
    };
    let mut rel = relative_path(cwd, &abs);
    if rel.starts_with("..") || rel.is_absolute() {
        rel = PathBuf::from(abs.file_name().unwrap_or_default());
    }
    let rel_str = posix_join(&rel);
    if rel_str.is_empty() || rel_str == "." {
        return None;
    }
    kebab(&rel_str)
}

fn relative_path(base: &Path, target: &Path) -> PathBuf {
    let base = lexical_abs(base);
    let target = lexical_abs(target);
    let base_comps: Vec<_> = base.components().collect();
    let target_comps: Vec<_> = target.components().collect();
    let mut i = 0;
    while i < base_comps.len() && i < target_comps.len() && base_comps[i] == target_comps[i] {
        i += 1;
    }
    let mut out = PathBuf::new();
    for _ in i..base_comps.len() {
        out.push("..");
    }
    for comp in &target_comps[i..] {
        out.push(comp.as_os_str());
    }
    out
}

fn lexical_abs(p: &Path) -> PathBuf {
    use std::path::Component;
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push(comp);
                }
            }
            other => out.push(other),
        }
    }
    out
}

fn posix_join(p: &Path) -> String {
    p.components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn kebab(s: &str) -> Option<String> {
    let lower = s.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut last_was_dash = false;
    for ch in lower.chars() {
        let is_sep = ch == '/' || ch == '\\' || ch == '.';
        let is_ok = ch.is_ascii_alphanumeric();
        if is_sep || !is_ok {
            if !last_was_dash {
                out.push('-');
                last_was_dash = true;
            }
        } else {
            out.push(ch);
            last_was_dash = false;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.chars().count() <= SLUG_MAX {
        Some(trimmed)
    } else {
        // Cap from the tail (chars, not bytes, to mirror JS string slicing).
        let chars: Vec<char> = trimmed.chars().collect();
        let tail: String = chars[chars.len() - SLUG_MAX..].iter().collect();
        Some(tail.trim_start_matches('-').to_string())
    }
}

/// Filename-safe UTC ISO timestamp: hyphens for separators, trailing `Z`.
pub fn now_filename_stamp(millis_since_epoch: i64) -> String {
    let iso = iso8601_utc(millis_since_epoch);
    // "2026-05-12T18:30:00.123Z" -> replace ':' and '.' with '-', then drop
    // the numeric run immediately before the trailing Z (the ".123" that just
    // became "-123").
    let replaced: String = iso
        .chars()
        .map(|c| if c == ':' || c == '.' { '-' } else { c })
        .collect();
    // strip a trailing "-\d+Z" back down to "Z"
    if let Some(z_pos) = replaced.rfind('Z') {
        let mut cut = z_pos;
        let bytes = replaced.as_bytes();
        if cut > 0 && bytes[cut - 1].is_ascii_digit() {
            let mut i = cut;
            while i > 0 && bytes[i - 1].is_ascii_digit() {
                i -= 1;
            }
            if i > 0 && bytes[i - 1] == b'-' {
                cut = i - 1;
            }
        }
        format!("{}Z", &replaced[..cut])
    } else {
        replaced
    }
}

fn iso8601_utc(millis: i64) -> String {
    // Minimal UTC-epoch-millis -> ISO8601 formatter (no external time crate
    // dependency), civil_from_days per Howard Hinnant's algorithm.
    let secs_total = millis.div_euclid(1000);
    let ms = millis.rem_euclid(1000);
    let days = secs_total.div_euclid(86400);
    let secs_of_day = secs_total.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, m, d, hh, mm, ss, ms
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Ordered snapshot frontmatter fields, in insertion order (mirrors
/// serializing a JS object literal with `Object.entries`).
pub type Frontmatter = Vec<(String, String)>;

fn serialize_frontmatter(fields: &Frontmatter) -> String {
    let mut lines = vec!["---".to_string()];
    for (key, value) in fields {
        let needs_quotes = value.contains(':') || value.contains('#');
        let rendered = if needs_quotes {
            serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""))
        } else {
            value.clone()
        };
        lines.push(format!("{key}: {rendered}"));
    }
    lines.push("---".to_string());
    lines.join("\n")
}

/// Parses the leading `---\n...\n---` frontmatter block into an ordered map.
/// Numeric-looking values are still returned as strings here (Rust callers
/// parse the fields they need); JSON-quoted strings are unquoted.
pub fn parse_frontmatter(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let re = regex::Regex::new(r"(?s)^---\r?\n(.*?)\r?\n---").unwrap();
    let body = match re.captures(text) {
        Some(caps) => caps[1].to_string(),
        None => return out,
    };
    for line in body.split("\r\n").flat_map(|l| l.split('\n')) {
        let Some(colon) = line.find(':') else { continue };
        let key = line[..colon].trim().to_string();
        let mut value = line[colon + 1..].trim().to_string();
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            if let Ok(unquoted) = serde_json::from_str::<String>(&value) {
                value = unquoted;
            }
        }
        out.insert(key, value);
    }
    out
}

/// Write a snapshot for `slug` under `<critique-dir>/<timestamp>__<slug>.md`.
/// `meta` supplies the frontmatter fields; `timestamp` and `slug` are always
/// added last so they win over any caller-supplied `meta` entries of the
/// same name (mirrors the JS spread-order guarantee).
pub fn write_snapshot(
    cwd: &Path,
    options: &TargetOptions,
    slug: &str,
    mut meta: Frontmatter,
    body: &str,
    now_millis: i64,
) -> std::io::Result<PathBuf> {
    let dir = get_critique_dir(cwd, options);
    fs::create_dir_all(&dir)?;
    let timestamp = now_filename_stamp(now_millis);
    let file_path = dir.join(format!("{timestamp}__{slug}.md"));
    meta.retain(|(k, _)| k != "timestamp" && k != "slug");
    meta.push(("timestamp".to_string(), timestamp));
    meta.push(("slug".to_string(), slug.to_string()));
    let front = serialize_frontmatter(&meta);
    fs::write(&file_path, format!("{front}\n{}\n", body.trim()))?;
    Ok(file_path)
}

/// All snapshot files for `slug`, sorted oldest -> newest (lexical == chronological
/// because filenames are timestamp-prefixed).
fn list_snapshots_for_slug(slug: &str, cwd: &Path, options: &TargetOptions) -> Vec<PathBuf> {
    let dir = get_critique_dir(cwd, options);
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return vec![],
    };
    let suffix = format!("__{slug}.md");
    let mut files: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(&suffix) {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    files.sort();
    files.into_iter().map(|f| dir.join(f)).collect()
}

pub struct Snapshot {
    pub path: PathBuf,
    pub body: String,
    pub meta: BTreeMap<String, String>,
}

/// The most recent snapshot for `slug`, or `None`.
pub fn read_latest_snapshot(slug: &str, cwd: &Path, options: &TargetOptions) -> Option<Snapshot> {
    let all = list_snapshots_for_slug(slug, cwd, options);
    let latest = all.last()?;
    let body = fs::read_to_string(latest).ok()?;
    let meta = parse_frontmatter(&body);
    Some(Snapshot {
        path: latest.clone(),
        body,
        meta,
    })
}

/// The last `limit` snapshots' frontmatter, oldest -> newest.
pub fn read_trend(
    slug: &str,
    limit: usize,
    cwd: &Path,
    options: &TargetOptions,
) -> Vec<BTreeMap<String, String>> {
    let all = list_snapshots_for_slug(slug, cwd, options);
    let start = all.len().saturating_sub(limit);
    all[start..]
        .iter()
        .filter_map(|f| fs::read_to_string(f).ok())
        .map(|body| parse_frontmatter(&body))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion_w2010_critique_{name}_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn slug_from_url() {
        let cwd = tmp_dir("slug_url");
        assert_eq!(
            slug_from_target("https://example.com/pricing/", &cwd),
            Some("example-com-pricing".to_string())
        );
    }

    #[test]
    fn slug_from_relative_file_path() {
        let cwd = tmp_dir("slug_rel");
        assert_eq!(
            slug_from_target("src/App.tsx", &cwd),
            Some("src-app-tsx".to_string())
        );
    }

    #[test]
    fn slug_from_empty_is_none() {
        let cwd = tmp_dir("slug_empty");
        assert_eq!(slug_from_target("", &cwd), None);
        assert_eq!(slug_from_target("   ", &cwd), None);
    }

    #[test]
    fn slug_caps_from_the_tail() {
        let cwd = tmp_dir("slug_cap");
        let long = "a/".repeat(40) + "final-name.tsx";
        let slug = slug_from_target(&long, &cwd).unwrap();
        assert!(slug.chars().count() <= SLUG_MAX);
        assert!(slug.ends_with("final-name-tsx"));
        assert!(!slug.starts_with('-'));
    }

    #[test]
    fn now_filename_stamp_has_no_colons_or_dots() {
        // 2026-05-16T18:30:00.123Z in epoch millis
        let millis: i64 = 1778956200123;
        let stamp = now_filename_stamp(millis);
        assert!(!stamp.contains(':'));
        assert!(!stamp.contains('.'));
        assert!(stamp.ends_with('Z'));
        assert_eq!(stamp, "2026-05-16T18-30-00Z");
    }

    #[test]
    fn write_and_read_latest_snapshot_roundtrip() {
        let cwd = tmp_dir("write_read");
        let options = TargetOptions::none();
        let meta = vec![
            ("score".to_string(), "82".to_string()),
            ("p0".to_string(), "1".to_string()),
            ("p1".to_string(), "3".to_string()),
        ];
        let path = write_snapshot(&cwd, &options, "src-app-tsx", meta, "# Critique\n\nBody text", 1778956200123)
            .unwrap();
        assert!(path.exists());

        let latest = read_latest_snapshot("src-app-tsx", &cwd, &options).unwrap();
        assert_eq!(latest.meta.get("slug").map(String::as_str), Some("src-app-tsx"));
        assert_eq!(latest.meta.get("score").map(String::as_str), Some("82"));
        assert!(latest.body.contains("Body text"));
    }

    #[test]
    fn read_latest_snapshot_none_when_missing() {
        let cwd = tmp_dir("read_missing");
        assert!(read_latest_snapshot("nope", &cwd, &TargetOptions::none()).is_none());
    }

    #[test]
    fn read_trend_returns_oldest_to_newest_limited() {
        let cwd = tmp_dir("trend");
        let options = TargetOptions::none();
        for (i, ts) in [1778956200123i64, 1778956300123, 1778956400123].iter().enumerate() {
            let meta = vec![("score".to_string(), (80 + i).to_string())];
            write_snapshot(&cwd, &options, "slug-x", meta, "body", *ts).unwrap();
        }
        let trend = read_trend("slug-x", 2, &cwd, &options);
        assert_eq!(trend.len(), 2);
        assert_eq!(trend[0].get("score").map(String::as_str), Some("81"));
        assert_eq!(trend[1].get("score").map(String::as_str), Some("82"));
    }

    #[test]
    fn frontmatter_quotes_values_with_colon_or_hash() {
        let fields = vec![("note".to_string(), "a: b # c".to_string())];
        let rendered = serialize_frontmatter(&fields);
        assert!(rendered.contains("note: \"a: b # c\""));
        let parsed = parse_frontmatter(&format!("{rendered}\nbody"));
        assert_eq!(parsed.get("note").map(String::as_str), Some("a: b # c"));
    }
}
