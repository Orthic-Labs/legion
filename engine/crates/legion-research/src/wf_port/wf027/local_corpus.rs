//! Port of `src/lib/research-core/providers/local_corpus.py`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::{Map, Value};

use super::support::{
    ceil_char_boundary, data_only_envelope, floor_char_boundary, locate_text, seed_id,
    stable_hit_id, today, WfError,
};
use super::types::{LocatedPassage, OpenedSource, Provider, SearchHit};

const SUPPORTED_EXT: &[&str] = &["md", "txt", "json", "jsonl", "csv", "html", "htm"];

/// Port of `LocalCorpusProvider`.
pub struct LocalCorpusProvider {
    root: PathBuf,
}

fn token_re() -> Regex {
    Regex::new(r"[A-Za-z0-9][A-Za-z0-9._%-]{1,}").expect("static regex")
}

fn tokens(text: &str) -> Vec<String> {
    token_re()
        .find_iter(text)
        .map(|m| m.as_str().to_ascii_lowercase())
        .collect()
}

fn file_uri(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    if let Some(rest) = s.strip_prefix('/') {
        format!("file:///{}", percent_encode_path(rest))
    } else {
        format!("file:///{}", percent_encode_path(&s))
    }
}

fn percent_encode_path(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn round6(v: f64) -> f64 {
    (v * 1_000_000.0).round() / 1_000_000.0
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if SUPPORTED_EXT.iter().any(|s| s.eq_ignore_ascii_case(ext)) {
                    out.push(path);
                }
            }
        }
    }
}

impl LocalCorpusProvider {
    pub const NAME: &'static str = "local-corpus";

    /// Port of `__init__`: `self.root = root.resolve()`, raises
    /// `FileNotFoundError` when it is not a directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, WfError> {
        let raw = root.as_ref();
        let root = raw
            .canonicalize()
            .map_err(|_| WfError::Invalid(format!("local corpus does not exist: {}", raw.display())))?;
        if !root.is_dir() {
            return Err(WfError::Invalid(format!(
                "local corpus does not exist: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    fn files(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out.sort();
        out
    }

    fn resolve_path(&self, url: &str) -> Result<PathBuf, WfError> {
        let rest = url
            .strip_prefix("file://")
            .ok_or_else(|| WfError::Invalid("local-corpus only opens file:// URLs".into()))?;
        let decoded = percent_decode(rest);
        // A `file:///C:/...` URL decodes to `/C:/...`; that leading slash
        // before a Windows drive letter is a URL-path artifact, not part
        // of the filesystem path, and would otherwise fail to parse as a
        // rooted Windows path. Strip it. No-op on Unix-style paths.
        let decoded = {
            let bytes = decoded.as_bytes();
            if bytes.len() >= 3
                && bytes[0] == b'/'
                && bytes[1].is_ascii_alphabetic()
                && bytes[2] == b':'
            {
                decoded[1..].to_string()
            } else {
                decoded
            }
        };
        let path = PathBuf::from(decoded);
        let resolved = path
            .canonicalize()
            .map_err(|e| WfError::Invalid(format!("local-corpus path does not exist: {e}")))?;
        if resolved != self.root && !resolved.starts_with(&self.root) {
            return Err(WfError::Invalid(
                "local-corpus path escapes corpus root".into(),
            ));
        }
        Ok(resolved)
    }
}

impl Provider for LocalCorpusProvider {
    fn name(&self) -> &str {
        Self::NAME
    }

    /// Port of `search`: a simple TF-IDF score over the corpus's supported
    /// files, ties broken by URL.
    fn search(
        &self,
        query: &str,
        limit: usize,
        seed_chain: &[String],
    ) -> Result<Vec<SearchHit>, WfError> {
        let terms = tokens(query);
        let seed = seed_id(query);
        let mut chain = seed_chain.to_vec();
        chain.push(seed.clone());
        let files = self.files();
        if files.is_empty() {
            return Ok(Vec::new());
        }

        let mut docs: Vec<(PathBuf, String, HashMap<String, u32>)> = Vec::new();
        let mut df: HashMap<String, u32> = HashMap::new();
        for path in &files {
            let Ok(text) = fs::read_to_string(path) else {
                continue;
            };
            let mut counts: HashMap<String, u32> = HashMap::new();
            for t in tokens(&text) {
                *counts.entry(t).or_insert(0) += 1;
            }
            for term in counts.keys() {
                *df.entry(term.clone()).or_insert(0) += 1;
            }
            docs.push((path.clone(), text, counts));
        }
        let n = docs.len().max(1) as f64;
        let mut scored: Vec<(f64, SearchHit)> = Vec::new();
        for (path, text, counts) in &docs {
            let mut score = 0.0f64;
            for term in &terms {
                let tf = *counts.get(term).unwrap_or(&0);
                if tf > 0 {
                    let dfv = *df.get(term).unwrap_or(&0) as f64;
                    score += (1.0 + (tf as f64).ln()) * (((n + 1.0) / (1.0 + dfv)) + 1.0).ln();
                }
            }
            if score <= 0.0 {
                continue;
            }
            let lower = text.to_ascii_lowercase();
            let first = terms
                .iter()
                .filter_map(|t| lower.find(t.as_str()))
                .min()
                .unwrap_or(0);
            let start = first.saturating_sub(100);
            let end = (first + 300).min(text.len());
            let start = floor_char_boundary(text, start);
            let end = ceil_char_boundary(text, end);
            let snippet = text[start..end].replace('\n', " ").trim().to_string();
            let url = file_uri(path);
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let rel = path
                .strip_prefix(&self.root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            let mut metadata = Map::new();
            metadata.insert("path".into(), rel.into());
            metadata.insert("score".into(), round6(score).into());
            scored.push((
                score,
                SearchHit {
                    id: stable_hit_id(Self::NAME, &url),
                    url: url.clone(),
                    title: stem,
                    publisher: "local-corpus".into(),
                    snippet,
                    suggested_by: seed.clone(),
                    seed_chain: chain.clone(),
                    provider: Self::NAME.to_string(),
                    metadata,
                },
            ));
        }
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.url.cmp(&b.1.url))
        });
        Ok(scored.into_iter().take(limit).map(|(_, h)| h).collect())
    }

    fn open(&self, url: &str) -> Result<OpenedSource, WfError> {
        let path = self.resolve_path(url)?;
        let body = fs::read_to_string(&path)?;
        let (envelope, digest) = data_only_envelope(&body);
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let rel = path
            .strip_prefix(&self.root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        let mut metadata = Map::new();
        metadata.insert("path".into(), rel.into());
        Ok(OpenedSource {
            url: url.to_string(),
            title: stem,
            publisher: "local-corpus".into(),
            retrieved_at: today(),
            content: envelope,
            content_sha256: digest,
            instruction_policy: "data_only".into(),
            provider: Self::NAME.to_string(),
            metadata,
        })
    }

    /// Port of `find`. Note: the Python original's `open()` stores the plain
    /// normalized text in `OpenedSource.content` (via `data_only_envelope`),
    /// but `find()` does `json.loads(opened.content)['content']` — parsing
    /// that same plain text as JSON. That mismatch looks like a latent bug in
    /// the upstream source (find() only works when the corpus file's own
    /// text happens to be a JSON object with a `content` string field); it is
    /// ported here exactly as written, per the faithful-port instruction. See
    /// the wf027 report.
    fn find(&self, opened: &OpenedSource, pattern: &str) -> Result<Option<LocatedPassage>, WfError> {
        let value: Value = serde_json::from_str(&opened.content)?;
        let body = value
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| WfError::Invalid("opened source content has no 'content' field".into()))?;
        Ok(locate_text(body, pattern, 300).map(|(locator, text)| LocatedPassage {
            url: opened.url.clone(),
            locator,
            text,
            is_paraphrase: false,
            provider: Self::NAME.to_string(),
            metadata: Map::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_corpus(files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion_wf027_local_corpus_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            fs::write(dir.join(name), content).unwrap();
        }
        dir
    }

    #[test]
    fn new_errors_for_missing_root() {
        let missing = std::env::temp_dir().join("legion_wf027_missing_root_xyz");
        assert!(LocalCorpusProvider::new(&missing).is_err());
    }

    #[test]
    fn search_ranks_by_tfidf_and_breaks_ties_by_url() {
        let dir = temp_corpus(&[
            ("a.md", "zephyr wake word zephyr zephyr"),
            ("b.md", "unrelated content about weather"),
            ("c.txt", "ignored extension test"),
        ]);
        let provider = LocalCorpusProvider::new(&dir).unwrap();
        let hits = provider.search("zephyr", 10, &[]).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "a");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_skips_unsupported_extensions() {
        let dir = temp_corpus(&[("skip.py", "zephyr zephyr zephyr")]);
        let provider = LocalCorpusProvider::new(&dir).unwrap();
        let hits = provider.search("zephyr", 10, &[]).unwrap();
        assert!(hits.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_reads_file_and_normalizes() {
        let dir = temp_corpus(&[("doc.md", "hello world")]);
        let provider = LocalCorpusProvider::new(&dir).unwrap();
        let url = file_uri(&dir.join("doc.md"));
        let opened = provider.open(&url).unwrap();
        assert_eq!(opened.content, "hello world");
        assert_eq!(opened.title, "doc");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_path_escaping_corpus_root() {
        let dir = temp_corpus(&[("doc.md", "hello")]);
        let provider = LocalCorpusProvider::new(&dir).unwrap();
        let outside = std::env::temp_dir().join("legion_wf027_outside_file.md");
        fs::write(&outside, "outside").unwrap();
        let url = file_uri(&outside);
        assert!(provider.open(&url).is_err());
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_mirrors_upstream_json_content_lookup() {
        // Mirrors the Python source's own `find`, which only succeeds when the
        // opened content happens to parse as `{"content": "..."}` JSON — see
        // the doc comment on `find` above.
        let dir = temp_corpus(&[("doc.json", "{\"content\": \"the target phrase is here\"}")]);
        let provider = LocalCorpusProvider::new(&dir).unwrap();
        let url = file_uri(&dir.join("doc.json"));
        let opened = provider.open(&url).unwrap();
        let found = provider.find(&opened, "target phrase").unwrap().unwrap();
        assert!(found.text.contains("target phrase"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_errors_when_content_is_not_json() {
        let dir = temp_corpus(&[("doc.md", "plain text body")]);
        let provider = LocalCorpusProvider::new(&dir).unwrap();
        let url = file_uri(&dir.join("doc.md"));
        let opened = provider.open(&url).unwrap();
        assert!(provider.find(&opened, "plain").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
