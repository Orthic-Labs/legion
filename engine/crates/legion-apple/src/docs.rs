//! Native, local-first Apple docset lookup.
//!
//! This reader consumes the Dash Apple API Reference layout directly. It never
//! downloads a docset, starts a helper process, or writes into a docset.

use brotli::Decompressor;
use rusqlite::{params, Connection, OpenFlags};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

const DEFAULT_MAX_RESULTS: usize = 20;
const MAX_RESULTS: usize = 100;
const DEFAULT_MAX_CHUNKS: usize = 8;
const MAX_CHUNKS: usize = 64;
const DEFAULT_MAX_BYTES: usize = 32 * 1024;
const MAX_BYTES: usize = 128 * 1024;
const DEFAULT_MAX_SCAN_ROWS: usize = 500_000;
const MAX_SCAN_ROWS: usize = 1_000_000;
const MAX_SOURCE_CHUNK_BYTES: u64 = 16 * 1024 * 1024;

/// Return supported native operations and their source-format boundary.
pub fn catalog() -> Value {
    json!({
        "adapter": "legion-apple-docs",
        "source": "local Dash Apple API Reference docset",
        "operations": {
            "discover": "Inspect one supplied docset or read-only Xcode docset candidate and list documentation roots",
            "search": "Bounded case-insensitive searchIndex lookup with exact read pointers",
            "read": "Read one DocC JSON document from cache.db refs and return bounded progressive chunks"
        },
        "arguments": {
            "docset_path": "Optional .docset path; DOCSET_ROOT and standard Xcode paths are fallback candidates",
            "xcode_path": "Optional Xcode.app or Documentation/DocSets path used only for local discovery",
            "language": "Preferred DocC interfaceLanguage, default swift",
            "limit": "Search/root result bound, default 20, maximum 100",
            "max_chunks": "Read content chunk bound, default 8, maximum 64",
            "max_bytes": "Read content byte bound, default 32768, maximum 131072"
        },
        "supported_format": {
            "index": "Contents/Resources/docSet.dsidx SQLite searchIndex table",
            "documents": "Contents/Resources/Documents/cache.db SQLite refs table",
            "chunks": "Contents/Resources/Documents/fs/<data_id>, raw JSON or Brotli-compressed JSON",
            "rendering": "DocC JSON metadata, variants, primaryContentSections, topicSections"
        },
        "effects": ["local filesystem read", "SQLite read-only connection"],
        "unsupported": ["remote documentation", "docset download/update", "unknown archive formats", "writes to docsets"]
    })
}

/// Invoke `discover`, `search`, or `read` using JSON arguments.
pub fn invoke(arguments: &Value) -> Result<Value, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    let operation = object
        .get("operation")
        .or_else(|| object.get("action"))
        .and_then(Value::as_str)
        .unwrap_or("discover")
        .to_ascii_lowercase();
    if operation == "catalog" {
        return Ok(catalog());
    }
    if !matches!(operation.as_str(), "discover" | "search" | "read") {
        return Err(format!("unknown Apple docs operation: {operation}"));
    }
    let source = Source::resolve(object)?;
    match operation.as_str() {
        "discover" => discover(&source, object),
        "search" => search(&source, object),
        "read" => read(&source, object),
        _ => unreachable!(),
    }
}

#[derive(Clone, Debug)]
struct Source {
    root: PathBuf,
    index: PathBuf,
    documents: PathBuf,
    cache: PathBuf,
    fs_root: PathBuf,
}

impl Source {
    fn resolve(arguments: &Map<String, Value>) -> Result<Self, String> {
        let supplied = string_argument(arguments, "docset_path")
            .or_else(|| string_argument(arguments, "docsetPath"));
        let root = if let Some(path) = supplied {
            expand_path(path)
        } else if let Some(path) = string_argument(arguments, "xcode_path")
            .or_else(|| string_argument(arguments, "xcodePath"))
        {
            find_docset_under(&expand_path(path))?.ok_or_else(|| {
                format!("unsupported Apple docs source: no .docset found under {path}")
            })?
        } else {
            default_docset().ok_or_else(|| {
                "unsupported Apple docs source: supply docset_path or xcode_path; no standard Xcode docset was found".to_string()
            })?
        };
        Self::from_root(root)
    }

    fn from_root(root: PathBuf) -> Result<Self, String> {
        let root = root.canonicalize().map_err(|error| {
            format!(
                "Apple docset path is unreadable: {} ({error})",
                root.display()
            )
        })?;
        if root.extension().and_then(|value| value.to_str()) != Some("docset") {
            return Err(format!(
                "unsupported Apple docs source: expected .docset directory, got {}",
                root.display()
            ));
        }
        let resources = root.join("Contents/Resources");
        let documents = resources.join("Documents");
        let index = resources.join("docSet.dsidx");
        let cache = documents.join("cache.db");
        let fs_root = documents.join("fs");
        if !resources.is_dir() || !documents.is_dir() || !index.is_file() || !cache.is_file() {
            return Err(format!(
                "unsupported Apple docs source: {} lacks docSet.dsidx or Documents/cache.db",
                root.display()
            ));
        }
        Ok(Self {
            root,
            index,
            documents,
            cache,
            fs_root,
        })
    }
}

fn default_docset() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(root) = std::env::var_os("DOCSET_ROOT") {
        candidates.push(PathBuf::from(root));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        candidates.push(home.join("Library/Developer/Shared/Documentation/DocSets"));
        candidates.push(home.join("Library/Application Support/Dash/DocSets/Apple_API_Reference/Apple_API_Reference.docset"));
    }
    candidates.push(PathBuf::from(
        "/Applications/Xcode.app/Contents/Developer/Documentation/DocSets",
    ));
    candidates
        .into_iter()
        .find_map(|path| find_docset_under(&path).ok().flatten())
}

fn find_docset_under(path: &Path) -> Result<Option<PathBuf>, String> {
    if path.extension().and_then(|value| value.to_str()) == Some("docset") {
        return Ok(path.to_path_buf().is_dir().then(|| path.to_path_buf()));
    }
    if !path.is_dir() {
        return Ok(None);
    }
    let mut candidates = fs::read_dir(path)
        .map_err(|error| {
            format!(
                "cannot inspect local Xcode path {}: {error}",
                path.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|entry| entry.extension().and_then(|value| value.to_str()) == Some("docset"))
        .collect::<Vec<_>>();
    candidates.sort();
    Ok(candidates.into_iter().next())
}

fn expand_path(value: &str) -> PathBuf {
    if value == "~" {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(value));
    }
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(value)
}

fn discover(source: &Source, arguments: &Map<String, Value>) -> Result<Value, String> {
    let index = open_read_only(&source.index)?;
    let cache = open_read_only(&source.cache)?;
    let roots = documentation_roots(
        &index,
        bounded(arguments, "limit", DEFAULT_MAX_RESULTS, MAX_RESULTS)?,
    )?;
    let ref_count: i64 = cache
        .query_row("SELECT COUNT(*) FROM refs", [], |row| row.get(0))
        .map_err(|error| format!("unsupported Apple docs cache schema: {error}"))?;
    Ok(json!({
        "operation": "discover",
        "supported": true,
        "source": source_pointer(source, None),
        "format": {
            "index_table": "searchIndex",
            "cache_table": "refs",
            "chunk_directory": source.fs_root,
            "cache_records": ref_count
        },
        "documentation_roots": roots,
        "limits": {"roots": bounded(arguments, "limit", DEFAULT_MAX_RESULTS, MAX_RESULTS)?}
    }))
}

fn search(source: &Source, arguments: &Map<String, Value>) -> Result<Value, String> {
    let query = string_argument(arguments, "query")
        .or_else(|| string_argument(arguments, "q"))
        .ok_or_else(|| "search requires query".to_string())?;
    let query = query.trim();
    if query.is_empty() || query.len() > 256 {
        return Err("search query must contain 1..256 characters".to_string());
    }
    let limit = bounded(arguments, "limit", DEFAULT_MAX_RESULTS, MAX_RESULTS)?;
    let index = open_read_only(&source.index)?;
    let path_prefix = string_argument(arguments, "path_prefix");
    let pattern = format!("%{query}%");
    let mut statement = if path_prefix.is_some() {
        index.prepare("SELECT name, type, path FROM searchIndex WHERE (name LIKE ?1 COLLATE NOCASE OR path LIKE ?1 COLLATE NOCASE) AND path LIKE ?2 COLLATE NOCASE ORDER BY name, path LIMIT ?3")
    } else {
        index.prepare("SELECT name, type, path FROM searchIndex WHERE (name LIKE ?1 COLLATE NOCASE OR path LIKE ?1 COLLATE NOCASE) ORDER BY name, path LIMIT ?2")
    }.map_err(|error| format!("unsupported Apple docs index schema: {error}"))?;
    let mut rows = if let Some(prefix) = path_prefix.as_deref() {
        statement.query(params![pattern, format!("{prefix}%"), limit as i64])
    } else {
        statement.query(params![pattern, limit as i64])
    }
    .map_err(|error| format!("Apple docs search failed: {error}"))?;
    let mut results = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| format!("Apple docs search failed: {error}"))?
    {
        let name: String = row.get(0).unwrap_or_default();
        let kind: i64 = row.get(1).unwrap_or_default();
        let raw_path: String = row.get(2).unwrap_or_default();
        results.push(json!({
            "name": name,
            "type": kind,
            "path": doc_path_from_index(&raw_path),
            "source": {
                "docset": source.root,
                "index": source.index,
                "table": "searchIndex",
                "name": name,
                "path": raw_path,
                "read": {"operation": "read", "path": doc_path_from_index(&raw_path)}
            }
        }));
    }
    Ok(json!({"operation": "search", "query": query, "results": results, "limit": limit}))
}

fn read(source: &Source, arguments: &Map<String, Value>) -> Result<Value, String> {
    let requested = string_argument(arguments, "path")
        .or_else(|| string_argument(arguments, "doc_path"))
        .ok_or_else(|| "read requires path".to_string())?;
    let path = doc_path_from_index(requested.trim());
    if !path.starts_with("/documentation/") {
        return Err(format!("unsupported Apple docs path: {path}"));
    }
    let language = string_argument(arguments, "language").unwrap_or_else(|| "swift".to_string());
    let max_chunks = bounded(arguments, "max_chunks", DEFAULT_MAX_CHUNKS, MAX_CHUNKS)?;
    let max_bytes = bounded(arguments, "max_bytes", DEFAULT_MAX_BYTES, MAX_BYTES)?;
    let max_rows = bounded(
        arguments,
        "max_scan_rows",
        DEFAULT_MAX_SCAN_ROWS,
        MAX_SCAN_ROWS,
    )?;
    let cache = open_read_only(&source.cache)?;
    let mut statement = cache
        .prepare("SELECT data_id, uuid, offset, length FROM refs ORDER BY data_id, offset LIMIT ?1")
        .map_err(|error| format!("unsupported Apple docs cache schema: {error}"))?;
    let mut rows = statement
        .query(params![max_rows as i64])
        .map_err(|error| format!("Apple docs cache read failed: {error}"))?;
    let mut chunks = HashMap::<i64, Vec<u8>>::new();
    let mut scanned = 0usize;
    let mut found: Option<(Value, SourcePointer)> = None;
    while let Some(row) = rows
        .next()
        .map_err(|error| format!("Apple docs cache read failed: {error}"))?
    {
        scanned += 1;
        let data_id: i64 = row
            .get(0)
            .map_err(|error| format!("invalid refs.data_id: {error}"))?;
        let uuid: String = row.get(1).unwrap_or_default();
        let offset: i64 = row
            .get(2)
            .map_err(|error| format!("invalid refs.offset: {error}"))?;
        let length: i64 = row
            .get(3)
            .map_err(|error| format!("invalid refs.length: {error}"))?;
        let bytes = if let Some(bytes) = chunks.get(&data_id) {
            bytes.clone()
        } else {
            let bytes = read_chunk(source, data_id)?;
            chunks.insert(data_id, bytes.clone());
            bytes
        };
        if offset < 0 || length < 0 || (offset as usize) > bytes.len() {
            continue;
        }
        let end = (offset as usize)
            .saturating_add(length as usize)
            .min(bytes.len());
        let document: Value = match serde_json::from_slice(&bytes[offset as usize..end]) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if document_paths(&document, &language)
            .iter()
            .any(|candidate| candidate == &path)
            || document_paths(&document, "")
                .iter()
                .any(|candidate| candidate == &path)
        {
            let encoding = chunk_encoding(source, data_id);
            found = Some((
                document,
                SourcePointer {
                    source: source.clone(),
                    data_id,
                    uuid,
                    offset,
                    length,
                    encoding,
                },
            ));
            break;
        }
    }
    let (document, pointer) = found.ok_or_else(|| {
        format!("Apple documentation path not found after scanning {scanned} cache records: {path}")
    })?;
    Ok(render_read(
        &document, &path, &language, pointer, max_chunks, max_bytes,
    ))
}

fn documentation_roots(index: &Connection, limit: usize) -> Result<Vec<Value>, String> {
    let mut statement = index.prepare("SELECT path FROM searchIndex WHERE path LIKE 'dash-apple-api://load?request_key=ls/documentation/%' LIMIT ?1")
        .map_err(|error| format!("unsupported Apple docs index schema: {error}"))?;
    let mut rows = statement
        .query(params![((limit * 200).min(20_000)) as i64])
        .map_err(|error| format!("Apple docs root lookup failed: {error}"))?;
    let mut roots = std::collections::BTreeSet::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| format!("Apple docs root lookup failed: {error}"))?
    {
        let raw: String = row.get(0).unwrap_or_default();
        let path = doc_path_from_index(&raw);
        let mut pieces = path.trim_start_matches('/').split('/');
        if pieces.next() == Some("documentation") {
            if let Some(module) = pieces.next() {
                roots.insert(format!("/documentation/{module}"));
            }
        }
    }
    Ok(roots
        .into_iter()
        .take(limit)
        .map(|path| json!({"path": path}))
        .collect())
}

fn render_read(
    document: &Value,
    path: &str,
    language: &str,
    pointer: SourcePointer,
    max_chunks: usize,
    max_bytes: usize,
) -> Value {
    let metadata = document.get("metadata").unwrap_or(&Value::Null);
    let mut chunks = Vec::new();
    let mut used = 0usize;
    let sections = document
        .get("primaryContentSections")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (index, section) in sections.iter().enumerate().take(max_chunks) {
        let mut text = String::new();
        collect_text(section, &mut text, max_bytes.saturating_sub(used));
        let text = text.trim().to_string();
        if text.is_empty() {
            continue;
        }
        let available = max_bytes.saturating_sub(used);
        let (text, truncated) = truncate_utf8(&text, available);
        used = used.saturating_add(text.len());
        chunks.push(json!({
            "index": index,
            "kind": section.get("kind").and_then(Value::as_str).unwrap_or("unknown"),
            "text": text,
            "truncated": truncated,
            "source": pointer.json_pointer(format!("/primaryContentSections/{index}"))
        }));
        if used >= max_bytes {
            break;
        }
    }
    json!({
        "operation": "read",
        "path": path,
        "language": language,
        "summary": {
            "title": metadata.get("title").and_then(Value::as_str).or_else(|| document.get("title").and_then(Value::as_str)),
            "role": metadata.get("roleHeading").or_else(|| document.get("kind")),
            "abstract": bounded_text(document.get("abstract"), 2048),
            "identifier": document.get("identifier").and_then(|value| value.get("url")),
            "variants": document_variants(document),
            "topic_section_count": document.get("topicSections").and_then(Value::as_array).map_or(0, Vec::len),
            "primary_section_count": sections.len()
        },
        "structure": structure(document),
        "chunks": chunks,
        "truncated": used >= max_bytes || sections.len() > max_chunks,
        "source": pointer.value()
    })
}

#[derive(Clone, Debug)]
struct SourcePointer {
    source: Source,
    data_id: i64,
    uuid: String,
    offset: i64,
    length: i64,
    encoding: &'static str,
}

impl SourcePointer {
    fn value(&self) -> Value {
        json!({"docset": self.source.root, "cache_db": self.source.cache, "table": "refs", "data_id": self.data_id, "uuid": self.uuid, "offset": self.offset, "length": self.length, "chunk_file": self.source.fs_root.join(self.data_id.to_string()), "encoding": self.encoding})
    }
    fn json_pointer(&self, pointer: String) -> Value {
        let mut value = self.value();
        value["json_pointer"] = Value::String(pointer);
        value
    }
}

fn source_pointer(source: &Source, extra: Option<Value>) -> Value {
    let mut value = json!({"kind": "dash-apple-docset", "docset": source.root, "index": source.index, "cache_db": source.cache, "documents": source.documents, "chunk_directory": source.fs_root});
    if let Some(extra) = extra {
        value["detail"] = extra;
    }
    value
}

fn structure(document: &Value) -> Value {
    let sections = document
        .get("primaryContentSections")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({
        "primary_content": sections.iter().enumerate().map(|(index, section)| json!({"index": index, "kind": section.get("kind"), "keys": section.as_object().map(|object| object.keys().cloned().collect::<Vec<_>>()).unwrap_or_default()})).collect::<Vec<_>>(),
        "topics": document.get("topicSections").and_then(Value::as_array).map(|items| items.iter().map(|item| json!({"title": item.get("title"), "identifier_count": item.get("identifiers").and_then(Value::as_array).map_or(0, Vec::len)})).collect::<Vec<_>>()).unwrap_or_default()
    })
}

fn document_variants(document: &Value) -> Vec<Value> {
    document.get("variants").and_then(Value::as_array).map(|variants| variants.iter().map(|variant| json!({"languages": variant.get("traits"), "paths": variant.get("paths")})).collect()).unwrap_or_default()
}

fn document_paths(document: &Value, language: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for variant in document
        .get("variants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let languages = variant
            .get("traits")
            .and_then(Value::as_array)
            .map(|traits| {
                traits
                    .iter()
                    .filter_map(|trait_value| {
                        trait_value.get("interfaceLanguage").and_then(Value::as_str)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if language.is_empty()
            || languages.is_empty()
            || languages.iter().any(|value| *value == language)
        {
            if let Some(items) = variant.get("paths").and_then(Value::as_array) {
                paths.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
            }
        }
    }
    paths
}

fn read_chunk(source: &Source, data_id: i64) -> Result<Vec<u8>, String> {
    if data_id < 0 {
        return Err(format!("invalid negative Apple docs data_id: {data_id}"));
    }
    let path = source.fs_root.join(data_id.to_string());
    let file_size = fs::metadata(&path)
        .map_err(|error| {
            format!(
                "cannot inspect Apple docs chunk {}: {error}",
                path.display()
            )
        })?
        .len();
    if file_size > MAX_SOURCE_CHUNK_BYTES {
        return Err(format!(
            "Apple docs chunk {} exceeds {} byte safety bound",
            path.display(),
            MAX_SOURCE_CHUNK_BYTES
        ));
    }
    let bytes = fs::read(&path)
        .map_err(|error| format!("cannot read Apple docs chunk {}: {error}", path.display()))?;
    if bytes
        .first()
        .is_some_and(|byte| *byte == b'{' || *byte == b'[')
    {
        return Ok(bytes);
    }
    let mut decoder = Decompressor::new(Cursor::new(bytes), 16 * 1024);
    let mut output = Vec::new();
    decoder
        .take(MAX_SOURCE_CHUNK_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|error| {
            format!(
                "cannot decompress Apple docs chunk {}: {error}",
                path.display()
            )
        })?;
    if output.len() as u64 > MAX_SOURCE_CHUNK_BYTES {
        return Err(format!(
            "decompressed Apple docs chunk {} exceeds {} byte safety bound",
            path.display(),
            MAX_SOURCE_CHUNK_BYTES
        ));
    }
    Ok(output)
}

fn chunk_encoding(source: &Source, data_id: i64) -> &'static str {
    fs::read(source.fs_root.join(data_id.to_string()))
        .ok()
        .and_then(|bytes| bytes.first().copied())
        .map_or("brotli", |byte| {
            if byte == b'{' || byte == b'[' {
                "json"
            } else {
                "brotli"
            }
        })
}

fn open_read_only(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|error| {
        format!(
            "cannot open Apple docs SQLite {} read-only: {error}",
            path.display()
        )
    })
}

fn doc_path_from_index(raw: &str) -> String {
    let raw = raw.split('#').next().unwrap_or(raw);
    if let Some(value) = raw.strip_prefix("dash-apple-api://load?request_key=") {
        return value.strip_prefix("ls").unwrap_or(value).to_string();
    }
    raw.to_string()
}

fn string_argument(arguments: &Map<String, Value>, key: &str) -> Option<String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn bounded(
    arguments: &Map<String, Value>,
    key: &str,
    default: usize,
    max: usize,
) -> Result<usize, String> {
    match arguments.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value > 0 && *value <= max)
            .ok_or_else(|| format!("{key} must be an integer in 1..{max}")),
    }
}

fn bounded_text(value: Option<&Value>, limit: usize) -> String {
    let mut text = String::new();
    if let Some(value) = value {
        collect_text(value, &mut text, limit);
    }
    truncate_utf8(text.trim(), limit).0
}

fn collect_text(value: &Value, output: &mut String, limit: usize) {
    if output.len() >= limit {
        return;
    }
    match value {
        Value::String(text) => {
            let (text, _) = truncate_utf8(text, limit.saturating_sub(output.len()));
            output.push_str(text);
            output.push(' ');
        }
        Value::Array(items) => {
            for item in items {
                collect_text(item, output, limit);
                if output.len() >= limit {
                    break;
                }
            }
        }
        Value::Object(object) => {
            for key in [
                "text",
                "title",
                "code",
                "name",
                "content",
                "inlineContent",
                "abstract",
            ] {
                if let Some(value) = object.get(key) {
                    collect_text(value, output, limit);
                    if output.len() >= limit {
                        break;
                    }
                }
            }
        }
        _ => {}
    }
}

fn truncate_utf8(value: &str, limit: usize) -> (&str, bool) {
    if value.len() <= limit {
        (value, false)
    } else {
        let mut end = limit;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        (&value[..end], true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture(PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> Fixture {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("legion-docs-{stamp}.docset"));
        let resources = root.join("Contents/Resources");
        let documents = resources.join("Documents");
        fs::create_dir_all(documents.join("fs")).unwrap();
        Connection::open(resources.join("docSet.dsidx")).unwrap().execute_batch("CREATE TABLE searchIndex(name TEXT, type INTEGER, path TEXT); INSERT INTO searchIndex VALUES ('Demo', 0, 'dash-apple-api://load?request_key=ls/documentation/demo');").unwrap();
        let cache_path = documents.join("cache.db");
        let cache = Connection::open(&cache_path).unwrap();
        cache
            .execute_batch(
                "CREATE TABLE refs(data_id INTEGER, uuid TEXT, offset INTEGER, length INTEGER);",
            )
            .unwrap();
        let document = br#"{"identifier":{"url":"doc://demo"},"metadata":{"title":"Demo","roleHeading":"Article"},"variants":[{"traits":[{"interfaceLanguage":"swift"}],"paths":["/documentation/demo"]}],"abstract":[{"type":"paragraph","inlineContent":[{"type":"text","text":"A local demo."}]}],"primaryContentSections":[{"kind":"content","content":[{"type":"paragraph","inlineContent":[{"type":"text","text":"Grounded content."}]}]}],"topicSections":[]}"#;
        fs::write(documents.join("fs/1"), document).unwrap();
        cache
            .execute(
                "INSERT INTO refs VALUES (1, 'uuid-demo', 0, ?1)",
                [document.len() as i64],
            )
            .unwrap();
        Fixture(root)
    }

    #[test]
    fn catalog_exposes_native_source_boundary() {
        let value = catalog();
        assert_eq!(
            value["operations"]["read"],
            "Read one DocC JSON document from cache.db refs and return bounded progressive chunks"
        );
        assert_eq!(
            value["supported_format"]["chunks"],
            "Contents/Resources/Documents/fs/<data_id>, raw JSON or Brotli-compressed JSON"
        );
    }

    #[test]
    fn discover_reports_roots_and_cache_records() {
        let fixture = fixture();
        let result = invoke(&json!({"operation":"discover", "docset_path": fixture.0})).unwrap();
        assert_eq!(result["supported"], true);
        assert_eq!(result["format"]["cache_records"], 1);
        assert_eq!(
            result["documentation_roots"][0]["path"],
            "/documentation/demo"
        );
    }

    #[test]
    fn search_returns_exact_read_pointer() {
        let fixture = fixture();
        let result =
            invoke(&json!({"operation":"search", "docset_path": fixture.0, "query":"demo"}))
                .unwrap();
        assert_eq!(result["results"][0]["path"], "/documentation/demo");
        assert_eq!(result["results"][0]["source"]["table"], "searchIndex");
        assert_eq!(
            result["results"][0]["source"]["read"]["path"],
            "/documentation/demo"
        );
    }

    #[test]
    fn read_returns_bounded_content_and_cache_pointer() {
        let fixture = fixture();
        let result = invoke(&json!({"operation":"read", "docset_path": fixture.0, "path":"/documentation/demo", "max_bytes":8})).unwrap();
        assert_eq!(result["summary"]["title"], "Demo");
        assert_eq!(result["source"]["data_id"], 1);
        assert_eq!(result["source"]["offset"], 0);
        assert_eq!(result["chunks"][0]["truncated"], true);
    }
}
