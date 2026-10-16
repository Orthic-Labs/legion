//! Optional Membrane/Blueprint artifact consumption; no transport or extraction service.
//! Lexical imports are dependency leads, never a call graph or proof of dead code.
use crate::source_cache::bytes_digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub const GRAPH_CONTRACT: &str = "legion-graph/1";
const MAX_FILES: usize = 20_000;
const MAX_NODES: usize = 50_000;
const MAX_EDGES: usize = 100_000;
const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

/// Load explicitly selected host data, never repository-discovered graph input.
/// RightKit pins the parent without following symlinks/reparse points & caps the
/// regular-file read before JSON parsing. On Unix that parent must be user-owned
/// & not group/other writable. This authenticates no Blueprint producer: callers
/// must still validate source/resolver bindings with `build_graph_context`.
pub fn load_host_artifact(path: &Path, disallowed_roots: &[&Path]) -> Result<Value, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("blueprint-artifact-input-path-not-absolute-or-traversal".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "blueprint-artifact-input-parent-missing".to_owned())?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "blueprint-artifact-input-file-name-invalid".to_owned())?;
    let directory = rightkit_fs::state::StateDir::open(parent)
        .map_err(|error| format!("blueprint-artifact-input-parent-rejected: {error}"))?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("blueprint-artifact-input-unavailable: {error}"))?;
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    if !metadata.is_file() || metadata.file_type().is_symlink() || reparse {
        return Err("blueprint-artifact-input-not-regular-file".into());
    }
    if metadata.len() > MAX_ARTIFACT_BYTES as u64 {
        return Err("blueprint-artifact-input-cap-exceeded".into());
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("blueprint-artifact-input-unavailable: {error}"))?;
    for root in disallowed_roots {
        let root = root
            .canonicalize()
            .map_err(|error| format!("blueprint-artifact-input-root-unavailable: {error}"))?;
        if canonical.starts_with(root) {
            return Err("blueprint-artifact-input-inside-audited-root".into());
        }
    }
    let bytes = directory
        .read(name, MAX_ARTIFACT_BYTES as u64)
        .map_err(|error| format!("blueprint-artifact-input-read-rejected: {error}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("blueprint-artifact-input-invalid-json: {error}"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceSpan {
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
    pub source_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContextEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub confidence: String,
    pub source: String,
    pub evidence: SourceSpan,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphUnknown {
    pub path: Option<String>,
    pub cause: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphContext {
    pub contract_version: String,
    pub blueprint_version: Option<String>,
    pub scoped_bytes_digest: String,
    pub covered_files_digest: Option<String>,
    pub resolver_config_digest: String,
    pub coverage_floor: String,
    pub freshness: String,
    pub trusted_files: Vec<String>,
    pub edges: Vec<ContextEdge>,
    pub unknowns: Vec<GraphUnknown>,
    pub truncated: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlastRadiusContext {
    pub coverage_floor: String,
    pub freshness: String,
    pub scoped_bytes_digest: String,
    pub covered_files_digest: Option<String>,
    pub blueprint_version: Option<String>,
    pub resolver_config_digest: String,
    pub certain: Vec<ContextEdge>,
    pub inferred: Vec<ContextEdge>,
    pub unknowns: Vec<GraphUnknown>,
    pub truncated: bool,
    /// Always false: even zero callers in a fresh partial graph cannot establish dead code.
    pub proves_dead_code: bool,
}

/// `scopedBytesDigest` binds ordered path -> raw SHA-256 hex over exact frozen bytes.
/// `coveredFilesDigest` independently binds sorted coverage membership.
pub fn scoped_bytes_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
    let digests: BTreeMap<_, _> = files
        .iter()
        .map(|(path, bytes)| (path, bytes_digest(bytes)))
        .collect();
    bytes_digest(&serde_json::to_vec(&digests).expect("string map serialization"))
}
pub fn covered_files_digest(files: &[String]) -> String {
    let paths: BTreeSet<_> = files.iter().collect();
    bytes_digest(&serde_json::to_vec(&paths).expect("string set serialization"))
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
fn unknown(path: Option<String>, cause: impl Into<String>) -> GraphUnknown {
    GraphUnknown {
        path,
        cause: cause.into(),
    }
}
fn span(value: &Value, path: &str, files: &BTreeMap<String, Vec<u8>>) -> Option<SourceSpan> {
    let path = value.get("path").and_then(Value::as_str).unwrap_or(path);
    if !safe_path(path) {
        return None;
    }
    let bytes = files.get(path)?;
    let range = value.get("range").unwrap_or(value);
    let start = range.get("startLine").and_then(Value::as_u64).or_else(|| {
        range
            .get("start")
            .and_then(|s| s.get("line"))
            .and_then(Value::as_u64)
    })?;
    let end = range
        .get("endLine")
        .and_then(Value::as_u64)
        .or_else(|| {
            range
                .get("end")
                .and_then(|s| s.get("line"))
                .and_then(Value::as_u64)
        })
        .unwrap_or(start);
    // 1-based lines; empty source has no valid source span.
    let line_count = if bytes.is_empty() {
        0
    } else {
        bytes.split(|b| *b == b'\n').count() as u64
    };
    if start == 0 || end < start || end > line_count {
        return None;
    }
    Some(SourceSpan {
        path: path.into(),
        start_line: start,
        end_line: end,
        source_digest: bytes_digest(bytes),
    })
}

pub fn build_graph_context(
    files: &BTreeMap<String, Vec<u8>>,
    artifact: Option<&Value>,
    resolver_config_digest: &str,
) -> GraphContext {
    let mut context = GraphContext {
        contract_version: GRAPH_CONTRACT.into(),
        scoped_bytes_digest: scoped_bytes_digest(files),
        resolver_config_digest: resolver_config_digest.into(),
        coverage_floor: "lexical-js-ts-relative-imports-only".into(),
        freshness: "artifact-absent".into(),
        ..Default::default()
    };
    lexical_edges(files, &mut context);
    let Some(artifact) = artifact else {
        context.unknowns.push(unknown(None, "blueprint-unavailable; lexical imports do not cover calls, dynamic dispatch or reflection"));
        return context;
    };
    context.freshness = "artifact-rejected-unbound-or-stale".into();
    if serde_json::to_vec(artifact).map_or(true, |v| v.len() > MAX_ARTIFACT_BYTES) {
        context.truncated = true;
        context
            .unknowns
            .push(unknown(None, "blueprint-artifact-cap-exceeded"));
        return context;
    }
    if let Err(cause) = consume_artifact(files, artifact, resolver_config_digest, &mut context) {
        context.unknowns.push(unknown(None, cause));
    }
    context.edges.sort_by(|a, b| {
        (&a.from, &a.to, &a.kind, &a.source).cmp(&(&b.from, &b.to, &b.kind, &b.source))
    });
    context.edges.dedup();
    context
}

/// Reuse only deterministic graph context for exact frozen source, supplied graph bytes &
/// validator/resolver identity. No model output, test/build result or network advisory enters here.
pub fn build_graph_context_cached(
    files: &BTreeMap<String, Vec<u8>>,
    artifact: Option<&Value>,
    resolver_config_digest: &str,
    cache: &mut crate::source_cache::SourceCache,
) -> GraphContext {
    let mut extra = BTreeMap::new();
    extra.insert(
        "artifactDigest".into(),
        bytes_digest(&serde_json::to_vec(&artifact).expect("JSON value serialization")),
    );
    let identity = crate::source_cache::FactIdentity {
        source_digest: scoped_bytes_digest(files), extractor_id: "audit-graph-context".into(),
        extractor_version: "2".into(), schema_version: GRAPH_CONTRACT.into(),
        config_digest: bytes_digest(format!("files={MAX_FILES};nodes={MAX_NODES};edges={MAX_EDGES};artifact={MAX_ARTIFACT_BYTES};js-ts-relative-imports/1").as_bytes()),
        resolver_digest: resolver_config_digest.into(), extra, ..Default::default()
    };
    let result = cache.fact(&identity, || {
        serde_json::to_vec(&build_graph_context(
            files,
            artifact,
            resolver_config_digest,
        ))
        .map_err(std::io::Error::other)
    });
    if let Ok(bytes) = result {
        if let Ok(context) = serde_json::from_slice(&bytes) {
            return context;
        }
        cache.stats.rejected_entries += 1;
    }
    build_graph_context(files, artifact, resolver_config_digest)
}

fn consume_artifact(
    files: &BTreeMap<String, Vec<u8>>,
    artifact: &Value,
    resolver: &str,
    context: &mut GraphContext,
) -> Result<(), String> {
    let fail = |message: &str| message.to_owned();
    if artifact.get("contractVersion").and_then(Value::as_str) != Some(GRAPH_CONTRACT) {
        return Err(fail("blueprint-foreign-contract"));
    }
    let version = artifact
        .get("blueprintVersion")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail("blueprint-unbound-version"))?;
    if artifact.get("resolverConfigDigest").and_then(Value::as_str) != Some(resolver) {
        return Err(fail("blueprint-resolver-unbound-or-stale"));
    }
    let covered = artifact
        .pointer("/coverage/files")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("blueprint-coverage-missing"))?;
    let nodes = artifact
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("blueprint-nodes-missing"))?;
    let edges = artifact
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("blueprint-edges-missing"))?;
    if covered.len() > MAX_FILES || nodes.len() > MAX_NODES || edges.len() > MAX_EDGES {
        context.truncated = true;
        return Err(fail("blueprint-graph-cap-exceeded"));
    }
    let mut subset = BTreeMap::new();
    for path in covered {
        let path = path
            .as_str()
            .filter(|p| safe_path(p))
            .ok_or_else(|| fail("blueprint-path-escape"))?;
        let bytes = files
            .get(path)
            .ok_or_else(|| fail("blueprint-foreign-file"))?;
        if subset.insert(path.to_owned(), bytes.clone()).is_some() {
            return Err(fail("blueprint-duplicate-coverage"));
        }
    }
    let covered_paths: Vec<_> = subset.keys().cloned().collect();
    let membership_digest = covered_files_digest(&covered_paths);
    if artifact.get("coveredFilesDigest").and_then(Value::as_str)
        != Some(membership_digest.as_str())
    {
        return Err(fail("blueprint-covered-files-unbound-or-stale"));
    }
    if artifact.get("scopedBytesDigest").and_then(Value::as_str)
        != Some(scoped_bytes_digest(&subset).as_str())
    {
        return Err(fail("blueprint-stale"));
    }
    // Validate entire identity before changing lexical floor. Invalid edges remain explicit unknowns.
    let mut node_map = BTreeMap::new();
    for node in nodes {
        let id = node
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("blueprint-node-id-missing"))?;
        let path = node
            .get("path")
            .and_then(Value::as_str)
            .filter(|p| safe_path(p))
            .ok_or_else(|| fail("blueprint-path-escape"))?;
        if !subset.contains_key(path) {
            return Err(fail("blueprint-node-outside-coverage"));
        }
        if !matches!(
            node.get("kind").and_then(Value::as_str),
            Some("file" | "symbol" | "test")
        ) {
            return Err(fail("blueprint-node-kind-unknown"));
        }
        if node_map.insert(id, (path, node)).is_some() {
            return Err(fail("blueprint-duplicate-node"));
        }
    }
    let mut accepted = Vec::new();
    let mut gaps = Vec::new();
    for edge in edges {
        let from = edge
            .get("from")
            .and_then(Value::as_str)
            .and_then(|id| node_map.get(id));
        let to = edge
            .get("to")
            .and_then(Value::as_str)
            .and_then(|id| node_map.get(id));
        let (Some((from, _)), Some((to, _))) = (from, to) else {
            gaps.push(unknown(None, "blueprint-edge-node-missing"));
            continue;
        };
        let kind = edge.get("kind").and_then(Value::as_str).unwrap_or("");
        let confidence = edge.get("confidence").and_then(Value::as_str).unwrap_or("");
        if !matches!(kind, "imports" | "calls" | "implements" | "tests")
            || !matches!(confidence, "certain" | "likely" | "possible")
        {
            gaps.push(unknown(
                Some((*from).into()),
                "blueprint-edge-kind-or-confidence-unknown",
            ));
            continue;
        }
        let evidence = edge.get("evidence").and_then(|v| span(v, from, &subset));
        let Some(evidence) = evidence.filter(|span| span.path == *from) else {
            gaps.push(unknown(
                Some((*from).into()),
                "blueprint-edge-source-span-missing",
            ));
            continue;
        };
        accepted.push(ContextEdge {
            from: (*from).into(),
            to: (*to).into(),
            kind: kind.into(),
            confidence: confidence.into(),
            source: "blueprint".into(),
            evidence,
        });
    }
    let explicitly_truncated = artifact
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    context.truncated |= explicitly_truncated;
    if explicitly_truncated {
        gaps.push(unknown(None, "blueprint-truncated"));
    }
    if let Some(unsupported) = artifact
        .pointer("/coverage/unsupported")
        .and_then(Value::as_array)
    {
        for gap in unsupported {
            gaps.push(unknown(
                gap.get("path")
                    .and_then(Value::as_str)
                    .filter(|p| safe_path(p))
                    .map(str::to_owned),
                format!(
                    "blueprint-unsupported: {}",
                    gap.get("cause")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                ),
            ));
        }
    }
    if let Some(unknowns) = artifact.get("unknowns").and_then(Value::as_array) {
        for gap in unknowns {
            gaps.push(unknown(
                gap.pointer("/location/path")
                    .and_then(Value::as_str)
                    .filter(|p| safe_path(p))
                    .map(str::to_owned),
                format!(
                    "blueprint-unknown: {}",
                    gap.get("cause")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified")
                ),
            ));
        }
    }
    // Retain lexical imports for files with malformed edges, explicit unknowns or truncation.
    // Only fully accepted per-file graph evidence may replace lexical edges.
    let gap_paths: BTreeSet<_> = gaps.iter().filter_map(|g| g.path.as_deref()).collect();
    let global_gap = gaps.iter().any(|g| g.path.is_none());
    context.edges.retain(|edge| {
        !subset.contains_key(&edge.from) || global_gap || gap_paths.contains(edge.from.as_str())
    });
    context.edges.extend(accepted);
    for path in files.keys().filter(|p| !subset.contains_key(*p)) {
        gaps.push(unknown(
            Some(path.clone()),
            "blueprint-file-uncovered; lexical floor",
        ));
    }
    context.unknowns.extend(gaps);
    context.trusted_files = covered_paths;
    context.blueprint_version = Some(version.into());
    context.freshness = "bound-to-frozen-covered-bytes".into();
    context.covered_files_digest = Some(membership_digest);
    context.coverage_floor = "provenance-bound-blueprint-plus-lexical-floor".into();
    // Even a fully covered file graph may omit dynamic relationships.
    context.unknowns.push(unknown(
        None,
        "graph absence never proves dead code; dynamic relationships remain unknown",
    ));
    Ok(())
}

impl GraphContext {
    pub fn compact_blast_radius(
        &self,
        changed_paths: &[String],
        max_edges: usize,
    ) -> BlastRadiusContext {
        let paths: BTreeSet<_> = changed_paths.iter().collect();
        let relevant: Vec<_> = self
            .edges
            .iter()
            .filter(|e| paths.contains(&e.from) || paths.contains(&e.to))
            .collect();
        let mut out = BlastRadiusContext {
            coverage_floor: self.coverage_floor.clone(),
            freshness: self.freshness.clone(),
            scoped_bytes_digest: self.scoped_bytes_digest.clone(),
            covered_files_digest: self.covered_files_digest.clone(),
            blueprint_version: self.blueprint_version.clone(),
            resolver_config_digest: self.resolver_config_digest.clone(),
            certain: Vec::new(),
            inferred: Vec::new(),
            unknowns: self.unknowns.iter().take(128).cloned().collect(),
            truncated: self.truncated || relevant.len() > max_edges || self.unknowns.len() > 128,
            proves_dead_code: false,
        };
        for edge in relevant.into_iter().take(max_edges) {
            if edge.source == "blueprint" && edge.confidence == "certain" {
                out.certain.push(edge.clone());
            } else {
                out.inferred.push(edge.clone());
            }
        }
        if out.truncated {
            out.unknowns
                .push(unknown(None, "blast-radius-context-truncated"));
        }
        out
    }
}

fn lexical_edges(files: &BTreeMap<String, Vec<u8>>, context: &mut GraphContext) {
    // Limited, line-oriented static import syntax only. No manifest fan-in or call inference.
    let imports = regex::Regex::new(
        r#"(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)["']([^"']+)["']"#,
    )
    .expect("literal regex");
    for (path, bytes) in files.iter().take(MAX_FILES) {
        if !safe_path(path) {
            context
                .unknowns
                .push(unknown(Some(path.clone()), "source-path-escape"));
            continue;
        }
        let Ok(source) = std::str::from_utf8(bytes) else {
            continue;
        };
        if !matches!(
            path.rsplit('.').next(),
            Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts")
        ) {
            continue;
        }
        for (line, text) in source.lines().enumerate() {
            // False lexical positives remain inferred leads; scanner does not claim parser coverage.
            for captures in imports.captures_iter(text) {
                let specifier = &captures[1];
                let Some(target) = resolve_relative(path, specifier, files) else {
                    if context.unknowns.len() < 1024 {
                        context.unknowns.push(unknown(
                            Some(path.clone()),
                            "lexical-import-unresolved-or-external",
                        ));
                    } else {
                        context.truncated = true;
                    }
                    continue;
                };
                if context.edges.len() >= MAX_EDGES {
                    context.truncated = true;
                    context
                        .unknowns
                        .push(unknown(None, "lexical-edge-cap-exceeded"));
                    return;
                }
                context.edges.push(ContextEdge {
                    from: path.clone(),
                    to: target,
                    kind: "imports".into(),
                    confidence: "possible".into(),
                    source: "lexical".into(),
                    evidence: SourceSpan {
                        path: path.clone(),
                        start_line: line as u64 + 1,
                        end_line: line as u64 + 1,
                        source_digest: bytes_digest(bytes),
                    },
                });
            }
        }
    }
    if files.len() > MAX_FILES {
        context.truncated = true;
        context
            .unknowns
            .push(unknown(None, "lexical-file-cap-exceeded"));
    }
}
fn resolve_relative(from: &str, import: &str, files: &BTreeMap<String, Vec<u8>>) -> Option<String> {
    if !import.starts_with('.')
        || import.contains('\\')
        || import.contains(':')
        || import.contains('\0')
    {
        return None;
    }
    let mut parts: Vec<_> = from.split('/').collect();
    parts.pop();
    for part in import.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            name => parts.push(name),
        }
    }
    let base = parts.join("/");
    for suffix in [
        "",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        "/index.ts",
        "/index.tsx",
        "/index.js",
    ] {
        let candidate = format!("{base}{suffix}");
        if files.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct HostArtifactFixture(std::path::PathBuf);
    impl HostArtifactFixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "legion-graph-host-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(root)
        }
    }
    impl Drop for HostArtifactFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn explicit_host_artifact_reaches_existing_source_binding_validation() {
        let fixture = HostArtifactFixture::new();
        let audited_root = fixture.0.join("repository");
        std::fs::create_dir(&audited_root).unwrap();
        let path = fixture.0.join("host-graph.json");
        let files = source();
        std::fs::write(&path, serde_json::to_vec(&artifact(&files)).unwrap()).unwrap();
        let loaded = load_host_artifact(&path, &[&audited_root]).unwrap();
        let graph = build_graph_context(&files, Some(&loaded), "resolver-v1");
        assert_eq!(graph.freshness, "bound-to-frozen-covered-bytes");
        assert!(graph.edges.iter().any(|edge| edge.source == "blueprint"));
        let stale = build_graph_context(&files, Some(&loaded), "another-resolver");
        assert!(stale.trusted_files.is_empty());
        assert!(stale.edges.iter().all(|edge| edge.source == "lexical"));
    }

    #[test]
    fn host_artifact_rejects_unbounded_or_repository_controlled_inputs() {
        let fixture = HostArtifactFixture::new();
        let path = fixture.0.join("graph.json");
        std::fs::write(&path, b"{}").unwrap();
        assert!(load_host_artifact(Path::new("graph.json"), &[]).is_err());
        assert!(load_host_artifact(&fixture.0.join("../graph.json"), &[]).is_err());
        assert_eq!(
            load_host_artifact(&path, &[&fixture.0]).unwrap_err(),
            "blueprint-artifact-input-inside-audited-root"
        );
        assert!(load_host_artifact(&fixture.0, &[]).is_err());
        std::fs::write(&path, b"invalid json").unwrap();
        assert!(load_host_artifact(&path, &[])
            .unwrap_err()
            .starts_with("blueprint-artifact-input-invalid-json"));
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_ARTIFACT_BYTES as u64 + 1)
            .unwrap();
        assert_eq!(
            load_host_artifact(&path, &[]).unwrap_err(),
            "blueprint-artifact-input-cap-exceeded"
        );
    }

    #[cfg(unix)]
    #[test]
    fn host_artifact_rejects_symlink_files_and_parent_components() {
        use std::os::unix::fs::symlink;
        let fixture = HostArtifactFixture::new();
        let path = fixture.0.join("graph.json");
        std::fs::write(&path, b"{}").unwrap();
        let link = fixture.0.join("linked.json");
        symlink(&path, &link).unwrap();
        assert!(load_host_artifact(&link, &[]).is_err());
        let linked_parent = fixture.0.join("parent-link");
        symlink(&fixture.0, &linked_parent).unwrap();
        assert!(load_host_artifact(&linked_parent.join("graph.json"), &[]).is_err());
    }

    fn source() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            (
                "src/a.ts".into(),
                b"import { b } from './b';\nb();\n".to_vec(),
            ),
            ("src/b.ts".into(), b"export function b() {}\n".to_vec()),
            ("src/other.py".into(), b"def dynamic(): pass\n".to_vec()),
        ])
    }
    fn artifact(files: &BTreeMap<String, Vec<u8>>) -> Value {
        let subset: BTreeMap<_, _> = files
            .iter()
            .filter(|(path, _)| path.ends_with(".ts"))
            .map(|(p, b)| (p.clone(), b.clone()))
            .collect();
        let paths: Vec<_> = subset.keys().cloned().collect();
        json!({"contractVersion":GRAPH_CONTRACT,"blueprintVersion":"1.2.3",
            "resolverConfigDigest":"resolver-v1","scopedBytesDigest":scoped_bytes_digest(&subset),
            "coveredFilesDigest":covered_files_digest(&paths),"coverage":{"files":paths,"unsupported":[]},
            "nodes":[{"id":"a","kind":"file","path":"src/a.ts"},
                {"id":"b","kind":"symbol","path":"src/b.ts","range":{"startLine":1,"endLine":1}}],
            "edges":[{"from":"a","to":"b","kind":"calls","confidence":"certain",
                "evidence":{"path":"src/a.ts","range":{"startLine":2,"endLine":2}}}],"unknowns":[]})
    }
    #[test]
    fn lexical_floor_is_relative_import_leads_never_manifest_fanin_or_dead_proof() {
        let files = source();
        let graph = build_graph_context(&files, None, "resolver-v1");
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].kind, "imports");
        assert_eq!(graph.edges[0].confidence, "possible");
        assert_eq!(graph.edges[0].to, "src/b.ts");
        let context = graph.compact_blast_radius(&["src/a.ts".into()], 8);
        assert!(context.certain.is_empty());
        assert_eq!(context.inferred.len(), 1);
        assert!(!context.proves_dead_code);
        assert!(!context.unknowns.is_empty());
    }
    #[test]
    fn partial_graph_keeps_uncovered_floor_and_certain_evidence_links() {
        let files = source();
        let graph = build_graph_context(&files, Some(&artifact(&files)), "resolver-v1");
        assert_eq!(graph.trusted_files.len(), 2);
        assert!(graph
            .unknowns
            .iter()
            .any(|g| g.path.as_deref() == Some("src/other.py")));
        let context = graph.compact_blast_radius(&["src/b.ts".into()], 8);
        assert_eq!(context.certain.len(), 1);
        assert_eq!(context.certain[0].evidence.start_line, 2);
        assert_eq!(
            context.certain[0].evidence.source_digest,
            bytes_digest(&files["src/a.ts"])
        );
        assert!(!context.proves_dead_code);
    }
    #[test]
    fn changed_bytes_config_or_provenance_rejects_trust() {
        let files = source();
        let original = artifact(&files);
        for field in [
            "contractVersion",
            "blueprintVersion",
            "scopedBytesDigest",
            "coveredFilesDigest",
            "resolverConfigDigest",
        ] {
            let mut changed = original.clone();
            changed[field] = json!("");
            let graph = build_graph_context(&files, Some(&changed), "resolver-v1");
            assert!(graph.trusted_files.is_empty(), "{field}");
            assert!(
                graph.edges.iter().all(|edge| edge.source == "lexical"),
                "{field}"
            );
            assert!(!graph.unknowns.is_empty());
        }
        let mut moved = files.clone();
        moved.insert("src/b.ts".into(), b"changed source\n".to_vec());
        let graph = build_graph_context(&moved, Some(&original), "resolver-v1");
        assert!(graph.trusted_files.is_empty());
        assert!(graph.unknowns.iter().any(|g| g.cause == "blueprint-stale"));
    }
    #[test]
    fn path_escape_or_missing_span_does_not_turn_into_certain_edge() {
        let files = source();
        let mut escaped = artifact(&files);
        escaped["nodes"][0]["path"] = json!("../outside.ts");
        let graph = build_graph_context(&files, Some(&escaped), "resolver-v1");
        assert!(graph.trusted_files.is_empty());
        assert!(graph
            .unknowns
            .iter()
            .any(|g| g.cause == "blueprint-path-escape"));
        let mut no_span = artifact(&files);
        no_span["edges"][0]["evidence"] = json!({"text":"trust me"});
        let graph = build_graph_context(&files, Some(&no_span), "resolver-v1");
        assert!(graph.edges.iter().all(|edge| edge.source == "lexical"));
        assert!(graph
            .unknowns
            .iter()
            .any(|g| g.cause == "blueprint-edge-source-span-missing"));
    }
    #[test]
    fn weak_edges_and_truncation_survive_as_unknown_leads() {
        let files = source();
        let mut partial = artifact(&files);
        partial["edges"][0]["confidence"] = json!("likely");
        partial["truncated"] = json!(true);
        let graph = build_graph_context(&files, Some(&partial), "resolver-v1");
        let context = graph.compact_blast_radius(&["src/a.ts".into()], 1);
        assert!(context.certain.is_empty());
        assert!(!context.inferred.is_empty());
        assert!(context.truncated);
        assert!(!context.proves_dead_code);
        assert!(graph.edges.iter().any(|edge| edge.source == "lexical"));
    }
    #[test]
    fn cold_warm_content_produces_identical_graph_artifact() {
        let files = source();
        let graph = artifact(&files);
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("legion-graph-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let cold = {
            let mut cache = crate::source_cache::SourceCache::open(&root, 1024 * 1024).unwrap();
            build_graph_context_cached(&files, Some(&graph), "resolver-v1", &mut cache)
        };
        let mut cache = crate::source_cache::SourceCache::open(&root, 1024 * 1024).unwrap();
        let warm = build_graph_context_cached(&files, Some(&graph), "resolver-v1", &mut cache);
        assert_eq!(
            serde_json::to_value(cold).unwrap(),
            serde_json::to_value(warm).unwrap()
        );
        assert_eq!(cache.stats.fact_hits, 1);
        let changed = build_graph_context_cached(&files, Some(&graph), "resolver-v2", &mut cache);
        assert!(changed.trusted_files.is_empty());
        drop(cache);
        let _ = std::fs::remove_dir_all(root);
    }
}
