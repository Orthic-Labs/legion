//! Integrity contracts for the two standalone Apple skill bundles.
//!
//! These tests prove packaging, provenance bookkeeping, and structural
//! contracts. They do not claim semantic quality or native Apple validation.

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

const APPLE_SKILLS: [&str; 2] = ["ios-development", "macos-development"];
const SHARED_TOPICS: [&str; 8] = [
    "architecture",
    "build-optimization",
    "concurrency",
    "persistence",
    "profiling",
    "release",
    "swiftui",
    "testing",
];
const BYTE_IDENTICAL_TOPICS: [&str; 5] = [
    "architecture",
    "build-optimization",
    "concurrency",
    "profiling",
    "release",
];

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root should resolve")
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn sha256(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn unquote_path(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                output.push((high * 16 + low) as u8 as char);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn prose(text: &str) -> String {
    let mut output = String::new();
    let mut fenced = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if !fenced {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn anchors(path: &Path) -> HashSet<String> {
    let text = fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let text = prose(&text);
    let heading = Regex::new(r"^#{1,6}\s+(.+?)\s*#*\s*$").unwrap();
    let html = Regex::new(r#"<a\s+(?:id|name)=["']([^"']+)"#).unwrap();
    let mut found = HashSet::new();
    let mut counts = HashMap::<String, usize>::new();
    for line in text.lines() {
        if let Some(capture) = heading.captures(line) {
            let mut slug = capture[1]
                .to_lowercase()
                .chars()
                .filter(|character| character.is_alphanumeric() || *character == '_' || *character == '-' || *character == ' ')
                .collect::<String>();
            slug = slug.replace(' ', "-");
            let suffix = counts.entry(slug.clone()).or_insert(0);
            let anchor = if *suffix == 0 {
                slug.clone()
            } else {
                format!("{slug}-{}", *suffix)
            };
            *suffix += 1;
            found.insert(anchor);
        }
        for capture in html.captures_iter(line) {
            found.insert(capture[1].to_string());
        }
    }
    found
}

fn local_links(path: &Path) -> Vec<(PathBuf, String)> {
    let text = fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let text = prose(&text);
    let links = Regex::new(r"\[[^\]]+\]\(([^)\s]+)").unwrap();
    links
        .captures_iter(&text)
        .filter_map(|capture| {
            let raw = capture[1].trim_start_matches('<').trim_end_matches('>');
            if raw.contains("://") || raw.starts_with('#') {
                return None;
            }
            let (raw_path, fragment) = raw.split_once('#').unwrap_or((raw, ""));
            let target = if raw_path.is_empty() {
                path.to_path_buf()
            } else {
                path.parent().unwrap().join(unquote_path(raw_path))
            };
            Some((target, fragment.to_string()))
        })
        .collect()
}

fn assert_reference_closure(root: &Path, bundle: &str) {
    let bundle_root = root.join("skills").join(bundle).canonicalize().unwrap();
    let entry = bundle_root.join("SKILL.md");
    let mut queue = VecDeque::from([entry]);
    let mut visited = HashSet::new();
    while let Some(path) = queue.pop_front() {
        let path = path.canonicalize().unwrap_or_else(|error| panic!("{bundle}: missing {}: {error}", path.display()));
        if !visited.insert(path.clone()) {
            continue;
        }
        for (target, fragment) in local_links(&path) {
            let resolved = target
                .canonicalize()
                .unwrap_or_else(|error| panic!("{bundle}: unresolved link {}: {error}", target.display()));
            assert!(resolved == bundle_root || resolved.starts_with(&bundle_root), "{bundle}: link escapes bundle: {}", target.display());
            if !fragment.is_empty() && resolved.extension().and_then(|extension| extension.to_str()) == Some("md") {
                assert!(anchors(&resolved).contains(&fragment), "{bundle}: broken anchor {}#{fragment}", resolved.display());
            }
            if resolved.extension().and_then(|extension| extension.to_str()) == Some("md") {
                queue.push_back(resolved);
            }
        }
    }

    for entry in walkdir::WalkDir::new(&bundle_root) {
        let entry = entry.unwrap();
        assert!(!entry.file_type().is_symlink(), "symlinks cannot ship in {bundle}");
        if entry.path().extension().and_then(|extension| extension.to_str()) == Some("md") {
            assert!(visited.contains(&entry.path().canonicalize().unwrap()), "{bundle}: unreachable Markdown reference {}", entry.path().display());
        }
    }
}

fn relative_files(path: &Path) -> HashSet<String> {
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().strip_prefix(path).unwrap().to_string_lossy().replace('\\', "/"))
        .collect()
}

fn assert_source_ledgers(root: &Path) {
    let inventory = read_json(&root.join("docs/apple-absorption/source-inventory.json"));
    let mut expected = Vec::<(String, Option<String>, Option<u64>)>::new();
    for source in inventory["sources"].as_array().unwrap() {
        for file in source["files"].as_array().unwrap() {
            let path = file["path"].as_str().unwrap().to_string();
            let hash = file["sha256"].as_str().map(str::to_string);
            if let Some(hash) = &hash {
                assert!(hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()), "invalid inventory hash: {path}");
            }
            let lines = file["lines"].as_u64();
            assert!(expected.iter().all(|(other_path, other_hash, _)| other_path != &path || other_hash != &hash), "duplicate inventory file identity: {path}");
            expected.push((path, hash, lines));
        }
    }

    let mut seen = HashSet::<usize>::new();
    for ledger_path in fs::read_dir(root.join("docs/apple-absorption")).unwrap().filter_map(Result::ok).filter(|entry| entry.path().extension().and_then(|extension| extension.to_str()) == Some("json")) {
        if ledger_path.file_name() == "source-inventory.json" {
            continue;
        }
        let ledger = read_json(&ledger_path.path());
        assert_eq!(ledger["schemaVersion"], 1, "{}", ledger_path.path().display());
        for source in ledger["sources"].as_array().unwrap() {
            let source_id = source["id"].as_str().unwrap();
            for file in source["files"].as_array().unwrap() {
                let source_path = file["path"].as_str().unwrap();
                let ledger_hash = file["sha256"].as_str().map(str::to_string);
                let identity = format!("{source_id}:{source_path}");
                let inventory_match = expected.iter().enumerate().find(|(_, (path, hash, _))| path == source_path && *hash == ledger_hash);
                if let Some((index, _)) = inventory_match {
                    assert!(seen.insert(index), "duplicate ledger file: {identity}");
                }
                assert!(file["review"].as_str().is_some_and(|review| !review.trim().is_empty()), "missing review disposition: {identity}");
                let rules = file.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
                let has_reason = file.get("reason").and_then(Value::as_str).is_some_and(|reason| !reason.trim().is_empty());
                let has_duplicate = file.get("duplicateOf").and_then(Value::as_str).is_some_and(|duplicate| !duplicate.trim().is_empty());
                assert!(!rules.is_empty() || has_reason || has_duplicate, "file has no rules/reason/duplicate: {identity}");
                for rule in rules {
                    let disposition = rule["disposition"].as_str().unwrap();
                    assert!(matches!(disposition, "kept" | "merged" | "rejected"), "invalid disposition {disposition}: {identity}");
                    assert!(rule["summary"].as_str().is_some_and(|summary| !summary.trim().is_empty()), "missing rule summary: {identity}");
                    assert!(rule["reason"].as_str().is_some_and(|reason| !reason.trim().is_empty()), "missing rule reason: {identity}");
                    let bounds = rule["sourceLines"].as_array().unwrap();
                    assert_eq!(bounds.len(), 2, "invalid source line range: {identity}");
                    let start = bounds[0].as_u64().unwrap();
                    let end = bounds[1].as_u64().unwrap();
                    assert!(start >= 1 && start <= end, "invalid source line range {start}..{end}: {identity}");
                    if let Some((_, value)) = inventory_match {
                        if let Some(expected_lines) = value.2 {
                            assert!(end <= expected_lines, "invalid source line range {start}..{end}: {identity}");
                        }
                    }
                    let destinations = rule.get("destinations").and_then(Value::as_array).cloned().unwrap_or_default();
                    if disposition != "rejected" {
                        assert!(!destinations.is_empty(), "retained rule lacks destination: {key:?}");
                    }
                    for destination in destinations {
                        let destination = destination.as_str().unwrap();
                        let (relative, fragment) = destination.split_once('#').unwrap_or((destination, ""));
                        let target = root.join(relative).canonicalize().unwrap_or_else(|error| panic!("{destination}: {error}"));
                        assert!(target.starts_with(root), "destination escapes repository: {destination}");
                        if !fragment.is_empty() && target.extension().and_then(|extension| extension.to_str()) == Some("md") {
                            assert!(anchors(&target).contains(fragment), "broken destination anchor: {destination}");
                        }
                    }
                }
            }
        }
    }
    assert_eq!(seen.len(), expected.len(), "source inventory has undispositioned files");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::{codex_skill_sidecars, host_projection, refresh_local_skill_manifests, skill_catalog};
    use crate::shared::skill_frontmatter::parse_skill_frontmatter_map;

    #[test]
    fn apple_references_form_standalone_closures_with_valid_anchors() {
        let root = repository_root();
        for bundle in APPLE_SKILLS {
            assert_reference_closure(&root, bundle);
        }
    }

    #[test]
    fn shared_technical_topics_are_mirrored() {
        let root = repository_root();
        for topic in SHARED_TOPICS {
            let left = root.join("skills/ios-development/references").join(topic);
            let right = root.join("skills/macos-development/references").join(topic);
            assert_eq!(relative_files(&left), relative_files(&right), "shared topic inventory differs: {topic}");
            if BYTE_IDENTICAL_TOPICS.contains(&topic) {
                for relative in relative_files(&left) {
                    assert_eq!(fs::read(left.join(&relative)).unwrap(), fs::read(right.join(&relative)).unwrap(), "shared topic content differs: {topic}/{relative}");
                }
            }
            assert!(fs::metadata(root.join("skills/ios-development/references").join(format!("{topic}.md"))).is_ok());
            assert!(fs::metadata(root.join("skills/macos-development/references").join(format!("{topic}.md"))).is_ok());
        }
    }

    #[test]
    fn source_inventory_ledgers_cover_hashes_ranges_and_destinations() {
        assert_source_ledgers(&repository_root());
    }

    #[test]
    fn generated_apple_manifests_match_payload_hashes() {
        let root = repository_root();
        for bundle in APPLE_SKILLS {
            let generated = refresh_local_skill_manifests::build_local_skill_manifest(&root, bundle).unwrap();
            let current = read_json(&generated.manifest_path);
            assert_eq!(current, generated.manifest, "manifest drift: {bundle}");
            assert_eq!(current["licenseState"], "licensed");
            assert_eq!(current["rightsReceipt"]["sourceManifest"], "config/source-manifest.json");
            for file in current["files"].as_array().unwrap() {
                let relative = file["path"].as_str().unwrap();
                let expected_digest = format!("sha256:{}", sha256(&root.join("skills").join(bundle).join(relative)));
                assert_eq!(file["digest"].as_str(), Some(expected_digest.as_str()));
            }
        }
    }

    #[test]
    fn apple_bundles_have_native_contracts_and_public_routing() {
        let root = repository_root();
        let (catalog, domains) = skill_catalog::build_skill_catalog(&root).unwrap();
        let projection = host_projection::build_projection(&root).unwrap();
        let mcp_schema = read_json(&root.join("src/registry/mcp-tools.json"));
        assert_eq!(projection["mcpTools"], mcp_schema["tools"]);
        assert!(projection["mcpTools"].as_array().unwrap().iter().any(|tool| tool["name"] == "legion_apple"));
        let sidecars = codex_skill_sidecars::expected_codex_sidecars(&root).unwrap();
        let engineering = domains["domains"].as_array().unwrap().iter().find(|domain| domain["id"] == "engineering").unwrap();
        for bundle in APPLE_SKILLS {
            let root_path = root.join("skills").join(bundle);
            let frontmatter = parse_skill_frontmatter_map(&fs::read_to_string(root_path.join("SKILL.md")).unwrap(), &format!("skills/{bundle}/SKILL.md")).unwrap();
            assert_eq!(frontmatter["kind"], "capability");
            assert_eq!(frontmatter["discoverability"], "public");
            assert!(root_path.join("references/release/contract.md").is_file());
            assert!(root_path.join("references/profiling/capture.md").is_file());
            assert!(root_path.join("references/profiling/export.md").is_file());
            assert!(root_path.join("references/profiling/hotspots.md").is_file());
            assert!(!root_path.join("scripts/tool_preflight.py").exists(), "Python preflight must not remain in {bundle}");
            let skill = catalog["bundles"].as_array().unwrap().iter().find(|item| item["id"] == bundle).unwrap();
            assert!(skill["hostRequirements"].as_array().unwrap().is_empty());
            assert!(engineering["children"].as_array().unwrap().iter().any(|child| child["id"] == bundle));
            assert!(skill["scopedRequirementDetails"].as_array().unwrap().iter().all(|item| item["degradation"].as_str().is_some_and(|value| !value.is_empty())));
            let host = projection["capabilities"].as_array().unwrap().iter().find(|item| item["id"] == bundle).unwrap();
            assert_eq!(host["invocation"]["user"], true);
            assert_eq!(host["invocation"]["model"], true);
            let (_, sidecar) = sidecars.iter().find(|(name, _)| name == bundle).unwrap();
            assert!(sidecar.contains("allow_implicit_invocation: true"));
        }
    }
}
