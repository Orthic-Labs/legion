//! Port of `authority_packet_errors()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~265-322), for
//! every packet shape except `packetType == "direct"` and
//! `packetType == "worker"` — see the module-level doc comment in
//! `wf_port::w2_044` for why those two branches are not ported in this
//! chunk.

use super::digest::{content_reference, sha256_digest, Reference};
use super::paths::resolve_declared_path;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Port of `packet_repository_root()`.
fn packet_repository_root(packet: &Value, artifact: &Path, errors: &mut Vec<String>) -> Option<PathBuf> {
    let declared = packet.get("repositoryRoot").and_then(|v| v.as_str());
    let root = match declared {
        Some(declared) => Some(resolve_declared_path(declared, artifact)),
        None => super::paths::repository_root(artifact),
    };
    match root {
        Some(root) if root.is_dir() && root.join(".git").exists() => Some(root),
        _ => {
            errors.push("authority packet requires an existing repository root".to_string());
            None
        }
    }
}

fn all_same_char(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => chars.all(|c| c == first) && !s.is_empty(),
        None => false,
    }
}

fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_sha256_digest(s: &str) -> bool {
    match s.strip_prefix("sha256:") {
        Some(hex) => hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        None => false,
    }
}

/// Port of `authority_packet_errors()`.
///
/// **Scope note**: when `packet.packetType` is `"direct"` or `"worker"`,
/// the Python validator raises many additional packet-type-specific
/// structural errors (dispatch waves, lanes, worker allowlists, executor
/// requirements, `managed_rust_route_errors`, ...) that this port does not
/// implement — see `wf_port::w2_044`'s module doc. Callers must not treat
/// an empty error list from this function as proof that a `direct`/`worker`
/// packet is fully valid.
pub fn authority_packet_errors(packet: &Value, artifact: &Path) -> (Vec<String>, Vec<Reference>) {
    let mut errors: Vec<String> = Vec::new();
    let mut references: Vec<Reference> = Vec::new();

    let packet_obj = match packet.as_object() {
        Some(obj) => obj,
        None => return (vec!["authority packet must be an object".to_string()], references),
    };

    let required = [
        "schemaVersion",
        "kind",
        "packetType",
        "sourceRevision",
        "promptDigest",
        "modelRouting",
    ];
    let missing_required = required.iter().any(|key| !packet_obj.contains_key(*key));
    let schema_ok = packet.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1);
    let kind_ok = packet.get("kind").and_then(|v| v.as_str()) == Some("legion-authority-dispatch");
    if missing_required || !schema_ok || !kind_ok {
        errors.push("authority packet base shape is invalid".to_string());
    }

    let source_revision = packet.get("sourceRevision").and_then(|v| v.as_str());
    let source_digest = source_revision
        .map(|s| s.strip_prefix("git:").unwrap_or(s))
        .map(|s| s.strip_prefix("sha256:").unwrap_or(s))
        .unwrap_or("");
    let source_revision_valid = match source_revision {
        Some(s) => {
            let git_form = is_hex40(s.strip_prefix("git:").unwrap_or(s));
            let content_form = is_sha256_digest(s);
            (git_form || content_form) && !all_same_char(source_digest)
        }
        None => false,
    };
    if !source_revision_valid {
        errors.push(
            "authority packet source revision must be an immutable git SHA or content digest"
                .to_string(),
        );
    }

    let prompt_digest = packet
        .get("promptDigest")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let prompt_hex = prompt_digest.strip_prefix("sha256:").unwrap_or("");
    if !is_sha256_digest(&prompt_digest) || all_same_char(prompt_hex) {
        errors.push("authority packet prompt digest must be a non-placeholder sha256 digest".to_string());
    }

    let root = packet_repository_root(packet, artifact, &mut errors);
    if let (Some(source_revision), Some(root)) = (source_revision, root.as_deref()) {
        if let Some(_hex) = source_revision.strip_prefix("sha256:") {
            let source_artifact = packet.get("sourceArtifact").and_then(|v| v.as_str());
            if let Some(source_path) = content_reference(
                source_artifact,
                artifact,
                "authority packet source",
                &mut errors,
                &mut references,
            ) {
                if let Ok(bytes) = std::fs::read(&source_path) {
                    let actual = sha256_digest(&bytes);
                    if source_revision != actual {
                        errors.push(
                            "authority packet source revision does not bind source artifact bytes"
                                .to_string(),
                        );
                    }
                }
            }
        } else {
            let revision = source_revision.strip_prefix("git:").unwrap_or(source_revision);
            if is_hex40(revision) {
                let resolved = Command::new("git")
                    .arg("-C")
                    .arg(root)
                    .arg("rev-parse")
                    .arg("--verify")
                    .arg(format!("{revision}^{{commit}}"))
                    .output();
                let ok = match resolved {
                    Ok(output) => {
                        output.status.success()
                            && String::from_utf8_lossy(&output.stdout).trim() == revision
                    }
                    Err(_) => false,
                };
                if !ok {
                    errors.push(
                        "authority packet source revision does not resolve to repository commit"
                            .to_string(),
                    );
                }
            }
        }
    }

    let prompt_artifact = packet.get("promptArtifact").and_then(|v| v.as_str());
    if let Some(prompt_path) = content_reference(
        prompt_artifact,
        artifact,
        "authority packet prompt",
        &mut errors,
        &mut references,
    ) {
        if let Ok(bytes) = std::fs::read(&prompt_path) {
            let actual_prompt_digest = sha256_digest(&bytes);
            if prompt_digest != actual_prompt_digest {
                errors.push("authority packet prompt digest does not bind prompt artifact bytes".to_string());
            }
        }
    }

    let routing = packet.get("modelRouting");
    let routing_ok = routing.and_then(|r| r.as_object()).is_some_and(|routing| {
        ["modelTier", "workerProfile", "routingRationale"]
            .iter()
            .all(|key| routing.get(*key).and_then(|v| v.as_str()).is_some_and(|v| !v.is_empty()))
    });
    if !routing_ok {
        errors.push("authority packet requires modelTier, workerProfile, routingRationale".to_string());
    }

    // NOTE: packetType == "direct" / "worker" structural checks
    // (validate-dispatch.py lines ~322-860) are not ported in this chunk.

    (errors, references)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git").arg("-C").args([dir.to_str().unwrap()]).args(args).status().unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn fixture_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("w2_044-authority-{name}-{}", std::process::id()))
    }

    #[test]
    fn missing_routing_rationale_is_reported() {
        let dir = fixture_dir("routing");
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);
        git(&dir, &["config", "user.email", "t@example.test"]);
        git(&dir, &["config", "user.name", "T"]);
        let prompt = dir.join("prompt.txt");
        std::fs::write(&prompt, b"exact captured prompt").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "init"]);
        let revision = String::from_utf8(
            Command::new("git").arg("-C").arg(&dir).args(["rev-parse", "HEAD"]).output().unwrap().stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let prompt_digest = sha256_digest(&std::fs::read(&prompt).unwrap());

        let packet = serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-authority-dispatch",
            "packetType": "sage",
            "repositoryRoot": dir.to_string_lossy(),
            "sourceRevision": revision,
            "promptArtifact": prompt.to_string_lossy(),
            "promptDigest": prompt_digest,
            "modelRouting": {"modelTier": "FRONTIER", "workerProfile": "strict"},
        });
        let artifact = dir.join("packet.json");
        let (errors, _) = authority_packet_errors(&packet, &artifact);
        assert!(
            errors.contains(&"authority packet requires modelTier, workerProfile, routingRationale".to_string()),
            "{errors:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn well_formed_sage_packet_is_clean() {
        let dir = fixture_dir("clean");
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);
        git(&dir, &["config", "user.email", "t@example.test"]);
        git(&dir, &["config", "user.name", "T"]);
        let prompt = dir.join("prompt.txt");
        std::fs::write(&prompt, b"exact captured prompt").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "init"]);
        let revision = String::from_utf8(
            Command::new("git").arg("-C").arg(&dir).args(["rev-parse", "HEAD"]).output().unwrap().stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let prompt_digest = sha256_digest(&std::fs::read(&prompt).unwrap());

        let packet = serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-authority-dispatch",
            "packetType": "sage",
            "repositoryRoot": dir.to_string_lossy(),
            "sourceRevision": revision,
            "promptArtifact": prompt.to_string_lossy(),
            "promptDigest": prompt_digest,
            "modelRouting": {"modelTier": "CHEAP_STRICT", "workerProfile": "strict", "routingRationale": "bounded execution"},
        });
        let artifact = dir.join("packet.json");
        let (errors, _) = authority_packet_errors(&packet, &artifact);
        assert!(errors.is_empty(), "{errors:?}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
