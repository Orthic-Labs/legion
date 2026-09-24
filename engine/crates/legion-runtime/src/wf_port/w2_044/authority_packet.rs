//! Port of `authority_packet_errors()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~265-636),
//! including every `packetType` branch (`direct`, `sage`, `oracle`/`seer`,
//! `alchemist`, `worker`). Packet r46 closed the `direct`/`worker`
//! structural-check gap this file's module doc previously described as
//! unported (lines ~322-636 of the Python source): dispatch-wave/lane
//! validation, worker OWN/READ/FORBIDDEN scope and collision checks,
//! `executorRequirement`/escalation policy validation, the Oracle
//! pre-execution audit contract, and the `worker` packet capsule/projection
//! checks are now ported in full below, reusing the scope primitives in
//! `wf_port::w2_045::path_utils`.

use super::digest::{content_reference, digest_path, sha256_digest, Reference};
use super::paths::{canonical_locator, resolve_declared_path};
use crate::wf_port::w2_045::path_utils::{
    direct_file_allowlist_path, direct_scope_path, scopes_overlap,
};
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn executor_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$").unwrap())
}

const EXECUTOR_SEMANTIC_REQUIREMENTS: [&str; 3] = ["forbidden", "conditional", "required"];
const EXECUTOR_ESCALATION_OUTCOMES: [&str; 7] = [
    "unsupported",
    "ambiguous",
    "unreachable",
    "denied",
    "terminated",
    "verification_failed",
    "observation_unavailable",
];

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

/// Mirrors Python truthiness for a JSON value (`bool(value)`), used where
/// the Python source relies on it (`not lens.get("id")`).
fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
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

    let packet_type = packet.get("packetType").and_then(|v| v.as_str());

    // Port of the local `reference()` closure (lines ~320-323): resolve a
    // `{path, digest}` object via `digest_path`, then also append it to
    // `references` (unlike the bare `digest_path` call sites above, which
    // only validate).
    let json_reference = |value: Option<&Value>, label: &str, errors: &mut Vec<String>, references: &mut Vec<Reference>| -> Option<PathBuf> {
        // Mirror Python's `reference()`: `digest_path` is called even when
        // the field is absent (`value is None`), which itself reports
        // "{label} requires path and sha256 digest" for any non-object.
        let null = Value::Null;
        let value = value.unwrap_or(&null);
        let path = digest_path(value, artifact, label, errors);
        if let Some(path) = &path {
            if let Some(digest) = value.get("digest").and_then(|v| v.as_str()) {
                references.push(Reference {
                    path: canonical_locator(path),
                    sha256: digest.to_string(),
                });
            }
        }
        path
    };

    match packet_type {
        Some("direct") => {
            direct_packet_errors(packet, artifact, root.as_deref(), &mut errors, &mut references);
        }
        Some("sage") => {
            let route = packet.get("routeBundle");
            let route_path = route.and_then(|r| r.get("path")).and_then(|v| v.as_str()).unwrap_or("");
            let sage_route_re = {
                static RE: OnceLock<Regex> = OnceLock::new();
                RE.get_or_init(|| Regex::new(r"sage-adjudication(?:\.[a-z0-9]+)?$").unwrap())
            };
            if !route.is_some_and(|r| r.is_object()) || !sage_route_re.is_match(route_path) {
                errors.push("Sage packet requires an exceptional sage-adjudication route bundle".to_string());
            } else {
                json_reference(route, "Sage route bundle", &mut errors, &mut references);
            }
        }
        Some("oracle") | Some("seer") => {
            let lens = packet.get("lens");
            let scope = packet.get("scope");
            let oracle = packet.get("oracle");
            let lens_id_present = lens
                .and_then(|l| l.as_object())
                .is_some_and(|obj| obj.get("id").is_some_and(json_truthy));
            if !lens.is_some_and(|l| l.is_object()) || !lens_id_present {
                errors.push("Oracle packet requires lens id".to_string());
            } else {
                json_reference(lens, "Oracle lens", &mut errors, &mut references);
            }
            let scope_obj = scope.and_then(|s| s.as_object());
            let read = scope_obj.and_then(|o| o.get("read")).and_then(|v| v.as_array());
            let forbidden = scope_obj.and_then(|o| o.get("forbidden")).and_then(|v| v.as_array());
            if scope_obj.is_none() || read.is_none() || forbidden.is_none() {
                errors.push("Oracle packet requires read-only scope".to_string());
            } else if let (Some(read), Some(forbidden)) = (read, forbidden) {
                let read_set: BTreeSet<String> =
                    read.iter().map(|v| v.to_string()).collect();
                if forbidden.iter().any(|v| read_set.contains(&v.to_string())) {
                    errors.push("Oracle scope overlaps forbidden paths".to_string());
                }
            }
            json_reference(oracle, "Oracle oracle", &mut errors, &mut references);
        }
        Some("alchemist") => {
            let contract = packet.get("executionContract");
            let scope = packet.get("scope");
            let contract_id = contract.and_then(|c| c.get("id")).and_then(|v| v.as_str()).unwrap_or("");
            let ec_id_re = {
                static RE: OnceLock<Regex> = OnceLock::new();
                RE.get_or_init(|| Regex::new(r"^EC-\d+$").unwrap())
            };
            let sealed = contract.and_then(|c| c.get("sealed")) == Some(&Value::Bool(true));
            let executable = contract.and_then(|c| c.get("executable")) == Some(&Value::Bool(true));
            if !contract.is_some_and(|c| c.is_object()) || !ec_id_re.is_match(contract_id) || !sealed || !executable {
                errors.push("Alchemist packet requires sealed executable contract".to_string());
            } else {
                json_reference(contract, "Alchemist execution contract", &mut errors, &mut references);
            }
            let scope_obj = scope.and_then(|s| s.as_object());
            let own = scope_obj.and_then(|o| o.get("own")).and_then(|v| v.as_array());
            let contract_own = scope_obj.and_then(|o| o.get("contractOwn")).and_then(|v| v.as_array());
            let subset_ok = match (own, contract_own) {
                (Some(own), Some(contract_own)) => {
                    let contract_own_set: BTreeSet<String> =
                        contract_own.iter().map(|v| v.to_string()).collect();
                    own.iter().all(|v| contract_own_set.contains(&v.to_string()))
                }
                _ => false,
            };
            if scope_obj.is_none() || own.is_none() || contract_own.is_none() || !subset_ok {
                errors.push("Alchemist OWN scope must be contract subset".to_string());
            }
        }
        Some("worker") => {
            let capsule = json_reference(packet.get("workerCapsule"), "Worker capsule", &mut errors, &mut references);
            if capsule.is_none() {
                errors.push("worker packet requires canonical WorkerCapsule".to_string());
            }
            let task_projection = packet.get("taskProjection");
            let artifact_projection = packet.get("artifactProjection");
            if !task_projection.is_some_and(|v| v.is_object()) || !artifact_projection.is_some_and(|v| v.is_object()) {
                errors.push("worker packet requires lossless task and artifact projections".to_string());
            } else {
                json_reference(task_projection, "Worker task projection", &mut errors, &mut references);
                json_reference(artifact_projection, "Worker artifact projection", &mut errors, &mut references);
            }
            json_reference(packet.get("oracle"), "Worker oracle", &mut errors, &mut references);
        }
        _ => {
            errors.push("authority packet type must be direct, sage, oracle, alchemist, or worker".to_string());
        }
    }

    if references.is_empty() {
        errors.push("authority packet requires at least one content-bound artifact".to_string());
    }

    (errors, references)
}

/// Port of the `packet_type == "direct"` branch of `authority_packet_errors`
/// (validate-dispatch.py lines ~324-607): dispatch-wave/lane validation,
/// worker OWN/READ/FORBIDDEN scope checks, `executorRequirement`/escalation
/// policy validation, and the Oracle pre-execution audit + recovery
/// contract checks.
fn direct_packet_errors(
    packet: &Value,
    artifact: &Path,
    root: Option<&Path>,
    errors: &mut Vec<String>,
    references: &mut Vec<Reference>,
) {
    let str_nonempty = |v: Option<&Value>| v.and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty());

    if !str_nonempty(packet.get("objective")) {
        errors.push("direct packet requires objective".to_string());
    }
    if !str_nonempty(packet.get("integrationOwner")) {
        errors.push("direct packet requires integration owner".to_string());
    }
    let authority = packet.get("authority").and_then(|v| v.as_array());
    match authority {
        None => errors.push("direct packet requires authority sources".to_string()),
        Some(list) if list.is_empty() => errors.push("direct packet requires authority sources".to_string()),
        Some(list) => {
            for (index, authority_path) in list.iter().enumerate() {
                let label = format!("direct authority {}", index + 1);
                let value = authority_path.as_str();
                content_reference(value, artifact, &label, errors, references);
            }
        }
    }

    // File-touch policy.
    let mut planned_files: BTreeSet<String> = BTreeSet::new();
    let file_touch_policy = packet.get("fileTouchPolicy").and_then(|v| v.as_object());
    let planned_files_raw = file_touch_policy.and_then(|p| p.get("plannedFiles")).and_then(|v| v.as_array());
    let policy_ok = file_touch_policy.is_some_and(|p| {
        p.get("mode").and_then(|v| v.as_str()) == Some("once-end-to-end")
            && p.get("allowUnplannedFiles") == Some(&Value::Bool(false))
    }) && planned_files_raw.is_some_and(|v| !v.is_empty());
    if !policy_ok {
        errors.push("direct packet requires closed once-end-to-end file-touch policy".to_string());
    } else if let Some(raw_planned) = planned_files_raw {
        if raw_planned.iter().any(|v| !v.as_str().is_some_and(|s| !s.trim().is_empty())) {
            errors.push("direct plannedFiles requires exact repository-relative file paths".to_string());
        } else {
            let normalized_planned: Vec<Option<String>> = raw_planned
                .iter()
                .map(|v| direct_file_allowlist_path(v.as_str().unwrap_or("")))
                .collect();
            if normalized_planned.iter().any(|v| v.is_none()) {
                errors.push("direct plannedFiles forbids globs, directories, and invalid paths".to_string());
            }
            planned_files = normalized_planned.into_iter().flatten().collect();
            if planned_files.len() != raw_planned.len() {
                errors.push("direct plannedFiles contains duplicate or aliased paths".to_string());
            }
            if let Some(root) = root {
                for path in &planned_files {
                    if root.join(path).is_dir() {
                        errors.push(format!("direct plannedFiles path is a directory: {path}"));
                    }
                }
            }
        }
    }

    // Dispatch waves.
    let mut dispatch_ids: BTreeSet<String> = BTreeSet::new();
    let mut dispatch_lanes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut declared_lanes: BTreeSet<String> = BTreeSet::new();
    let dispatches = packet.get("dispatches").and_then(|v| v.as_array());
    match dispatches {
        None => errors.push("direct packet requires dependency-ordered dispatch waves".to_string()),
        Some(list) if list.is_empty() => {
            errors.push("direct packet requires dependency-ordered dispatch waves".to_string())
        }
        Some(list) => {
            let mut prior_dispatches: BTreeSet<String> = BTreeSet::new();
            for (index, dispatch) in list.iter().enumerate() {
                let label = format!("direct dispatch {}", index + 1);
                let dispatch_obj = match dispatch.as_object() {
                    Some(obj) => obj,
                    None => {
                        errors.push(format!("{label} must be an object"));
                        continue;
                    }
                };
                let dispatch_id = dispatch_obj.get("id").and_then(|v| v.as_str());
                let dispatch_id = match dispatch_id {
                    Some(id) if !id.trim().is_empty() => id.to_string(),
                    _ => {
                        errors.push(format!("{label} requires id"));
                        continue;
                    }
                };
                if dispatch_ids.contains(&dispatch_id) {
                    errors.push(format!("direct dispatch id is duplicated: {dispatch_id}"));
                    continue;
                }
                dispatch_ids.insert(dispatch_id.clone());

                let dependencies_raw = dispatch_obj.get("dependsOn").and_then(|v| v.as_array());
                let mut dependencies: Vec<String> = Vec::new();
                let deps_valid = dependencies_raw.is_some_and(|list| {
                    let strs: Vec<&str> = list.iter().filter_map(|v| v.as_str()).collect();
                    strs.len() == list.len()
                        && list.iter().all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty()))
                        && {
                            let set: BTreeSet<&str> = strs.iter().copied().collect();
                            set.len() == strs.len()
                        }
                });
                if !deps_valid {
                    errors.push(format!("{label} dependsOn requires unique prior dispatch ids"));
                } else if let Some(list) = dependencies_raw {
                    dependencies = list.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    if dependencies.iter().any(|d| !prior_dispatches.contains(d)) {
                        errors.push(format!("{label} dependsOn must reference only earlier dispatches"));
                    }
                }
                if index == 0 && !dependencies.is_empty() {
                    errors.push("first direct dispatch wave cannot have dependencies".to_string());
                }
                if index > 0 && dependencies.is_empty() {
                    errors.push(format!("{label} lacks dependency; move its lanes into first eligible wave"));
                }

                let lanes_raw = dispatch_obj.get("lanes").and_then(|v| v.as_array());
                let lanes_valid = lanes_raw.is_some_and(|list| {
                    !list.is_empty()
                        && list.iter().all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty()))
                        && {
                            let strs: Vec<&str> = list.iter().filter_map(|v| v.as_str()).collect();
                            let set: BTreeSet<&str> = strs.iter().copied().collect();
                            set.len() == strs.len()
                        }
                });
                if !lanes_valid {
                    errors.push(format!("{label} requires unique lane ids"));
                    dispatch_lanes.insert(dispatch_id.clone(), BTreeSet::new());
                } else if let Some(list) = lanes_raw {
                    let lane_set: BTreeSet<String> = list.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    let overlap: Vec<&String> = declared_lanes.intersection(&lane_set).collect();
                    if !overlap.is_empty() {
                        let mut names: Vec<String> = overlap.into_iter().cloned().collect();
                        names.sort();
                        errors.push(format!("direct lanes appear in multiple dispatches: {}", names.join(", ")));
                    }
                    declared_lanes.extend(lane_set.clone());
                    dispatch_lanes.insert(dispatch_id.clone(), lane_set);
                }

                let completion_checks = dispatch_obj.get("completionChecks").and_then(|v| v.as_array());
                let checks_valid = completion_checks
                    .is_some_and(|list| !list.is_empty() && list.iter().all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty())));
                if !checks_valid {
                    errors.push(format!("{label} requires completion checks"));
                }
                prior_dispatches.insert(dispatch_id);
            }
        }
    }

    // Workers.
    let workers = packet.get("workers").and_then(|v| v.as_array());
    match workers {
        None => errors.push("direct packet requires at least one worker".to_string()),
        Some(list) if list.is_empty() => errors.push("direct packet requires at least one worker".to_string()),
        Some(list) => {
            let mut worker_ids: BTreeSet<String> = BTreeSet::new();
            let mut owned_paths: BTreeMap<String, String> = BTreeMap::new();
            for (index, worker) in list.iter().enumerate() {
                let label = format!("direct worker {}", index + 1);
                let worker_obj = match worker.as_object() {
                    Some(obj) => obj,
                    None => {
                        errors.push(format!("{label} must be an object"));
                        continue;
                    }
                };
                let raw_id = worker_obj.get("id").and_then(|v| v.as_str());
                let worker_id = match raw_id {
                    Some(id) if !id.trim().is_empty() => {
                        if worker_ids.contains(id) {
                            errors.push(format!("direct worker id is duplicated: {id}"));
                        } else {
                            worker_ids.insert(id.to_string());
                        }
                        id.to_string()
                    }
                    _ => {
                        errors.push(format!("{label} requires id"));
                        format!("#{}", index + 1)
                    }
                };
                let dispatch_id = worker_obj.get("dispatch").and_then(|v| v.as_str());
                match dispatch_id {
                    Some(id) if dispatch_ids.contains(id) => {
                        if !dispatch_lanes.get(id).is_some_and(|lanes| lanes.contains(&worker_id)) {
                            errors.push(format!("{label} is not listed in dispatch {id}"));
                        }
                    }
                    _ => errors.push(format!("{label} requires known dispatch wave")),
                }

                let mut semantic_requirement: Option<&str> = None;
                if worker_obj.contains_key("executorRequirement") {
                    let executor_requirement = worker_obj.get("executorRequirement").and_then(|v| v.as_object());
                    match executor_requirement {
                        None => errors.push(format!("{label} executorRequirement must be an object")),
                        Some(er) => {
                            semantic_requirement = er.get("semanticRequirement").and_then(|v| v.as_str());
                            if !semantic_requirement.is_some_and(|s| EXECUTOR_SEMANTIC_REQUIREMENTS.contains(&s)) {
                                errors.push(format!("{label} executorRequirement has invalid semanticRequirement"));
                            }
                            for field_name in ["capabilities", "effects", "authorityCeiling"] {
                                let values = er.get(field_name).and_then(|v| v.as_array());
                                let ok = values.is_some_and(|list| {
                                    !list.is_empty()
                                        && list.iter().all(|v| {
                                            v.as_str().is_some_and(|s| executor_token_re().is_match(s))
                                        })
                                        && {
                                            let strs: Vec<&str> = list.iter().filter_map(|v| v.as_str()).collect();
                                            let set: BTreeSet<&str> = strs.iter().copied().collect();
                                            set.len() == strs.len()
                                        }
                                });
                                if !ok {
                                    errors.push(format!("{label} executorRequirement requires valid {field_name}"));
                                }
                            }
                            let completion = er.get("completion").and_then(|v| v.as_array());
                            let completion_ok = completion.is_some_and(|list| {
                                !list.is_empty()
                                    && list.iter().all(|check| {
                                        check.as_object().is_some_and(|c| {
                                            c.get("kind").and_then(|v| v.as_str()).is_some_and(|s| executor_token_re().is_match(s))
                                                && c.get("id").and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty())
                                        })
                                    })
                            });
                            if !completion_ok {
                                errors.push(format!("{label} executorRequirement requires valid completion checks"));
                            } else if let Some(list) = completion {
                                let ids: Vec<&str> = list
                                    .iter()
                                    .filter_map(|c| c.get("id").and_then(|v| v.as_str()))
                                    .collect();
                                let set: BTreeSet<&str> = ids.iter().copied().collect();
                                if set.len() != ids.len() {
                                    errors.push(format!("{label} executorRequirement completion ids must be unique"));
                                }
                            }
                            let escalation = er.get("escalation").and_then(|v| v.as_object());
                            let mut permitted_on: Vec<String> = Vec::new();
                            let mut forbidden_on: Vec<String> = Vec::new();
                            match escalation {
                                None => errors.push(format!("{label} executorRequirement requires escalation policy")),
                                Some(escalation) => {
                                    for (field_name, target) in [
                                        ("permittedOn", &mut permitted_on),
                                        ("forbiddenOn", &mut forbidden_on),
                                    ] {
                                        let outcomes = escalation.get(field_name).and_then(|v| v.as_array());
                                        let ok = outcomes.is_some_and(|list| {
                                            list.iter().all(|v| {
                                                v.as_str().is_some_and(|s| EXECUTOR_ESCALATION_OUTCOMES.contains(&s))
                                            }) && {
                                                let strs: Vec<&str> = list.iter().filter_map(|v| v.as_str()).collect();
                                                let set: BTreeSet<&str> = strs.iter().copied().collect();
                                                set.len() == strs.len()
                                            }
                                        });
                                        if !ok {
                                            errors.push(format!("{label} executorRequirement requires valid escalation {field_name}"));
                                        }
                                        if let Some(list) = outcomes {
                                            *target = list.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                                        }
                                    }
                                    let permitted_set: BTreeSet<&str> = permitted_on.iter().map(|s| s.as_str()).collect();
                                    let forbidden_set: BTreeSet<&str> = forbidden_on.iter().map(|s| s.as_str()).collect();
                                    if !permitted_set.is_disjoint(&forbidden_set) {
                                        errors.push(format!("{label} executorRequirement escalation policies overlap"));
                                    }
                                    if permitted_set.contains("denied") {
                                        errors.push(format!("{label} executorRequirement escalation permits denied"));
                                    }
                                    if semantic_requirement == Some("forbidden") && !permitted_on.is_empty() {
                                        errors.push(format!("{label} executorRequirement forbids semantic escalation"));
                                    }
                                    if semantic_requirement == Some("conditional") && permitted_on.is_empty() {
                                        errors.push(format!("{label} executorRequirement conditional requires escalation"));
                                    }
                                }
                            }
                        }
                    }
                } else if !worker_obj.get("executor").and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty()) {
                    errors.push(format!("{label} requires executor"));
                }

                // OWN/READ/FORBIDDEN scopes.
                let mut normalized: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
                for (scope_name, key, required_scope) in
                    [("OWN", "allowlist", true), ("READ", "read", false), ("FORBIDDEN", "forbidden", false)]
                {
                    let values = worker_obj.get(key).and_then(|v| v.as_array());
                    let values_ok = values.is_some_and(|list| {
                        (!required_scope || !list.is_empty())
                            && list.iter().all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty()))
                    });
                    if !values_ok {
                        errors.push(format!("{label} requires valid {scope_name} paths"));
                        normalized.insert(scope_name, BTreeSet::new());
                    } else if let Some(list) = values {
                        let path_values: Vec<Option<String>> = list
                            .iter()
                            .map(|v| {
                                let s = v.as_str().unwrap_or("");
                                if scope_name == "OWN" {
                                    direct_file_allowlist_path(s)
                                } else {
                                    direct_scope_path(s)
                                }
                            })
                            .collect();
                        if path_values.iter().any(|v| v.is_none()) {
                            if scope_name == "OWN" {
                                errors.push(format!("{label} allowlist forbids globs, directories, and invalid paths"));
                            } else {
                                errors.push(format!("{label} contains invalid {scope_name} path"));
                            }
                        }
                        let set: BTreeSet<String> = path_values.into_iter().flatten().collect();
                        if set.len() != list.len() {
                            errors.push(format!("{label} contains duplicate {scope_name} paths"));
                        }
                        normalized.insert(scope_name, set);
                    }
                }
                let own = normalized.get("OWN").cloned().unwrap_or_default();
                let read = normalized.get("READ").cloned().unwrap_or_default();
                let forbidden = normalized.get("FORBIDDEN").cloned().unwrap_or_default();
                if let Some(root) = root {
                    for path in &own {
                        if root.join(path).is_dir() {
                            errors.push(format!("{label} allowlist path is a directory: {path}"));
                        }
                    }
                }
                if !own.is_disjoint(&forbidden) {
                    errors.push(format!("{label} OWN overlaps FORBIDDEN"));
                }
                if !read.is_disjoint(&forbidden) {
                    errors.push(format!("{label} READ overlaps FORBIDDEN"));
                }
                for path in &own {
                    let collisions: Vec<(String, String)> = owned_paths
                        .iter()
                        .filter(|(owned_path, _)| scopes_overlap(path, owned_path))
                        .map(|(p, o)| (p.clone(), o.clone()))
                        .collect();
                    if !collisions.is_empty() {
                        for (owned_path, owner) in collisions {
                            errors.push(format!(
                                "direct OWN collision: {path} overlaps {owned_path} owned by {owner} and {worker_id}"
                            ));
                        }
                    } else {
                        owned_paths.insert(path.clone(), worker_id.clone());
                    }
                }

                let checks = worker_obj.get("checks").and_then(|v| v.as_array());
                let checks_ok = checks
                    .is_some_and(|list| !list.is_empty() && list.iter().all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty())));
                if !checks_ok {
                    errors.push(format!("{label} requires acceptance checks"));
                }

                let dependencies = worker_obj.get("dependencies").and_then(|v| v.as_array());
                let deps_ok = match dependencies {
                    None => true,
                    Some(list) => {
                        list.iter().all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty())) && {
                            let strs: Vec<&str> = list.iter().filter_map(|v| v.as_str()).collect();
                            let set: BTreeSet<&str> = strs.iter().copied().collect();
                            set.len() == strs.len()
                        }
                    }
                };
                if !deps_ok {
                    errors.push(format!("{label} dependencies must be unique worker ids"));
                }
            }

            let known_ids: BTreeSet<String> = list
                .iter()
                .filter_map(|w| w.as_object())
                .filter_map(|w| w.get("id").and_then(|v| v.as_str()).map(String::from))
                .collect();
            if worker_ids != declared_lanes {
                let missing: Vec<&String> = declared_lanes.difference(&worker_ids).collect();
                let extra: Vec<&String> = worker_ids.difference(&declared_lanes).collect();
                if !missing.is_empty() {
                    let names: Vec<String> = missing.into_iter().cloned().collect();
                    errors.push(format!("direct dispatch lanes missing workers: {}", names.join(", ")));
                }
                if !extra.is_empty() {
                    let names: Vec<String> = extra.into_iter().cloned().collect();
                    errors.push(format!("direct workers missing dispatch lane membership: {}", names.join(", ")));
                }
            }
            let owned_file_set: BTreeSet<String> = owned_paths.keys().cloned().collect();
            let missing_files: Vec<&String> = planned_files.difference(&owned_file_set).collect();
            let unplanned_files: Vec<&String> = owned_file_set.difference(&planned_files).collect();
            if !missing_files.is_empty() {
                let names: Vec<String> = missing_files.into_iter().cloned().collect();
                errors.push(format!("direct planned files lack lane allowlist: {}", names.join(", ")));
            }
            if !unplanned_files.is_empty() {
                let names: Vec<String> = unplanned_files.into_iter().cloned().collect();
                errors.push(format!("direct lane allowlist contains unplanned files: {}", names.join(", ")));
            }
            for worker in list {
                let worker_obj = match worker.as_object() {
                    Some(obj) => obj,
                    None => continue,
                };
                let worker_id = worker_obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let dependencies = worker_obj.get("dependencies").and_then(|v| v.as_array());
                if let Some(list) = dependencies {
                    for dependency in list.iter().filter_map(|v| v.as_str()) {
                        if dependency == worker_id {
                            errors.push(format!("direct worker {worker_id} cannot depend on itself"));
                        } else if !known_ids.contains(dependency) {
                            errors.push(format!("direct worker {worker_id} has unknown dependency: {dependency}"));
                        } else {
                            errors.push(format!("direct lane {worker_id} dependencies belong on dispatch wave, not worker"));
                        }
                    }
                }
            }
        }
    }

    // Oracle pre-execution audit contract.
    let required_oracle_checks: [&str; 5] = [
        "allowlist-completeness",
        "lane-disjointness",
        "dependency-validity",
        "maximum-safe-parallelization",
        "end-to-end-lane-closure",
    ];
    let oracle_audit = packet.get("oracleAudit").and_then(|v| v.as_object());
    let oracle_ok = oracle_audit.is_some_and(|audit| {
        audit.get("required") == Some(&Value::Bool(true))
            && audit.get("mode").and_then(|v| v.as_str()) == Some("adversarial")
            && audit.get("status").and_then(|v| v.as_str()) == Some("required-before-execution")
            && audit.get("checks").and_then(|v| v.as_array()).is_some_and(|checks| {
                let set: BTreeSet<&str> = checks.iter().filter_map(|v| v.as_str()).collect();
                required_oracle_checks.iter().all(|c| set.contains(c))
            })
    });
    if !oracle_ok {
        errors.push("direct packet requires adversarial Oracle pre-execution audit contract".to_string());
    }

    // Recovery contract.
    let recovery = packet.get("recovery").and_then(|v| v.as_object());
    let recovery_ok = recovery.is_some_and(|recovery| {
        let max_retries_ok = recovery.get("maxRetries").and_then(|v| v.as_i64()).is_some_and(|n| (0..=2).contains(&n));
        let stop_ok = recovery.get("stopConditions").and_then(|v| v.as_array()).is_some_and(|list| {
            !list.is_empty() && list.iter().all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty()))
        });
        let return_ok = recovery.get("returnFields").and_then(|v| v.as_array()).is_some_and(|list| {
            !list.is_empty() && list.iter().all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty()))
        });
        max_retries_ok && stop_ok && return_ok
    });
    if !recovery_ok {
        errors.push("direct packet requires bounded recovery and return contract".to_string());
    }
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
        let route = dir.join("sage-adjudication.json");
        std::fs::write(&route, b"{}").unwrap();
        let route_digest = sha256_digest(&std::fs::read(&route).unwrap());

        let packet = serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-authority-dispatch",
            "packetType": "sage",
            "repositoryRoot": dir.to_string_lossy(),
            "sourceRevision": revision,
            "promptArtifact": prompt.to_string_lossy(),
            "promptDigest": prompt_digest,
            "modelRouting": {"modelTier": "CHEAP_STRICT", "workerProfile": "strict", "routingRationale": "bounded execution"},
            "routeBundle": {"path": route.to_string_lossy(), "digest": route_digest},
        });
        let artifact = dir.join("packet.json");
        let (errors, _) = authority_packet_errors(&packet, &artifact);
        assert!(errors.is_empty(), "{errors:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Port of `test_validate_dispatch.py`'s direct-packet structural
    /// coverage, for the `packetType == "direct"` branch this chunk added
    /// (validate-dispatch.py lines ~324-607): a minimal but fully valid
    /// direct packet (one dispatch wave, one worker, matching allowlist/
    /// planned-files, Oracle audit contract, bounded recovery) is clean,
    /// and dropping the Oracle audit contract reproduces the Python error.
    #[test]
    fn direct_packet_minimal_valid_shape_is_clean() {
        let dir = fixture_dir("direct-clean");
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);
        git(&dir, &["config", "user.email", "t@example.test"]);
        git(&dir, &["config", "user.name", "T"]);
        let prompt = dir.join("prompt.txt");
        std::fs::write(&prompt, b"exact captured prompt").unwrap();
        let authority_doc = dir.join("authority.md");
        std::fs::write(&authority_doc, b"authority source").unwrap();
        std::fs::write(dir.join("planned.rs"), b"// planned").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "init"]);
        let revision = String::from_utf8(
            Command::new("git").arg("-C").arg(&dir).args(["rev-parse", "HEAD"]).output().unwrap().stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let prompt_digest = sha256_digest(&std::fs::read(&prompt).unwrap());

        let direct_packet = |include_oracle: bool| {
            let mut packet = serde_json::json!({
                "schemaVersion": 1,
                "kind": "legion-authority-dispatch",
                "packetType": "direct",
                "repositoryRoot": dir.to_string_lossy(),
                "sourceRevision": revision,
                "promptArtifact": prompt.to_string_lossy(),
                "promptDigest": prompt_digest,
                "modelRouting": {"modelTier": "FRONTIER", "workerProfile": "strict", "routingRationale": "bounded"},
                "objective": "ship the thing",
                "integrationOwner": "dispatcher",
                "authority": [authority_doc.to_string_lossy()],
                "fileTouchPolicy": {
                    "mode": "once-end-to-end",
                    "allowUnplannedFiles": false,
                    "plannedFiles": ["planned.rs"],
                },
                "dispatches": [
                    {"id": "wave-1", "dependsOn": [], "lanes": ["worker-1"], "completionChecks": ["done"]},
                ],
                "workers": [
                    {
                        "id": "worker-1",
                        "dispatch": "wave-1",
                        "executor": "claude",
                        "allowlist": ["planned.rs"],
                        "read": [],
                        "forbidden": [],
                        "checks": ["cargo test"],
                        "dependencies": [],
                    },
                ],
                "recovery": {
                    "maxRetries": 1,
                    "stopConditions": ["repeat failure"],
                    "returnFields": ["status"],
                },
            });
            if include_oracle {
                packet["oracleAudit"] = serde_json::json!({
                    "required": true,
                    "mode": "adversarial",
                    "status": "required-before-execution",
                    "checks": [
                        "allowlist-completeness",
                        "lane-disjointness",
                        "dependency-validity",
                        "maximum-safe-parallelization",
                        "end-to-end-lane-closure",
                    ],
                });
            }
            packet
        };

        let artifact = dir.join("packet.json");
        let (errors, _) = authority_packet_errors(&direct_packet(true), &artifact);
        assert!(errors.is_empty(), "{errors:?}");

        let (errors, _) = authority_packet_errors(&direct_packet(false), &artifact);
        assert!(
            errors.contains(&"direct packet requires adversarial Oracle pre-execution audit contract".to_string()),
            "{errors:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Port of the Python direct-packet OWN-collision check
    /// (`direct OWN collision: ... overlaps ... owned by ...`).
    #[test]
    fn direct_packet_reports_own_collision() {
        let packet = serde_json::json!({
            "packetType": "direct",
            "workers": [
                {
                    "id": "worker-1",
                    "dispatch": "wave-1",
                    "allowlist": ["a/b.rs"],
                    "read": [],
                    "forbidden": [],
                    "checks": ["c"],
                },
                {
                    "id": "worker-2",
                    "dispatch": "wave-1",
                    "allowlist": ["a/b.rs"],
                    "read": [],
                    "forbidden": [],
                    "checks": ["c"],
                },
            ],
            "dispatches": [
                {"id": "wave-1", "dependsOn": [], "lanes": ["worker-1", "worker-2"], "completionChecks": ["done"]},
            ],
        });
        let mut errors = Vec::new();
        let mut references = Vec::new();
        direct_packet_errors(&packet, Path::new("/nonexistent/packet.json"), None, &mut errors, &mut references);
        assert!(
            errors.iter().any(|e| e.contains("direct OWN collision: a/b.rs overlaps a/b.rs owned by worker-1 and worker-2")),
            "{errors:?}"
        );
    }

    /// Port of the Python worker-packet capsule/projection requirement.
    #[test]
    fn worker_packet_requires_capsule_and_projections() {
        let packet = serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-authority-dispatch",
            "packetType": "worker",
            "modelRouting": {"modelTier": "FRONTIER", "workerProfile": "strict", "routingRationale": "bounded"},
        });
        let artifact = PathBuf::from("/nonexistent/packet.json");
        let (errors, _) = authority_packet_errors(&packet, &artifact);
        assert!(
            errors.contains(&"worker packet requires canonical WorkerCapsule".to_string()),
            "{errors:?}"
        );
        assert!(
            errors.contains(&"worker packet requires lossless task and artifact projections".to_string()),
            "{errors:?}"
        );
    }

    /// Port of the Python Oracle scope-overlap check.
    #[test]
    fn oracle_packet_reports_scope_overlap() {
        let packet = serde_json::json!({
            "packetType": "oracle",
            "lens": {"id": "some-lens"},
            "scope": {"read": ["a/b.rs"], "forbidden": ["a/b.rs"]},
        });
        // Exercised through the full authority_packet_errors dispatcher;
        // unrelated base-shape errors are expected alongside it since the
        // fixture omits schemaVersion/kind/sourceRevision/etc.
        let (all_errors, _refs) = authority_packet_errors(&packet, Path::new("/nonexistent/packet.json"));
        assert!(
            all_errors.iter().any(|e| e == "Oracle scope overlaps forbidden paths"),
            "{all_errors:?}"
        );
    }
}
