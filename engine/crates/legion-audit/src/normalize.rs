use legion_contracts::ProviderResult;

pub fn normalize(mut result: ProviderResult) -> ProviderResult {
    result.findings.sort_by(|a, b| a.id.cmp(&b.id));
    result.coverage_gaps.sort();
    result.coverage_gaps.dedup();
    result.degradation.sort();
    result.degradation.dedup();
    result
}

pub fn normalize_all(results: impl IntoIterator<Item = ProviderResult>) -> Vec<ProviderResult> {
    let mut output: Vec<_> = results.into_iter().map(normalize).collect();
    output.sort_by(|a, b| a.provider.cmp(&b.provider));
    output
}

// ---------------------------------------------------------------------------
// Replay-equivalence digest
//
// The byte-integrity digests (`integrity::digest`, plan digests, artifact
// digests) answer "are these exact bytes unchanged?". `replay_digest` answers
// a different question: "did a re-run reach the same audit outcome?". It is
// computed over a normalized view that removes volatile fields, so two
// independent runs of the same frozen scope compare equal while any semantic
// difference (findings, gaps, coverage, verdict, plan content) does not. The
// two digests are never interchangeable: replay digests carry the distinct
// `replay-sha256:` prefix and must not be used as integrity evidence.
//
// Volatile fields (removed at any depth):
//   * keys named exactly: timestamp, generatedAt, createdAt, startedAt,
//     finishedAt, completedAt, updatedAt, observedAt, duration, elapsed,
//     wallClock, pid, hostname, host, machineId, runId, nonce, epoch,
//     planKey, signature, planSignature, seal.signature (via `signature`),
//     sourcePerformance, snapshotManifest, executionRoot, baselineRoot,
//     sourceRepository, outDir, runDir, cwd, tempDir, scratchDir, receiptId, packetDigest,
//     reasoningEpochDigest
//   * keys ending in `At`, `_at`, `Ms`, `_ms` (timestamps and durations)
// Value rewrites:
//   * a path segment chain rooted at a temporary directory (`/tmp/<x>`,
//     `/private/tmp/<x>`, `/var/folders/<a>/<b>/T/<x>`, `\AppData\Local\Temp\<x>`,
//     or the host's own `std::env::temp_dir()`)
//     becomes `<tmp>`; the remainder of the path is kept.
// Ordering noise: arrays under these keys are order-insensitive and sorted by
// canonical form: findings, coverageGaps, coverage_gaps, gaps, degradation,
// providers, providerResults, provider_reconciliation, results, checks,
// artifacts, files, plannedProviders. All other arrays stay order-sensitive.
// ---------------------------------------------------------------------------

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Prefix of a replay-equivalence digest (distinct from byte-integrity digests).
pub const REPLAY_DIGEST_PREFIX: &str = "replay-sha256:";

const VOLATILE_KEYS: &[&str] = &[
    "timestamp",
    "generatedAt",
    "createdAt",
    "startedAt",
    "finishedAt",
    "completedAt",
    "updatedAt",
    "observedAt",
    "duration",
    "elapsed",
    "wallClock",
    "pid",
    "hostname",
    "host",
    "machineId",
    "runId",
    "nonce",
    "epoch",
    "planKey",
    "signature",
    "planSignature",
    "sourcePerformance",
    "snapshotManifest",
    "executionRoot",
    "baselineRoot",
    "sourceRepository",
    "outDir",
    "runDir",
    "cwd",
    "tempDir",
    "scratchDir",
    "receiptId",
    // Lens packets embed the run's own epoch identity, so their digest is per-run.
    "packetDigest",
    "reasoningEpochDigest",
];

const UNORDERED_KEYS: &[&str] = &[
    "findings",
    "coverageGaps",
    "coverage_gaps",
    "gaps",
    "degradation",
    "providers",
    "providerResults",
    "provider_reconciliation",
    "results",
    "checks",
    "artifacts",
    "files",
    "plannedProviders",
];

fn is_volatile_key(key: &str) -> bool {
    VOLATILE_KEYS.contains(&key)
        || key.ends_with("At")
        || key.ends_with("_at")
        || key.ends_with("Ms")
        || key.ends_with("_ms")
}

fn strip_temp_paths(text: &str) -> String {
    // (marker, extra segments consumed after the marker before the unique run dir)
    const MARKERS: &[&str] = &[
        "/private/tmp/",
        "/tmp/",
        "\\AppData\\Local\\Temp\\",
        "/AppData/Local/Temp/",
    ];
    let mut output = text.to_owned();
    // The host's own temp root (e.g. a managed build temp) also holds per-run
    // directories; its first child is the unique run directory.
    let host_temp = std::env::temp_dir();
    let host_temp = host_temp.to_string_lossy();
    let host_marker = format!("{}/", host_temp.trim_end_matches(['/', '\\']));
    if host_marker.len() > 1 {
        let mut from = 0;
        while let Some(found) = output[from..].find(host_marker.as_str()) {
            let start = from + found;
            let after = start + host_marker.len();
            let end = output[after..]
                .find(['/', '\\'])
                .map(|offset| after + offset)
                .unwrap_or(output.len());
            output.replace_range(start..end, "<tmp>");
            from = start + "<tmp>".len();
        }
    }
    // Per-run scratch directories named `legion-audit-<kind>-<pid>-<nanos>[-n]`:
    // keep the kind, drop the process/time digits.
    let mut rebuilt = String::with_capacity(output.len());
    for (index, segment) in output.split('/').enumerate() {
        if index > 0 {
            rebuilt.push('/');
        }
        if segment.starts_with("legion-audit-") && segment.chars().any(|c| c.is_ascii_digit()) {
            let mut previous_digit = false;
            for c in segment.chars() {
                if c.is_ascii_digit() {
                    if !previous_digit {
                        rebuilt.push('N');
                    }
                    previous_digit = true;
                } else {
                    rebuilt.push(c);
                    previous_digit = false;
                }
            }
        } else {
            rebuilt.push_str(segment);
        }
    }
    output = rebuilt;
    // `/var/folders/<a>/<b>/T/<x>`
    while let Some(start) = output.find("/var/folders/") {
        let tail = &output[start + "/var/folders/".len()..];
        let mut parts = tail.splitn(5, '/');
        let (a, b, t, unique) = (parts.next(), parts.next(), parts.next(), parts.next());
        let consumed = match (a, b, t, unique) {
            (Some(a), Some(b), Some("T"), Some(unique)) => a.len() + b.len() + 3 + unique.len() + 1,
            _ => break,
        };
        let end = start + "/var/folders/".len() + consumed - 1;
        output.replace_range(start..end.min(output.len()), "<tmp>");
    }
    for marker in MARKERS {
        while let Some(start) = output.find(marker) {
            let after = start + marker.len();
            let separators: &[char] = &['/', '\\'];
            let end = output[after..]
                .find(separators)
                .map(|offset| after + offset)
                .unwrap_or(output.len());
            if end == after && after >= output.len() {
                output.replace_range(start..after, "<tmp>");
                break;
            }
            output.replace_range(start..end, "<tmp>");
        }
    }
    output
}

/// Normalized replay view of an arbitrary JSON document.
pub fn replay_normalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(key, _)| !is_volatile_key(key))
                .map(|(key, child)| {
                    let mut normalized = replay_normalize(child);
                    if UNORDERED_KEYS.contains(&key.as_str()) {
                        if let Value::Array(items) = &mut normalized {
                            items.sort_by_key(canonical_sort_key);
                        }
                    }
                    (key.clone(), normalized)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(replay_normalize).collect()),
        Value::String(text) => Value::String(strip_temp_paths(text)),
        other => other.clone(),
    }
}

fn canonical_sort_key(value: &Value) -> String {
    legion_contracts::canonical_json_bytes(value)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// `replay-sha256:<hex>` over the canonical bytes of the normalized view.
pub fn replay_digest(value: &Value) -> Result<String, crate::error::AuditError> {
    let bytes = legion_contracts::canonical_json_bytes(&replay_normalize(value))
        .map_err(|error| crate::error::AuditError::Invalid(error.to_string()))?;
    Ok(format!(
        "{REPLAY_DIGEST_PREFIX}{}",
        hex::encode(Sha256::digest(bytes))
    ))
}

/// JSON-pointer paths at which the normalized views of `a` and `b` differ.
/// Empty means replay-equivalent.
pub fn replay_differences(a: &Value, b: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    diff(&replay_normalize(a), &replay_normalize(b), "", &mut paths);
    paths
}

fn diff(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(left), Value::Object(right)) => {
            let keys: std::collections::BTreeSet<_> = left.keys().chain(right.keys()).collect();
            for key in keys {
                let child = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                match (left.get(key), right.get(key)) {
                    (Some(l), Some(r)) => diff(l, r, &child, out),
                    _ => out.push(child),
                }
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            if left.len() != right.len() {
                out.push(format!("{path}#length"));
            }
            for (index, (l, r)) in left.iter().zip(right).enumerate() {
                diff(l, r, &format!("{path}/{index}"), out);
            }
        }
        _ if a == b => {}
        _ => out.push(if path.is_empty() {
            "/".into()
        } else {
            path.into()
        }),
    }
}
