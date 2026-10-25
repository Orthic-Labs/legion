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
//   * the explicit measured-time keys listed in `VOLATILE_KEYS` (timestamps
//     such as createdAt/created_at/startedAtMs/expires_at, and measured
//     durations such as durationMs/duration_ms/elapsed_ms/wall_time_ms).
//     There is NO suffix rule: configured bounds such as `timeoutMs`,
//     `timeout_ms`, `providerTimeoutMs`, `leaseMs`, `termination_grace_ms`
//     are semantic provider/plan inputs and stay in the digest.
// Value rewrites:
//   * ONLY the single generated run-directory segment directly after a
//     temporary root (`/tmp/`, `/private/tmp/` (folded onto `/tmp/`),
//     `/var/folders/<a>/<b>/T/`, `\AppData\Local\Temp\`, or the host's
//     `std::env::temp_dir()`) becomes `<tmp>` (root+segment). A segment is
//     generated only when it is >= 6 chars and contains a digit, or is >= 8
//     hex chars. The segment ends at a path separator, whitespace or quote;
//     later segments and surrounding prose are kept verbatim, and
//     non-generated segments (`/tmp/a` vs `/tmp/b`) are never collapsed.
//   * per-run scratch directories named `legion-audit-<kind>-<pid>-<nanos>[-n]`
//     keep the kind and lose their digits (`legion-audit-security-N-N-N`),
//     wherever they sit in a path whose separators are `/` or `\`.
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
    // Journal head recorded in the report (sequence/digest of this run).
    "journalSealedAt",
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
    // Measured timestamps (camelCase and snake_case forms emitted by Legion).
    "created_at",
    "expiresAt",
    "expires_at",
    "expires_at_ms",
    "issuedAt",
    "issued_at",
    "retrievedAt",
    "retrieved_at",
    "recordedAt",
    "recorded_at",
    "checkedAt",
    "checked_at",
    "collectedAt",
    "collected_at",
    "lastSeenAt",
    "firstSeenAt",
    "resolvedAt",
    "stagedAt",
    "generated_at",
    "started_at",
    "completed_at",
    "finished_at",
    "updated_at",
    "observed_at",
    "observed_at_ms",
    "started_at_ms",
    "completed_at_ms",
    "startedAtMs",
    "completedAtMs",
    "mtime_ms",
    "mtimeMs",
    // Measured durations (not configured bounds such as timeoutMs).
    "durationMs",
    "duration_ms",
    "elapsedMs",
    "elapsed_ms",
    "wallTimeMs",
    "wall_time_ms",
    "activeTimeMs",
    "active_time_ms",
    "totalMs",
    "total_ms",
    "remainingMs",
    "remaining_ms",
    "savings_ms",
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
}

fn is_segment_end(c: char) -> bool {
    matches!(c, '/' | '\\' | '"' | '\'' | '`' | ')' | ',' | ';') || c.is_whitespace()
}

/// A per-run generated directory name: random/pid/time suffix, not a plain word.
fn looks_generated(segment: &str) -> bool {
    let len = segment.chars().count();
    let has_digit = segment.chars().any(|c| c.is_ascii_digit());
    let hex = len >= 8 && segment.chars().all(|c| c.is_ascii_hexdigit());
    (len >= 6 && has_digit) || hex
}

/// Replace `root + <generated segment>` by `<tmp>` for each occurrence of
/// `root`; `root_len_at` returns the byte length of the root match at a
/// position so shaped roots (`/var/folders/<a>/<b>/T/`) can be supported.
fn rewrite_generated_after(
    text: &str,
    find_root: impl Fn(&str, usize) -> Option<(usize, usize)>,
) -> String {
    let mut output = String::with_capacity(text.len());
    let mut from = 0;
    while let Some((start, after)) = find_root(text, from) {
        output.push_str(&text[from..start]);
        let end = text[after..]
            .find(is_segment_end)
            .map(|offset| after + offset)
            .unwrap_or(text.len());
        if looks_generated(&text[after..end]) {
            output.push_str("<tmp>");
            from = end;
        } else {
            output.push_str(&text[start..after]);
            from = after;
        }
    }
    output.push_str(&text[from..]);
    output
}

fn literal_root(marker: String) -> impl Fn(&str, usize) -> Option<(usize, usize)> {
    move |text, from| {
        text[from..]
            .find(marker.as_str())
            .map(|offset| (from + offset, from + offset + marker.len()))
    }
}

fn var_folders_root(text: &str, from: usize) -> Option<(usize, usize)> {
    const PREFIX: &str = "/var/folders/";
    let mut search = from;
    while let Some(offset) = text[search..].find(PREFIX) {
        let start = search + offset;
        let mut rest = &text[start + PREFIX.len()..];
        let mut consumed = start + PREFIX.len();
        let mut ok = true;
        for expected in [None, None, Some("T")] {
            match rest.split_once('/') {
                Some((part, tail)) if !part.is_empty() && expected.map_or(true, |e| e == part) => {
                    consumed += part.len() + 1;
                    rest = tail;
                }
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return Some((start, consumed));
        }
        search = start + PREFIX.len();
    }
    None
}

fn strip_temp_paths(text: &str) -> String {
    strip_random_suffixes(&strip_temp_roots(text))
}

/// Per-run random report directory suffixes (`report-<check>-<16+ hex>`)
/// anywhere in a path: keep the name, drop the random part. Only segments that
/// start with `report-` and end in `-<16+ lowercase hex>` are rewritten.
fn strip_random_suffixes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut segment = String::new();
    let flush = |segment: &mut String, out: &mut String| {
        if let Some((head, tail)) = segment.rsplit_once('-') {
            // Only Legion's own per-run report directories; never digests or
            // commit ids inside messages.
            if head.starts_with("report-")
                && tail.len() >= 16
                && tail
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                out.push_str(head);
                out.push_str("-<rand>");
                segment.clear();
                return;
            }
        }
        out.push_str(segment);
        segment.clear();
    };
    for c in text.chars() {
        if matches!(c, '/' | '\\' | ' ' | '"' | '\'') {
            flush(&mut segment, &mut out);
            out.push(c);
        } else {
            segment.push(c);
        }
    }
    flush(&mut segment, &mut out);
    out
}

fn strip_temp_roots(text: &str) -> String {
    // `/private/tmp/` is the same directory as `/tmp/` on macOS.
    let mut output = text.replace("/private/tmp/", "/tmp/");
    output = rewrite_generated_after(&output, var_folders_root);
    for marker in ["/tmp/", "\\AppData\\Local\\Temp\\", "/AppData/Local/Temp/"] {
        output = rewrite_generated_after(&output, literal_root(marker.to_owned()));
    }
    // The host's own temp root (e.g. a managed build temp).
    let host_temp = std::env::temp_dir();
    let host_temp = host_temp.to_string_lossy();
    let host_marker = format!("{}/", host_temp.trim_end_matches(['/', '\\']));
    if host_marker.len() > 1 {
        output = rewrite_generated_after(&output, literal_root(host_marker));
    }
    collapse_scratch_segments(&output)
}

/// Per-run scratch directories named `legion-audit-<kind>-<pid>-<nanos>[-n]`:
/// keep the kind, drop the process/time digits. Path segments end at `/` or
/// `\`, so Windows paths (`<run>\legion-audit-security-7036-...-7\f`) collapse
/// exactly like Unix ones; separators are kept verbatim.
fn collapse_scratch_segments(text: &str) -> String {
    let mut rebuilt = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let (segment, separator, tail) = match rest.find(['/', '\\']) {
            // Both separators are single-byte ASCII, so `index + 1` is a char boundary.
            Some(index) => (&rest[..index], &rest[index..=index], &rest[index + 1..]),
            None => (rest, "", ""),
        };
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
        if separator.is_empty() {
            return rebuilt;
        }
        rebuilt.push_str(separator);
        rest = tail;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn n(text: &str) -> String {
        strip_temp_paths(text)
    }

    #[test]
    fn message_text_after_temp_path_is_preserved() {
        assert_ne!(
            n("writes /tmp/x.sh then deletes data"),
            n("writes /tmp/x.sh then reads data")
        );
        assert_eq!(
            n("wrote /tmp/run-12345 then deleted data"),
            "wrote <tmp> then deleted data"
        );
    }

    #[test]
    fn distinct_temp_subpaths_differ() {
        assert_ne!(n("/tmp/a/f"), n("/tmp/b/f"));
        assert_ne!(n("/tmp/run12345/a/f"), n("/tmp/run12345/b/f"));
        assert_eq!(n("/tmp/run12345/f"), n("/private/tmp/abc99999/f"));
    }

    #[test]
    fn scratch_directories_collapse_under_both_path_separators() {
        let unix = n("<run>/legion-audit-security-7036-1792898495145995832-7/syft-native.yaml");
        assert_eq!(unix, "<run>/legion-audit-security-N-N-N/syft-native.yaml");
        // Windows paths: the same run-specific scratch directory, `\` separated.
        let windows = n(r"<run>\legion-audit-security-7036-1792898495145995832-7\syft-native.yaml");
        assert_eq!(
            windows,
            r"<run>\legion-audit-security-N-N-N\syft-native.yaml"
        );
        assert_eq!(
            windows,
            n(r"<run>\legion-audit-security-9912-1792898501294029350-7\syft-native.yaml")
        );
        // Mixed separators and a trailing directory name behave the same way.
        assert_eq!(
            n(r"C:\x/legion-audit-security-1-2-3\f"),
            n(r"C:\x/legion-audit-security-9-8-7\f")
        );
        assert_eq!(
            n(r"<run>\legion-audit-security-1-2-3"),
            r"<run>\legion-audit-security-N-N-N"
        );
    }

    #[test]
    fn scratch_collapse_keeps_distinct_names_and_following_segments() {
        // Only the digits of the scratch directory name are dropped.
        assert_ne!(
            n(r"<run>\legion-audit-security-1-2-3\a"),
            n(r"<run>\legion-audit-security-1-2-3\b")
        );
        assert_ne!(
            n(r"<run>\legion-audit-security-1-2-3\f"),
            n(r"<run>\legion-audit-other-1-2-3\f")
        );
        assert_ne!(n(r"<run>\run-a\f"), n(r"<run>\run-b\f"));
        // A segment that merely contains the prefix later in its text stays verbatim.
        assert_eq!(
            n(r"<run>\x-legion-audit-security-1-2-3\f"),
            r"<run>\x-legion-audit-security-1-2-3\f"
        );
        assert_eq!(n("plain text 12345"), "plain text 12345");
        assert_eq!(n(""), "");
    }

    #[test]
    fn replay_equivalence_ignores_windows_scratch_directories_in_command_args() {
        let receipt = |scratch: &str| {
            json!({"provider": "supply-chain.license-sbom-provenance", "result": {"details": {
                "executionReceipt": {"command": {"executable": "syft", "args": [
                    "scan", "dir:.", "--config", format!(r"<run>\{scratch}\syft-native.yaml")
                ]}}
            }}})
        };
        let a = receipt("legion-audit-security-7036-1792898495145995832-7");
        let b = receipt("legion-audit-security-9912-1792898501294029350-7");
        assert!(replay_differences(&a, &b).is_empty());
        assert_eq!(replay_digest(&a).unwrap(), replay_digest(&b).unwrap());
        // A different tool argument is still a semantic difference.
        let mut c = b.clone();
        c["result"]["details"]["executionReceipt"]["command"]["args"][1] = json!("dir:other");
        assert_eq!(
            replay_differences(&a, &c),
            vec!["/result/details/executionReceipt/command/args/1".to_owned()]
        );
    }

    #[test]
    fn timeout_bounds_are_not_volatile_but_timestamps_are() {
        assert!(!is_volatile_key("timeoutMs"));
        assert!(!is_volatile_key("timeout_ms"));
        assert!(!is_volatile_key("providerTimeoutMs"));
        assert!(is_volatile_key("createdAt"));
        assert!(is_volatile_key("started_at_ms"));
        assert!(is_volatile_key("durationMs"));
        let a = json!({"bounds": {"timeoutMs": 1000}, "createdAt": "x"});
        let b = json!({"bounds": {"timeoutMs": 2000}, "createdAt": "y"});
        assert_ne!(replay_digest(&a).unwrap(), replay_digest(&b).unwrap());
    }
}
