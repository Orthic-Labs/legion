//! Trusted ingest of reasoning-lens results produced by session subagents.
//!
//! `legion audit --out <dir>` freezes a run, writes one `pending-host` lens
//! packet per applicable reasoning provider, and generates a random per-run
//! epoch key. The CLI process is the trusted reasoning host: a subagent runs a
//! packet and hands back a result file, and `ingest_lens_result` validates it
//! against the frozen run, checks that every finding (and every withdrawal)
//! carries a verbatim code anchor that matches the file bytes at the frozen
//! revision, and only then MACs a receipt with the epoch key. `recompute_run`
//! rebuilds the verdict from the original execution plus the ingested
//! receipts, so a reasoning lens counts as having run only through an ingested,
//! MAC-verified receipt.
//!
//! The MAC proves the receipt was minted by the CLI during validation of this
//! run; the anchor check is what makes the result content falsifiable.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_contracts::{
    canonical_digest, Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
    ReportStatus, ReportV1,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{
    authenticate_receipt, followup, lens_plan, lens_schemas,
    security_adjudication::{
        adjudicate_scanner_candidates, confirmed_findings, confirmed_paths,
        ConfirmedSecurityFinding, ScannerCandidate, ADJUDICATOR_PROVIDER_ID,
    },
    verify_authenticated_receipt, verify_response, LensPartRef, PendingLensWork,
    ReasoningHostResponse, ReasoningReceipt, REASONING_PROVIDER_IDS, REASONING_RECEIPT_KIND,
    REASONING_RECEIPT_SCHEMA_VERSION,
};
use crate::{
    error::AuditError,
    execution::ExecutionReport,
    inventory::{FilesystemInventorySource, InventoryDenominator, InventorySource},
    report::canonical_report,
};

pub const EPOCH_KEY_FILE: &str = "epoch.key";
pub const LENS_PACKET_DIR: &str = "lens-packets";
pub const LENS_RECEIPT_DIR: &str = "lens-receipts";
pub const INGEST_HOST: &str = "legion-cli-ingest";
pub const LENS_RESULT_KIND: &str = "legion-lens-result";
const EPOCH_DOMAIN: &[u8] = b"legion-audit-epoch:v1";
const NOT_COMPLETE_GAP: &str = "selected reasoning lenses did not complete";

/// Lens-schema finding fields (`lens_schemas.rs`: the shared shape plus the
/// per-lens extras `verificationMethod`, `ponytailTag`, `parentFindingId`)
/// that the consolidated finding projection carries in `evidence`.
/// `reviewAxis`/`sourceQuote`/`sourceLocation`/`disposition`/
/// `changeAttribution` are projected by `report.rs` from `lensFindings`.
const LENS_TRIAGE_FIELDS: &[&str] = &[
    "lens",
    "confidence",
    "verifyStatus",
    "verificationMethod",
    "ponytailTag",
    "parentFindingId",
    "action",
];

pub(super) fn invalid(message: impl Into<String>) -> AuditError {
    AuditError::Invalid(message.into())
}

pub(super) fn io(error: std::io::Error, what: &str) -> AuditError {
    AuditError::Invalid(format!("{what}: {error}"))
}

pub(super) fn read_json(path: &Path) -> Result<Value, AuditError> {
    let bytes =
        fs::read(path).map_err(|error| io(error, &format!("could not read {}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("{} is not valid JSON: {error}", path.display())))
}

pub(super) fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, AuditError> {
    fs::create_dir_all(dir).map_err(|error| io(error, "could not create run directory"))?;
    let destination = dir.join(name);
    let temporary = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    fs::write(&temporary, bytes).map_err(|error| io(error, "could not write run artifact"))?;
    fs::rename(&temporary, &destination)
        .map_err(|error| io(error, "could not publish run artifact"))?;
    Ok(destination)
}

// ---------------------------------------------------------------------------
// Epoch key
// ---------------------------------------------------------------------------

/// Digest recorded in the plan and report for an epoch key. It identifies the
/// key without revealing it.
pub fn epoch_digest(key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EPOCH_DOMAIN);
    hasher.update(key);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// A fresh 32-byte key for one audit run (plan signing or receipt MACs).
pub fn ephemeral_key() -> Vec<u8> {
    random_key()
}

fn random_key() -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut key = [0u8; 32];
        if let Ok(mut file) = fs::File::open("/dev/urandom") {
            if file.read_exact(&mut key).is_ok() {
                return key.to_vec();
            }
        }
    }
    // Portable fallback: std's per-process random hasher keys mixed with the
    // clock and process id.
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = Sha256::new();
    for round in 0..8u64 {
        let mut state = std::collections::hash_map::RandomState::new().build_hasher();
        state.write_u64(round);
        hasher.update(state.finish().to_le_bytes());
    }
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    hasher.finalize().to_vec()
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AuditError> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| io(error, "could not create epoch key"))?;
    file.write_all(bytes)
        .map_err(|error| io(error, "could not write epoch key"))
}

/// Generates a fresh per-run epoch key under `run_dir` (mode 0600 on Unix),
/// discarding any receipts a previous run left there, and returns its digest.
pub fn create_epoch(run_dir: &Path) -> Result<String, AuditError> {
    fs::create_dir_all(run_dir).map_err(|error| io(error, "could not create run directory"))?;
    let key = random_key();
    let path = run_dir.join(EPOCH_KEY_FILE);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(run_dir.join(LENS_RECEIPT_DIR));
    write_private(&path, hex::encode(&key).as_bytes())?;
    Ok(epoch_digest(&key))
}

/// Loads the epoch key of a run and its digest.
pub fn load_epoch(run_dir: &Path) -> Result<(Vec<u8>, String), AuditError> {
    let path = run_dir.join(EPOCH_KEY_FILE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path)
            .map_err(|error| io(error, "run has no epoch key; rerun `legion audit --out`"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(invalid(
                "epoch key is readable by group or others; refusing to use it",
            ));
        }
    }
    let text = fs::read_to_string(&path)
        .map_err(|error| io(error, "run has no epoch key; rerun `legion audit --out`"))?;
    let key = hex::decode(text.trim()).map_err(|_| invalid("epoch key is not hex"))?;
    if key.len() < 16 {
        return Err(invalid("epoch key is too short"));
    }
    let digest = epoch_digest(&key);
    Ok((key, digest))
}

// ---------------------------------------------------------------------------
// Anchors
// ---------------------------------------------------------------------------

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

struct FrozenFiles<'a> {
    root: &'a Path,
    digests: BTreeMap<String, String>,
}

impl FrozenFiles<'_> {
    /// Verifies an anchor `{path, line, text}`: the path is in the frozen
    /// inventory, the file bytes still match the frozen digest, and `text`
    /// occurs verbatim starting on `line`. Returns the anchored path and line.
    fn check(&self, who: &str, anchor: Option<&Value>) -> Result<(String, u64), AuditError> {
        let object = anchor.and_then(Value::as_object).ok_or_else(|| {
            invalid(format!(
                "{who}: a code anchor {{path, line, text}} is required"
            ))
        })?;
        let path = object
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{who}: anchor.path is required")))?;
        let line = object
            .get("line")
            .and_then(Value::as_u64)
            .filter(|line| *line >= 1)
            .ok_or_else(|| invalid(format!("{who}: anchor.line must be a 1-based line number")))?;
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .ok_or_else(|| {
                invalid(format!(
                    "{who}: anchor.text must be non-empty verbatim code"
                ))
            })?;
        if !safe_relative(path) {
            return Err(invalid(format!(
                "{who}: anchor.path {path} is not a safe relative path"
            )));
        }
        let expected = self.digests.get(path).ok_or_else(|| {
            invalid(format!(
                "{who}: anchor path {path} is not in the frozen inventory"
            ))
        })?;
        let bytes = fs::read(self.root.join(path))
            .map_err(|error| io(error, &format!("{who}: could not read anchor file {path}")))?;
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if &actual != expected {
            return Err(AuditError::SourceDrift(format!(
                "{who}: {path} differs from the frozen revision"
            )));
        }
        let content = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
        let needle = text.replace("\r\n", "\n");
        let found = content.match_indices(needle.as_str()).any(|(index, _)| {
            content[..index]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count() as u64
                + 1
                == line
        });
        if !found {
            return Err(invalid(format!(
                "{who}: anchor text does not appear verbatim at {path}:{line} in the frozen file"
            )));
        }
        Ok((path.to_owned(), line))
    }
}

fn evidence_covers(evidence: &[Value], path: &str, line: u64) -> bool {
    evidence.iter().filter_map(Value::as_str).any(|entry| {
        let Some((entry_path, range)) = entry.rsplit_once(':') else {
            return false;
        };
        if entry_path != path {
            return false;
        }
        let (start, end) = range.split_once('-').unwrap_or((range, range));
        match (start.parse::<u64>(), end.parse::<u64>()) {
            (Ok(start), Ok(end)) => start <= line && line <= end,
            _ => false,
        }
    })
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/// What an accepted ingest minted.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestedLens {
    pub provider: String,
    pub lens_ids: Vec<String>,
    pub findings: usize,
    pub withdrawn: usize,
    pub anchors_verified: usize,
    /// Denominator paths the packet proves were examined (see `packet_coverage`).
    pub examined: u64,
    pub expected: u64,
    pub complete: bool,
    pub coverage_gaps: Vec<String>,
    pub receipt_id: String,
    pub receipt_path: String,
    /// For a part of a multi-part provider: the part just ingested. The
    /// `examined`/`complete`/`coverage_gaps` above are then the PROVIDER-level
    /// aggregate over every ingested part, so the outstanding work is named
    /// (`reasoning-parts-pending:<provider>:<ingested>/<total>`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts_ingested: Option<u32>,
    /// Part numbers still awaiting ingest.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parts_pending: Vec<u32>,
}

/// Coverage derived from what the lens packet carried, never from the
/// submitter's attestation.
struct PacketCoverage {
    examined: u64,
    gaps: Vec<String>,
    detail: Value,
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Examined coverage for one packet. `bounded-excerpts` packets count only
/// denominator paths whose excerpt is present and untruncated; omitted and
/// truncated paths become a coverage gap. `candidate-verdicts` packets (the
/// security adjudicator) are covered only when every scanner candidate got a
/// verdict. A packet that records no basis proves nothing.
fn packet_coverage(
    provider_id: &str,
    packet: &Value,
    denominator_paths: &[String],
    candidates_supplied: bool,
    part: Option<LensPartRef>,
) -> PacketCoverage {
    let expected = denominator_paths.len() as u64;
    let coverage = packet
        .get("excerptCoverage")
        .filter(|value| value.is_object());
    let basis = coverage
        .and_then(|value| value.get("basis"))
        .and_then(Value::as_str)
        .unwrap_or("unrecorded");
    match basis {
        "bounded-excerpts" => {
            let included = string_list(coverage.and_then(|value| value.get("examinedPaths")))
                .into_iter()
                .collect::<BTreeSet<_>>();
            let examined = denominator_paths
                .iter()
                .filter(|path| included.contains(*path))
                .count() as u64;
            let truncated = string_list(coverage.and_then(|value| value.get("truncatedPaths")));
            let omitted = coverage
                .and_then(|value| value.get("omittedPaths"))
                .cloned()
                .unwrap_or(Value::Array(Vec::new()));
            if let Some(part) = part {
                // A part proves only what it carries. Provider-level
                // completeness is the union over parts (`merge_parts`).
                let denominator: BTreeSet<&str> =
                    denominator_paths.iter().map(String::as_str).collect();
                let examined_paths = denominator_paths
                    .iter()
                    .filter(|path| included.contains(*path))
                    .cloned()
                    .collect::<Vec<_>>();
                let chunked: Vec<Value> = coverage
                    .and_then(|value| value.get("chunkedPaths"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter(|item| {
                                item.get("path")
                                    .and_then(Value::as_str)
                                    .is_some_and(|path| denominator.contains(path))
                            })
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                let part_meta = packet.get("part").cloned().unwrap_or(Value::Null);
                return PacketCoverage {
                    examined,
                    gaps: vec![format!(
                        "reasoning-part-scope:{provider_id}:part {}/{}",
                        part.number, part.total
                    )],
                    detail: json!({
                        "basis": basis,
                        "examined": examined,
                        "expected": expected,
                        "part": {"number": part.number, "total": part.total},
                        "requiredParts": part_meta.get("requiredParts"),
                        "overCeiling": part_meta.get("overCeiling"),
                        "partPaths": part_meta.get("paths"),
                        "examinedPaths": examined_paths,
                        "chunkedPaths": chunked,
                        "omittedPaths": omitted,
                        "truncatedPaths": truncated,
                    }),
                };
            }
            let gaps = if examined < expected {
                vec![format!(
                    "reasoning-excerpt-coverage:{provider_id}:{examined}/{expected} paths examined ({} omitted, {} truncated)",
                    omitted.as_array().map_or(0, Vec::len),
                    truncated.len()
                )]
            } else {
                Vec::new()
            };
            PacketCoverage {
                examined,
                gaps,
                detail: json!({
                    "basis": basis,
                    "examined": examined,
                    "expected": expected,
                    "omittedPaths": omitted,
                    "truncatedPaths": truncated,
                }),
            }
        }
        "candidate-verdicts" => {
            let examined = if candidates_supplied { expected } else { 0 };
            PacketCoverage {
                examined,
                gaps: if candidates_supplied {
                    Vec::new()
                } else {
                    vec![format!("scanner-candidates-unavailable:{provider_id}")]
                },
                detail: json!({"basis": basis, "examined": examined, "expected": expected}),
            }
        }
        _ => PacketCoverage {
            examined: 0,
            gaps: vec![format!("excerpt-coverage-unrecorded:{provider_id}")],
            detail: json!({"basis": "unrecorded", "examined": 0, "expected": expected}),
        },
    }
}

pub(super) fn expected_request_id(work: &PendingLensWork) -> Result<String, AuditError> {
    let request = &work.request;
    let packet_digest =
        canonical_digest(&request.packet).map_err(|error| invalid(error.to_string()))?;
    let signature = if request.plan_signature.is_empty() {
        Value::Null
    } else {
        Value::String(request.plan_signature.clone())
    };
    let identity = json!({
        "invocationEpoch": "pending-host",
        "packetDigest": packet_digest,
        "providerId": request.provider_id,
        "contract": request.contract,
        "planDigest": request.plan_digest,
        "planSignature": signature,
        "repositoryId": request.repository_id,
        "inventoryGeneration": request.inventory_generation,
        "inventoryDigest": request.inventory_digest,
        "denominatorDigest": request.denominator_digest,
        "denominatorCount": request.denominator_count,
        "denominatorPaths": request.denominator_paths,
    });
    canonical_digest(&identity).map_err(|error| invalid(error.to_string()))
}

fn string_field<'a>(value: &'a Value, field: &str, who: &str) -> Result<&'a str, AuditError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{who}: `{field}` is required")))
}

fn array_field(value: &Value, field: &str, who: &str) -> Result<Vec<Value>, AuditError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(_) => Err(invalid(format!("{who}: `{field}` must be an array"))),
    }
}

fn parse_packet(path: &Path) -> Result<PendingLensWork, AuditError> {
    serde_json::from_value(read_json(path)?)
        .map_err(|error| invalid(format!("lens packet is invalid: {error}")))
}

/// `<provider>.part-NNNN.json` files under `dir`, sorted by part number.
fn part_packet_files(dir: &Path, provider_id: &str) -> Vec<(u32, PathBuf)> {
    let prefix = format!("{provider_id}.part-");
    let mut files = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let number = name
                .strip_prefix(prefix.as_str())?
                .strip_suffix(".json")?
                .parse::<u32>()
                .ok()?;
            Some((number, entry.path()))
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

/// Finds the lens packet a result was produced from. A single un-numbered
/// packet is `<provider>.json`; a partitioned provider has
/// `<provider>.part-NNNN.json` files plus `<provider>.index.json`, and the
/// result's `packetDigest` selects the part (the index is only a hint; the
/// part file's own digest decides).
fn locate_packet(
    run_dir: &Path,
    provider_id: &str,
    result: &Value,
) -> Result<PendingLensWork, AuditError> {
    let dir = run_dir.join(LENS_PACKET_DIR);
    let single = dir.join(format!("{provider_id}.json"));
    let parts = part_packet_files(&dir, provider_id);
    if single.is_file() {
        if !parts.is_empty() {
            return Err(invalid(format!(
                "lens packets for {provider_id} are ambiguous: both {provider_id}.json and numbered parts exist; rerun `legion audit --out`"
            )));
        }
        let work = parse_packet(&single)?;
        if let Some(part) = work.part() {
            return Err(invalid(format!(
                "{provider_id}.json is part {}/{} of a partitioned lens; part packets must be filed as {provider_id}.part-NNNN.json (rerun `legion audit --out` with a current CLI)",
                part.number, part.total
            )));
        }
        return Ok(work);
    }
    if parts.is_empty() {
        return parse_packet(&single);
    }
    let wanted = result.get("packetDigest").and_then(Value::as_str);
    let hinted = read_json(&dir.join(format!("{provider_id}.index.json")))
        .ok()
        .and_then(|index| {
            index
                .get("parts")?
                .as_array()?
                .iter()
                .find(|entry| entry.get("packetDigest").and_then(Value::as_str) == wanted)
                .and_then(|entry| entry.get("part")?.as_u64())
        })
        .and_then(|number| u32::try_from(number).ok());
    let mut ordered = parts.clone();
    if let Some(hint) = hinted {
        ordered.sort_by_key(|(number, _)| *number != hint);
    }
    for (number, path) in ordered {
        let work = parse_packet(&path)?;
        let digest =
            canonical_digest(&work.request.packet).map_err(|error| invalid(error.to_string()))?;
        if Some(digest.as_str()) == wanted {
            return match work.part() {
                Some(part) if part.number == number => Ok(work),
                _ => Err(invalid(format!(
                    "{} does not carry part number {number}",
                    path.display()
                ))),
            };
        }
    }
    Err(invalid(format!(
        "lens result for {provider_id}: packetDigest does not match any of the {} lens packet parts",
        parts.len()
    )))
}

/// Validates a lens result against the frozen run and, when accepted, writes a
/// MAC'd receipt to `<run>/lens-receipts/<provider>.json` (or
/// `<provider>.part-NNNN.json` for one part of a partitioned lens).
///
/// Result shape (`kind: legion-lens-result`):
/// `{schemaVersion:1, kind, provider, packetDigest, planDigest, complete:true,
///   findings:[{...lens schema fields, anchor:{path,line,text}}],
///   withdrawn:[{id, reason, disproof:{path,line,text}}],
///   verdicts:[{candidateId, verdict, ...}]  (legacy.security.adjudication only:
///     exactly one per packet `scannerCandidates` entry; a surviving verdict
///     also needs a finding with id `adjudicated:<candidateId>`),
///   details:{semanticReview?, changeRisk?}}`
///
/// `complete:true` only attests the submitter finished. Examined coverage is
/// computed from the paths the packet carried: omitted or truncated excerpts
/// leave a coverage gap and the receipt is `partial`, not `complete`.
pub fn ingest_lens_result(
    run_dir: &Path,
    provider_id: &str,
    result: &Value,
) -> Result<IngestedLens, AuditError> {
    if !REASONING_PROVIDER_IDS.contains(&provider_id) {
        return Err(invalid(format!(
            "{provider_id} is not a reasoning provider"
        )));
    }
    let who = format!("lens result for {provider_id}");

    // --- the frozen run -----------------------------------------------------
    let plan = read_json(&run_dir.join("plan.json"))?;
    let seal_digest = plan
        .pointer("/seal/digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("plan.json has no seal digest"))?;
    let revision = plan
        .pointer("/binding/repositoryRevision")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("plan.json has no repository revision"))?;
    let plan_epoch = plan
        .pointer("/epoch/digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("this run records no epoch; rerun `legion audit --out`"))?;
    let root = PathBuf::from(
        plan.get("repository")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("plan.json has no repository root"))?,
    );
    let (key, digest) = load_epoch(run_dir)?;
    if digest != plan_epoch {
        return Err(invalid(
            "epoch key does not match the epoch recorded in plan.json",
        ));
    }
    let execution: ExecutionReport =
        serde_json::from_value(read_json(&run_dir.join("execution.json"))?)
            .map_err(|error| invalid(format!("execution.json is invalid: {error}")))?;
    let slot = execution
        .results
        .iter()
        .find(|entry| entry.provider == provider_id)
        .ok_or_else(|| invalid(format!("{provider_id} is not part of this run")))?;
    if !execution
        .pending_host
        .iter()
        .any(|pending| pending == provider_id)
    {
        return Err(invalid(format!(
            "{provider_id} was not pending-host in this run"
        )));
    }
    let required = slot.result.required;

    // --- the lens packet -----------------------------------------------------
    let work = locate_packet(run_dir, provider_id, result)?;
    let part = work.part();
    let request = &work.request;
    request.validate().map_err(|error| {
        invalid(format!(
            "{error}; only signed plans can be ingested (set AUDIT_PLAN_SIGNING_KEY)"
        ))
    })?;
    if work.provider_id != provider_id
        || request.provider_id != provider_id
        || work.status != "pending-host"
    {
        return Err(invalid("lens packet does not belong to this provider"));
    }
    if request.plan_digest != seal_digest || request.inventory_generation != revision {
        return Err(invalid(
            "lens packet is not bound to this run's frozen plan",
        ));
    }
    if request.request_id != expected_request_id(&work)? {
        return Err(invalid(
            "lens packet binding was altered after the run froze",
        ));
    }
    let packet_digest =
        canonical_digest(&request.packet).map_err(|error| invalid(error.to_string()))?;

    // --- the submitted result ------------------------------------------------
    if result.get("kind").and_then(Value::as_str) != Some(LENS_RESULT_KIND)
        || result.get("schemaVersion").and_then(Value::as_u64) != Some(1)
    {
        return Err(invalid(format!(
            "{who}: kind must be {LENS_RESULT_KIND} with schemaVersion 1"
        )));
    }
    if string_field(result, "provider", &who)? != provider_id {
        return Err(invalid(format!("{who}: provider does not match")));
    }
    if string_field(result, "packetDigest", &who)? != packet_digest {
        return Err(invalid(format!(
            "{who}: packetDigest does not match the lens packet (expected {packet_digest})"
        )));
    }
    if string_field(result, "planDigest", &who)? != request.plan_digest {
        return Err(invalid(format!(
            "{who}: planDigest does not match the frozen plan"
        )));
    }
    if result.get("complete").and_then(Value::as_bool) != Some(true) {
        return Err(invalid(format!(
            "{who}: must attest complete examination of the packet denominator; leave the lens pending instead"
        )));
    }
    let findings = array_field(result, "findings", &who)?;
    let withdrawn = array_field(result, "withdrawn", &who)?;
    let extra_details = match result.get("details") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err(invalid(format!("{who}: `details` must be an object"))),
    };
    if let Some(key) = extra_details
        .keys()
        .find(|key| !matches!(key.as_str(), "semanticReview" | "changeRisk"))
    {
        return Err(invalid(format!(
            "{who}: details.{key} is not an accepted detail"
        )));
    }

    // --- findings against the lens schema -------------------------------------
    if let Some(lens) = lens_plan::lens_id_for_provider(provider_id) {
        lens_schemas::validate_lens_output(lens, &findings).map_err(|errors| {
            invalid(format!(
                "{who}: report-schema validation failed: {}",
                errors
                    .iter()
                    .map(|error| format!("{}: {}", error.field, error.reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        })?;
    }

    // --- anchors against the frozen bytes ---------------------------------------
    let source = FilesystemInventorySource::new(&root)?;
    let inventory = source.inventory(&request.repository_id)?;
    if inventory.generation != request.inventory_generation {
        return Err(AuditError::SourceDrift(
            "the working tree no longer matches the frozen revision; rerun the audit".into(),
        ));
    }
    let frozen = FrozenFiles {
        root: &root,
        digests: inventory
            .entries
            .iter()
            .filter_map(|entry| {
                entry
                    .digest
                    .clone()
                    .map(|digest| (entry.path.clone(), digest))
            })
            .collect(),
    };
    let mut anchors_verified = 0usize;
    let mut seen_ids = BTreeSet::new();
    let mut finding_refs = Vec::new();
    let mut titles = Map::new();
    let mut messages = Map::new();
    let mut locations = Map::new();
    let mut finding_evidence = Map::new();
    for (index, finding) in findings.iter().enumerate() {
        let id = string_field(finding, "id", &format!("{who} finding {index}"))?;
        let label = format!("{who} finding {id}");
        if !seen_ids.insert(id.to_owned()) {
            return Err(invalid(format!("{label}: duplicate finding id")));
        }
        let (path, line) = frozen.check(&label, finding.get("anchor"))?;
        let evidence = finding
            .get("evidence")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !evidence_covers(&evidence, &path, line) {
            return Err(invalid(format!(
                "{label}: evidence must include a file:line entry covering the anchor {path}:{line}"
            )));
        }
        anchors_verified += 1;
        finding_refs.push(FindingRef {
            id: FindingId::new(id)?,
            severity: finding
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("info")
                .to_owned(),
        });
        titles.insert(
            id.to_owned(),
            json!(finding
                .get("title")
                .or_else(|| finding.get("action"))
                .and_then(Value::as_str)
                .unwrap_or("Lens finding")),
        );
        messages.insert(
            id.to_owned(),
            json!(finding
                .get("failureScenario")
                .and_then(Value::as_str)
                .unwrap_or("Lens reported a finding")),
        );
        locations.insert(id.to_owned(), Value::Array(evidence));
        // Lens triage fields the lens schema defines, carried into the
        // public finding's evidence (the full finding stays in
        // `details.lensFindings`). Existing summary keys are unchanged.
        let mut triage = Map::new();
        for field in LENS_TRIAGE_FIELDS {
            if let Some(value) = finding.get(*field) {
                triage.insert((*field).to_owned(), value.clone());
            }
        }
        finding_evidence.insert(id.to_owned(), Value::Object(triage));
    }
    if let Some(part) = part {
        ensure_ids_unique_across_parts(run_dir, provider_id, part.number, &seen_ids)?;
    }
    for (index, entry) in withdrawn.iter().enumerate() {
        let id = string_field(entry, "id", &format!("{who} withdrawn {index}"))?;
        let label = format!("{who} withdrawn {id}");
        string_field(entry, "reason", &label)?;
        // A withdrawal is only accepted with the verbatim line that disproves the claim.
        frozen.check(&label, entry.get("disproof"))?;
        anchors_verified += 1;
    }

    // --- security verdicts (adjudicator only) --------------------------------------
    let submitted_verdicts = array_field(result, "verdicts", &who)?;
    let mut candidates_supplied = false;
    let mut verdict_details: Option<(Value, Value)> = None;
    if provider_id == ADJUDICATOR_PROVIDER_ID {
        match request.packet.get("scannerCandidates") {
            Some(Value::Array(items)) => {
                let candidates: Vec<ScannerCandidate> =
                    serde_json::from_value(Value::Array(items.clone()))
                        .map_err(|error| invalid(format!("{who}: packet candidates: {error}")))?;
                let verdicts =
                    adjudicate_scanner_candidates(&candidates, &submitted_verdicts, &packet_digest)
                        .map_err(|error| invalid(format!("{who}: {error}")))?;
                for verdict in verdicts
                    .iter()
                    .filter(|verdict| verdict.verdict.is_surviving())
                {
                    let finding_id = format!("adjudicated:{}", verdict.candidate_id);
                    if !seen_ids.contains(&finding_id) {
                        return Err(invalid(format!(
                            "{who}: surviving verdict for {} needs an anchored finding with id {finding_id}",
                            verdict.candidate_id
                        )));
                    }
                }
                let confirmed = confirmed_findings(&candidates, &verdicts);
                verdict_details = Some((
                    serde_json::to_value(&verdicts).map_err(|error| invalid(error.to_string()))?,
                    serde_json::to_value(&confirmed).map_err(|error| invalid(error.to_string()))?,
                ));
                candidates_supplied = true;
            }
            _ if submitted_verdicts.is_empty() => {}
            _ => {
                return Err(invalid(format!(
                    "{who}: verdicts submitted but the packet carries no scanner candidates"
                )))
            }
        }
    } else if !submitted_verdicts.is_empty() {
        return Err(invalid(format!(
            "{who}: only {ADJUDICATOR_PROVIDER_ID} accepts verdicts"
        )));
    }
    let coverage = packet_coverage(
        provider_id,
        &request.packet,
        &request.denominator_paths,
        candidates_supplied,
        part,
    );
    let complete = coverage.gaps.is_empty();
    let status = if complete {
        ProviderStatus::Complete
    } else {
        ProviderStatus::Partial
    };

    // --- build the result and the MAC'd receipt ----------------------------------
    let expected = request.denominator_count;
    let mut details: BTreeMap<String, Value> = BTreeMap::new();
    details.insert("reasoningHostState".into(), json!("ingested"));
    details.insert("lensIds".into(), json!(work.lens_ids));
    details.insert("lensFindings".into(), Value::Array(findings.clone()));
    details.insert("withdrawnFindings".into(), Value::Array(withdrawn.clone()));
    details.insert("findingTitles".into(), Value::Object(titles));
    details.insert("findingMessages".into(), Value::Object(messages));
    details.insert("findingLocations".into(), Value::Object(locations));
    details.insert("findingEvidence".into(), Value::Object(finding_evidence));
    details.insert(
        "ingest".into(),
        json!({
            "host": INGEST_HOST,
            "epochDigest": digest,
            "packetDigest": packet_digest,
            "anchorsVerified": anchors_verified,
        }),
    );
    details.insert("packetCoverage".into(), coverage.detail.clone());
    if let Some((verdicts, confirmed)) = verdict_details {
        details.insert("securityVerdicts".into(), verdicts);
        details.insert("securityConfirmed".into(), confirmed);
    }
    for (field, value) in extra_details {
        details.insert(field, value);
    }
    let provider = ProviderId::new(provider_id)?;
    let provider_result = ProviderResult {
        schema_version: 1,
        provider,
        applicable: true,
        required,
        status,
        complete,
        coverage: Some(Coverage {
            denominator_digest: request.denominator_digest.clone(),
            expected,
            examined: coverage.examined,
            gaps: coverage.gaps.clone(),
        }),
        findings: finding_refs,
        coverage_gaps: coverage.gaps.clone(),
        degradation: Vec::new(),
        details,
    };
    provider_result
        .validate()
        .map_err(|error| invalid(format!("{who}: {error}")))?;
    let result_digest =
        canonical_digest(&provider_result).map_err(|error| invalid(error.to_string()))?;
    let receipt_id = format!(
        "ingest-{}",
        canonical_digest(&json!({"requestId": request.request_id, "resultDigest": result_digest}))
            .map_err(|error| invalid(error.to_string()))?
            .trim_start_matches("sha256:")
            .chars()
            .take(32)
            .collect::<String>()
    );
    let mut receipt = ReasoningReceipt {
        schema_version: REASONING_RECEIPT_SCHEMA_VERSION,
        kind: REASONING_RECEIPT_KIND.into(),
        receipt_id: receipt_id.clone(),
        request_id: request.request_id.clone(),
        provider_id: provider_id.into(),
        contract: request.contract.clone(),
        plan_digest: request.plan_digest.clone(),
        plan_signature: request.plan_signature.clone(),
        repository_id: request.repository_id.clone(),
        inventory_generation: request.inventory_generation.clone(),
        inventory_digest: request.inventory_digest.clone(),
        denominator_digest: request.denominator_digest.clone(),
        denominator_count: request.denominator_count,
        result_digest,
        status,
        complete,
        gaps: coverage.gaps.clone(),
        authentication: Value::Null,
    };
    receipt.authentication =
        authenticate_receipt(&receipt, &key, INGEST_HOST, &digest).map_err(invalid)?;
    let paths: BTreeSet<&String> = request.denominator_paths.iter().collect();
    let denominator = InventoryDenominator {
        entries: inventory
            .entries
            .iter()
            .filter(|entry| paths.contains(&entry.path))
            .cloned()
            .collect(),
        digest: request.denominator_digest.clone(),
    };
    let response = ReasoningHostResponse {
        result: provider_result,
        receipt,
    };
    // The same reconciliation the in-process host path runs: receipt binding,
    // MAC, lens schema, semantic-review and change-risk validation.
    let accepted = verify_response(request, &denominator, &response, &key)
        .map_err(|error| invalid(format!("{who} rejected: {error}")))?;

    let mut stored = json!({
        "schemaVersion": 1,
        "kind": "legion-lens-receipt",
        "provider": provider_id,
        "result": accepted,
    });
    let receipt_name = match part {
        Some(part) => {
            stored["part"] = json!({"number": part.number, "total": part.total});
            format!("{provider_id}.part-{:04}.json", part.number)
        }
        None => format!("{provider_id}.json"),
    };
    let path = write_atomic(
        &run_dir.join(LENS_RECEIPT_DIR),
        &receipt_name,
        &serde_json::to_vec_pretty(&stored).map_err(|error| invalid(error.to_string()))?,
    )?;
    let mut ingested = IngestedLens {
        provider: provider_id.into(),
        lens_ids: work.lens_ids.clone(),
        findings: findings.len(),
        withdrawn: withdrawn.len(),
        anchors_verified,
        examined: coverage.examined,
        expected,
        complete,
        coverage_gaps: coverage.gaps,
        receipt_id,
        receipt_path: path.to_string_lossy().into_owned(),
        part: None,
        parts_total: None,
        parts_ingested: None,
        parts_pending: Vec::new(),
    };
    if let Some(part) = part {
        // Report the PROVIDER-level state after this part: the union over
        // every ingested part, with the outstanding work named.
        let loaded = load_receipts(run_dir, &plan, &execution, Some(provider_id))?;
        let merged = loaded
            .iter()
            .find(|entry| entry.provider == provider_id)
            .ok_or_else(|| invalid(format!("{who}: the ingested part receipt did not load")))?;
        ingested.examined = merged
            .result
            .coverage
            .as_ref()
            .map_or(0, |coverage| coverage.examined);
        ingested.complete = merged.result.complete;
        ingested.coverage_gaps = merged.result.coverage_gaps.clone();
        ingested.part = Some(part.number);
        if let Some(progress) = &merged.parts {
            ingested.parts_total = Some(progress.total);
            ingested.parts_ingested = Some(progress.ingested.len() as u32);
            ingested.parts_pending = progress.pending.clone();
        }
    }
    Ok(ingested)
}

/// Rejects a part whose finding ids collide with another ingested part's:
/// the consolidated report keys findings by id.
fn ensure_ids_unique_across_parts(
    run_dir: &Path,
    provider_id: &str,
    part_number: u32,
    ids: &BTreeSet<String>,
) -> Result<(), AuditError> {
    let dir = run_dir.join(LENS_RECEIPT_DIR);
    let prefix = format!("{provider_id}.part-");
    for entry in fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(other) = name
            .strip_prefix(prefix.as_str())
            .and_then(|rest| rest.strip_suffix(".json"))
            .and_then(|number| number.parse::<u32>().ok())
        else {
            continue;
        };
        if other == part_number {
            continue;
        }
        let Ok(value) = read_json(&entry.path()) else {
            continue;
        };
        let used = value
            .pointer("/result/details/lensFindings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|finding| finding.get("id").and_then(Value::as_str));
        for id in used {
            if ids.contains(id) {
                return Err(invalid(format!(
                    "finding id {id} is already used by part {other} of {provider_id}; ids must be unique across parts (prefix with p{part_number:04}-)"
                )));
            }
        }
    }
    Ok(())
}

/// Reads `result_file` and ingests it. See `ingest_lens_result`.
pub fn ingest_lens_result_file(
    run_dir: &Path,
    provider_id: &str,
    result_file: &Path,
) -> Result<IngestedLens, AuditError> {
    let result = read_json(result_file)?;
    ingest_lens_result(run_dir, provider_id, &result)
}

// ---------------------------------------------------------------------------
// Verdict recomputation
// ---------------------------------------------------------------------------

/// The verdict rebuilt from the original execution and the ingested receipts.
#[derive(Clone, Debug)]
pub struct Recomputed {
    pub report: ReportV1,
    pub execution: ExecutionReport,
    /// Providers whose lens is backed by a verified ingested receipt.
    pub ingested: Vec<String>,
    /// Reasoning providers still `pending-host`, including partitioned
    /// providers with parts not yet ingested (see `lens_parts`).
    pub pending: Vec<String>,
    /// Surviving security verdicts from ingested adjudication receipts: the
    /// trigger for variant analysis.
    pub confirmed_security: Vec<ConfirmedSecurityFinding>,
    /// Part progress of every partitioned provider with at least one
    /// ingested part (also reported as the `lensParts` report claim).
    pub lens_parts: BTreeMap<String, PartsProgress>,
}

fn verify_ingested(
    provider: &str,
    result: &ProviderResult,
    key: &[u8],
    epoch: &str,
    execution: &ExecutionReport,
) -> Result<(), AuditError> {
    let who = format!("lens receipt for {provider}");
    let receipt: ReasoningReceipt = serde_json::from_value(
        result
            .details
            .get("executionReceipt")
            .cloned()
            .ok_or_else(|| invalid(format!("{who}: result carries no receipt")))?,
    )
    .map_err(|error| invalid(format!("{who}: {error}")))?;
    verify_authenticated_receipt(&receipt, key)
        .map_err(|error| invalid(format!("{who}: {error}")))?;
    if receipt
        .authentication
        .get("epochDigest")
        .and_then(Value::as_str)
        != Some(epoch)
    {
        return Err(invalid(format!("{who}: minted under a different epoch")));
    }
    let mut bare = result.clone();
    bare.details.remove("executionReceipt");
    let bare_digest = canonical_digest(&bare).map_err(|error| invalid(error.to_string()))?;
    if bare_digest != receipt.result_digest {
        return Err(invalid(format!("{who}: result was altered after ingest")));
    }
    if receipt.provider_id != provider
        || result.provider.to_string() != provider
        || receipt.plan_digest != execution.plan_digest
        || receipt.inventory_digest != execution.inventory_digest
        || receipt.inventory_generation != execution.generation
        || receipt.complete != result.complete
        || receipt.status != result.status
        || receipt.gaps != result.coverage_gaps
        || (receipt.complete && !receipt.gaps.is_empty())
    {
        return Err(invalid(format!(
            "{who}: not bound to this run or its completeness is inconsistent"
        )));
    }
    if !execution
        .pending_host
        .iter()
        .any(|pending| pending == provider)
    {
        return Err(invalid(format!(
            "{who}: provider was not pending-host in this run"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Receipts: single and per-part
// ---------------------------------------------------------------------------

/// Progress of a partitioned provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartsProgress {
    pub total: u32,
    pub ingested: Vec<u32>,
    pub pending: Vec<u32>,
}

/// One provider's verified receipt state: the result the verdict is rebuilt
/// from (the union over parts for a partitioned provider) and its progress.
struct LoadedReceipt {
    provider: String,
    result: ProviderResult,
    parts: Option<PartsProgress>,
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// Merges the verified per-part results of one provider into the single
/// provider-level result: examined coverage is the union of the ingested
/// parts' paths (plus split files whose every chunk was covered), the provider
/// is complete only when every part is ingested and nothing is omitted or
/// unscheduled, and the outstanding work is named in the gaps.
fn merge_parts(
    provider: &str,
    mut parts: Vec<(u32, u32, ProviderResult)>,
) -> Result<(ProviderResult, PartsProgress), AuditError> {
    let who = format!("lens receipts for {provider}");
    parts.sort_by_key(|(number, _, _)| *number);
    let total = parts
        .first()
        .map(|(_, total, _)| *total)
        .ok_or_else(|| invalid(format!("{who}: no parts")))?;
    let template = parts[0].2.clone();
    let template_coverage = template
        .coverage
        .clone()
        .ok_or_else(|| invalid(format!("{who}: part result carries no coverage")))?;

    let mut examined_paths: BTreeSet<String> = BTreeSet::new();
    let mut chunk_state: BTreeMap<String, (u64, BTreeSet<u64>)> = BTreeMap::new();
    let mut omitted: BTreeMap<String, String> = BTreeMap::new();
    let mut over_ceiling = Value::Null;
    let mut finding_refs: Vec<FindingRef> = Vec::new();
    let mut finding_ids: BTreeSet<String> = BTreeSet::new();
    let mut lens_findings: Vec<Value> = Vec::new();
    let mut withdrawn: Vec<Value> = Vec::new();
    let mut titles = Map::new();
    let mut messages = Map::new();
    let mut locations = Map::new();
    let mut evidence = Map::new();
    let mut anchors_verified = 0u64;
    let mut part_receipts: Vec<Value> = Vec::new();
    let mut ingest_parts: Vec<Value> = Vec::new();
    let mut semantic_reviews: Vec<(u32, Value)> = Vec::new();
    let mut change_risks: Vec<(u32, Value)> = Vec::new();
    let mut ingested: Vec<u32> = Vec::new();

    for (number, file_total, result) in &parts {
        let coverage = result
            .coverage
            .as_ref()
            .ok_or_else(|| invalid(format!("{who}: part {number} carries no coverage")))?;
        let packet_coverage = result
            .details
            .get("packetCoverage")
            .ok_or_else(|| invalid(format!("{who}: part {number} records no packet coverage")))?;
        let recorded_number = packet_coverage
            .pointer("/part/number")
            .and_then(Value::as_u64);
        let recorded_total = packet_coverage
            .pointer("/part/total")
            .and_then(Value::as_u64);
        if recorded_number != Some(u64::from(*number))
            || recorded_total != Some(u64::from(*file_total))
            || *file_total != total
            || coverage.denominator_digest != template_coverage.denominator_digest
            || coverage.expected != template_coverage.expected
        {
            return Err(invalid(format!(
                "{who}: part {number} is not consistent with the other parts of this run"
            )));
        }
        ingested.push(*number);
        if over_ceiling.is_null() {
            if let Some(value) = packet_coverage.get("overCeiling").filter(|v| !v.is_null()) {
                over_ceiling = value.clone();
            }
        }
        examined_paths.extend(string_list(packet_coverage.get("examinedPaths")));
        for item in packet_coverage
            .get("chunkedPaths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(path), Some(chunk), Some(chunks)) = (
                item.get("path").and_then(Value::as_str),
                item.get("chunk").and_then(Value::as_u64),
                item.get("chunks").and_then(Value::as_u64),
            ) else {
                return Err(invalid(format!(
                    "{who}: part {number} has a malformed chunk record"
                )));
            };
            let state = chunk_state
                .entry(path.to_owned())
                .or_insert((chunks, BTreeSet::new()));
            if state.0 != chunks {
                return Err(invalid(format!(
                    "{who}: part {number} disagrees on the chunk count of {path}"
                )));
            }
            state.1.insert(chunk);
        }
        for item in packet_coverage
            .get("omittedPaths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(path) = item.get("path").and_then(Value::as_str) {
                omitted.insert(
                    path.to_owned(),
                    item.get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("omitted")
                        .to_owned(),
                );
            }
        }
        for finding in &result.findings {
            if !finding_ids.insert(finding.id.as_str().to_owned()) {
                return Err(invalid(format!(
                    "{who}: finding id {} appears in more than one part",
                    finding.id
                )));
            }
            finding_refs.push(finding.clone());
        }
        let detail_array = |field: &str| {
            result
                .details
                .get(field)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        lens_findings.extend(detail_array("lensFindings"));
        withdrawn.extend(detail_array("withdrawnFindings"));
        for (field, target) in [
            ("findingTitles", &mut titles),
            ("findingMessages", &mut messages),
            ("findingLocations", &mut locations),
            ("findingEvidence", &mut evidence),
        ] {
            if let Some(Value::Object(map)) = result.details.get(field) {
                for (key, value) in map {
                    target.insert(key.clone(), value.clone());
                }
            }
        }
        anchors_verified += result
            .details
            .get("ingest")
            .and_then(|ingest| ingest.get("anchorsVerified"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let receipt = result.details.get("executionReceipt");
        part_receipts.push(json!({
            "part": number,
            "receiptId": receipt.and_then(|r| r.get("receiptId")),
            "requestId": receipt.and_then(|r| r.get("requestId")),
        }));
        ingest_parts.push(json!({
            "part": number,
            "packetDigest": result.details.get("ingest").and_then(|i| i.get("packetDigest")),
        }));
        if let Some(review) = result.details.get("semanticReview") {
            semantic_reviews.push((*number, review.clone()));
        }
        if let Some(risk) = result.details.get("changeRisk") {
            change_risks.push((*number, risk.clone()));
        }
    }

    let mut covered = examined_paths;
    let mut partial: Vec<String> = Vec::new();
    for (path, (chunks, seen)) in &chunk_state {
        if covered.contains(path) {
            continue;
        }
        if (1..=*chunks).all(|chunk| seen.contains(&chunk)) {
            covered.insert(path.clone());
        } else {
            partial.push(path.clone());
        }
    }
    for path in omitted.keys() {
        covered.remove(path);
    }
    let expected = template_coverage.expected;
    let examined = (covered.len() as u64).min(expected);
    let pending: Vec<u32> = (1..=total).filter(|n| !ingested.contains(n)).collect();

    let mut gaps = Vec::new();
    if !pending.is_empty() {
        gaps.push(format!(
            "reasoning-parts-pending:{provider}:{}/{}",
            ingested.len(),
            total
        ));
    }
    if let Some(object) = over_ceiling.as_object() {
        gaps.push(format!(
            "reasoning-denominator-over-ceiling:{provider}:{} parts required, ceiling {}, {} paths unscheduled",
            object.get("requiredParts").and_then(Value::as_u64).unwrap_or(0),
            object.get("ceiling").and_then(Value::as_u64).unwrap_or(0),
            object.get("unscheduledPathCount").and_then(Value::as_u64).unwrap_or(0),
        ));
    }
    if pending.is_empty() && examined < expected {
        gaps.push(format!(
            "reasoning-excerpt-coverage:{provider}:{examined}/{expected} paths examined ({} omitted, {} partially covered)",
            omitted.len(),
            partial.len()
        ));
    }
    let complete = gaps.is_empty() && examined >= expected;

    let mut details: BTreeMap<String, Value> = BTreeMap::new();
    details.insert("reasoningHostState".into(), json!("ingested"));
    details.insert(
        "lensIds".into(),
        template
            .details
            .get("lensIds")
            .cloned()
            .unwrap_or(Value::Array(Vec::new())),
    );
    details.insert("lensFindings".into(), Value::Array(lens_findings));
    details.insert("withdrawnFindings".into(), Value::Array(withdrawn));
    details.insert("findingTitles".into(), Value::Object(titles));
    details.insert("findingMessages".into(), Value::Object(messages));
    details.insert("findingLocations".into(), Value::Object(locations));
    details.insert("findingEvidence".into(), Value::Object(evidence));
    details.insert(
        "ingest".into(),
        json!({
            "host": INGEST_HOST,
            "epochDigest": template.details.get("ingest").and_then(|i| i.get("epochDigest")),
            "anchorsVerified": anchors_verified,
            "parts": ingest_parts,
        }),
    );
    details.insert("partReceipts".into(), Value::Array(part_receipts));
    details.insert(
        "packetCoverage".into(),
        json!({
            "basis": "bounded-excerpts",
            "examined": examined,
            "expected": expected,
            "partsTotal": total,
            "partsIngested": ingested,
            "partsPending": pending,
            "omittedPaths": omitted
                .iter()
                .map(|(path, reason)| json!({"path": path, "reason": reason}))
                .collect::<Vec<_>>(),
            "partiallyCoveredPaths": partial,
            "overCeiling": over_ceiling,
        }),
    );
    if !semantic_reviews.is_empty() {
        details.insert(
            "semanticReview".into(),
            merge_semantic_reviews(&semantic_reviews, !pending.is_empty()),
        );
    }
    if !change_risks.is_empty() {
        details.insert("changeRisk".into(), merge_change_risks(&change_risks));
    }

    let result = ProviderResult {
        schema_version: 1,
        provider: template.provider.clone(),
        applicable: true,
        required: template.required,
        status: if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        coverage: Some(Coverage {
            denominator_digest: template_coverage.denominator_digest.clone(),
            expected,
            examined,
            gaps: gaps.clone(),
        }),
        findings: finding_refs,
        coverage_gaps: gaps,
        degradation: Vec::new(),
        details,
    };
    result
        .validate()
        .map_err(|error| invalid(format!("{who}: {error}")))?;
    Ok((
        result,
        PartsProgress {
            total,
            ingested,
            pending,
        },
    ))
}

/// Union of per-part semantic reviews: any unproven part (or an outstanding
/// part) leaves the axis unproven; otherwise findings > pass > not-applicable.
fn merge_semantic_reviews(reviews: &[(u32, Value)], parts_pending: bool) -> Value {
    let axis = reviews
        .iter()
        .find_map(|(_, review)| review.get("axis").and_then(Value::as_str))
        .unwrap_or("");
    let statuses: Vec<&str> = reviews
        .iter()
        .filter_map(|(_, review)| review.get("status").and_then(Value::as_str))
        .collect();
    let status = if parts_pending || statuses.contains(&"unproven") {
        "unproven"
    } else if statuses.contains(&"findings") {
        "findings"
    } else if statuses.contains(&"pass") {
        "pass"
    } else {
        "not-applicable"
    };
    let mut reasons = reviews
        .iter()
        .map(|(number, review)| {
            format!(
                "part {number}: {}",
                review.get("reason").and_then(Value::as_str).unwrap_or("")
            )
        })
        .collect::<Vec<_>>();
    if parts_pending {
        reasons.push("some packet parts are not yet reviewed".to_owned());
    }
    let sources = reviews
        .iter()
        .flat_map(|(_, review)| {
            review
                .get("sources")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    json!({"axis": axis, "status": status, "reason": reasons.join("; "), "sources": sources})
}

/// Union of per-part change-risk records: the most severe reversibility wins
/// (`one-way` > `unknown` > `reversible`), reasons and evidence concatenate.
fn merge_change_risks(risks: &[(u32, Value)]) -> Value {
    let reversibilities: Vec<&str> = risks
        .iter()
        .filter_map(|(_, risk)| risk.get("reversibility").and_then(Value::as_str))
        .collect();
    let reversibility = if reversibilities.contains(&"one-way") {
        "one-way"
    } else if reversibilities.contains(&"unknown") {
        "unknown"
    } else {
        "reversible"
    };
    let join = |field: &str| {
        let mut seen = Vec::new();
        for (_, risk) in risks {
            if let Some(text) = risk.get(field).and_then(Value::as_str) {
                if !seen.contains(&text) {
                    seen.push(text);
                }
            }
        }
        seen.join("; ")
    };
    let evidence = |field: &str| {
        let mut out: Vec<Value> = Vec::new();
        for (_, risk) in risks {
            for item in risk
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if !out.contains(item) {
                    out.push(item.clone());
                }
            }
        }
        out
    };
    json!({
        "reversibility": reversibility,
        "blastRadius": join("blastRadius"),
        "reason": join("reason"),
        "beforeEvidence": evidence("beforeEvidence"),
        "afterEvidence": evidence("afterEvidence"),
    })
}

/// Loads and verifies every lens receipt (optionally only `only`'s). A
/// partitioned provider's `<provider>.part-NNNN.json` receipts are each
/// verified independently (MAC, epoch, plan binding, result digest) and then
/// merged into one provider-level result.
fn load_receipts(
    run_dir: &Path,
    plan: &Value,
    execution: &ExecutionReport,
    only: Option<&str>,
) -> Result<Vec<LoadedReceipt>, AuditError> {
    let dir = run_dir.join(LENS_RECEIPT_DIR);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let plan_epoch = plan
        .pointer("/epoch/digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("lens receipts are present but the run records no epoch"))?;
    let (key, digest) = load_epoch(run_dir)?;
    if digest != plan_epoch {
        return Err(invalid(
            "epoch key does not match the epoch recorded in plan.json",
        ));
    }
    let mut files = fs::read_dir(&dir)
        .map_err(|error| io(error, "could not list lens receipts"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".json") && !name.starts_with('.'))
        })
        .collect::<Vec<_>>();
    files.sort();
    let mut singles: Vec<LoadedReceipt> = Vec::new();
    let mut grouped: BTreeMap<String, Vec<(u32, u32, ProviderResult)>> = BTreeMap::new();
    for file in files {
        let value = read_json(&file)?;
        let provider = value
            .get("provider")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{} names no provider", file.display())))?
            .to_owned();
        if only.is_some_and(|only| only != provider) {
            continue;
        }
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let part = value
            .get("part")
            .filter(|part| !part.is_null())
            .map(|part| {
                (
                    part.get("number").and_then(Value::as_u64),
                    part.get("total").and_then(Value::as_u64),
                )
            });
        let result: ProviderResult =
            serde_json::from_value(value.get("result").cloned().unwrap_or(Value::Null))
                .map_err(|error| invalid(format!("{}: {error}", file.display())))?;
        match part {
            None => {
                if name != format!("{provider}.json") {
                    return Err(invalid(format!(
                        "{} is filed under the wrong provider",
                        file.display()
                    )));
                }
                verify_ingested(&provider, &result, &key, &digest, execution)?;
                singles.push(LoadedReceipt {
                    provider,
                    result,
                    parts: None,
                });
            }
            Some((Some(number), Some(total))) => {
                let (number, total) = match (u32::try_from(number), u32::try_from(total)) {
                    (Ok(number), Ok(total)) if number >= 1 && number <= total => (number, total),
                    _ => {
                        return Err(invalid(format!(
                            "{} records an invalid part number",
                            file.display()
                        )))
                    }
                };
                if name != format!("{provider}.part-{number:04}.json") {
                    return Err(invalid(format!(
                        "{} is filed under the wrong provider or part",
                        file.display()
                    )));
                }
                verify_ingested(&provider, &result, &key, &digest, execution)?;
                grouped
                    .entry(provider)
                    .or_default()
                    .push((number, total, result));
            }
            Some(_) => {
                return Err(invalid(format!(
                    "{} records an invalid part",
                    file.display()
                )))
            }
        }
    }
    for (provider, parts) in grouped {
        if singles.iter().any(|single| single.provider == provider) {
            return Err(invalid(format!(
                "lens receipts for {provider} mix a whole-lens receipt with part receipts"
            )));
        }
        let (result, progress) = merge_parts(&provider, parts)?;
        singles.push(LoadedReceipt {
            provider,
            result,
            parts: Some(progress),
        });
    }
    singles.sort_by(|left, right| left.provider.cmp(&right.provider));
    Ok(singles)
}

// ---------------------------------------------------------------------------
// Packet files and the part index
// ---------------------------------------------------------------------------

pub const LENS_INDEX_KIND: &str = "legion-lens-packet-index";

/// The `<provider>.index.json` for a partitioned provider: every part, its
/// packet digest and request id, and the paths homed in it. `None` for a
/// provider whose denominator fits one un-numbered packet.
fn part_index(items: &[&PendingLensWork]) -> Result<Option<Value>, AuditError> {
    let Some(first) = items.first() else {
        return Ok(None);
    };
    if first.part().is_none() {
        return Ok(None);
    }
    let mut parts = Vec::new();
    for item in items {
        let Some(part) = item.part() else {
            return Err(invalid(format!(
                "{} mixes numbered and un-numbered packets",
                item.provider_id
            )));
        };
        let meta = item
            .request
            .packet
            .get("part")
            .cloned()
            .unwrap_or(Value::Null);
        let paths = meta.get("paths").cloned().unwrap_or(Value::Null);
        parts.push(json!({
            "part": part.number,
            "file": item.packet_file_name(),
            "packetDigest": canonical_digest(&item.request.packet)
                .map_err(|error| invalid(error.to_string()))?,
            "requestId": item.request.request_id,
            "pathCount": paths.as_array().map_or(0, Vec::len),
            "pathsDigest": meta.get("pathsDigest"),
            "paths": paths,
            "continuedPaths": meta.get("continuedPaths"),
            "chunkCount": item
                .request
                .packet
                .get("excerpts")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            "omitted": item.request.packet.pointer("/excerptCoverage/omittedPaths"),
        }));
    }
    let meta = first
        .request
        .packet
        .get("part")
        .cloned()
        .unwrap_or(Value::Null);
    Ok(Some(json!({
        "schemaVersion": 1,
        "kind": LENS_INDEX_KIND,
        "provider": first.provider_id,
        "planDigest": first.request.plan_digest,
        "denominatorDigest": first.request.denominator_digest,
        "denominatorCount": first.request.denominator_count,
        "totalParts": items.len(),
        "requiredParts": meta.get("requiredParts"),
        "overCeiling": meta.get("overCeiling"),
        "parts": parts,
    })))
}

/// Per-provider status items for pending lens work, in the shape the CLI
/// reports (`provider`, `lensIds`, `status`, `packet`, `packetDigest`,
/// `planDigest`), plus for a partitioned provider `parts` (each with its
/// packet path, digest and path count), `partsTotal` and `index`. `packet` is
/// the single packet, or the first part, so existing consumers keep working.
/// `packet_dir` is where the packets were (or will be) written.
pub fn lens_packet_items(
    work: &[PendingLensWork],
    packet_dir: Option<&Path>,
) -> Result<Vec<Value>, AuditError> {
    let mut order: Vec<&str> = Vec::new();
    for item in work {
        if !order.contains(&item.provider_id.as_str()) {
            order.push(item.provider_id.as_str());
        }
    }
    let mut out = Vec::new();
    for provider in order {
        let items: Vec<&PendingLensWork> = work
            .iter()
            .filter(|item| item.provider_id == provider)
            .collect();
        let first = items[0];
        let path_of =
            |item: &PendingLensWork| packet_dir.map(|dir| dir.join(item.packet_file_name()));
        let digest_of = |item: &PendingLensWork| {
            canonical_digest(&item.request.packet).map_err(|error| invalid(error.to_string()))
        };
        let mut entry = json!({
            "provider": first.provider_id,
            "lensIds": first.lens_ids,
            "status": "pending-host",
            "packet": path_of(first),
            "packetDigest": digest_of(first)?,
            "planDigest": first.request.plan_digest,
        });
        if first.part().is_some() {
            let mut listed = Vec::new();
            for item in items.iter().copied() {
                let meta = item
                    .request
                    .packet
                    .get("part")
                    .cloned()
                    .unwrap_or(Value::Null);
                listed.push(json!({
                    "part": item.part().map(|part| part.number),
                    "packet": path_of(item),
                    "packetDigest": digest_of(item)?,
                    "requestId": item.request.request_id,
                    "pathCount": meta.get("paths").and_then(Value::as_array).map_or(0, Vec::len),
                    "status": "pending-host",
                }));
            }
            let meta = first
                .request
                .packet
                .get("part")
                .cloned()
                .unwrap_or(Value::Null);
            entry["partsTotal"] = json!(items.len());
            entry["requiredParts"] = meta.get("requiredParts").cloned().unwrap_or(Value::Null);
            entry["overCeiling"] = meta.get("overCeiling").cloned().unwrap_or(Value::Null);
            entry["index"] =
                json!(packet_dir.map(|dir| dir.join(format!("{provider}.index.json"))));
            entry["parts"] = Value::Array(listed);
        }
        out.push(entry);
    }
    Ok(out)
}

/// Writes lens packets under `packet_dir` (`<out>/lens-packets`): the single
/// `<provider>.json` when a provider's denominator fits one part, otherwise
/// `<provider>.part-NNNN.json` for every part plus `<provider>.index.json`.
/// Stale packet files of a provider (an earlier run with a different part
/// count) are removed first. Returns the same items as `lens_packet_items`.
pub fn write_lens_packets(
    packet_dir: &Path,
    work: &[PendingLensWork],
) -> Result<Vec<Value>, AuditError> {
    let items = lens_packet_items(work, Some(packet_dir))?;
    let mut providers: Vec<&str> = Vec::new();
    for item in work {
        if !providers.contains(&item.provider_id.as_str()) {
            providers.push(item.provider_id.as_str());
        }
    }
    for provider in providers {
        let group: Vec<&PendingLensWork> = work
            .iter()
            .filter(|item| item.provider_id == provider)
            .collect();
        let _ = fs::remove_file(packet_dir.join(format!("{provider}.json")));
        let _ = fs::remove_file(packet_dir.join(format!("{provider}.index.json")));
        for (_, stale) in part_packet_files(packet_dir, provider) {
            let _ = fs::remove_file(stale);
        }
        for item in &group {
            let bytes =
                serde_json::to_vec_pretty(item).map_err(|error| invalid(error.to_string()))?;
            write_atomic(packet_dir, &item.packet_file_name(), &bytes)?;
        }
        if let Some(index) = part_index(&group)? {
            let bytes =
                serde_json::to_vec_pretty(&index).map_err(|error| invalid(error.to_string()))?;
            write_atomic(packet_dir, &format!("{provider}.index.json"), &bytes)?;
        }
    }
    Ok(items)
}

/// Rebuilds the run verdict. Reasoning lenses count as ran only when a lens
/// receipt verifies (MAC, epoch, plan binding, result digest); everything else
/// stays exactly as the original execution reported it.
pub fn recompute_run(run_dir: &Path) -> Result<Recomputed, AuditError> {
    let execution: ExecutionReport =
        serde_json::from_value(read_json(&run_dir.join("execution.json"))?)
            .map_err(|error| invalid(format!("execution.json is invalid: {error}")))?;
    let stored: ReportV1 = serde_json::from_value(read_json(&run_dir.join("report.json"))?)
        .map_err(|error| invalid(format!("report.json is invalid: {error}")))?;
    let plan = read_json(&run_dir.join("plan.json"))?;
    let loaded = load_receipts(run_dir, &plan, &execution, None)?;
    let lens_parts: BTreeMap<String, PartsProgress> = loaded
        .iter()
        .filter_map(|entry| {
            entry
                .parts
                .clone()
                .map(|progress| (entry.provider.clone(), progress))
        })
        .collect();
    let receipts: Vec<(String, ProviderResult)> = loaded
        .into_iter()
        .map(|entry| (entry.provider, entry.result))
        .collect();
    let repository = stored.targets.first().cloned().unwrap_or_default();
    let original = canonical_report(&repository, &execution)?;

    let ingested: BTreeSet<String> = receipts
        .iter()
        .map(|(provider, _)| provider.clone())
        .collect();
    let mut next = execution.clone();
    let mut resolved = BTreeSet::new();
    let mut partial: BTreeSet<String> = BTreeSet::new();
    let mut confirmed_security: Vec<ConfirmedSecurityFinding> = Vec::new();
    for (provider, result) in &receipts {
        let slot = next
            .results
            .iter_mut()
            .find(|entry| &entry.provider == provider)
            .ok_or_else(|| invalid(format!("{provider} is not part of this run")))?;
        resolved.extend(slot.result.coverage_gaps.iter().cloned());
        resolved.insert(format!("reasoning-lens-pending-host:{provider}"));
        slot.result = result.clone();
        slot.skipped = false;
        if let Some(confirmed) = result.details.get("securityConfirmed") {
            confirmed_security.extend(
                serde_json::from_value::<Vec<ConfirmedSecurityFinding>>(confirmed.clone())
                    .map_err(|error| invalid(format!("{provider}: securityConfirmed: {error}")))?,
            );
        }
        // Only a lens whose packet coverage is proven counts as having run; a
        // partial receipt stays incomplete and carries its own coverage gaps.
        if result.complete {
            resolved.insert(format!("provider-incomplete:{provider}"));
            if let Some(lenses) = result.details.get("lensIds").and_then(Value::as_array) {
                next.lenses_ran.extend(
                    lenses
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned),
                );
            }
        } else {
            partial.insert(provider.clone());
        }
    }
    // A gap another still-pending provider reports (the shared host-unavailable
    // gap) must survive.
    for entry in &next.results {
        if !ingested.contains(&entry.provider) {
            for gap in &entry.result.coverage_gaps {
                resolved.remove(gap);
            }
        }
    }
    next.gaps.retain(|gap| !resolved.contains(gap));
    for (provider, result) in &receipts {
        if partial.contains(provider) {
            next.gaps.extend(result.coverage_gaps.iter().cloned());
        }
    }
    next.gaps.sort();
    next.gaps.dedup();
    // A partitioned provider with parts still to ingest stays pending.
    next.pending_host.retain(|provider| {
        !ingested.contains(provider)
            || lens_parts
                .get(provider)
                .is_some_and(|progress| !progress.pending.is_empty())
    });
    next.lenses_ran.sort();
    next.lenses_ran.dedup();
    if next.lenses_ran == next.selected_reasoning_lenses {
        next.gaps.retain(|gap| gap != NOT_COMPLETE_GAP);
    }

    let rebuilt = canonical_report(&repository, &next)?;
    let original_gaps: BTreeSet<&String> = original.gaps.iter().collect();
    // Gaps the CLI added outside the engine (input, parity, packet gaps) carry over.
    let mut gaps: BTreeSet<String> = stored
        .gaps
        .iter()
        .filter(|gap| !original_gaps.contains(gap))
        .cloned()
        .collect();
    gaps.extend(rebuilt.gaps.iter().cloned());
    let variant_paths = confirmed_paths(&confirmed_security);
    let mut findings = rebuilt.findings.clone();
    let mut followup_claim: Option<Value> = None;
    if !confirmed_security.is_empty() {
        // Variant analysis is required for every surviving finding, and the
        // frozen plan's `confirmedSecurityFinding` denominator was empty, so
        // the lens cannot run inside this run: it runs in the follow-up plan
        // under `<run>/followup/`. The gap clears only when that follow-up is
        // complete and its digest chain (parent plan, confirmed verdicts,
        // signed follow-up plan, MAC'd variant receipt) verifies.
        let state = followup::evaluate(run_dir, &plan, &execution, &confirmed_security);
        followup_claim = Some(state.claim());
        match state {
            followup::FollowupState::Complete(done) => {
                let known: BTreeSet<String> = findings
                    .iter()
                    .map(|finding| finding.id.as_str().to_owned())
                    .collect();
                for finding in done.findings {
                    if known.contains(finding.id.as_str()) {
                        gaps.insert(format!("duplicate-finding-id:{}", finding.id));
                    } else {
                        findings.push(finding);
                    }
                }
                findings.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
            }
            _ => {
                gaps.insert(format!(
                    "security-variant-analysis-pending:{} confirmed finding(s)",
                    confirmed_security.len()
                ));
            }
        }
    }
    let status = if !gaps.is_empty() {
        ReportStatus::Incomplete
    } else if findings.is_empty() {
        ReportStatus::Clean
    } else {
        ReportStatus::Findings
    };

    let mut report = stored;
    report.status = status;
    report.findings = findings;
    report.gaps = gaps.into_iter().collect();
    for (name, value) in rebuilt.claims.iter() {
        report.claims.insert(name.clone(), value.clone());
    }
    for (name, value) in rebuilt.extensions.iter() {
        report.extensions.insert(name.clone(), value.clone());
    }
    let label = match status {
        ReportStatus::Clean => "pass",
        ReportStatus::Findings => "findings",
        _ => "incomplete",
    };
    let full_audit = report.gaps.is_empty();
    report.claims.insert("auditStatus".into(), json!(label));
    report.claims.insert(
        "qualityGate".into(),
        json!(if status == ReportStatus::Clean {
            "proven"
        } else {
            "unproven"
        }),
    );
    if !confirmed_security.is_empty() {
        report.claims.insert(
            "securityVariantTrigger".into(),
            json!({
                "selector": "confirmedSecurityFinding",
                "confirmed": confirmed_security,
                "paths": variant_paths,
            }),
        );
    }
    if let Some(claim) = followup_claim {
        report
            .claims
            .insert("securityVariantFollowup".into(), claim);
    }
    report.claims.insert(
        "ingestedLenses".into(),
        json!(ingested.iter().collect::<Vec<_>>()),
    );
    if !lens_parts.is_empty() {
        report.claims.insert("lensParts".into(), json!(lens_parts));
    }
    if let Some(Value::Array(items)) = report.claims.get_mut("lensWork") {
        for item in items {
            let provider = item
                .get("provider")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            if let (Some(provider), Some(object)) = (provider, item.as_object_mut()) {
                if ingested.contains(&provider) {
                    let state = if partial.contains(&provider) {
                        "ingested-partial"
                    } else {
                        "ingested"
                    };
                    object.insert("status".into(), json!(state));
                }
            }
        }
    }
    if let Some(Value::Object(coverage)) = report.claims.get_mut("providerCoverage") {
        coverage.insert("fullAudit".into(), json!(full_audit));
    }
    report.validate()?;
    Ok(Recomputed {
        report,
        pending: next.pending_host.clone(),
        confirmed_security,
        execution: next,
        ingested: ingested.into_iter().collect(),
        lens_parts,
    })
}
