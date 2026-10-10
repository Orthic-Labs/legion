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
    authenticate_receipt, lens_plan, lens_schemas,
    security_adjudication::{
        adjudicate_scanner_candidates, confirmed_findings, confirmed_paths,
        ConfirmedSecurityFinding, ScannerCandidate, ADJUDICATOR_PROVIDER_ID,
    },
    verify_authenticated_receipt, verify_response, PendingLensWork, ReasoningHostResponse,
    ReasoningReceipt, REASONING_PROVIDER_IDS, REASONING_RECEIPT_KIND,
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

fn invalid(message: impl Into<String>) -> AuditError {
    AuditError::Invalid(message.into())
}

fn io(error: std::io::Error, what: &str) -> AuditError {
    AuditError::Invalid(format!("{what}: {error}"))
}

fn read_json(path: &Path) -> Result<Value, AuditError> {
    let bytes =
        fs::read(path).map_err(|error| io(error, &format!("could not read {}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("{} is not valid JSON: {error}", path.display())))
}

fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, AuditError> {
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
) -> PacketCoverage {
    let expected = denominator_paths.len() as u64;
    let coverage = packet.get("excerptCoverage").filter(|value| value.is_object());
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

fn expected_request_id(work: &PendingLensWork) -> Result<String, AuditError> {
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

/// Validates a lens result against the frozen run and, when accepted, writes a
/// MAC'd receipt to `<run>/lens-receipts/<provider>.json`.
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
    let packet_path = run_dir
        .join(LENS_PACKET_DIR)
        .join(format!("{provider_id}.json"));
    let work: PendingLensWork = serde_json::from_value(read_json(&packet_path)?)
        .map_err(|error| invalid(format!("lens packet is invalid: {error}")))?;
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
                for verdict in verdicts.iter().filter(|verdict| verdict.verdict.is_surviving()) {
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

    let stored = json!({
        "schemaVersion": 1,
        "kind": "legion-lens-receipt",
        "provider": provider_id,
        "result": accepted,
    });
    let path = write_atomic(
        &run_dir.join(LENS_RECEIPT_DIR),
        &format!("{provider_id}.json"),
        &serde_json::to_vec_pretty(&stored).map_err(|error| invalid(error.to_string()))?,
    )?;
    Ok(IngestedLens {
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
    })
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
    /// Reasoning providers still `pending-host`.
    pub pending: Vec<String>,
    /// Surviving security verdicts from ingested adjudication receipts: the
    /// trigger for variant analysis.
    pub confirmed_security: Vec<ConfirmedSecurityFinding>,
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

fn load_receipts(
    run_dir: &Path,
    plan: &Value,
    execution: &ExecutionReport,
) -> Result<Vec<(String, ProviderResult)>, AuditError> {
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
    let mut receipts = Vec::new();
    for file in files {
        let value = read_json(&file)?;
        let provider = value
            .get("provider")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{} names no provider", file.display())))?
            .to_owned();
        if file.file_name().and_then(|name| name.to_str())
            != Some(format!("{provider}.json").as_str())
        {
            return Err(invalid(format!(
                "{} is filed under the wrong provider",
                file.display()
            )));
        }
        let result: ProviderResult =
            serde_json::from_value(value.get("result").cloned().unwrap_or(Value::Null))
                .map_err(|error| invalid(format!("{}: {error}", file.display())))?;
        verify_ingested(&provider, &result, &key, &digest, execution)?;
        receipts.push((provider, result));
    }
    Ok(receipts)
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
    let receipts = load_receipts(run_dir, &plan, &execution)?;
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
    next.pending_host
        .retain(|provider| !ingested.contains(provider));
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
    if !confirmed_security.is_empty() {
        // Variant analysis is required for every surviving finding, and the
        // frozen plan's `confirmedSecurityFinding` denominator was empty, so
        // the lens cannot run inside this run: say so instead of reporting
        // the finding as fully handled.
        gaps.insert(format!(
            "security-variant-analysis-pending:{} confirmed finding(s)",
            confirmed_security.len()
        ));
    }
    let status = if !gaps.is_empty() {
        ReportStatus::Incomplete
    } else if rebuilt.findings.is_empty() {
        ReportStatus::Clean
    } else {
        ReportStatus::Findings
    };

    let mut report = stored;
    report.status = status;
    report.findings = rebuilt.findings.clone();
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
    report.claims.insert(
        "ingestedLenses".into(),
        json!(ingested.iter().collect::<Vec<_>>()),
    );
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
    })
}
