//! Read-only qualification inputs & authenticated native evidence export.
//! Neither interface issues receipts, invokes a model, or grants qualification.
use super::{authenticated_calls, digest, digest_bytes, invalid, model, read_json};
use crate::{
    error::AuditError,
    native_providers::reasoning::{self, ingest, PendingLensWork, REASONING_PROVIDER_IDS},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path},
};

pub const EXPORT_SCHEMA: &str = "legion-reasoning-runtime-export/1";
pub const PREFLIGHT_SCHEMA: &str = "legion-reasoning-runtime-preflight/1";
pub const MAX_CALLS: u64 = 44;
pub const PER_CALL_TOKENS: u64 = 150_000;
pub const MAX_RESERVED_TOKENS: u64 = MAX_CALLS * PER_CALL_TOKENS;
const MAX_AUTHOR_PACKETS: usize = 8;
pub const MEMBER_PROVIDERS: [&[&str]; 3] = [
    &[
        "reasoning.security",
        "legacy.security.adjudication",
        "legacy.security.variant-analysis",
        "reasoning.correctness",
        "reasoning.doc-drift",
        "reasoning.schema",
    ],
    &[
        "reasoning.architecture",
        "reasoning.minimize",
        "reasoning.naming",
        "reasoning.dead-file",
        "reasoning.performance",
        "reasoning.ai-slop",
    ],
    &[
        "reasoning.a11y",
        "reasoning.data-safety",
        "reasoning.resilience",
        "reasoning.platform-parity",
        "reasoning.release-readiness",
    ],
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Member {
    schema: String,
    member_id: String,
    member_index: usize,
    corpus_root: String,
    provider_ids: Vec<String>,
    case_ids: Vec<String>,
    source_root: String,
    source_files: BTreeMap<String, String>,
    cases_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Cases {
    schema: String,
    providers: Vec<String>,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Case {
    case_id: String,
    provider_ids: Vec<String>,
    fixture_root: String,
    expected: Expected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    positive: Option<Vec<Anchor>>,
    negative: Option<Negative>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    path: String,
    line: u64,
    text: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Negative {
    no_findings: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PacketPlan {
    schema: String,
    packets: Vec<Packet>,
    max_calls: u64,
    max_tokens: u64,
    per_call_tokens: u64,
    width: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Packet {
    packet_id: String,
    case_ids: Vec<String>,
    provider_ids: Vec<String>,
}

fn relative(value: &str) -> Result<&Path, AuditError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.split('/').any(str::is_empty)
        || (value.contains('\\') || value.contains(':'))
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(invalid(
            "qualification path must be relative POSIX components",
        ));
    }
    Ok(path)
}

fn source_bytes(root: &Path, relative_path: &str) -> Result<Vec<u8>, AuditError> {
    let mut path = root.to_path_buf();
    for part in relative(relative_path)?.components() {
        path.push(part);
        if fs::symlink_metadata(&path)
            .map_err(|error| invalid(error.to_string()))?
            .file_type()
            .is_symlink()
        {
            return Err(invalid("qualification source refuses symlinks"));
        }
    }
    let mut file = rightkit_fs::handle::open_read_nofollow(
        &path,
        &rightkit_fs::handle::ReadOptions::new().share_read_only(true),
    )
    .map_err(|error| invalid(error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| invalid(error.to_string()))?;
    let identity =
        rightkit_fs::FileKey::of_file(&file, &path).map_err(|error| invalid(error.to_string()))?;
    if !opened.is_file() || opened.len() > 16 * 1024 * 1024 {
        return Err(invalid("qualification source exceeds file bound"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| invalid(error.to_string()))?;
    super::validate_runtime_read(
        &path,
        &file,
        &opened,
        identity,
        bytes.len(),
        16 * 1024 * 1024,
    )?;
    Ok(bytes)
}

/// Validates source-owned controls & proposed grouping without preparing a run,
/// resolving a session, reserving tokens, spawning a process, or minting evidence.
/// Proposed grouping is deliberately not a frozen production dispatch.
pub fn preflight(root: &Path, cases: &Value, plan: &Value) -> Result<Value, AuditError> {
    if fs::symlink_metadata(root)
        .map_err(|error| invalid(error.to_string()))?
        .file_type()
        .is_symlink()
    {
        return Err(invalid("qualification root refuses symlinks"));
    }
    let root = fs::canonicalize(root).map_err(|error| invalid(error.to_string()))?;
    let controls: Cases =
        serde_json::from_value(cases.clone()).map_err(|error| invalid(error.to_string()))?;
    let packets: PacketPlan =
        serde_json::from_value(plan.clone()).map_err(|error| invalid(error.to_string()))?;
    let providers: BTreeSet<_> = REASONING_PROVIDER_IDS
        .into_iter()
        .map(str::to_owned)
        .collect();
    if controls.schema != "legion-reasoning-runtime-cases/1"
        || controls.providers.len() != providers.len()
        || controls.providers.iter().cloned().collect::<BTreeSet<_>>() != providers
        || controls.cases.len() != 34
        || packets.schema != "legion-reasoning-runtime-packet-plan/1"
        || packets.packets.len() != 8
        || packets.max_calls != MAX_CALLS
        || packets.max_tokens != MAX_RESERVED_TOKENS
        || packets.per_call_tokens != PER_CALL_TOKENS
        || packets.width != 1
    {
        return Err(invalid(
            "qualification corpus/provider/packet/budget boundary mismatch",
        ));
    }
    let mut case_map = BTreeMap::new();
    let mut polarities = BTreeMap::<String, (u32, u32)>::new();
    let mut roots = BTreeSet::new();
    for case in &controls.cases {
        if case.case_id.is_empty()
            || case.provider_ids.len() != 1
            || !providers.contains(&case.provider_ids[0])
            || case_map.insert(case.case_id.clone(), case).is_some()
            || !roots.insert(case.fixture_root.clone())
        {
            return Err(invalid(
                "qualification cases require distinct roots/identities & one canonical provider",
            ));
        }
        relative(&case.fixture_root)?;
        let polarity = polarities.entry(case.provider_ids[0].clone()).or_default();
        match (&case.expected.positive, &case.expected.negative) {
            (Some(anchors), None) if !anchors.is_empty() && anchors.len() <= 16 => {
                polarity.0 += 1;
                for anchor in anchors {
                    if anchor.line == 0 || anchor.text.is_empty() {
                        return Err(invalid("qualification anchor missing"));
                    }
                    let path = format!(
                        "{}/{}",
                        case.fixture_root,
                        relative(&anchor.path)?.display()
                    );
                    let text = String::from_utf8(source_bytes(&root, &path)?)
                        .map_err(|error| invalid(error.to_string()))?;
                    if text.lines().nth(
                        usize::try_from(anchor.line - 1)
                            .map_err(|error| invalid(error.to_string()))?,
                    ) != Some(anchor.text.as_str())
                    {
                        return Err(invalid("qualification anchor differs from source"));
                    }
                }
            }
            (None, Some(negative)) if negative.no_findings => {
                polarity.1 += 1;
            }
            _ => {
                return Err(invalid(
                    "qualification case requires exactly one explicit polarity",
                ))
            }
        }
        let fixture = root.join(&case.fixture_root);
        if !fixture.is_dir()
            || fs::symlink_metadata(&fixture)
                .map_err(|error| invalid(error.to_string()))?
                .file_type()
                .is_symlink()
        {
            return Err(invalid("qualification fixture root missing/unsafe"));
        }
    }
    if polarities.len() != providers.len() || polarities.values().any(|value| *value != (1, 1)) {
        return Err(invalid(
            "each provider requires one planted & one clean control",
        ));
    }
    let mut assigned = BTreeSet::new();
    let mut packet_ids = BTreeSet::new();
    for packet in &packets.packets {
        let mut expected = BTreeSet::new();
        if packet.packet_id.is_empty()
            || !packet_ids.insert(&packet.packet_id)
            || packet.case_ids.is_empty()
        {
            return Err(invalid("qualification packet identity missing/duplicate"));
        }
        for id in &packet.case_ids {
            let case = case_map
                .get(id)
                .ok_or_else(|| invalid("qualification packet references unknown control"))?;
            if !assigned.insert(id) {
                return Err(invalid("qualification control assigned more than once"));
            }
            expected.extend(case.provider_ids.iter().cloned());
        }
        if packet.provider_ids.len() != expected.len()
            || packet.provider_ids.iter().cloned().collect::<BTreeSet<_>>() != expected
        {
            return Err(invalid("qualification packet provider/control mismatch"));
        }
    }
    if assigned.len() != controls.cases.len() {
        return Err(invalid("qualification packet plan omits controls"));
    }
    Ok(
        json!({"schema":PREFLIGHT_SCHEMA,"casesDigest":digest(cases)?,"packetPlanDigest":digest(plan)?,"providers":providers,"cases":34,"proposedPackets":8,"maxCalls":MAX_CALLS,"reservationCeilingTokens":MAX_RESERVED_TOKENS,"perCallReservationTokens":PER_CALL_TOKENS,"width":1,"modelCalls":0,"productionDispatchValidated":false,"qualification":false}),
    )
}

/// Replays original native authentication, then exports retained JSON bytes.
/// Caller/retrieval provenance remains external; this is never a registration
/// record or proof that all seventeen providers ran. Child follow-up runs must
/// be exported separately & bound to their original shared accounting root.
pub fn export_run(run: &Path) -> Result<Value, AuditError> {
    let run = fs::canonicalize(run).map_err(|error| invalid(error.to_string()))?;
    model::enforce_prior_receipts(&run)?;
    let calls = authenticated_calls(&run)?;
    if calls.is_empty() || calls.len() > MAX_CALLS as usize {
        return Err(invalid(
            "qualification export requires bounded genuine native calls",
        ));
    }
    if calls.iter().any(|call| call["strictNoRetry"] != true) {
        return Err(invalid(
            "qualification export requires native strict-no-retry policy",
        ));
    }
    // Native recomputation checks result MACs, frozen plan/epoch/snapshot,
    // independent verification & original result digests. No new receipt.
    let recomputed = ingest::recompute_run(&run)?;
    let mut packets = Vec::new();
    let mut artifacts = Vec::new();
    let mut total = 0usize;
    // Retain the original reservation ledger, not reconstructed accounting
    // assertions. Shared-budget children may have no local ledger; their
    // authenticated call IDs must reconcile against the captured parent.
    for name in [crate::next::STATE_FILE, crate::next::DISPATCH_FILE] {
        if !run.join(name).exists() {
            continue;
        }
        let bytes = source_bytes(&run, name)?;
        total += bytes.len();
        let text = String::from_utf8(bytes.clone()).map_err(|error| invalid(error.to_string()))?;
        artifacts.push(
            json!({"path":name,"sha256":digest_bytes(&bytes),"bytes":bytes.len(),"utf8":text}),
        );
    }
    for directory in [
        "lens-packets",
        "lens-results",
        "runtime-author-results",
        "runtime-calls",
        "runtime-delivery",
        "runtime-verification",
        "runtime-adjudication",
        "lens-receipts",
        "adjudication/packets",
        "adjudication/results",
    ] {
        let path = run.join(directory);
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(invalid(error.to_string())),
        };
        let mut paths = entries
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| invalid(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        for path in paths {
            if artifacts.len() >= 512 {
                return Err(invalid("qualification export artifact bound exceeded"));
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("qualification artifact name invalid"))?;
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                return Err(invalid("qualification export refuses unexpected artifact"));
            }
            let relative = format!("{directory}/{name}");
            let bytes = source_bytes(&run, &relative)?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| invalid("qualification export size overflow"))?;
            if total > 64 * 1024 * 1024 {
                return Err(invalid("qualification export total byte bound exceeded"));
            }
            let text =
                String::from_utf8(bytes.clone()).map_err(|error| invalid(error.to_string()))?;
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
            if directory == "lens-packets" && !name.ends_with(".index.json") {
                let work: PendingLensWork =
                    serde_json::from_value(value).map_err(|error| invalid(error.to_string()))?;
                if name != work.packet_file_name() {
                    return Err(invalid("qualification packet filename mismatch"));
                }
                packets.push(json!({"packet":work,"authenticatedEvidence":ingest::authenticated_runtime_evidence(&run, &work.request)?}));
            }
            artifacts.push(json!({"path":relative,"sha256":digest_bytes(&bytes),"bytes":bytes.len(),"utf8":text}));
        }
    }
    Ok(
        json!({"schema":EXPORT_SCHEMA,"run":run,"plan":super::read_plan_json(&run.join("plan.json"))?,"runtime":read_json(&run.join("review-runtime.json"))?,"authenticatedCalls":calls,"packets":packets,"ingested":recomputed.ingested,"pending":recomputed.pending,"report":recomputed.report,"execution":recomputed.execution,"artifacts":artifacts,"rawNativeStdoutRetained":false,"qualification":false,"productionQualification":false,"wholeProviderQualification":false}),
    )
}

fn validate_production_packet_bound(dispatch: &Value) -> Result<(), AuditError> {
    let seats = dispatch["seats"]
        .as_array()
        .ok_or_else(|| invalid("qualification production author packets missing"))?;
    // Count actual physical author requests, not proposed fixture groups or
    // logical lens packet files shared inside each production seat.
    if seats.is_empty()
        || seats.len() > MAX_AUTHOR_PACKETS
        || dispatch["requiredSeats"].as_u64() != Some(seats.len() as u64)
    {
        return Err(invalid(
            "qualification production dispatch exceeds eight author packets or count differs",
        ));
    }
    Ok(())
}

fn member_binding(run: &Path, plan: &Value) -> Result<(Member, BTreeSet<String>), AuditError> {
    let parent = run
        .parent()
        .ok_or_else(|| invalid("qualification member parent missing"))?;
    let member: Member =
        serde_json::from_value(read_json(&parent.join("qualification-member.json"))?)
            .map_err(|error| invalid(error.to_string()))?;
    let expected = MEMBER_PROVIDERS
        .get(member.member_index)
        .ok_or_else(|| invalid("qualification member index differs"))?;
    if member.schema != "legion-reasoning-qualification-member/1"
        || member.member_id != format!("run-{:02}", member.member_index + 1)
        || member.provider_ids
            != expected
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        || fs::canonicalize(&member.source_root).map_err(|error| invalid(error.to_string()))?
            != fs::canonicalize(parent.join("fixture-source"))
                .map_err(|error| invalid(error.to_string()))?
        || plan
            .pointer("/reviewContext/sourceRepository")
            .and_then(Value::as_str)
            != Some(member.source_root.as_str())
    {
        return Err(invalid(
            "qualification member source/provider binding differs",
        ));
    }
    let corpus = Path::new(&member.corpus_root);
    let raw = source_bytes(corpus, "cases.json")?;
    if digest_bytes(&raw) != member.cases_digest {
        return Err(invalid("qualification cases digest differs"));
    }
    let controls: Cases =
        serde_json::from_slice(&raw).map_err(|error| invalid(error.to_string()))?;
    preflight(
        corpus,
        &serde_json::from_slice(&raw).map_err(|error| invalid(error.to_string()))?,
        &read_json(&corpus.join("packet-plan.json"))?,
    )?;
    let selected: Vec<_> = controls
        .cases
        .iter()
        .filter(|case| {
            case.provider_ids.len() == 1 && member.provider_ids.contains(&case.provider_ids[0])
        })
        .collect();
    let mut cases: Vec<_> = selected.iter().map(|case| case.case_id.clone()).collect();
    cases.sort();
    if selected.len() != expected.len() * 2
        || member.case_ids != cases
        || member.source_files.is_empty()
    {
        return Err(invalid("qualification paired member cases differ"));
    }
    let roots: Vec<_> = selected
        .iter()
        .map(|case| {
            case.fixture_root
                .strip_prefix("fixtures/")
                .ok_or_else(|| invalid("qualification fixture prefix differs"))
        })
        .collect::<Result<_, _>>()?;
    fn collect(
        root: &Path,
        directory: &Path,
        files: &mut BTreeSet<String>,
    ) -> Result<(), AuditError> {
        for entry in fs::read_dir(directory).map_err(|error| invalid(error.to_string()))? {
            let path = entry.map_err(|error| invalid(error.to_string()))?.path();
            if fs::symlink_metadata(&path)
                .map_err(|error| invalid(error.to_string()))?
                .file_type()
                .is_symlink()
                || files.len() > 1000
            {
                return Err(invalid("qualification member source unsafe/oversized"));
            }
            if path.is_dir() {
                collect(root, &path, files)?;
            } else {
                files.insert(
                    path.strip_prefix(root)
                        .map_err(|error| invalid(error.to_string()))?
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
        Ok(())
    }
    let mut original_files = BTreeSet::new();
    for root in &roots {
        collect(
            &corpus.join("fixtures"),
            &corpus.join("fixtures").join(root),
            &mut original_files,
        )?;
    }
    if original_files != member.source_files.keys().cloned().collect() {
        return Err(invalid("qualification member omits original case source"));
    }
    for (name, sha) in &member.source_files {
        relative(name)?;
        if !roots
            .iter()
            .any(|root| name.starts_with(&format!("{root}/")))
            || digest_bytes(&source_bytes(corpus, &format!("fixtures/{name}"))?) != *sha
            || digest_bytes(&source_bytes(Path::new(&member.source_root), name)?) != *sha
        {
            return Err(invalid("qualification member source bytes differ"));
        }
    }
    let snapshot = plan
        .pointer("/reviewContext/snapshotManifest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("qualification snapshot missing"))?;
    let snapshot = read_json(Path::new(snapshot))?;
    let files: BTreeSet<_> = snapshot["files"]
        .as_object()
        .ok_or_else(|| invalid("qualification snapshot files missing"))?
        .keys()
        .cloned()
        .collect();
    if files != member.source_files.keys().cloned().collect() {
        return Err(invalid("qualification snapshot/source subset differs"));
    }
    let mut providers: BTreeSet<_> = member.provider_ids.iter().cloned().collect();
    providers.insert("security.misuse-resistance".into());
    Ok((member, providers))
}

/// Inspect a genuine prepared production plan before any paid call. This
/// validates native frozen artifacts without leasing a seat or probing a CLI.
/// Conditional security stages remain explicit; proposed packet groups cannot
/// override production batching, stage readiness or fresh verifier scheduling.
pub fn preflight_run(run: &Path) -> Result<Value, AuditError> {
    let run = fs::canonicalize(run).map_err(|error| invalid(error.to_string()))?;
    if !authenticated_calls(&run)?.is_empty() {
        return Err(invalid(
            "qualification dispatch preflight requires a fresh run",
        ));
    }
    let verified = ingest::recompute_run(&run)?;
    let plan = super::read_plan_json(&run.join("plan.json"))?;
    let dispatch = read_json(&run.join("lens-dispatch.json"))?;
    let (member, expected) = member_binding(&run, &plan)?;
    let quota = dispatch
        .pointer("/reasoningBudget/maxSeats")
        .and_then(Value::as_u64)
        .filter(|quota| (1..=MAX_CALLS).contains(quota))
        .ok_or_else(|| invalid("qualification remaining quota invalid"))?;
    // Reconstruct the complete original packet universe from the canonical
    // sealed scope, verified inventory, immutable source & native candidates.
    // Scalar budget checks alone cannot authenticate dispatch membership.
    let (frozen, inventory, execution) = ingest::frozen_reasoning_basis(&run)?;
    let source = Path::new(&frozen.plan().repository_id);
    let candidates = reasoning::scanner_candidates_from_execution(source, &frozen, &execution);
    let work = reasoning::pending_lens_work_with_candidates(
        source,
        &frozen,
        &inventory,
        Some(&candidates),
    )?;
    let logical_requests: BTreeSet<_> = work
        .iter()
        .map(|item| item.request.request_id.as_str())
        .collect();
    if logical_requests.len() != work.len() || logical_requests.len() > 8 {
        return Err(invalid(
            "qualification logical pending requests exceed fresh verifier item capacity",
        ));
    }
    let mut expected_packets = BTreeSet::new();
    for item in &work {
        item.request.validate().map_err(invalid)?;
        let name = item.packet_file_name();
        if !expected_packets.insert(name.clone())
            || read_json(&run.join(ingest::LENS_PACKET_DIR).join(&name))?
                != serde_json::to_value(item).map_err(|error| invalid(error.to_string()))?
        {
            return Err(invalid(
                "qualification packet differs from canonical frozen source",
            ));
        }
    }
    let mut actual_packets = BTreeSet::new();
    for entry in fs::read_dir(run.join(ingest::LENS_PACKET_DIR))
        .map_err(|error| invalid(error.to_string()))?
    {
        if actual_packets.len() > 512 {
            return Err(invalid("qualification packet count exceeds bound"));
        }
        let path = entry.map_err(|error| invalid(error.to_string()))?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("qualification packet name invalid"))?;
        if !name.ends_with(".index.json") {
            actual_packets.insert(name.to_owned());
        }
    }
    let canonical = ingest::lens_dispatch_plan_checked(
        &work,
        &ingest::DispatchLimits {
            seat_token_budget: PER_CALL_TOKENS,
            wave_width: 1,
            run_token_budget: quota * PER_CALL_TOKENS,
            max_total_seats: quota,
        },
    )?;
    if actual_packets != expected_packets || dispatch != canonical {
        return Err(invalid(
            "qualification dispatch differs from canonical frozen production plan",
        ));
    }
    validate_production_packet_bound(&dispatch)?;
    let selected = plan["providers"]
        .as_array()
        .ok_or_else(|| invalid("frozen provider selection missing"))?;
    if selected.len() != expected.len()
        || selected
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            != expected
        || dispatch.pointer("/reasoningBudget/schemaVersion") != Some(&json!(2))
        || dispatch.pointer("/reasoningBudget/totalTokens") != Some(&json!(quota * PER_CALL_TOKENS))
        || dispatch.pointer("/reasoningBudget/perCallTokens") != Some(&json!(PER_CALL_TOKENS))
        || dispatch.pointer("/reasoningBudget/maxSeats") != Some(&json!(quota))
        || dispatch.pointer("/limits/waveWidth") != Some(&json!(1))
        || dispatch["withinLimits"] != true
        || dispatch["boundedAudit"] != false
        || dispatch["coverageMode"] != "exhaustive"
    {
        return Err(invalid(
            "qualification frozen production selection/budget/coverage mismatch",
        ));
    }
    Ok(
        json!({"schema":"legion-reasoning-runtime-dispatch-preflight/1","run":run,"memberId":member.member_id,"memberIndex":member.member_index,"caseIds":member.case_ids,"providerIds":member.provider_ids,"expectedPlantedPositives":member.provider_ids.len(),"knownAnswerExpectedPositives":member.provider_ids.len(),"expectedPairedCleanControls":member.provider_ids.len(),"expectedVerifierItems":member.provider_ids.len(),"logicalPendingRequestCount":logical_requests.len(),"zeroFindingReviewHeadroom":8-member.provider_ids.len(),"verifierItemCap":8,"verifierEnvelopeBasis":"known-answer expectation; logical requests are a lower bound, multiple findings and zero-finding reviews remain subject to native cap","plannedFreshBatchVerifierAdmissions":1,"plannedAuthorSeats":dispatch["requiredSeats"],"remainingAdmissions":quota,"planDigest":plan.pointer("/seal/digest"),"dispatchDigest":digest(&dispatch)?,"dispatch":dispatch,"pending":verified.pending,"modelCalls":0,"productionDispatchValidated":true,"qualification":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_author_packet_cap_counts_real_seats_not_summary_or_logical_packets() {
        let seat = json!({"packets":["correctness.json", "architecture.json", "security.json"]});
        let dispatch = json!({"seats":vec![seat.clone(); MAX_AUTHOR_PACKETS],"requiredSeats":8});
        assert!(validate_production_packet_bound(&dispatch).is_ok());
        let mut extra = dispatch.clone();
        extra["seats"].as_array_mut().unwrap().push(seat);
        // A forged eight-seat summary cannot hide a ninth physical request.
        assert!(validate_production_packet_bound(&extra).is_err());
        extra["requiredSeats"] = json!(9);
        assert!(validate_production_packet_bound(&extra).is_err());
        let mut mismatch = dispatch;
        mismatch["requiredSeats"] = json!(7);
        assert!(validate_production_packet_bound(&mismatch).is_err());
        for missing in [json!({}), json!({"seats":[],"requiredSeats":0})] {
            assert!(validate_production_packet_bound(&missing).is_err());
        }
    }
}
