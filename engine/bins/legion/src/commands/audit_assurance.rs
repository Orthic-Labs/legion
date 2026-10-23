//! CLI adapter for Audit production-assurance profiles.
//!
//! Thin wiring only: the policy (denominator freeze, evidence reconciliation,
//! gate verdict) lives in `legion_audit::assurance`; reporting projections live
//! in `legion_report`. Nothing here decides eligibility or runs a scan.
use super::{CommandError, CommandResult};
use clap::Args;
use legion_audit::{
    artifact_evidence::{
        verify_artifact_evidence, ArtifactEvidenceEnvelope, ExpectedEvidence, ProvenanceVerifier,
        TrustEnrollment, UnconfiguredVerifier, ARTIFACT_EVIDENCE_SCHEMA_VERSION,
        MAX_RAW_ARTIFACT_BYTES,
    },
    assurance::{
        gate_run, AuditAssuranceV1, EvidenceKind, GateVerdict, ObligationCandidate,
        ObligationEvidence, ObligationId, ProductTarget, RunGateError, SelectionScope, SnapshotRef,
    },
    evidence_issuers::{default_issuers_path, HostEvidenceVerifier},
    profiles::{AuditProfile, FrozenProfile, RuntimeConstraint},
    AuditPlan,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

/// Rule/profile revision frozen into every new-profile obligation identity.
pub const PROFILE_REVISION: &str = "legion-audit-profile/1";
const MAX_INPUT_BYTES: u64 = 1024 * 1024;

/// Assurance flags shared by `legion audit`. They require a new profile.
#[derive(Debug, Clone, Default, Args)]
pub struct AssuranceArgs {
    /// Native-only execution constraint frozen into the profile. New profiles
    /// default to it; imported evidence discloses its upstream runtime.
    #[arg(long = "runtime-policy", value_parser = ["no-node-python"])]
    pub runtime_policy: Option<String>,
    /// Product contract JSON: product, target, optional variant/snapshots and
    /// extra obligation candidates. Requires pre-pr|repository|release.
    #[arg(long = "product-contract")]
    pub product_contract: Option<PathBuf>,
    /// Imported artifact-evidence manifest JSON (repeatable). Unverified
    /// imports leave their obligation unmet.
    #[arg(long = "artifact-manifest")]
    pub artifact_manifests: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductContract {
    product: String,
    target: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    snapshots: Vec<SnapshotRef>,
    #[serde(default)]
    obligations: Vec<ObligationCandidate>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactManifest {
    obligation: ObligationId,
    envelope: Value,
    expected: ExpectedEvidence,
    attestation_path: String,
    #[serde(default)]
    artifacts: BTreeMap<String, String>,
}

/// A resolved request for assurance. `None` from [`request`] means legacy.
#[derive(Debug)]
pub struct AssuranceRequest {
    pub profile: AuditProfile,
    pub constraint: RuntimeConstraint,
    contract: Option<ProductContract>,
    pub imported: Vec<ObligationEvidence>,
    pub import_gaps: Vec<String>,
    pub import_records: Vec<Value>,
    /// Frozen provider/scope selection, set by `audit` once filters resolve.
    /// Building without it is refused: a plan that cannot prove its scope is
    /// never assurance-eligible.
    selection: Option<SelectionScope>,
}

/// Profile used when `--profile` is not given. The legacy `standard` profile
/// is reachable only by naming it.
pub const DEFAULT_PROFILE: &str = "repository";

/// The explicit legacy profile name. It freezes no denominator and can never
/// pass the assurance gate; it rejects assurance-only flags.
pub const LEGACY_PROFILE: &str = "standard";

/// `standard` (named explicitly) stays legacy and rejects assurance-only flags
/// rather than silently ignoring them. Any other name must be one of
/// `pre-pr`, `repository`, `release`: an unknown or mistyped name is a usage
/// error (exit 4), never a silent fall back to legacy behaviour.
pub fn request(
    profile: &str,
    args: &AssuranceArgs,
) -> Result<Option<AssuranceRequest>, CommandError> {
    if profile == LEGACY_PROFILE {
        if args.runtime_policy.is_some()
            || args.product_contract.is_some()
            || !args.artifact_manifests.is_empty()
        {
            return Err(CommandError::usage(
                "--runtime-policy, --product-contract and --artifact-manifest require --profile pre-pr, repository or release",
            ));
        }
        return Ok(None);
    }
    let Some(profile) = AuditProfile::parse(profile) else {
        return Err(CommandError::usage(format!(
            "unknown --profile `{profile}`: expected pre-pr, repository or release (or `standard` for the legacy profile)"
        )));
    };
    let constraint = match args.runtime_policy.as_deref() {
        None | Some("no-node-python") => RuntimeConstraint::NoNodePython,
        Some(other) => {
            return Err(CommandError::usage(format!(
                "unsupported --runtime-policy {other}"
            )))
        }
    };
    let contract = args
        .product_contract
        .as_deref()
        .map(|path| {
            let value = read_json(path, "product contract")?;
            serde_json::from_value::<ProductContract>(value)
                .map_err(|error| CommandError::usage(format!("invalid product contract: {error}")))
        })
        .transpose()?;
    let mut request = AssuranceRequest {
        profile,
        constraint,
        contract,
        imported: Vec::new(),
        import_gaps: Vec::new(),
        import_records: Vec::new(),
        selection: None,
    };
    let enrolled = if args.artifact_manifests.is_empty() {
        None
    } else {
        load_issuers(&args.artifact_manifests, &mut request)
    };
    for manifest in &args.artifact_manifests {
        import_manifest(&mut request, manifest, enrolled.as_ref())?;
    }
    Ok(Some(request))
}

fn read_json(path: &Path, label: &str) -> Result<Value, CommandError> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| CommandError::usage(format!("{label} {}: {error}", path.display())))?;
    if !metadata.is_file() || metadata.len() > MAX_INPUT_BYTES {
        return Err(CommandError::usage(format!(
            "{label} {} must be a regular file under 1 MiB",
            path.display()
        )));
    }
    let bytes = std::fs::read(path).map_err(super::io_error)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| CommandError::usage(format!("invalid {label}: {error}")))
}

fn contained(base: &Path, relative: &str) -> Result<PathBuf, CommandError> {
    let candidate = Path::new(relative);
    if relative.is_empty()
        || candidate.is_absolute()
        || !candidate
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(CommandError::usage(format!(
            "artifact manifest path `{relative}` must be relative and stay inside the manifest directory"
        )));
    }
    Ok(base.join(candidate))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, CommandError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| CommandError::usage(format!("{}: {error}", path.display())))?;
    if !metadata.is_file() || metadata.len() > MAX_RAW_ARTIFACT_BYTES as u64 {
        return Err(CommandError::usage(format!(
            "{} must be a regular file within the artifact size limit",
            path.display()
        )));
    }
    std::fs::read(path).map_err(super::io_error)
}

/// Load the host-owned issuer enrollment (`audit-evidence-issuers.json` in the
/// LEGION state root). Absent file: no enrollment (imports stay unmet). An
/// untrustworthy file is recorded as a gap and also yields no enrollment. The
/// working directory and every manifest directory count as audited roots, so a
/// repository-supplied enrollment can never be loaded.
fn load_issuers(
    manifests: &[PathBuf],
    request: &mut AssuranceRequest,
) -> Option<(HostEvidenceVerifier, TrustEnrollment)> {
    let path = default_issuers_path()?;
    let mut roots: Vec<PathBuf> = std::env::current_dir().into_iter().collect();
    for manifest in manifests {
        if let Some(parent) = manifest.parent() {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            roots.push(parent.to_path_buf());
        }
    }
    match HostEvidenceVerifier::load(&path, &roots) {
        Ok(found) => found,
        Err(reason) => {
            request
                .import_gaps
                .push(format!("evidence-issuer-enrollment-untrusted:{reason}"));
            None
        }
    }
}

/// Verify one imported manifest. With no host-owned issuer enrollment the
/// verifier is unconfigured and verification fails closed with named reasons:
/// the import is recorded and the obligation stays unmet. Only a signature by
/// an enrolled issuer, bound to the expected subject, can satisfy it.
fn import_manifest(
    request: &mut AssuranceRequest,
    path: &Path,
    enrolled: Option<&(HostEvidenceVerifier, TrustEnrollment)>,
) -> Result<(), CommandError> {
    let manifest: ArtifactManifest = serde_json::from_value(read_json(path, "artifact manifest")?)
        .map_err(|error| CommandError::usage(format!("invalid artifact manifest: {error}")))?;
    let base = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let envelope = ArtifactEvidenceEnvelope::from_value(&manifest.envelope)
        .map_err(|error| CommandError::usage(error.to_string()))?;
    let mut raw = BTreeMap::new();
    for (name, relative) in &manifest.artifacts {
        raw.insert(name.clone(), read_bounded(&contained(&base, relative)?)?);
    }
    let attestation = read_bounded(&contained(&base, &manifest.attestation_path)?)?;
    let empty = TrustEnrollment {
        schema_version: ARTIFACT_EVIDENCE_SCHEMA_VERSION,
        issuers: Vec::new(),
    };
    let (trust, verifier): (&TrustEnrollment, &dyn ProvenanceVerifier) = match enrolled {
        Some((verifier, trust)) => (trust, verifier),
        None => (&empty, &UnconfiguredVerifier),
    };
    let verdict = verify_artifact_evidence(
        &envelope,
        &raw,
        &attestation,
        &manifest.expected,
        trust,
        verifier,
        &now_rfc3339_utc(),
    );
    let upstream = envelope.upstream_runtime.clone();
    match (&verdict.record, verdict.satisfies_obligation) {
        (Some(record), true) => {
            request.imported.push(ObligationEvidence {
                obligation: manifest.obligation.clone(),
                kind: manifest.obligation.evidence_kind,
                provider_id: None,
                coverage: None,
                finding_ids: if matches!(
                    record.outcome,
                    legion_audit::artifact_evidence::EvidenceOutcome::Passed
                ) {
                    Vec::new()
                } else {
                    vec![format!("imported:{}", record.evidence_id)]
                },
                evidence_refs: vec![format!("artifact-evidence:{}", record.evidence_id)],
                artifact_digest: Some(record.artifact_digest.clone()),
                attested_by: Some(record.attestor.clone()),
                authenticated: record.authenticated,
                produced_by_runtime: upstream.clone(),
                qualification: None,
            });
            request.import_records.push(json!({
                "evidenceId": record.evidence_id, "verified": true,
                "upstreamRuntime": upstream, "newlyExecuted": record.newly_executed,
            }));
        }
        _ => {
            request.import_gaps.push(format!(
                "artifact-import-unverified:{}:{}",
                envelope.evidence_id,
                verdict.reasons.join(",")
            ));
            request.import_records.push(json!({
                "evidenceId": envelope.evidence_id, "verified": false,
                "reasons": verdict.reasons, "upstreamRuntime": upstream,
            }));
        }
    }
    Ok(())
}

impl AssuranceRequest {
    /// Record the resolved provider/scope selection to freeze into the plan.
    pub fn set_selection(&mut self, selection: SelectionScope) {
        self.selection = Some(selection);
    }

    /// The selection to bind into the plan, or a refusal when none was set.
    pub fn selection(&self) -> Result<&SelectionScope, String> {
        self.selection
            .as_ref()
            .ok_or_else(|| "assurance plan requires a frozen selection scope".to_owned())
    }

    /// Freeze the denominator against the compiled plan: one provider-execution
    /// candidate per compiled provider (proven inapplicable ones freeze as
    /// `inapplicable`), plus contract-declared candidates.
    pub fn build(
        &self,
        plan: &AuditPlan,
        root: &Path,
        runtime: &[ObligationCandidate],
    ) -> Result<AuditAssuranceV1, String> {
        let digest = if plan.inventory_digest.starts_with("sha256:") {
            plan.inventory_digest.clone()
        } else {
            format!("sha256:{}", plan.inventory_digest)
        };
        let fallback = root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "repository".into());
        let target = match &self.contract {
            Some(contract) => ProductTarget {
                product: contract.product.clone(),
                snapshots: if contract.snapshots.is_empty() {
                    vec![SnapshotRef {
                        repository_id: contract.product.clone(),
                        snapshot_digest: digest.clone(),
                    }]
                } else {
                    contract.snapshots.clone()
                },
                target: contract.target.clone(),
                variant: contract.variant.clone(),
            },
            None => ProductTarget {
                product: fallback.clone(),
                snapshots: vec![SnapshotRef {
                    repository_id: fallback,
                    snapshot_digest: digest,
                }],
                target: "repository".into(),
                variant: None,
            },
        };
        let declared = self
            .contract
            .as_ref()
            .map(|contract| contract.obligations.clone())
            .unwrap_or_default();
        // Host/plan-derived obligations only; the unauthenticated contract
        // may add or tighten (see `AuditAssuranceV1::freeze_for_profile`)
        // but never replace, de-require or mark these inapplicable.
        let mut candidates: Vec<ObligationCandidate> = plan
            .providers
            .iter()
            .map(|provider| ObligationCandidate {
                concern: provider.id.clone(),
                evidence_kind: EvidenceKind::ProviderExecution,
                required_in: vec![
                    AuditProfile::PrePr,
                    AuditProfile::Repository,
                    AuditProfile::Release,
                ],
                provider_ids: vec![provider.id.clone()],
                required_denominator_digest: None,
                proven_inapplicable_reason: provider.not_applicable().then(|| {
                    "provider-not-applicable-at-freeze: selector matched nothing or host declaration absent".to_owned()
                }),
            })
            .collect();
        // Repository-declared runtime journeys / target obligations (host reads
        // them from the frozen inventory); they only add obligations.
        candidates.extend(runtime.iter().cloned());
        let profile = FrozenProfile::freeze(self.profile, PROFILE_REVISION, self.constraint)
            .map_err(|error| error.to_string())?;
        AuditAssuranceV1::freeze_for_profile(profile, target, &candidates, &declared)
            .map_err(|error| error.to_string())
    }

    /// Compact structured summary for command output.
    pub fn summary(&self, plan: &AuditPlan) -> Value {
        let frozen = plan.assurance_binding().ok().flatten();
        json!({
            "profile": self.profile.as_str(),
            "runtimeConstraint": self.constraint,
            "frozenSummary": frozen.map(|item| item.summary),
            "imports": self.import_records,
        })
    }
}

// ---------------------------------------------------------------- gate

#[derive(Debug, Clone, Args)]
pub struct GateArgs {
    /// Frozen audit run directory (plan.json, report.json, journal, receipts).
    #[arg(long)]
    pub run: PathBuf,
    /// Required claim strength. When omitted the required strength is
    /// `release` (never the run's own profile); the output always states it.
    #[arg(long, value_parser = ["pre-pr", "repository", "release"])]
    pub profile: Option<String>,
}

/// Exit codes follow the repository convention: 0 success, 1 policy/findings
/// block, 2 incomplete, 5 integrity failure.
///
/// The verdict is rebuilt from verified evidence (signed plan, finalized
/// journal, signed provider receipts); `report.json` claims are cross-checked,
/// never trusted. Unsigned assurance plans are refused, and filtered runs are
/// incomplete for every profile.
pub fn gate(args: GateArgs) -> CommandResult {
    let run = std::fs::canonicalize(&args.run)
        .map_err(|error| CommandError::incomplete(format!("{}: {error}", args.run.display())))?;
    let required = args
        .profile
        .as_deref()
        .map(|name| {
            AuditProfile::parse(name)
                .ok_or_else(|| CommandError::usage(format!("unknown --profile `{name}`")))
        })
        .transpose()?;
    let decision = gate_run(&run, required, &now_rfc3339_utc()).map_err(|error| match error {
        RunGateError::Incomplete(message) => CommandError::incomplete(message),
        RunGateError::Integrity(message) => CommandError::integrity(message),
    })?;
    let (label, code) = match decision.verdict {
        GateVerdict::Eligible => ("eligible", 0),
        GateVerdict::BlockedFindings => ("blocked-findings", 1),
        GateVerdict::Incomplete => ("incomplete", 2),
    };
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-audit-gate",
        "run": run,
        "verdict": label,
        "reasons": decision.reasons,
        "requiredProfile": decision.required.as_str(),
        "requiredProfileSource": if decision.required_explicit { "explicit" } else { "default-release" },
        "frozenProfile": decision.frozen_profile.map(|profile| profile.as_str()),
        "fullScope": decision.full_scope,
        "verifiedProviders": decision.verified_providers,
        "planDigest": decision.plan_digest,
        "keyCustody": decision.key_custody,
        "registryDigest": decision.registry_digest,
        "importsCounted": false,
        "__json_exit_code": code,
    }))
}

// ---------------------------------------------------------- projections

fn cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// `report --report assurance`: projection of the saved assurance extension.
pub fn assurance_projection(
    report: &legion_contracts::ReportV2,
    format: &str,
) -> Result<String, CommandError> {
    let extension = report.assurance_extension().ok_or_else(|| {
        CommandError::incomplete(
            "report carries no auditAssuranceV1 extension (legacy profile run)",
        )
    })?;
    let assurance =
        AuditAssuranceV1::from_value(extension, &now_rfc3339_utc()).map_err(|error| {
            CommandError::incomplete(format!("invalid assurance extension: {error}"))
        })?;
    match format {
        "json" => serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "kind": "audit-assurance-projection",
            "status": report.status,
            "gaps": report.gaps,
            "assurance": extension,
        }))
        .map(|text| text + "\n")
        .map_err(super::io_error),
        _ => {
            let summary = &assurance.summary;
            let mut out = format!(
                "## Audit assurance\n\nProfile: {} (revision {}), runtime constraint: {:?}\n\nCompletion: {:?}; findings: {:?}; release eligibility: {:?}\n\n",
                assurance.profile.profile.as_str(),
                assurance.profile.revision,
                assurance.runtime_constraint,
                summary.completion,
                summary.finding_outcome,
                summary.release_eligibility,
            );
            out.push_str(&format!(
                "Total {}, satisfied {}, findings {}, unmet {}, deferred {}, waived {}, inapplicable {}\n\n",
                summary.total, summary.satisfied, summary.findings, summary.unmet,
                summary.deferred, summary.waived, summary.inapplicable
            ));
            out.push_str("| Target | Concern | Evidence | Status | Reason |\n| --- | --- | --- | --- | --- |\n");
            for item in &assurance.obligations {
                out.push_str(&format!(
                    "| {} | {} | {:?} | {:?} | {} |\n",
                    cell(&item.id.target),
                    cell(&item.id.concern),
                    item.id.evidence_kind,
                    item.status,
                    cell(item.reason.as_deref().unwrap_or("")),
                ));
            }
            Ok(out)
        }
    }
}

/// Resolve the repository root for store-backed projections: a directory
/// argument is the root; a report file names it through `targets[0]`.
pub fn store_root(path: &Path) -> Result<PathBuf, CommandError> {
    let meta = std::fs::metadata(path).map_err(|error| {
        CommandError::internal(format!(
            "Error: ENOENT: no such file or directory, open '{}' ({error})",
            path.display()
        ))
    })?;
    if meta.is_dir() {
        return Ok(path.to_path_buf());
    }
    let value: Value = serde_json::from_slice(&std::fs::read(path).map_err(super::io_error)?)
        .map_err(|error| CommandError::usage(format!("invalid report: {error}")))?;
    let view = legion_contracts::Report::read_any(&value)
        .map_err(|error| CommandError::usage(format!("invalid report: {error}")))?;
    view.targets
        .first()
        .map(PathBuf::from)
        .filter(|root| root.is_dir())
        .ok_or_else(|| {
            CommandError::usage("report names no repository directory; pass the repository root")
        })
}

fn mtime_rfc3339(path: &Path) -> Option<String> {
    let secs = std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(rfc3339_from_secs(secs))
}

/// `report --report trend`: cohort-aware comparison over the saved report
/// store. Order is by report file modification time (reports carry no clock);
/// that basis is stated in the output.
pub fn trend_projection(root: &Path, format: &str) -> Result<String, CommandError> {
    use legion_report::trend::{build, render_markdown, to_value, Cohort, TrendPoint};
    let (index, _) = legion_audit::finding_history::load_or_rebuild(root)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let dir = root.join(".audit/state/reports");
    let mut rows: Vec<(Option<String>, TrendPoint)> = Vec::new();
    for indexed in &index.reports {
        let path = dir.join(&indexed.file);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let Ok(view) = legion_contracts::Report::read_any(&value) else {
            continue;
        };
        let assurance = view
            .assurance_extension()
            .and_then(|ext| AuditAssuranceV1::from_value(ext, &now_rfc3339_utc()).ok());
        let at = mtime_rfc3339(&path);
        let mut point = TrendPoint {
            run_id: serde_json::to_value(&view.report_id)
                .ok()
                .and_then(|id| id.as_str().map(str::to_owned))
                .unwrap_or_else(|| indexed.report_digest.clone()),
            at: at.clone(),
            cohort: Cohort {
                scope_digest: legion_audit::digest(&view.scope).ok(),
                ..Cohort::default()
            },
            open_findings: Some(view.findings.len() as u64),
            complete: indexed.baseline_eligible,
            ..TrendPoint::default()
        };
        if let Some(item) = assurance {
            let summary = &item.summary;
            point.cohort.profile = Some(item.profile.profile.as_str().to_owned());
            point.cohort.targets_digest = legion_audit::digest(&item.product_target).ok();
            point.cohort.rules_digest = Some(item.profile.revision.clone());
            point.denominator = Some(summary.total);
            point.examined = Some(summary.satisfied + summary.findings);
            point.excluded = Some(summary.inapplicable);
            point.unknown = Some(summary.unmet + summary.deferred + summary.waived);
        }
        rows.push((at, point));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.run_id.cmp(&b.1.run_id)));
    let trend = build(rows.into_iter().map(|(_, point)| point).collect());
    match format {
        "json" => {
            let mut value = to_value(&trend);
            if let Some(object) = value.as_object_mut() {
                object.insert("order".into(), json!("report-file-modification-time"));
            }
            serde_json::to_string_pretty(&value)
                .map(|text| text + "\n")
                .map_err(super::io_error)
        }
        _ => Ok(render_markdown(&trend)),
    }
}

/// `report --report debt`: marker/suppression debt harvested from the
/// repository inventory. No history ledger is read, so ages stay unknown.
pub fn debt_projection(root: &Path, format: &str) -> Result<String, CommandError> {
    use legion_audit::{debt, InventorySource as _};
    let source = super::audit_inventory_source(root)?;
    let inventory = source
        .inventory(&root.to_string_lossy())
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let now = now_rfc3339_utc();
    let mut records = Vec::new();
    for path in inventory.paths() {
        let full = root.join(path);
        let Ok(meta) = std::fs::metadata(&full) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_INPUT_BYTES * 4 {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&full) {
            records.extend(debt::harvest(path, &text));
        }
    }
    let rows: Vec<Value> = records
        .iter()
        .map(|record| {
            json!({
                "record": record,
                "assessment": debt::assess(record, &now, debt::DebtPolicy::default()),
            })
        })
        .collect();
    match format {
        "json" => serde_json::to_string_pretty(&json!({
            "schemaVersion": debt::DEBT_SCHEMA_VERSION,
            "kind": "audit-debt-projection",
            "ageBasis": "unknown: no first-seen ledger supplied",
            "count": rows.len(),
            "items": rows,
        }))
        .map(|text| text + "\n")
        .map_err(super::io_error),
        _ => {
            let mut out = format!(
                "## Audit debt\n\n{} item(s). Ages are unknown without a first-seen ledger.\n\n| Path | Line | Kind | Token | Accepted | Advisories |\n| --- | --- | --- | --- | --- | --- |\n",
                records.len()
            );
            for record in &records {
                let assessment = debt::assess(record, &now, debt::DebtPolicy::default());
                out.push_str(&format!(
                    "| {} | {} | {:?} | {} | {} | {} |\n",
                    cell(&record.path),
                    record.line,
                    record.kind,
                    cell(&record.token),
                    record.accepted,
                    cell(&assessment.advisories.join(", ")),
                ));
            }
            Ok(out)
        }
    }
}

// --------------------------------------------------------------- time

pub fn now_rfc3339_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_from_secs(secs)
}

fn rfc3339_from_secs(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let rem = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_instants() {
        assert_eq!(rfc3339_from_secs(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_secs(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn legacy_profile_rejects_assurance_flags_and_stays_legacy_otherwise() {
        assert!(request("standard", &AssuranceArgs::default())
            .unwrap()
            .is_none());
        // A typo or wrong-case name is never a silent legacy fallback.
        for bad in ["releaes", "Release", "", "pre_pr"] {
            assert_eq!(request(bad, &AssuranceArgs::default()).unwrap_err().code, 4);
        }
        assert_eq!(DEFAULT_PROFILE, "repository");
        let args = AssuranceArgs {
            runtime_policy: Some("no-node-python".into()),
            ..AssuranceArgs::default()
        };
        assert_eq!(request("standard", &args).unwrap_err().code, 4);
        let new = request("release", &args).unwrap().unwrap();
        assert_eq!(new.profile, AuditProfile::Release);
        assert_eq!(new.constraint, RuntimeConstraint::NoNodePython);
    }

    #[test]
    fn manifest_paths_must_stay_inside_the_manifest_directory() {
        let base = Path::new("/tmp/m");
        assert!(contained(base, "a/b.bin").is_ok());
        assert!(contained(base, "../x").is_err());
        assert!(contained(base, "/etc/passwd").is_err());
        assert!(contained(base, "").is_err());
    }

    #[test]
    fn gate_on_missing_run_is_incomplete_not_success() {
        let error = gate(GateArgs {
            run: PathBuf::from("/nonexistent-legion-gate-run"),
            profile: None,
        })
        .unwrap_err();
        assert_eq!(error.code, 2);
    }
}
