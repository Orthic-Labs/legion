//! Context-aware finding history (A15).
//!
//! Layers assurance dispositions over the existing `p12_pipeline::store`
//! lifecycle; it is not a second finding ledger. The legacy `status`
//! (`open|resolved|dismissed|superseded`) is never rewritten here. A record
//! gains an additive `assurance` object ([`assurance_patch`]) that callers
//! merge into the record they hand to `FindingStore::upsert`.
//!
//! Invariants enforced by [`reconcile`]:
//!
//! * Verified-fixed needs valid [`ResolutionEvidence`] bound to a complete
//!   run plus a regression condition. Absence of the finding, a removed TODO,
//!   a deleted symbol, a removed scanner or a legacy `resolved`/`dismissed`
//!   status never proves repair.
//! * A relocation is lineage only: it yields `UnresolvedLocation`, never
//!   resolution or a re-confirmed position.
//! * Reuse of a prior result requires an unchanged [`ReuseKey`]; unknown
//!   dependency closure, stale advisory data or a changed rule revision force
//!   `NeedsRevalidation`. Reused and executed results stay distinguishable.
//! * Findings outside a run's covered scope, or in an incomplete run, are
//!   preserved unchanged (a narrow clean diff run closes nothing).
//! * Findings are matched by stable id only; shared symbol names never merge.
//!
//! The derived history index is rebuildable from immutable completed reports
//! under `.audit/state/reports`; reports are read, never rewritten.

use crate::dependency_inventory::DependencyInventory;
use crate::domain_contract::{BindingStatus, DomainContextBinding, DomainContractSet};
use crate::p12_pipeline::sha256_value;
use crate::AuditError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const HISTORY_INDEX_SCHEMA_VERSION: u32 = 1;
const INDEX_DIR: &str = ".audit/audit";
const INDEX_FILE: &str = "finding-history-index.json";
const REPORTS_DIR: &str = ".audit/state/reports";
const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> AuditError {
    AuditError::Invalid(message.into())
}

// ------------------------------------------------------------ dispositions

/// Assurance disposition layered over the legacy status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    New,
    Open,
    VerifiedFixed,
    UnresolvedLocation,
    NeedsRevalidation,
}

/// How the current disposition was obtained. `Reused` is never `Executed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Basis {
    Executed,
    Reused,
    /// The run did not examine this finding; the prior state was carried.
    NotExamined,
}

/// Authority context from the legacy lifecycle. Never implies repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Standing {
    Active,
    /// Legacy `resolved` without matching resolution evidence.
    LegacyResolvedUnverified,
    /// Dismissed / accepted risk by an authority; not a repair.
    Dismissed,
    Superseded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Dismissal {
    pub authority: String,
    pub reason: String,
    pub at: Option<String>,
}

// ------------------------------------------------------------- reuse key

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClosureState {
    #[default]
    NotApplicable,
    Known,
    Unknown,
}

/// Everything a prior result depended on. Any difference invalidates reuse.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReuseKey {
    pub rule_id: String,
    pub rule_revision: String,
    pub profile: Option<String>,
    pub target_digest: Option<String>,
    /// Relevant source files: path -> content digest.
    pub source_digests: BTreeMap<String, String>,
    /// Callers/consumers of the finding site: path -> content digest.
    pub caller_digests: BTreeMap<String, String>,
    pub config_digest: Option<String>,
    pub contract_set_digest: Option<String>,
    pub contract_scoped_digest: Option<String>,
    pub domain_binding: Option<DomainContextBinding>,
    pub dependency_graph_digest: Option<String>,
    pub dependency_source_digest: Option<String>,
    pub dependency_metadata_digest: Option<String>,
    /// `current` is the only freshness that permits reuse.
    pub advisory_freshness: Option<String>,
    pub registry_freshness: Option<String>,
    pub dependency_closure: ClosureState,
}

impl ReuseKey {
    /// Binds the dependency digests/freshness of a frozen inventory.
    pub fn bind_dependencies(&mut self, inventory: &DependencyInventory) {
        self.dependency_graph_digest = Some(inventory.graph_digest.clone());
        self.dependency_source_digest = Some(inventory.source_digest.clone());
        self.dependency_metadata_digest = inventory.metadata_digest.clone();
        self.advisory_freshness = Some(inventory.freshness.advisory.label().to_owned());
        self.registry_freshness = Some(inventory.freshness.registry.label().to_owned());
        self.dependency_closure = if inventory.complete {
            ClosureState::Known
        } else {
            ClosureState::Unknown
        };
    }

    /// Binds the domain contract set and the digest scoped to `term_ids`.
    pub fn bind_domain(&mut self, set: &DomainContractSet, term_ids: &[String]) {
        self.contract_set_digest = Some(set.set_digest.clone());
        self.contract_scoped_digest = Some(set.scoped_digest(term_ids));
        self.domain_binding = Some(set.binding());
    }
}

fn opt_changed(label: &str, a: &Option<String>, b: &Option<String>, out: &mut Vec<String>) {
    if a != b {
        out.push(format!("{label} changed"));
    }
}

fn map_changed(
    label: &str,
    a: &BTreeMap<String, String>,
    b: &BTreeMap<String, String>,
    out: &mut Vec<String>,
) {
    if a != b {
        let keys: BTreeSet<&String> = a
            .keys()
            .chain(b.keys())
            .filter(|k| a.get(*k) != b.get(*k))
            .collect();
        let shown: Vec<&str> = keys.iter().take(5).map(|k| k.as_str()).collect();
        out.push(format!("{label} changed: {}", shown.join(", ")));
    }
}

/// Why `prior` may not be reused for `current`. Empty means reusable.
pub fn invalidation_reasons(
    prior: &ReuseKey,
    current: &ReuseKey,
    current_domain: Option<&DomainContractSet>,
) -> Vec<String> {
    let mut out = Vec::new();
    if prior.rule_id != current.rule_id {
        out.push("rule id changed".into());
    }
    if prior.rule_revision != current.rule_revision {
        out.push("rule revision changed".into());
    }
    opt_changed("profile", &prior.profile, &current.profile, &mut out);
    opt_changed("target", &prior.target_digest, &current.target_digest, &mut out);
    map_changed("source", &prior.source_digests, &current.source_digests, &mut out);
    map_changed("caller", &prior.caller_digests, &current.caller_digests, &mut out);
    opt_changed("config", &prior.config_digest, &current.config_digest, &mut out);
    opt_changed(
        "contract set",
        &prior.contract_set_digest,
        &current.contract_set_digest,
        &mut out,
    );
    opt_changed(
        "contract scoped term",
        &prior.contract_scoped_digest,
        &current.contract_scoped_digest,
        &mut out,
    );
    if let Some(binding) = &prior.domain_binding {
        match current_domain {
            None => out.push("domain contract set unavailable".into()),
            Some(set) => {
                if let BindingStatus::Invalidated { reasons } = binding.verify_against(set) {
                    out.extend(reasons.into_iter().map(|r| format!("domain contract: {r}")));
                }
            }
        }
    }
    let dependent = prior.dependency_closure != ClosureState::NotApplicable
        || current.dependency_closure != ClosureState::NotApplicable
        || prior.dependency_graph_digest.is_some()
        || current.dependency_graph_digest.is_some();
    if dependent {
        if prior.dependency_closure != ClosureState::Known
            || current.dependency_closure != ClosureState::Known
        {
            out.push("dependency closure unknown".into());
        }
        opt_changed(
            "dependency graph",
            &prior.dependency_graph_digest,
            &current.dependency_graph_digest,
            &mut out,
        );
        opt_changed(
            "dependency source",
            &prior.dependency_source_digest,
            &current.dependency_source_digest,
            &mut out,
        );
        opt_changed(
            "dependency metadata",
            &prior.dependency_metadata_digest,
            &current.dependency_metadata_digest,
            &mut out,
        );
        for (label, freshness) in [
            ("advisory", &current.advisory_freshness),
            ("registry", &current.registry_freshness),
        ] {
            if freshness.as_deref() != Some("current") {
                out.push(format!("{label} data not current"));
            }
        }
        opt_changed(
            "advisory freshness",
            &prior.advisory_freshness,
            &current.advisory_freshness,
            &mut out,
        );
    }
    out
}

// -------------------------------------------------------- resolution proof

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionKind {
    /// The same rule, same revision, re-executed over the finding's site.
    RuleRerunClean,
    RegressionTestPasses,
    /// Repair accepted by a named reviewer.
    ReviewedRepair,
}

/// Accepted proof that a finding was repaired. Deleting the flagged text,
/// symbol or scanner is not evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionEvidence {
    pub finding_id: String,
    pub kind: ResolutionKind,
    /// Digest of the completed report that carries this evidence.
    pub report_digest: String,
    pub rule_id: String,
    pub rule_revision: String,
    /// What would reintroduce the defect (test name, rule, assertion).
    pub regression_condition: String,
    pub accepted_by: Option<String>,
    pub evidence_digest: String,
}

fn sha256_ref(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

impl ResolutionEvidence {
    /// Err names the first reason this evidence cannot verify a fix.
    pub fn validate(&self, prior: &PriorFinding, run: &RunView) -> Result<(), String> {
        if self.finding_id != prior.id {
            return Err("evidence is for a different finding".into());
        }
        if !run.complete {
            return Err("run incomplete".into());
        }
        if !sha256_ref(&self.report_digest) || self.report_digest != run.report_digest {
            return Err("evidence not bound to this completed report".into());
        }
        if !sha256_ref(&self.evidence_digest) {
            return Err("evidence digest missing".into());
        }
        if self.regression_condition.trim().is_empty() {
            return Err("regression condition missing".into());
        }
        if self.rule_id != prior.rule_id {
            return Err("evidence rule differs from finding rule".into());
        }
        if self.kind == ResolutionKind::RuleRerunClean
            && run.executed_rules.get(&self.rule_id) != Some(&self.rule_revision)
        {
            return Err("rule was not executed at the evidence revision".into());
        }
        if self.kind == ResolutionKind::ReviewedRepair
            && self.accepted_by.as_deref().map_or(true, |a| a.trim().is_empty())
        {
            return Err("reviewed repair has no accepting reviewer".into());
        }
        Ok(())
    }
}

// ------------------------------------------------------------ inputs/outputs

/// Prior state of one finding, derived from a `FindingStore` record plus its
/// additive `assurance` object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorFinding {
    pub id: String,
    pub rule_id: String,
    pub rule_revision: String,
    pub path: String,
    /// Legacy store status, unchanged.
    pub legacy_status: String,
    pub disposition: Option<Disposition>,
    pub reuse_key: Option<ReuseKey>,
    pub dismissal: Option<Dismissal>,
    pub superseded_by: Option<String>,
}

impl PriorFinding {
    /// Reads a store record. Returns `None` when mandatory fields are absent.
    pub fn from_record(record: &Value) -> Option<Self> {
        let text = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_owned);
        let provenance = record.get("provenance")?;
        let assurance = record.get("assurance");
        Some(Self {
            id: text(record.get("id")).filter(|s| !s.is_empty())?,
            rule_id: text(provenance.get("ruleId"))?,
            rule_revision: text(provenance.get("version")).unwrap_or_default(),
            path: text(record.get("evidenceLoci")?.get(0)?.get("path"))?,
            legacy_status: text(record.get("status"))?,
            disposition: assurance
                .and_then(|a| a.get("disposition"))
                .and_then(|d| serde_json::from_value(d.clone()).ok()),
            reuse_key: assurance
                .and_then(|a| a.get("reuseKey"))
                .and_then(|k| serde_json::from_value(k.clone()).ok()),
            dismissal: record
                .get("dismissal")
                .and_then(|d| serde_json::from_value(d.clone()).ok()),
            superseded_by: text(record.get("supersededBy")),
        })
    }
}

/// What the latest run actually examined and produced. Callers build this
/// from a validated completed report; an incomplete run sets `complete=false`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RunView {
    pub report_digest: String,
    pub complete: bool,
    /// Rules that really executed: rule id -> revision.
    pub executed_rules: BTreeMap<String, String>,
    /// Files the run examined (normalized `/` paths).
    pub covered_paths: BTreeSet<String>,
    /// Stable ids emitted by this run (executed or reused).
    pub present: BTreeSet<String>,
    /// Subset of `present` carried from cache instead of executed.
    pub reused: BTreeSet<String>,
    /// id -> lineage candidate digest for relocated findings.
    pub relocated: BTreeMap<String, String>,
    /// Ids whose file/symbol no longer exists in the examined source.
    pub missing_symbols: BTreeSet<String>,
    /// Current reuse key per id, for reuse validation.
    pub reuse_keys: BTreeMap<String, ReuseKey>,
    pub evidence: BTreeMap<String, ResolutionEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub id: String,
    pub disposition: Disposition,
    pub basis: Basis,
    pub standing: Standing,
    pub reasons: Vec<String>,
}

impl Assessment {
    pub fn verified_fixed(&self) -> bool {
        self.disposition == Disposition::VerifiedFixed
    }
}

fn norm(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches('/').to_owned()
}

fn standing_of(prior: &PriorFinding) -> Standing {
    if prior.dismissal.is_some() || prior.legacy_status == "dismissed" {
        Standing::Dismissed
    } else if prior.legacy_status == "superseded" || prior.superseded_by.is_some() {
        Standing::Superseded
    } else if prior.legacy_status == "resolved"
        && prior.disposition != Some(Disposition::VerifiedFixed)
    {
        Standing::LegacyResolvedUnverified
    } else {
        Standing::Active
    }
}

/// Carries a prior state when the run did not examine the finding.
fn preserved(prior: &PriorFinding, standing: Standing) -> Disposition {
    match prior.disposition {
        Some(Disposition::New) => Disposition::Open,
        Some(d) => d,
        None if standing == Standing::LegacyResolvedUnverified => Disposition::NeedsRevalidation,
        None => Disposition::Open,
    }
}

/// Reconciles prior findings with the latest run. Output is sorted by id and
/// contains one entry per prior plus one `New` per unmatched present id.
pub fn reconcile(
    priors: &[PriorFinding],
    run: &RunView,
    domain: Option<&DomainContractSet>,
) -> Result<Vec<Assessment>, AuditError> {
    let mut seen = BTreeSet::new();
    for prior in priors {
        if !seen.insert(prior.id.as_str()) {
            return Err(invalid(format!("duplicate prior finding id: {}", prior.id)));
        }
    }
    let mut out = Vec::with_capacity(priors.len());
    for prior in priors {
        out.push(assess(prior, run, domain));
    }
    for id in &run.present {
        if !seen.contains(id.as_str()) {
            out.push(Assessment {
                id: id.clone(),
                disposition: Disposition::New,
                basis: Basis::Executed,
                standing: Standing::Active,
                reasons: vec!["first observed".into()],
            });
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn assess(prior: &PriorFinding, run: &RunView, domain: Option<&DomainContractSet>) -> Assessment {
    let standing = standing_of(prior);
    let mut reasons: Vec<String> = Vec::new();
    let result = |disposition, basis, standing, reasons| Assessment {
        id: prior.id.clone(),
        disposition,
        basis,
        standing,
        reasons,
    };
    if standing == Standing::Dismissed {
        reasons.push("dismissed by authority; not a repair".into());
    } else if standing == Standing::LegacyResolvedUnverified {
        reasons.push("legacy resolved status has no verified-fix evidence".into());
    }

    // 1. Still reported by this run.
    if run.present.contains(&prior.id) {
        if prior.disposition == Some(Disposition::VerifiedFixed) {
            reasons.push("previously verified fixed; regressed".into());
        }
        if run.reused.contains(&prior.id) {
            let invalid_reasons = match (&prior.reuse_key, run.reuse_keys.get(&prior.id)) {
                (Some(old), Some(new)) => invalidation_reasons(old, new, domain),
                _ => vec!["reuse key unavailable".into()],
            };
            if !invalid_reasons.is_empty() {
                reasons.extend(invalid_reasons);
                return result(Disposition::NeedsRevalidation, Basis::Reused, standing, reasons);
            }
            return result(Disposition::Open, Basis::Reused, standing, reasons);
        }
        return result(Disposition::Open, Basis::Executed, standing, reasons);
    }

    // 2. Relocated: lineage candidate only.
    if let Some(candidate) = run.relocated.get(&prior.id) {
        reasons.push(format!(
            "relocation candidate {candidate} is lineage only; not re-verified"
        ));
        return result(Disposition::UnresolvedLocation, Basis::Executed, standing, reasons);
    }

    // 3. Symbol/file gone: never a closure.
    if run.missing_symbols.contains(&prior.id) {
        reasons.push("symbol or file no longer present; removal is not resolution".into());
        return result(Disposition::UnresolvedLocation, Basis::Executed, standing, reasons);
    }

    // 4. Absent: was it genuinely examined?
    if !run.complete {
        reasons.push("latest run incomplete; prior state carried".into());
        return result(preserved(prior, standing), Basis::NotExamined, standing, reasons);
    }
    let Some(executed_revision) = run.executed_rules.get(&prior.rule_id) else {
        reasons.push("rule or scanner did not run; absence proves nothing".into());
        return result(preserved(prior, standing), Basis::NotExamined, standing, reasons);
    };
    if !run.covered_paths.contains(&norm(&prior.path)) {
        reasons.push("finding site outside this run's scope; prior state carried".into());
        return result(preserved(prior, standing), Basis::NotExamined, standing, reasons);
    }
    if *executed_revision != prior.rule_revision {
        reasons.push("rule revision changed since the finding was recorded".into());
        return result(Disposition::NeedsRevalidation, Basis::Executed, standing, reasons);
    }
    match run.evidence.get(&prior.id) {
        Some(evidence) => match evidence.validate(prior, run) {
            Ok(()) => {
                let standing = if standing == Standing::LegacyResolvedUnverified {
                    Standing::Active
                } else {
                    standing
                };
                reasons.retain(|r| !r.starts_with("legacy resolved"));
                reasons.push("verified by accepted resolution evidence".into());
                result(Disposition::VerifiedFixed, Basis::Executed, standing, reasons)
            }
            Err(why) => {
                reasons.push(format!("resolution evidence rejected: {why}"));
                result(Disposition::NeedsRevalidation, Basis::Executed, standing, reasons)
            }
        },
        None => {
            reasons.push("absent without resolution evidence or regression condition".into());
            result(Disposition::NeedsRevalidation, Basis::Executed, standing, reasons)
        }
    }
}

/// Additive object to merge into a store record before
/// `FindingStore::upsert`. Never touches the legacy `status`.
pub fn assurance_patch(assessment: &Assessment, reuse_key: Option<&ReuseKey>) -> Value {
    json!({
        "assurance": {
            "disposition": assessment.disposition,
            "basis": assessment.basis,
            "standing": assessment.standing,
            "reasons": assessment.reasons,
            "reuseKey": reuse_key,
        }
    })
}

/// The only legacy transition an assessment may suggest: `resolved` for a
/// verified fix. Everything else returns `None` (status is left as is).
pub fn suggested_legacy_status(assessment: &Assessment) -> Option<&'static str> {
    assessment.verified_fixed().then_some("resolved")
}

// ------------------------------------------------------------------ index

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedReport {
    pub file: String,
    pub size: u64,
    pub report_digest: String,
    pub status: String,
    /// Completed clean/findings report without gaps; the only baseline form.
    pub baseline_eligible: bool,
    pub finding_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RejectedReport {
    pub file: String,
    pub size: u64,
    pub reason: String,
}

/// Derived, rebuildable index of completed-run lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryIndex {
    pub schema_version: u32,
    pub reports: Vec<IndexedReport>,
    pub rejected: Vec<RejectedReport>,
    pub index_digest: String,
}

impl HistoryIndex {
    fn seal(reports: Vec<IndexedReport>, rejected: Vec<RejectedReport>) -> Self {
        let mut index = Self {
            schema_version: HISTORY_INDEX_SCHEMA_VERSION,
            reports,
            rejected,
            index_digest: String::new(),
        };
        index.index_digest = index.compute_digest();
        index
    }

    fn compute_digest(&self) -> String {
        sha256_value(&json!({
            "schemaVersion": self.schema_version,
            "reports": self.reports,
            "rejected": self.rejected,
        }))
    }

    /// Latest-first view is the caller's; this returns eligible reports in
    /// directory (digest-name) order.
    pub fn baselines(&self) -> impl Iterator<Item = &IndexedReport> {
        self.reports.iter().filter(|r| r.baseline_eligible)
    }
}

fn classify(file: &str, bytes: &[u8]) -> Result<IndexedReport, String> {
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    let expected = file.trim_end_matches(".json");
    if digest.trim_start_matches("sha256:") != expected {
        return Err("content digest does not match file name".into());
    }
    let report: Value = serde_json::from_slice(bytes).map_err(|_| "not valid JSON".to_owned())?;
    let status = report
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| "report status missing".to_owned())?
        .to_owned();
    let gaps = report
        .get("gaps")
        .and_then(Value::as_array)
        .map(|g| g.len())
        .ok_or_else(|| "report gaps missing".to_owned())?;
    let mut ids: Vec<String> = report
        .get("findings")
        .and_then(Value::as_array)
        .ok_or_else(|| "report findings missing".to_owned())?
        .iter()
        .filter_map(|f| f.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    ids.sort();
    ids.dedup();
    Ok(IndexedReport {
        file: file.to_owned(),
        size: bytes.len() as u64,
        report_digest: digest,
        baseline_eligible: matches!(status.as_str(), "clean" | "findings") && gaps == 0,
        status,
        finding_ids: ids,
    })
}

fn report_files(root: &Path) -> Result<Vec<(String, u64)>, AuditError> {
    let dir = root.join(REPORTS_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(invalid(error.to_string())),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| invalid(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") {
            continue;
        }
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| invalid(e.to_string()))?;
        if !meta.is_file() {
            // Symlinks and directories are not immutable report copies.
            files.push((name, u64::MAX));
            continue;
        }
        files.push((name, meta.len()));
    }
    files.sort();
    Ok(files)
}

/// Rebuilds the index from immutable reports. Reports that fail digest,
/// shape or size checks are listed as rejected and never become baselines.
pub fn rebuild_index(root: &Path) -> Result<HistoryIndex, AuditError> {
    let dir = root.join(REPORTS_DIR);
    let mut reports = Vec::new();
    let mut rejected = Vec::new();
    for (file, size) in report_files(root)? {
        let reject = |reason: &str| RejectedReport {
            file: file.clone(),
            size,
            reason: reason.to_owned(),
        };
        if size == u64::MAX {
            rejected.push(reject("not a regular file"));
            continue;
        }
        if size > MAX_REPORT_BYTES {
            rejected.push(reject("report exceeds size bound"));
            continue;
        }
        let bytes = match std::fs::read(dir.join(&file)) {
            Ok(bytes) => bytes,
            Err(error) => {
                rejected.push(reject(&error.to_string()));
                continue;
            }
        };
        match classify(&file, &bytes) {
            Ok(report) => reports.push(report),
            Err(reason) => rejected.push(reject(&reason)),
        }
    }
    Ok(HistoryIndex::seal(reports, rejected))
}

fn index_matches_reports(index: &HistoryIndex, files: &[(String, u64)]) -> bool {
    if index.schema_version != HISTORY_INDEX_SCHEMA_VERSION
        || index.index_digest != index.compute_digest()
    {
        return false;
    }
    let mut known: Vec<(String, u64)> = index
        .reports
        .iter()
        .map(|r| (r.file.clone(), r.size))
        .chain(index.rejected.iter().map(|r| (r.file.clone(), r.size)))
        .collect();
    known.sort();
    known == files
}

/// Returns the cached index when it is intact and still describes exactly the
/// reports on disk; otherwise rebuilds and atomically replaces the derived
/// file under a lock. Reports are never written. The bool is `true` on rebuild.
pub fn load_or_rebuild(root: &Path) -> Result<(HistoryIndex, bool), AuditError> {
    let files = report_files(root)?;
    let path = root.join(INDEX_DIR).join(INDEX_FILE);
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(index) = serde_json::from_slice::<HistoryIndex>(&bytes) {
            if index_matches_reports(&index, &files) {
                return Ok((index, false));
            }
        }
    }
    let dir = root.join(INDEX_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| invalid(e.to_string()))?;
    let _writer = rightkit_fs::FileLock::acquire(
        &dir.join("finding-history.lock"),
        &rightkit_fs::LockOptions::default().labeled("audit-finding-history-index"),
    )
    .map_err(|e| invalid(e.to_string()))?;
    let index = rebuild_index(root)?;
    let bytes = serde_json::to_vec(&index).map_err(|e| invalid(e.to_string()))?;
    rightkit_fs::state::StateDir::create(&dir)
        .map_err(|e| invalid(e.to_string()))?
        .write(INDEX_FILE, &bytes)
        .map_err(|e| invalid(e.to_string()))?;
    Ok((index, true))
}
