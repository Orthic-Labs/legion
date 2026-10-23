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
    opt_changed(
        "target",
        &prior.target_digest,
        &current.target_digest,
        &mut out,
    );
    map_changed(
        "source",
        &prior.source_digests,
        &current.source_digests,
        &mut out,
    );
    map_changed(
        "caller",
        &prior.caller_digests,
        &current.caller_digests,
        &mut out,
    );
    opt_changed(
        "config",
        &prior.config_digest,
        &current.config_digest,
        &mut out,
    );
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
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
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
        if self.kind == ResolutionKind::ReviewedRepair {
            let reviewer = self.accepted_by.as_deref().map(str::trim).unwrap_or("");
            if reviewer.is_empty() {
                return Err("reviewed repair has no accepting reviewer".into());
            }
            let folded = reviewer.to_lowercase();
            if run
                .producers
                .iter()
                .any(|p| p.trim().to_lowercase() == folded)
            {
                return Err("reviewer must be distinct from the run producer".into());
            }
            if !run.vouched_artifacts.contains(&self.evidence_digest) {
                return Err(
                    "reviewed repair evidence digest does not refer to an artifact of the verified run"
                        .into(),
                );
            }
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
    /// True only for a view built by [`verified_run_view`] from a run that
    /// passed the journal, signature and receipt checks of the gate.
    pub verified: bool,
    /// Identities that produced the run (run id, plan key id, machine actors);
    /// a reviewer must be none of them.
    pub producers: BTreeSet<String>,
    /// Digests of artifacts the verified journal vouches for (receipts and
    /// the finalized report); `ReviewedRepair` evidence must name one.
    pub vouched_artifacts: BTreeSet<String>,
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
                return result(
                    Disposition::NeedsRevalidation,
                    Basis::Reused,
                    standing,
                    reasons,
                );
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
        return result(
            Disposition::UnresolvedLocation,
            Basis::Executed,
            standing,
            reasons,
        );
    }

    // 3. Symbol/file gone: never a closure.
    if run.missing_symbols.contains(&prior.id) {
        reasons.push("symbol or file no longer present; removal is not resolution".into());
        return result(
            Disposition::UnresolvedLocation,
            Basis::Executed,
            standing,
            reasons,
        );
    }

    // 4. Absent: was it genuinely examined?
    if !run.complete {
        reasons.push("latest run incomplete; prior state carried".into());
        return result(
            preserved(prior, standing),
            Basis::NotExamined,
            standing,
            reasons,
        );
    }
    let Some(executed_revision) = run.executed_rules.get(&prior.rule_id) else {
        reasons.push("rule or scanner did not run; absence proves nothing".into());
        return result(
            preserved(prior, standing),
            Basis::NotExamined,
            standing,
            reasons,
        );
    };
    if !run.covered_paths.contains(&norm(&prior.path)) {
        reasons.push("finding site outside this run's scope; prior state carried".into());
        return result(
            preserved(prior, standing),
            Basis::NotExamined,
            standing,
            reasons,
        );
    }
    if *executed_revision != prior.rule_revision {
        reasons.push("rule revision changed since the finding was recorded".into());
        return result(
            Disposition::NeedsRevalidation,
            Basis::Executed,
            standing,
            reasons,
        );
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
                result(
                    Disposition::VerifiedFixed,
                    Basis::Executed,
                    standing,
                    reasons,
                )
            }
            Err(why) => {
                reasons.push(format!("resolution evidence rejected: {why}"));
                result(
                    Disposition::NeedsRevalidation,
                    Basis::Executed,
                    standing,
                    reasons,
                )
            }
        },
        None => {
            reasons.push("absent without resolution evidence or regression condition".into());
            result(
                Disposition::NeedsRevalidation,
                Basis::Executed,
                standing,
                reasons,
            )
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

// ------------------------------------------------ finalization / resolution

/// Prior findings that keep a run from completing: stored findings absent
/// from the current run that no valid [`ResolutionEvidence`], dismissal
/// authority or supersession accounts for. Each entry is `(id, reason)`.
pub fn open_history_blockers(
    root: &Path,
    present_ids: &BTreeSet<String>,
    report_complete: bool,
    report_digest: &str,
) -> Result<Vec<(String, String)>, AuditError> {
    let store = crate::p12_pipeline::store::FindingStore::new(root);
    let records = store.load().map_err(|error| invalid(error.to_string()))?;
    let mut priors = Vec::new();
    let mut blockers = Vec::new();
    for record in &records {
        match PriorFinding::from_record(record) {
            Some(prior) => priors.push(prior),
            None => {
                let id = record.get("id").and_then(Value::as_str).unwrap_or("?");
                if record.get("status").and_then(Value::as_str) != Some("superseded") {
                    blockers.push((id.to_owned(), "stored record cannot be assessed".to_owned()));
                }
            }
        }
    }
    // The run view is deliberately conservative: it names no executed rules
    // and no covered paths, so absence alone can never verify a fix. Only a
    // stored, previously validated verified-fixed disposition is carried.
    let run = RunView {
        report_digest: report_digest.to_owned(),
        complete: report_complete,
        present: present_ids.clone(),
        ..RunView::default()
    };
    for assessment in reconcile(&priors, &run, None)? {
        if assessment.disposition == Disposition::New || present_ids.contains(&assessment.id) {
            continue;
        }
        let authorized_dismissal = priors.iter().any(|prior| {
            prior.id == assessment.id
                && prior
                    .dismissal
                    .as_ref()
                    .is_some_and(|d| !d.authority.trim().is_empty() && !d.reason.trim().is_empty())
        });
        let blocks = match assessment.standing {
            Standing::Dismissed => !authorized_dismissal,
            Standing::Superseded => false,
            Standing::Active | Standing::LegacyResolvedUnverified => {
                assessment.disposition != Disposition::VerifiedFixed
            }
        };
        if blocks {
            blockers.push((
                assessment.id.clone(),
                format!(
                    "{:?}: {}",
                    assessment.disposition,
                    assessment.reasons.join("; ")
                ),
            ));
        }
    }
    blockers.sort();
    blockers.dedup();
    Ok(blockers)
}

/// Applies history reconciliation to a finalized report: prior findings that
/// are not accounted for become gaps and a clean/findings report becomes
/// `incomplete`. A missing store is a no-op; an unreadable one fails closed.
pub fn apply_history_gate(
    root: &Path,
    report: &mut legion_contracts::ReportV1,
) -> Result<(), AuditError> {
    let custody = history_custody_gaps(root);
    if !custody.is_empty() {
        report.gaps.extend(custody);
        downgrade(report);
    }
    if !root
        .join(".audit")
        .join("audit")
        .join("findings.jsonl")
        .is_file()
    {
        report.gaps.sort();
        report.gaps.dedup();
        return Ok(());
    }
    let present: BTreeSet<String> = report
        .findings
        .iter()
        .map(|finding| finding.id.as_str().to_owned())
        .collect();
    let complete = matches!(
        report.status,
        legion_contracts::ReportStatus::Clean | legion_contracts::ReportStatus::Findings
    ) && report.gaps.is_empty();
    let digest = sha256_value(&json!({"id": report.report_id.as_str(), "findings": present}));
    let digest = if digest.starts_with("sha256:") {
        digest
    } else {
        format!("sha256:{digest}")
    };
    match open_history_blockers(root, &present, complete, &digest) {
        Ok(blockers) => {
            for (id, _) in &blockers {
                report.gaps.push(format!("finding-history-unresolved:{id}"));
            }
            if !blockers.is_empty() {
                downgrade(report);
            }
        }
        Err(error) => {
            report
                .gaps
                .push(format!("finding-history-unreadable:{error}"));
            downgrade(report);
        }
    }
    report.gaps.sort();
    report.gaps.dedup();
    Ok(())
}

fn downgrade(report: &mut legion_contracts::ReportV1) {
    if matches!(
        report.status,
        legion_contracts::ReportStatus::Clean | legion_contracts::ReportStatus::Findings
    ) {
        report.status = legion_contracts::ReportStatus::Incomplete;
    }
}

/// `findings resolve`/`dismiss` semantics. `verified-fixed` needs valid
/// [`ResolutionEvidence`] bound to a complete run; without evidence only a
/// dismissal with authority and reason is recorded (never a repair claim).
pub fn resolve_finding(
    store: &crate::p12_pipeline::store::FindingStore,
    id: &str,
    evidence: Option<(&ResolutionEvidence, &RunView)>,
    dismissal: Option<Dismissal>,
    generation: Option<&str>,
) -> Result<Value, AuditError> {
    let record = store
        .get(id)
        .map_err(|error| invalid(error.to_string()))?
        .ok_or_else(|| invalid(format!("unknown finding: {id}")))?;
    let prior = PriorFinding::from_record(&record)
        .ok_or_else(|| invalid("stored finding record cannot be assessed"))?;
    let mut merged = record.clone();
    let object = merged
        .as_object_mut()
        .ok_or_else(|| invalid("finding record must be an object"))?;
    let now = crate::p12_pipeline::store::utc_now();
    match (evidence, dismissal) {
        (Some((evidence, run)), _) => {
            if !run.verified {
                return Err(invalid(
                    "resolution evidence rejected: the run was not verified by the gate",
                ));
            }
            evidence.validate(&prior, run).map_err(|why| {
                invalid(format!(
                    "resolution evidence rejected: {why}; resolve requires valid evidence"
                ))
            })?;
            let assessment = Assessment {
                id: prior.id.clone(),
                disposition: Disposition::VerifiedFixed,
                basis: Basis::Executed,
                standing: Standing::Active,
                reasons: vec![format!("verified by {:?} evidence", evidence.kind)],
            };
            if let Some(patch) = assurance_patch(&assessment, prior.reuse_key.as_ref())
                .get("assurance")
                .cloned()
            {
                let mut patch = patch;
                patch["resolutionEvidence"] =
                    serde_json::to_value(evidence).map_err(|error| invalid(error.to_string()))?;
                object.insert("assurance".into(), patch);
            }
            object.insert("status".into(), json!("resolved"));
            let resolved = generation
                .map(str::to_owned)
                .or_else(|| {
                    record
                        .get("lastSeenGeneration")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_default();
            object.insert("resolvedGeneration".into(), json!(resolved));
            object.insert("resolvedAt".into(), json!(now));
        }
        (None, Some(dismissal)) => {
            if dismissal.authority.trim().is_empty() || dismissal.reason.trim().is_empty() {
                return Err(invalid(
                    "a dismissal needs an authority and a reason; without resolution evidence a finding is never resolved",
                ));
            }
            object.insert("status".into(), json!("dismissed"));
            object.insert(
                "dismissal".into(),
                serde_json::to_value(Dismissal {
                    at: dismissal.at.or_else(|| Some(now.clone())),
                    ..dismissal
                })
                .map_err(|error| invalid(error.to_string()))?,
            );
            object.insert("resolvedAt".into(), json!(now));
        }
        (None, None) => {
            return Err(invalid(
                "resolve requires ResolutionEvidence; otherwise dismiss with an authority and reason",
            ));
        }
    }
    store
        .upsert(&merged, None)
        .map_err(|error| invalid(error.to_string()))
}

/// Builds the verification [`RunView`] from a run directory that passes the
/// same verification as `legion audit gate`: signed plan, hash-chained and
/// anchored journal, signed receipts. The run must be complete, belong to
/// `repo`, and `report.json` must be the report the journal last vouched for.
/// Executed rules and covered paths stay empty: this view can validate
/// `RegressionTestPasses` and `ReviewedRepair` evidence bound to the report
/// digest, never rule-rerun absence.
pub fn verified_run_view(run: &Path, repo: &Path) -> Result<RunView, AuditError> {
    use crate::assurance::{gate_run, GateVerdict};
    use crate::journal::{
        bytes_digest, current_report_digest, verify_dir, Expectation, JournalAnchor,
    };

    let gate = gate_run(run, None, &crate::p12_pipeline::store::utc_now())
        .map_err(|error| invalid(format!("run failed gate verification: {error:?}")))?;
    if gate.verdict == GateVerdict::Incomplete {
        return Err(invalid(format!(
            "run failed gate verification: {}",
            gate.reasons.join("; ")
        )));
    }
    let read = |name: &str| -> Result<Vec<u8>, AuditError> {
        std::fs::read(run.join(name)).map_err(|e| invalid(format!("{name}: {e}")))
    };
    let outer: Value = serde_json::from_slice(&read("plan.json")?)
        .map_err(|e| invalid(format!("plan.json: {e}")))?;
    let native = outer
        .get("nativePlan")
        .ok_or_else(|| invalid("plan.json carries no nativePlan"))?;
    let plan_digest = native
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("nativePlan digest is missing"))?;
    if plan_digest != gate.plan_digest {
        return Err(invalid("plan digest differs from the gated plan"));
    }
    let planned_repo = native
        .pointer("/plan/repositoryId")
        .or_else(|| native.pointer("/plan/repository_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("run plan names no repository"))?;
    let planned_repo = std::fs::canonicalize(planned_repo)
        .map_err(|e| invalid(format!("run repository is not resolvable: {e}")))?;
    let repo = std::fs::canonicalize(repo).map_err(|e| invalid(e.to_string()))?;
    // The plan names the frozen snapshot tree; its sealed manifest (verified
    // before use) names the source repository it was captured from.
    let source_repo = match planned_repo
        .parent()
        .map(|object| object.join("manifest.json"))
        .filter(|manifest| manifest.is_file())
    {
        Some(manifest) => {
            let snapshot = crate::snapshot::FrozenSnapshot::open(&manifest)?;
            if snapshot.manifest.execution_root != planned_repo {
                return Err(invalid(
                    "run plan does not name its snapshot's execution root",
                ));
            }
            std::fs::canonicalize(&snapshot.manifest.scope.source_root)
                .map_err(|e| invalid(format!("snapshot source is not resolvable: {e}")))?
        }
        None => planned_repo,
    };
    if source_repo != repo {
        return Err(invalid("run belongs to a different repository"));
    }
    let anchor =
        JournalAnchor::read(run)?.ok_or_else(|| invalid("run has no signed journal anchor"))?;
    let verification = verify_dir(
        run,
        plan_digest,
        &Expectation {
            require_finalized: true,
            expected_head: None,
            final_plan_digest: Some(anchor.effective_plan_digest.clone()),
        },
    );
    if !verification.defects.is_empty() || verification.unsealed_tail > 0 {
        return Err(invalid("run journal is not intact"));
    }
    let report_bytes = read("report.json")?;
    let report_digest = bytes_digest(&report_bytes);
    if current_report_digest(&verification.events) != Some(report_digest.as_str()) {
        return Err(invalid(
            "report.json is not the report the run journal last vouched for",
        ));
    }
    let report: Value =
        serde_json::from_slice(&report_bytes).map_err(|e| invalid(e.to_string()))?;
    let status = report.get("status").and_then(Value::as_str).unwrap_or("");
    let gaps_empty = report
        .get("gaps")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    if !(matches!(status, "clean" | "findings") && gaps_empty) {
        return Err(invalid("run is not a complete run"));
    }
    let mut producers: BTreeSet<String> = ["legion", "audit", "system", "auto", "automation"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    if let Some(binding) = outer.get("planKey") {
        for key in ["runId", "keyId"] {
            if let Some(value) = binding.get(key).and_then(Value::as_str) {
                producers.insert(value.to_owned());
            }
        }
    }
    let vouched_artifacts = verification
        .events
        .iter()
        .map(|event| event.payload_digest.clone())
        .chain(std::iter::once(report_digest.clone()))
        .collect();
    Ok(RunView {
        report_digest,
        complete: true,
        present: report
            .get("findings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|f| f.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect(),
        verified: true,
        producers,
        vouched_artifacts,
        ..RunView::default()
    })
}

// ------------------------------------------------- host history custody

const HOST_LEDGER_DIR: &str = "audit-finding-history";
pub const GAP_STORE_MISSING: &str = "finding-history-store-missing-or-rolled-back";

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostLedger {
    schema_version: u32,
    repo_digest: String,
    store_digest: String,
    open_finding_ids: Vec<String>,
    known_finding_ids: Vec<String>,
    generation: u64,
}

fn host_ledger_path(repo: &Path) -> Result<std::path::PathBuf, AuditError> {
    let state = crate::integrity::host_plan_key_dir()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| invalid("Legion state root unavailable"))?;
    let repo = std::fs::canonicalize(repo).map_err(|e| invalid(e.to_string()))?;
    if state.starts_with(&repo) {
        return Err(invalid(
            "host state root lies inside the audited repository",
        ));
    }
    let id = hex::encode(Sha256::digest(repo.to_string_lossy().as_bytes()));
    Ok(state.join(HOST_LEDGER_DIR).join(format!("{id}.json")))
}

/// `Ok(None)` only when no ledger exists. Same hardening as the host owner
/// policy: no symlinks, regular file, owned by this user, mode 0600, private
/// parent directory.
fn load_host_ledger(path: &Path) -> Result<Option<HostLedger>, AuditError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(invalid(format!("{}: {e}", path.display()))),
        Ok(_) => {}
    }
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let uid = legion_effects::sandbox_runtime::effective_uid();
        let parent = path
            .parent()
            .ok_or_else(|| invalid("ledger has no parent"))?;
        let pm = std::fs::metadata(parent).map_err(|e| invalid(e.to_string()))?;
        if pm.mode() & 0o022 != 0 || (pm.uid() != uid && pm.uid() != 0) {
            return Err(invalid(
                "ledger directory is group/world writable or foreign-owned",
            ));
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(legion_effects::sandbox_runtime::o_nofollow())
            .open(path)
            .map_err(|e| invalid(e.to_string()))?;
        let meta = file.metadata().map_err(|e| invalid(e.to_string()))?;
        if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(invalid(
                "ledger must be a regular 0600 file owned by this user",
            ));
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(&mut file, 1 << 20), &mut bytes)
            .map_err(|e| invalid(e.to_string()))?;
        bytes
    };
    #[cfg(not(unix))]
    let bytes = std::fs::read(path).map_err(|e| invalid(e.to_string()))?;
    let ledger: HostLedger =
        serde_json::from_slice(&bytes).map_err(|e| invalid(format!("ledger: {e}")))?;
    if ledger.schema_version != 1 {
        return Err(invalid("unsupported ledger schema version"));
    }
    Ok(Some(ledger))
}

fn write_host_ledger(path: &Path, ledger: &HostLedger) -> Result<(), AuditError> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| invalid("ledger has no parent"))?;
    std::fs::create_dir_all(dir).map_err(|e| invalid(e.to_string()))?;
    let bytes = serde_json::to_vec(ledger).map_err(|e| invalid(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let mut file = options.open(&tmp).map_err(|e| invalid(e.to_string()))?;
    file.write_all(&bytes).map_err(|e| invalid(e.to_string()))?;
    file.sync_all().map_err(|e| invalid(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| invalid(e.to_string()))
}

/// Compares the repository's finding store with the host-held ledger and, when
/// the store is consistent, refreshes the ledger. Returns gap strings; any
/// gap means history cannot be trusted and the caller must not pass.
pub fn history_custody_gaps(repo: &Path) -> Vec<String> {
    use crate::p12_pipeline::store::FindingStore;
    let ledger_path = match host_ledger_path(repo) {
        Ok(path) => path,
        Err(error) => return vec![format!("finding-history-ledger-unavailable:{error}")],
    };
    let ledger = match load_host_ledger(&ledger_path) {
        Ok(ledger) => ledger,
        Err(error) => return vec![format!("finding-history-ledger-unreadable:{error}")],
    };
    let store = FindingStore::new(repo);
    let had_findings = ledger
        .as_ref()
        .is_some_and(|l| !l.known_finding_ids.is_empty());
    let bytes = match std::fs::read(store.path()) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return vec![format!("finding-history-unreadable:{e}")],
    };
    let Some(bytes) = bytes else {
        return if had_findings {
            vec![GAP_STORE_MISSING.to_owned()]
        } else {
            Vec::new()
        };
    };
    let records = match store.load() {
        Ok(records) => records,
        Err(error) => {
            return vec![if had_findings {
                GAP_STORE_MISSING.to_owned()
            } else {
                format!("finding-history-unreadable:{error}")
            }]
        }
    };
    let mut known = BTreeSet::new();
    let mut open = BTreeSet::new();
    for record in &records {
        if let Some(id) = record.get("id").and_then(Value::as_str) {
            known.insert(id.to_owned());
            if record.get("status").and_then(Value::as_str) == Some("open") {
                open.insert(id.to_owned());
            }
        }
    }
    if let Some(ledger) = &ledger {
        if ledger
            .known_finding_ids
            .iter()
            .any(|id| !known.contains(id))
        {
            return vec![GAP_STORE_MISSING.to_owned()];
        }
    }
    if known.is_empty() && ledger.is_none() {
        return Vec::new();
    }
    let next = HostLedger {
        schema_version: 1,
        repo_digest: hex::encode(Sha256::digest(
            std::fs::canonicalize(repo)
                .unwrap_or_default()
                .to_string_lossy()
                .as_bytes(),
        )),
        store_digest: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        open_finding_ids: open.into_iter().collect(),
        known_finding_ids: known.into_iter().collect(),
        generation: ledger.map_or(1, |l| l.generation + 1),
    };
    match write_host_ledger(&ledger_path, &next) {
        Ok(()) => Vec::new(),
        Err(error) => vec![format!("finding-history-ledger-unwritable:{error}")],
    }
}
