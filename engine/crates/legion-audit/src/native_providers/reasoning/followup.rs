//! Follow-up plan for security variant analysis.
//!
//! `legacy.security.variant-analysis` is selected by `confirmedSecurityFinding`,
//! which is empty when the parent plan is frozen: the confirmed findings only
//! exist after the adjudication lens is ingested. This module compiles and
//! freezes a SECOND plan over confirmed seed files plus deterministic
//! in-inventory sibling, caller, and root-cause context, then binds it to the
//! parent run:
//!
//! * the follow-up plan carries `bounds.followup` = parent plan digest, the
//!   digest of the confirmed findings (their verdict digests) and the confirmed
//!   paths, so its digest and HMAC cover the binding;
//! * it lives in a self-contained run directory `<run>/followup/` (own
//!   `plan.json`, `frozen-plan.json`, `epoch.key`, `execution.json`,
//!   `report.json`, `lens-packets/`, `lens-receipts/`), so the ordinary
//!   `ingest_lens_result` / `recompute_run` machinery runs on it unchanged;
//! * the variant lens packet carries the confirmed findings as `variantSeeds`.
//!
//! `evaluate` is what the parent `recompute_run` consults: the
//! `security-variant-analysis-pending` gap clears only when the follow-up is
//! complete AND the whole chain verifies.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use legion_contracts::{canonical_digest, Finding};
use serde_json::{json, Value};

use super::{
    ingest::{
        create_epoch, expected_request_id, install_epoch_key, invalid, io, lens_packet_items,
        load_epoch, read_json, recompute_run, write_atomic, write_lens_packets, LENS_PACKET_DIR,
        LENS_RECEIPT_DIR,
    },
    pending_lens_work,
    security_adjudication::{confirmed_paths, ConfirmedSecurityFinding, ADJUDICATOR_PROVIDER_ID},
    PendingLensWork, ReasoningProviderExecutor,
};
use crate::{
    amendment::{self, AmendmentChainRecord, AmendmentOperation},
    error::AuditError,
    execution::{execute, ExecutionReport},
    inventory::{FilesystemInventorySource, InventorySource},
    plan::{AuditPlan, FOLLOWUP_BOUND},
    report::canonical_report,
};

/// Run-relative directory of the follow-up run.
pub const FOLLOWUP_DIR: &str = "followup";
/// File holding the complete frozen follow-up plan (plan.json only records its seal).
pub const FROZEN_PLAN_FILE: &str = "frozen-plan.json";
/// The provider the follow-up plan exists for.
pub const VARIANT_PROVIDER_ID: &str = "legacy.security.variant-analysis";

/// File in the follow-up run directory holding the sealed [`VariantLedger`].
pub const VARIANT_LEDGER_FILE: &str = "variant-ledger.json";
/// Host-side per-part inputs the ledger aggregates (unresolved/matched claims).
pub const VARIANT_LEDGER_INPUT_FILE: &str = "variant-ledger-input.json";
/// Signed generation of the parent plan that adds this follow-up run.
pub const FOLLOWUP_CHAIN_FILE: &str = "plan-amendments.json";
/// A follow-up without a ledger stays pending: the variant-lens ingest writes
/// the sealed ledger, so an absent ledger after ingest is an incomplete pass.
pub const VARIANT_LEDGER_REQUIRED: bool = true;

/// Root-cause signature (SEC 4.4, 9.5): digest over the normalized rule, sink
/// class, and missing control that define the variant family.
pub fn root_cause_signature(
    rule: &str,
    sink: &str,
    missing_control: &str,
) -> Result<String, AuditError> {
    let parts = [rule, sink, missing_control].map(|part| part.trim().to_lowercase());
    if parts.iter().any(String::is_empty) {
        return Err(invalid(
            "root-cause signature needs a rule, a sink, and a missing control",
        ));
    }
    canonical_digest(&json!({"rule": parts[0], "sink": parts[1], "missingControl": parts[2]}))
        .map_err(|error| invalid(error.to_string()))
}

/// Outcome of assessing a ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerAssessment {
    Complete,
    /// Counts are consistent but variants remain unexamined or unresolved.
    Incomplete(String),
    /// Counts contradict each other; never trusted.
    Inconsistent(String),
}

/// Variant ledger: the denominator-bound accounting of a pattern-exhaustion
/// pass. It is sealed with a digest and bound to the parent plan, the
/// follow-up plan, and the confirmed verdicts, so a stale or hand-edited
/// ledger cannot clear the variant pass.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VariantLedger {
    pub root_cause_signature: String,
    /// Repository denominator size the pass was bound to.
    pub denominator_count: u64,
    /// Matches enumerated for the root-cause signature.
    pub matched: u64,
    /// Matches actually looked at: confirmed + rejected + unresolved.
    pub examined: u64,
    pub confirmed: u64,
    pub rejected: u64,
    pub unresolved: u64,
    /// One reason per rejected variant (required when `rejected > 0`).
    #[serde(default)]
    pub rejection_reasons: Vec<String>,
    pub parent_plan_digest: String,
    pub followup_plan_digest: String,
    pub confirmed_digest: String,
    #[serde(default)]
    pub ledger_digest: String,
}

impl VariantLedger {
    fn unsealed_digest(&self) -> Result<String, AuditError> {
        let mut copy = self.clone();
        copy.ledger_digest = String::new();
        canonical_digest(&json!(copy)).map_err(|error| invalid(error.to_string()))
    }

    /// Seal the ledger with its own digest.
    pub fn seal(mut self) -> Result<Self, AuditError> {
        self.ledger_digest = self.unsealed_digest()?;
        Ok(self)
    }

    pub fn assess(&self) -> LedgerAssessment {
        if self.root_cause_signature.trim().is_empty() {
            return LedgerAssessment::Inconsistent("root-cause signature is empty".into());
        }
        let accounted = self
            .confirmed
            .checked_add(self.rejected)
            .and_then(|sum| sum.checked_add(self.unresolved));
        if accounted != Some(self.examined) {
            return LedgerAssessment::Inconsistent(format!(
                "examined {} != confirmed {} + rejected {} + unresolved {}",
                self.examined, self.confirmed, self.rejected, self.unresolved
            ));
        }
        if self.examined > self.matched {
            return LedgerAssessment::Inconsistent(format!(
                "examined {} exceeds matched {}",
                self.examined, self.matched
            ));
        }
        if self.rejected > 0 && self.rejection_reasons.len() < self.rejected as usize {
            return LedgerAssessment::Inconsistent(
                "rejected variants lack recorded reasons".into(),
            );
        }
        if self
            .rejection_reasons
            .iter()
            .any(|reason| reason.trim().is_empty())
        {
            return LedgerAssessment::Inconsistent("a rejection reason is blank".into());
        }
        if self.unresolved > 0 {
            return LedgerAssessment::Incomplete(format!(
                "{} unresolved variant(s) of {} matched",
                self.unresolved, self.matched
            ));
        }
        if self.examined < self.matched {
            return LedgerAssessment::Incomplete(format!(
                "{} of {} matched variant(s) not yet examined",
                self.matched - self.examined,
                self.matched
            ));
        }
        LedgerAssessment::Complete
    }

    /// True only when every matched variant was confirmed or rejected.
    pub fn is_complete(&self) -> bool {
        self.assess() == LedgerAssessment::Complete
    }

    /// Verify the seal and the binding to this follow-up.
    pub fn verify_binding(
        &self,
        parent_plan_digest: &str,
        followup_plan_digest: &str,
        confirmed_digest: &str,
        denominator_count: u64,
    ) -> Result<(), AuditError> {
        if self.ledger_digest != self.unsealed_digest()? {
            return Err(invalid("variant ledger digest does not match its content"));
        }
        if self.parent_plan_digest != parent_plan_digest
            || self.followup_plan_digest != followup_plan_digest
            || self.confirmed_digest != confirmed_digest
            || self.denominator_count != denominator_count
        {
            return Err(invalid(
                "variant ledger is not bound to this parent plan, follow-up plan, confirmed verdicts, and denominator",
            ));
        }
        Ok(())
    }

    /// The `variantLedger` receipt claim.
    pub fn claim(&self) -> Value {
        json!({
            "status": if self.is_complete() { "complete" } else { "incomplete" },
            "rootCauseSignature": self.root_cause_signature,
            "denominatorCount": self.denominator_count,
            "matched": self.matched,
            "examined": self.examined,
            "confirmed": self.confirmed,
            "rejected": self.rejected,
            "unresolved": self.unresolved,
            "ledgerDigest": self.ledger_digest,
        })
    }
}

/// Build the signed generation of the parent plan that adds this follow-up run
/// (`amendment::apply_followup`). The executed follow-up plan stays the
/// single-provider plan; this generation is its verifiable lineage. A parent
/// that already lists the variant provider gets the run under a distinct
/// `.followup` provider id (plan provider ids are unique).
fn followup_generation(
    parent_plan_json: &Value,
    key: &[u8],
    followup: &crate::plan::FrozenPlan,
) -> Result<(AmendmentChainRecord, amendment::AppliedAmendment), AuditError> {
    let base = amendment::frozen_plan_from_run_json(parent_plan_json, key)?;
    let mut provider = followup
        .plan()
        .providers
        .first()
        .cloned()
        .ok_or_else(|| invalid("follow-up plan holds no provider"))?;
    if base
        .plan()
        .providers
        .iter()
        .any(|existing| existing.id == provider.id)
    {
        provider.id = format!("{}.followup", provider.id);
    }
    let binding = followup
        .plan()
        .followup_binding()
        .cloned()
        .ok_or_else(|| invalid("follow-up plan carries no parent binding"))?;
    let (next, applied) = amendment::apply_followup(
        &base,
        provider,
        binding,
        "security variant analysis follow-up",
        amendment::now_unix(),
        key,
    )?;
    let chain = AmendmentChainRecord::new(&base, vec![applied.clone()], &next)?;
    Ok((chain, applied))
}

/// Replay the recorded follow-up generation against the parent plan and bind
/// it to the executed follow-up plan.
fn verify_followup_generation(
    dir: &Path,
    parent_plan_json: &Value,
    parent_digest: &str,
    parent_key: &[u8],
    frozen: &AuditPlan,
) -> Result<(), AuditError> {
    let bytes = fs::read(dir.join(FOLLOWUP_CHAIN_FILE)).map_err(|error| {
        io(
            error,
            "follow-up carries no signed generation of the parent plan",
        )
    })?;
    let record: AmendmentChainRecord = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("follow-up plan generation is invalid: {error}")))?;
    let base = amendment::frozen_plan_from_run_json(parent_plan_json, parent_key)?;
    if base.digest() != parent_digest || record.genesis_plan_digest != base.digest() {
        return Err(invalid(
            "follow-up plan generation is bound to a different parent plan",
        ));
    }
    let [link] = record.links.as_slice() else {
        return Err(invalid("follow-up plan generation must be one link"));
    };
    let (next, applied) = amendment::apply(&base, &link.amendment, parent_key)?;
    if applied.result_plan_digest != link.result_plan_digest
        || applied.result_generation != link.result_generation
        || record.result_digest() != Some(next.digest())
    {
        return Err(invalid(
            "follow-up plan generation does not reproduce its recorded result",
        ));
    }
    let [AmendmentOperation::AddFollowupRun { provider, followup }] =
        link.amendment.body.operations.as_slice()
    else {
        return Err(invalid(
            "follow-up plan generation is not a single follow-up run",
        ));
    };
    let [executed] = frozen.providers.as_slice() else {
        return Err(invalid("follow-up plan must hold exactly one provider"));
    };
    if Some(followup) != frozen.followup_binding()
        || provider.configuration != executed.configuration
        || provider.lens_ids != executed.lens_ids
        || provider.role != executed.role
    {
        return Err(invalid(
            "follow-up plan generation differs from the executed follow-up plan",
        ));
    }
    Ok(())
}

/// (confirmed, rejected, rejection reasons) over every authenticated variant
/// receipt of the follow-up run (single packet or every part).
pub(super) fn variant_receipt_counts(
    run_dir: &Path,
) -> Result<(u64, u64, Vec<String>), AuditError> {
    let dir = run_dir.join(LENS_RECEIPT_DIR);
    let single = format!("{VARIANT_PROVIDER_ID}.json");
    let prefix = format!("{VARIANT_PROVIDER_ID}.part-");
    let (mut confirmed, mut rejected, mut reasons) = (0u64, 0u64, Vec::new());
    let mut names = Vec::new();
    for entry in fs::read_dir(&dir)
        .map_err(|error| io(error, "could not list the variant receipts"))?
        .filter_map(Result::ok)
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == single || (name.starts_with(&prefix) && name.ends_with(".json")) {
            names.push(entry.path());
        }
    }
    names.sort();
    for path in names {
        let receipt = read_json(&path)?;
        confirmed += receipt
            .pointer("/result/details/lensFindings")
            .and_then(Value::as_array)
            .map_or(0, |items| items.len() as u64);
        for entry in receipt
            .pointer("/result/details/withdrawnFindings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            rejected += 1;
            reasons.push(
                entry
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
    }
    Ok((confirmed, rejected, reasons))
}

/// Called by the variant-lens ingest: seal `<followup>/variant-ledger.json`
/// from the authenticated receipts plus the host-recorded per-part inputs. The
/// optional result field `variantLedger` carries `unresolved`, `matched` and
/// `rootCause {rule, sink, missingControl}`; otherwise the signature derives
/// from the packet's variant seeds. Unresolved variants keep the pass
/// incomplete.
pub(super) fn record_variant_pass(
    run_dir: &Path,
    plan: &Value,
    packet: &Value,
    result: &Value,
    part: Option<u32>,
) -> Result<(), AuditError> {
    let binding = plan
        .get("followupOf")
        .ok_or_else(|| invalid("plan.json is not a follow-up"))?;
    let text = |name: &str| {
        binding
            .get(name)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| invalid(format!("followupOf.{name} is missing")))
    };
    let denominator = binding
        .get("analysisPaths")
        .and_then(Value::as_array)
        .map(|paths| paths.len() as u64)
        .ok_or_else(|| invalid("followupOf.analysisPaths is missing"))?;
    let submitted = match result.get("variantLedger") {
        None | Some(Value::Null) => json!({}),
        Some(value) if value.is_object() => value.clone(),
        Some(_) => return Err(invalid("variantLedger must be an object")),
    };
    let count = |name: &str| -> Result<u64, AuditError> {
        match submitted.get(name) {
            None | Some(Value::Null) => Ok(0),
            Some(value) => value
                .as_u64()
                .ok_or_else(|| invalid(format!("variantLedger.{name} must be a count"))),
        }
    };
    let mut input = match fs::read(run_dir.join(VARIANT_LEDGER_INPUT_FILE)) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
            .map_err(|error| invalid(format!("variant ledger input is invalid: {error}")))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({"parts": {}}),
        Err(error) => return Err(io(error, "could not read the variant ledger input")),
    };
    let key = part.map_or_else(|| "0".to_owned(), |number| number.to_string());
    input["parts"][&key] =
        json!({"unresolved": count("unresolved")?, "matched": count("matched")?});
    if input.get("rootCause").is_none() {
        let seeds = packet
            .get("variantSeeds")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let field = |name: &str| -> String {
            let mut values: BTreeSet<String> = seeds
                .iter()
                .filter_map(|seed| seed.get(name))
                .filter_map(|value| match value {
                    Value::Null => None,
                    Value::String(text) => Some(text.trim().to_owned()),
                    other => Some(other.to_string()),
                })
                .filter(|value| !value.is_empty())
                .collect();
            if values.is_empty() {
                values.insert("unspecified".into());
            }
            values.into_iter().collect::<Vec<_>>().join("|")
        };
        let from = |name: &str, derived: String| {
            submitted
                .pointer(&format!("/rootCause/{name}"))
                .and_then(Value::as_str)
                .map_or(derived, ToOwned::to_owned)
        };
        input["rootCause"] = json!({
            "rule": from("rule", field("rule")),
            "sink": from("sink", field("sink")),
            "missingControl": from("missingControl", field("missingControl")),
        });
    }
    let cause = |name: &str| {
        input["rootCause"][name]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };
    let signature = root_cause_signature(&cause("rule"), &cause("sink"), &cause("missingControl"))?;
    let (confirmed, rejected, rejection_reasons) = variant_receipt_counts(run_dir)?;
    let parts = input["parts"].as_object().cloned().unwrap_or_default();
    let sum = |name: &str| -> u64 {
        parts
            .values()
            .map(|entry| entry.get(name).and_then(Value::as_u64).unwrap_or(0))
            .sum()
    };
    let unresolved = sum("unresolved");
    let examined = confirmed
        .checked_add(rejected)
        .and_then(|total| total.checked_add(unresolved))
        .ok_or_else(|| invalid("variant ledger count overflow"))?;
    let ledger = VariantLedger {
        root_cause_signature: signature,
        denominator_count: denominator,
        matched: sum("matched").max(examined),
        examined,
        confirmed,
        rejected,
        unresolved,
        rejection_reasons,
        parent_plan_digest: text("parentPlanDigest")?,
        followup_plan_digest: seal_digest(plan, "follow-up plan.json")?,
        confirmed_digest: text("confirmedDigest")?,
        ledger_digest: String::new(),
    }
    .seal()?;
    let to_bytes = |value: &Value| {
        serde_json::to_vec_pretty(value).map_err(|error| invalid(error.to_string()))
    };
    write_atomic(run_dir, VARIANT_LEDGER_INPUT_FILE, &to_bytes(&input)?)?;
    write_atomic(run_dir, VARIANT_LEDGER_FILE, &to_bytes(&json!(ledger))?)?;
    Ok(())
}

/// What `compile_followup` produced (or found already in place).
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FollowupPlanned {
    pub dir: PathBuf,
    pub plan_path: PathBuf,
    pub plan_digest: String,
    pub parent_plan_digest: String,
    pub confirmed_paths: Vec<String>,
    pub analysis_paths: Vec<String>,
    pub seeds: usize,
    pub provider: String,
    /// The variant lens packet files: one unnumbered packet, or every
    /// `<provider>.part-NNNN.json` of a partitioned denominator, in part order.
    pub packets: Vec<PathBuf>,
    /// Digest of each packet in `packets` (same order).
    pub packet_digests: Vec<String>,
    /// The existing follow-up already matched the parent and was left untouched.
    pub reused: bool,
}

/// State of the follow-up as seen from the parent run.
#[derive(Clone, Debug)]
pub enum FollowupState {
    /// No follow-up has been compiled.
    Absent,
    /// Compiled and chain-verified, but the variant lens is not (fully) ingested.
    Pending(String),
    /// The follow-up exists but its chain does not verify against the parent.
    Invalid(String),
    /// Ingested, complete, and verified.
    Complete(FollowupDone),
}

#[derive(Clone, Debug)]
pub struct FollowupDone {
    pub plan_digest: String,
    pub parent_plan_digest: String,
    pub confirmed_paths: Vec<String>,
    pub analysis_paths: Vec<String>,
    pub findings: Vec<Finding>,
    /// Sealed, binding-verified variant ledger; `None` while the ingest path
    /// has not produced one (reported as `variantLedger.status = "absent"`).
    pub variant_ledger: Option<VariantLedger>,
}

impl FollowupState {
    /// The `securityVariantFollowup` report claim.
    pub fn claim(&self) -> Value {
        match self {
            Self::Absent => json!({"status": "absent"}),
            Self::Pending(reason) => json!({"status": "pending", "reason": reason}),
            Self::Invalid(reason) => json!({"status": "invalid", "reason": reason}),
            Self::Complete(done) => json!({
                "status": "complete",
                "planDigest": done.plan_digest,
                "parentPlanDigest": done.parent_plan_digest,
                "confirmedPaths": done.confirmed_paths,
                "analysisPaths": done.analysis_paths,
                "findings": done.findings.len(),
                "variantLedger": done
                    .variant_ledger
                    .as_ref()
                    .map_or_else(|| json!({"status": "absent"}), VariantLedger::claim),
            }),
        }
    }
}

fn seal_digest(plan_json: &Value, who: &str) -> Result<String, AuditError> {
    plan_json
        .pointer("/seal/digest")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid(format!("{who} has no seal digest")))
}

/// Digest binding the follow-up to the exact confirmed verdicts (each carries
/// its verdict digest).
fn confirmed_digest(confirmed: &[ConfirmedSecurityFinding]) -> Result<String, AuditError> {
    canonical_digest(&json!(confirmed)).map_err(|error| invalid(error.to_string()))
}

/// Paths of the confirmed findings; every confirmed finding must be scoped to a
/// file, otherwise variant analysis cannot be bound to a denominator.
fn scoped_paths(confirmed: &[ConfirmedSecurityFinding]) -> Result<Vec<String>, AuditError> {
    if let Some(unscoped) = confirmed.iter().find(|finding| finding.path.is_none()) {
        return Err(invalid(format!(
            "confirmed finding {} carries no source path; variant analysis cannot be scoped to it",
            unscoped.candidate_id
        )));
    }
    let paths = confirmed_paths(confirmed);
    if paths.is_empty() {
        return Err(invalid("no confirmed security finding to analyse"));
    }
    Ok(paths)
}

/// Deterministic review scope: confirmed files, their source siblings, and
/// first-party source files with a lexical reference to the seed module stem.
/// Every path comes from the frozen inventory; relationships are separately
/// recorded so seeds are never confused with context candidates.
fn expanded_scope(
    root: &Path,
    inventory: &crate::inventory::InventoryEnvelope,
    confirmed_paths: &[String],
    variant_seeds: &[Value],
) -> Result<(Vec<String>, Value), AuditError> {
    let seeds = confirmed_paths.iter().cloned().collect::<BTreeSet<_>>();
    let mut relations = BTreeMap::<String, BTreeSet<String>>::new();
    for seed in &seeds {
        if !inventory.entries.iter().any(|entry| &entry.path == seed) {
            return Err(AuditError::SourceDrift(
                "a confirmed finding path is not part of the frozen inventory".into(),
            ));
        }
        relations
            .entry(seed.clone())
            .or_default()
            .insert("confirmed-seed".into());
    }

    let parents = seeds
        .iter()
        .map(|path| {
            (
                path.clone(),
                Path::new(path)
                    .parent()
                    .map(|parent| parent.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    let stems = seeds
        .iter()
        .map(|path| {
            (
                path.clone(),
                Path::new(path)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        io(
            error,
            "could not resolve the Audit root for variant analysis",
        )
    })?;
    let mut source_contents = BTreeMap::<String, String>::new();
    for entry in inventory.entries.iter().filter(|entry| entry.source_file) {
        let candidate_parent = Path::new(&entry.path)
            .parent()
            .map(|parent| parent.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        for (seed, parent) in &parents {
            if entry.path == *seed {
                continue;
            }
            if candidate_parent == *parent {
                relations
                    .entry(entry.path.clone())
                    .or_default()
                    .insert(format!("sibling-of:{seed}"));
            }
        }

        let candidate = root.join(&entry.path);
        let canonical = fs::canonicalize(&candidate)
            .map_err(|error| io(error, "could not resolve a frozen variant source path"))?;
        if !canonical.starts_with(&canonical_root) {
            return Err(invalid(format!(
                "variant source path {} escapes the Audit root",
                entry.path
            )));
        }
        let bytes = fs::read(canonical)
            .map_err(|error| io(error, "could not read a frozen variant source path"))?;
        let contents = String::from_utf8_lossy(&bytes).into_owned();
        source_contents.insert(entry.path.clone(), contents.clone());
        for (seed, stem) in &stems {
            if contains_identifier(&contents, stem) {
                relations
                    .entry(entry.path.clone())
                    .or_default()
                    .insert(format!("caller-reference:{seed}"));
            }
        }
    }

    let mut root_cause_token_files = BTreeMap::<String, Vec<String>>::new();
    for seed in variant_seeds {
        let seed_path = seed
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("variant seed has no path"))?;
        let excerpt = seed
            .get("evidenceExcerpt")
            .and_then(Value::as_str)
            .unwrap_or_default();
        for token in identifier_tokens(excerpt) {
            let matches = source_contents
                .iter()
                .filter(|(_, contents)| contains_identifier(contents, &token))
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>();
            // A token seen in only the seed has no sibling variant; an
            // ubiquitous token is too noisy to define useful search scope.
            if !(2..=16).contains(&matches.len()) {
                continue;
            }
            for path in matches {
                if path == seed_path {
                    continue;
                }
                relations
                    .entry(path.clone())
                    .or_default()
                    .insert(format!("root-cause-token:{seed_path}:{token}"));
                root_cause_token_files
                    .entry(token.clone())
                    .or_default()
                    .push(path);
            }
        }
    }

    let paths = relations.keys().cloned().collect::<Vec<_>>();
    let relation_values = relations
        .into_iter()
        .map(|(path, reasons)| {
            json!({
                "path": path,
                "relations": reasons.into_iter().collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    Ok((
        paths,
        json!({
            "paths": relation_values,
            "rootCauseSearch": {
                "status": "examined-frozen-source-files",
                "seedTokenMatches": root_cause_token_files,
            }
        }),
    ))
}

fn identifier_tokens(source: &str) -> BTreeSet<String> {
    const STOPWORDS: &[&str] = &[
        "async", "await", "const", "else", "error", "false", "fn", "function", "let", "match",
        "null", "return", "self", "string", "true", "type", "value", "var",
    ];
    source
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| token.len() >= 4 && !STOPWORDS.contains(token))
        .map(ToOwned::to_owned)
        .collect()
}

fn contains_identifier(source: &str, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    source.match_indices(token).any(|(start, _)| {
        let end = start + token.len();
        let identifier = |character: Option<char>| {
            character.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
        };
        !identifier(source[..start].chars().next_back())
            && !identifier(source[end..].chars().next())
    })
}

/// One seed per confirmed finding: scanner rule/location plus the adjudicator's
/// reasoning, joined from the parent adjudication packet and receipt.
fn seeds(run_dir: &Path, confirmed: &[ConfirmedSecurityFinding]) -> Result<Vec<Value>, AuditError> {
    let packet = read_json(
        &run_dir
            .join(LENS_PACKET_DIR)
            .join(format!("{ADJUDICATOR_PROVIDER_ID}.json")),
    )?;
    let candidates = packet
        .pointer("/request/packet/scannerCandidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let receipt = read_json(
        &run_dir
            .join(super::ingest::LENS_RECEIPT_DIR)
            .join(format!("{ADJUDICATOR_PROVIDER_ID}.json")),
    )?;
    let verdicts = receipt
        .pointer("/result/details/securityVerdicts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let by_id = |items: &[Value], key: &str, id: &str| -> Value {
        items
            .iter()
            .find(|item| item.get(key).and_then(Value::as_str) == Some(id))
            .cloned()
            .unwrap_or(Value::Null)
    };
    Ok(confirmed
        .iter()
        .map(|finding| {
            let candidate = by_id(&candidates, "findingId", &finding.candidate_id);
            let verdict = by_id(&verdicts, "candidateId", &finding.candidate_id);
            let pick =
                |source: &Value, field: &str| source.get(field).cloned().unwrap_or(Value::Null);
            json!({
                "parentFindingId": format!("adjudicated:{}", finding.candidate_id),
                "candidateId": finding.candidate_id,
                "rule": pick(&candidate, "rule"),
                "provider": pick(&candidate, "provider"),
                "path": finding.path,
                "line": finding.line,
                "severity": finding.severity,
                "message": pick(&candidate, "message"),
                "evidenceExcerpt": pick(&candidate, "evidenceExcerpt"),
                "verdict": finding.verdict,
                "verdictDigest": finding.verdict_digest,
                "rationale": pick(&verdict, "rationale"),
                "threatModel": pick(&verdict, "threatModel"),
                "reachability": pick(&verdict, "reachability"),
                "impact": pick(&verdict, "impact"),
                "sink": pick(&verdict, "sink"),
                "proof": pick(&verdict, "proof"),
            })
        })
        .collect())
}

/// Every variant lens packet of the follow-up on disk, with its file path: the
/// single unnumbered packet, or all `<provider>.part-NNNN.json` parts in part
/// order. Errors when neither exists.
fn variant_packets(dir: &Path) -> Result<Vec<(PathBuf, PendingLensWork)>, AuditError> {
    let lens_dir = dir.join(LENS_PACKET_DIR);
    let single = lens_dir.join(format!("{VARIANT_PROVIDER_ID}.json"));
    let files: Vec<PathBuf> = if single.is_file() {
        vec![single]
    } else {
        let prefix = format!("{VARIANT_PROVIDER_ID}.part-");
        let mut parts: Vec<PathBuf> = fs::read_dir(&lens_dir)
            .map_err(|error| io(error, "could not list the variant lens packets"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".json"))
            })
            .collect();
        parts.sort();
        parts
    };
    if files.is_empty() {
        return Err(io(
            std::io::Error::from(std::io::ErrorKind::NotFound),
            "follow-up has no variant lens packet",
        ));
    }
    files
        .into_iter()
        .map(|path| -> Result<(PathBuf, PendingLensWork), AuditError> {
            let work: PendingLensWork =
                serde_json::from_value(read_json(&path)?).map_err(|error| {
                    invalid(format!("{} is not a lens packet: {error}", path.display()))
                })?;
            Ok((path, work))
        })
        .collect()
}

/// The pending reason while some variant packet parts are not yet ingested.
/// A single packet keeps the plain wording.
fn parts_pending_reason(missing: &[u32], total: usize) -> String {
    if total <= 1 {
        return "the variant-analysis lens result has not been ingested".into();
    }
    let named = missing
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "variant-analysis packet part(s) {named} of {total} not yet ingested; the follow-up covers the variant denominator only once every part is ingested"
    )
}

/// Compiles, freezes and writes the follow-up plan for `parent_run`, plus the
/// variant lens packet. Returns `None` when the parent run has no confirmed
/// security finding (no follow-up, no gap). `variant_spec` is the registry's
/// `legacy.security.variant-analysis` provider.
///
/// Idempotent: a follow-up that already matches the parent's current confirmed
/// findings is left untouched (so an ingested variant receipt survives); one
/// that does not is regenerated from scratch.
pub fn compile_followup(
    parent_run: &Path,
    variant_spec: &legion_contracts::ProviderSpec,
) -> Result<Option<FollowupPlanned>, AuditError> {
    if variant_spec.id.to_string() != VARIANT_PROVIDER_ID {
        return Err(invalid(format!(
            "follow-up provider must be {VARIANT_PROVIDER_ID}, not {}",
            variant_spec.id
        )));
    }
    let recomputed = recompute_run(parent_run)?;
    let confirmed = recomputed.confirmed_security;
    if confirmed.is_empty() {
        return Ok(None);
    }
    let paths = scoped_paths(&confirmed)?;
    let digest_of_confirmed = confirmed_digest(&confirmed)?;
    let parent_plan = read_json(&parent_run.join("plan.json"))?;
    let parent_digest = seal_digest(&parent_plan, "plan.json")?;
    let dir = parent_run.join(FOLLOWUP_DIR);

    let root = PathBuf::from(
        parent_plan
            .get("repository")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("plan.json has no repository root"))?,
    );
    let revision = parent_plan
        .pointer("/binding/repositoryRevision")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("plan.json has no repository revision"))?;
    let adjudication: PendingLensWork = serde_json::from_value(read_json(
        &parent_run
            .join(LENS_PACKET_DIR)
            .join(format!("{ADJUDICATOR_PROVIDER_ID}.json")),
    )?)
    .map_err(|error| invalid(format!("adjudication packet is invalid: {error}")))?;
    let inventory =
        FilesystemInventorySource::new(&root)?.inventory(&adjudication.request.repository_id)?;
    if inventory.generation != revision
        || parent_plan
            .pointer("/binding/inventoryDigest")
            .and_then(Value::as_str)
            != Some(inventory.digest.as_str())
    {
        return Err(AuditError::SourceDrift(
            "the working tree no longer matches the frozen revision; rerun the audit".into(),
        ));
    }
    let review_context = parent_plan
        .get("reviewContext")
        .cloned()
        .ok_or_else(|| invalid("variant follow-up requires parent frozen reviewContext"))?;
    let manifest = review_context
        .get("snapshotManifest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("variant follow-up requires immutable snapshot"))?;
    let snapshot = crate::snapshot::FrozenSnapshot::open(Path::new(manifest))?;
    snapshot.verify_source_current()?;
    if review_context.get("snapshotKey").and_then(Value::as_str)
        != Some(snapshot.manifest.key.as_str())
    {
        return Err(invalid("variant follow-up snapshot identity mismatch"));
    }
    let mut variant_spec = variant_spec.clone();
    variant_spec
        .reasoning
        .as_object_mut()
        .ok_or_else(|| invalid("variant reasoning contract must be object"))?
        .insert("reviewContext".into(), review_context.clone());
    let parent_dispatch = read_json(&parent_run.join("lens-dispatch.json"))?;
    let variant_seeds = seeds(parent_run, &confirmed)?;
    let (analysis_paths, scope_relations) =
        expanded_scope(&root, &inventory, &paths, &variant_seeds)?;
    if let Some(existing) = reuse(
        &dir,
        &parent_digest,
        &digest_of_confirmed,
        &paths,
        &analysis_paths,
        &scope_relations,
        &review_context,
    ) {
        return Ok(Some(existing));
    }

    // The follow-up is signed with the PARENT's plan key (host custody), never
    // a fresh key: it is a generation of the parent plan. The lens-receipt MAC
    // epoch stays a fresh per-run key, except for a legacy parent whose plan
    // key and epoch key are one run-directory key (inherited unchanged).
    let (parent_key, key_source) =
        match crate::integrity::resolve_plan_key(parent_run, &parent_plan) {
            crate::integrity::PlanKeyResolution::Found { key, source } => (key, source),
            crate::integrity::PlanKeyResolution::Unverifiable { reason } => {
                return Err(invalid(format!("unverifiable-signature: {reason}")));
            }
        };
    let epoch = if key_source == crate::integrity::PlanKeySource::LegacyRunDirEpoch {
        install_epoch_key(&dir, &parent_key)?
    } else {
        create_epoch(&dir)?
    };
    let plan = AuditPlan::compile_followup(
        &inventory,
        &variant_spec,
        &paths,
        &analysis_paths,
        &scope_relations,
        &parent_digest,
        &digest_of_confirmed,
    )?
    .freeze(Some(parent_key.as_slice()))?;
    let plan_key_record = match key_source {
        crate::integrity::PlanKeySource::HostState => {
            let run_id = crate::integrity::new_run_id()?;
            let key_id =
                crate::integrity::store_host_plan_key(&dir, &run_id, plan.digest(), &parent_key)?;
            json!({"runId": run_id, "keyId": key_id, "custody": "host-state"})
        }
        _ => Value::Null,
    };
    // Signed generation of the parent plan adding this follow-up run; verified
    // again by `evaluate`. Refusal (legacy schema 1 parent, unsigned parent,
    // binding mismatch) fails the follow-up closed.
    let (chain, applied) = followup_generation(&parent_plan, &parent_key, &plan)?;
    let execution = execute(
        &plan,
        &inventory,
        &ReasoningProviderExecutor::unavailable(&root),
    )?;
    if execution.pending_host != [VARIANT_PROVIDER_ID] {
        return Err(invalid(
            "the follow-up plan did not leave the variant lens pending-host",
        ));
    }
    // Every part of a partitioned variant denominator is bound to the follow-up:
    // each carries the seeds and the parent binding, and gets its own request id.
    let mut works: Vec<PendingLensWork> = pending_lens_work(&root, &plan, &inventory)?
        .into_iter()
        .filter(|item| item.provider_id == VARIANT_PROVIDER_ID)
        .collect();
    if works.is_empty() {
        return Err(invalid(
            "the follow-up plan produced no variant lens packet",
        ));
    }
    let seed_count = variant_seeds.len();
    for work in works.iter_mut() {
        let packet = work
            .request
            .packet
            .as_object_mut()
            .ok_or_else(|| invalid("variant lens packet is not an object"))?;
        packet.insert("variantSeeds".into(), Value::Array(variant_seeds.clone()));
        packet.insert("variantScope".into(), scope_relations.clone());
        packet.insert(
            "followup".into(),
            json!({
                "parentPlanDigest": parent_digest,
                "confirmedDigest": digest_of_confirmed,
                "confirmedPaths": paths,
                "analysisPaths": analysis_paths,
                "scopeRelations": scope_relations,
            }),
        );
        let request_id = expected_request_id(&*work)?;
        work.request.request_id = request_id;
    }
    let packet_dir = dir.join(LENS_PACKET_DIR);
    let lens_work = Value::Array(lens_packet_items(&works, Some(packet_dir.as_path()))?);
    let packet_digests = works
        .iter()
        .map(|work| {
            canonical_digest(&work.request.packet).map_err(|error| invalid(error.to_string()))
        })
        .collect::<Result<Vec<String>, AuditError>>()?;
    let packets: Vec<PathBuf> = works
        .iter()
        .map(|work| packet_dir.join(work.packet_file_name()))
        .collect();

    let repository = root.to_string_lossy().into_owned();
    let mut report = canonical_report(&repository, &execution)?;
    report.claims.insert("lensWork".into(), lens_work);
    report.claims.insert(
        "followupOf".into(),
        json!({"parentPlanDigest": parent_digest, "confirmedDigest": digest_of_confirmed}),
    );
    let plan_json = json!({
        "schemaVersion": 1,
        "kind": "audit-provider-plan",
        "repository": repository,
        "reviewContext": review_context,
        "snapshotManifest": snapshot.manifest_path,
        "nativePlan": {"schemaVersion":1,"digest":plan.digest(),"signature":plan.signature(),"plan":plan.plan()},
        "binding": {
            "repositoryRevision": execution.generation,
            "inventoryDigest": execution.inventory_digest,
        },
        "seal": {
            "digest": plan.digest(),
            "authenticity": "hmac-sha256",
            "signature": plan.signature(),
        },
        "providers": execution.planned_providers,
        "epoch": {"digest": epoch, "keyFile": super::ingest::EPOCH_KEY_FILE},
        "planKey": plan_key_record,
        "followupOf": {
            "kind": "security-variant-analysis",
            "parentPlanDigest": parent_digest,
            "confirmedDigest": digest_of_confirmed,
            "confirmedPaths": paths,
            "analysisPaths": analysis_paths,
        },
    });
    let to_bytes = |value: &Value| {
        serde_json::to_vec_pretty(value).map_err(|error| invalid(error.to_string()))
    };
    write_atomic(
        &dir,
        FROZEN_PLAN_FILE,
        &to_bytes(&serde_json::to_value(plan.plan()).map_err(|error| invalid(error.to_string()))?)?,
    )?;
    write_atomic(&dir, FOLLOWUP_CHAIN_FILE, &to_bytes(&json!(chain))?)?;
    // Journal event only on a live (unfinalized) parent journal at generation 1.
    if chain.links.len() == 1 && applied.result_generation == 2 {
        amendment::record_in_journal(
            parent_run,
            &parent_digest,
            &applied,
            applied.amendment.body.issued_at_unix,
        )?;
    }
    // Writes the single packet or every numbered part plus the part index, and
    // removes stale packet files of an earlier partitioning.
    write_lens_packets(&packet_dir, &works)?;
    let limit = |name: &str, fallback: u64| {
        parent_dispatch
            .pointer(&format!("/limits/{name}"))
            .and_then(Value::as_u64)
            .unwrap_or(fallback)
    };
    let defaults = super::ingest::DispatchLimits::default();
    super::ingest::write_lens_dispatch(
        &dir,
        &works,
        &super::ingest::DispatchLimits {
            seat_token_budget: limit("seatTokenBudget", defaults.seat_token_budget),
            wave_width: limit("waveWidth", defaults.wave_width),
            run_token_budget: limit("runTokenBudget", defaults.run_token_budget),
            max_total_seats: limit("maxTotalSeats", defaults.max_total_seats),
        },
    )?;
    write_atomic(
        &dir,
        "execution.json",
        &to_bytes(&serde_json::to_value(&execution).map_err(|error| invalid(error.to_string()))?)?,
    )?;
    write_atomic(
        &dir,
        "report.json",
        &to_bytes(
            &crate::report::lift_report_v2(
                &report,
                legion_contracts::ReportScope {
                    spec: "whole".into(),
                    base_ref_oid: None,
                    merge_base_oid: None,
                    head: execution.generation.clone(),
                    snapshot_key: None,
                    index_schema_version: None,
                },
            )?
            .to_value_for_schema(legion_contracts::REPORT_SCHEMA_V2)
            .map_err(|error| invalid(error.to_string()))?,
        )?,
    )?;
    let plan_path = write_atomic(&dir, "plan.json", &to_bytes(&plan_json)?)?;
    // `legion verify` reconciles a run's facts against its plan; the follow-up
    // is a self-contained run, so it carries its own facts bound to its plan.
    // It inherits the parent's workspace, scope and network policy and starts
    // with no checks: the variant lens is its only, still pending, provider.
    let parent_facts = read_json(&parent_run.join("facts.json")).unwrap_or_else(|_| json!({}));
    let facts = json!({
        "schemaVersion": 1,
        "kind": "audit-facts",
        "workspace": parent_facts.get("workspace").cloned().unwrap_or(Value::Null),
        "out_dir": Value::Null,
        "plan": plan_json,
        "checks": [],
        "lenses_ran": [],
        "incomplete": true,
        "provider_reconciliation": {"valid": false, "providerResults": []},
        "network_policy": parent_facts.get("network_policy").cloned().unwrap_or(Value::Null),
        "scope": parent_facts.get("scope").cloned().unwrap_or(Value::Null),
    });
    write_atomic(&dir, "facts.json", &to_bytes(&facts)?)?;
    Ok(Some(FollowupPlanned {
        dir: dir.clone(),
        plan_path,
        plan_digest: plan.digest().to_owned(),
        parent_plan_digest: parent_digest,
        confirmed_paths: paths,
        analysis_paths,
        seeds: seed_count,
        provider: VARIANT_PROVIDER_ID.into(),
        packets,
        packet_digests,
        reused: false,
    }))
}

/// An already-compiled follow-up that still matches the parent.
fn reuse(
    dir: &Path,
    parent_digest: &str,
    confirmed_digest: &str,
    paths: &[String],
    analysis_paths: &[String],
    scope_relations: &Value,
    review_context: &Value,
) -> Option<FollowupPlanned> {
    let plan_json = read_json(&dir.join("plan.json")).ok()?;
    let frozen: AuditPlan =
        serde_json::from_value(read_json(&dir.join(FROZEN_PLAN_FILE)).ok()?).ok()?;
    let binding = frozen.followup_binding()?;
    let context_matches = plan_json.get("reviewContext") == Some(review_context)
        && frozen.providers.iter().all(|provider| {
            provider
                .configuration
                .get("reasoning")
                .and_then(|reasoning| reasoning.get("reviewContext"))
                == Some(review_context)
        })
        && dir.join("lens-dispatch.json").is_file()
        && dir.join(FOLLOWUP_CHAIN_FILE).is_file();
    let matches = context_matches
        && binding.get("parentPlanDigest").and_then(Value::as_str) == Some(parent_digest)
        && binding.get("confirmedDigest").and_then(Value::as_str) == Some(confirmed_digest)
        && binding.get("confirmedPaths") == Some(&json!(paths))
        && binding.get("analysisPaths") == Some(&json!(analysis_paths))
        && binding.get("scopeRelations") == Some(scope_relations)
        && binding.get("scopeVersion").and_then(Value::as_u64) == Some(2)
        && crate::integrity::plan_digest(&frozen).ok().as_deref()
            == plan_json.pointer("/seal/digest").and_then(Value::as_str);
    if !matches {
        return None;
    }
    let packets = variant_packets(dir).ok()?;
    let seeds = packets[0]
        .1
        .request
        .packet
        .get("variantSeeds")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let packet_digests = packets
        .iter()
        .map(|(_, work)| canonical_digest(&work.request.packet).ok())
        .collect::<Option<Vec<String>>>()?;
    Some(FollowupPlanned {
        dir: dir.to_path_buf(),
        plan_path: dir.join("plan.json"),
        plan_digest: seal_digest(&plan_json, "plan.json").ok()?,
        parent_plan_digest: parent_digest.to_owned(),
        confirmed_paths: paths.to_vec(),
        analysis_paths: analysis_paths.to_vec(),
        seeds,
        provider: VARIANT_PROVIDER_ID.into(),
        packets: packets.into_iter().map(|(path, _)| path).collect(),
        packet_digests,
        reused: true,
    })
}

/// What the parent `recompute_run` consults. Verifies the follow-up against
/// the parent: the signed follow-up plan, its binding to the parent plan digest
/// and to the confirmed verdicts, its exact path scope, and (through the
/// ordinary `recompute_run` on `<run>/followup`) the MAC'd variant receipt.
pub fn evaluate(
    run_dir: &Path,
    parent_plan: &Value,
    parent_execution: &ExecutionReport,
    confirmed: &[ConfirmedSecurityFinding],
) -> FollowupState {
    let dir = run_dir.join(FOLLOWUP_DIR);
    if !dir.join("plan.json").is_file() {
        return FollowupState::Absent;
    }
    check(run_dir, &dir, parent_plan, parent_execution, confirmed)
        .unwrap_or_else(|error| FollowupState::Invalid(error.to_string()))
}

fn check(
    run_dir: &Path,
    dir: &Path,
    parent_plan: &Value,
    parent_execution: &ExecutionReport,
    confirmed: &[ConfirmedSecurityFinding],
) -> Result<FollowupState, AuditError> {
    let parent_digest = seal_digest(parent_plan, "parent plan.json")?;
    if parent_digest != parent_execution.plan_digest {
        return Err(invalid(
            "parent plan.json seal differs from the executed parent plan",
        ));
    }
    let paths = scoped_paths(confirmed)?;
    let digest_of_confirmed = confirmed_digest(confirmed)?;
    let root = PathBuf::from(
        parent_plan
            .get("repository")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("parent plan.json has no repository root"))?,
    );
    let parent_revision = parent_plan
        .pointer("/binding/repositoryRevision")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("parent plan.json has no repository revision"))?;
    let parent_inventory_digest = parent_plan
        .pointer("/binding/inventoryDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("parent plan.json has no inventory digest"))?;
    let inventory = FilesystemInventorySource::new(&root)?.inventory(
        parent_plan
            .get("repository")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("parent plan.json has no repository root"))?,
    )?;
    if inventory.generation != parent_revision || inventory.digest != parent_inventory_digest {
        return Err(AuditError::SourceDrift(
            "the working tree no longer matches the frozen revision; rerun the audit".into(),
        ));
    }
    let (expected_analysis_paths, expected_scope_relations) =
        expanded_scope(&root, &inventory, &paths, &seeds(run_dir, confirmed)?)?;

    let plan_json = read_json(&dir.join("plan.json"))?;
    let frozen: AuditPlan = serde_json::from_value(read_json(&dir.join(FROZEN_PLAN_FILE))?)
        .map_err(|error| invalid(format!("{FROZEN_PLAN_FILE} is invalid: {error}")))?;
    let (_, epoch) = load_epoch(dir)?;
    if plan_json.pointer("/epoch/digest").and_then(Value::as_str) != Some(epoch.as_str()) {
        return Err(invalid("follow-up epoch key does not match its plan.json"));
    }
    // The follow-up plan key resolves through its own host-custody binding and
    // must be the parent's plan key: a fresh or substituted key is refused.
    let key = crate::integrity::plan_signing_key_for_run(dir)?;
    let parent_key = crate::integrity::plan_signing_key_for_run(run_dir)?;
    if key != parent_key {
        return Err(invalid(
            "follow-up plan is not signed with the parent plan key",
        ));
    }
    let digest = seal_digest(&plan_json, "follow-up plan.json")?;
    let signature = plan_json
        .pointer("/seal/signature")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("follow-up plan.json carries no signature"))?;
    crate::integrity::verify(&frozen, &digest, Some(signature), Some(key.as_slice()))?;
    verify_followup_generation(dir, parent_plan, &parent_digest, &parent_key, &frozen)?;

    let binding = frozen
        .bounds
        .get(FOLLOWUP_BOUND)
        .ok_or_else(|| invalid("follow-up plan carries no parent binding"))?;
    if binding.get("parentPlanDigest").and_then(Value::as_str) != Some(parent_digest.as_str()) {
        return Err(invalid(
            "follow-up plan is bound to a different parent plan digest",
        ));
    }
    if binding.get("confirmedDigest").and_then(Value::as_str) != Some(digest_of_confirmed.as_str())
    {
        return Err(invalid(
            "follow-up plan is bound to different confirmed verdicts",
        ));
    }
    if binding.get("confirmedPaths") != Some(&json!(paths)) {
        return Err(invalid(
            "follow-up plan is not scoped to the confirmed finding paths",
        ));
    }
    if binding.get("scopeVersion").and_then(Value::as_u64) != Some(2)
        || binding.get("analysisPaths") != Some(&json!(expected_analysis_paths))
        || binding.get("scopeRelations") != Some(&expected_scope_relations)
    {
        return Err(invalid(
            "follow-up plan does not match the deterministic sibling and caller scope",
        ));
    }
    let [provider] = frozen.providers.as_slice() else {
        return Err(invalid("follow-up plan must hold exactly one provider"));
    };
    let frozen_paths: BTreeSet<&str> = provider
        .configuration
        .get("selector")
        .and_then(|selector| selector.get("paths"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if provider.id != VARIANT_PROVIDER_ID
        || provider
            .configuration
            .get("selector")
            .and_then(|selector| selector.get("op"))
            .and_then(Value::as_str)
            != Some("confirmedSecurityFinding")
        || frozen_paths
            != expected_analysis_paths
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        || provider
            .configuration
            .get("denominatorCount")
            .and_then(Value::as_u64)
            != Some(expected_analysis_paths.len() as u64)
    {
        return Err(invalid(
            "follow-up provider is not the variant analysis over its frozen sibling and caller paths",
        ));
    }

    let execution: ExecutionReport =
        serde_json::from_value(read_json(&dir.join("execution.json"))?)
            .map_err(|error| invalid(format!("follow-up execution.json is invalid: {error}")))?;
    if execution.plan_digest != digest || execution.planned_providers != [VARIANT_PROVIDER_ID] {
        return Err(invalid("follow-up execution is not bound to its plan"));
    }
    let packets = variant_packets(dir)?;

    // The ordinary verdict recomputation over the follow-up run: receipts must
    // verify (MAC, epoch, plan binding, result digest).
    let recomputed = recompute_run(dir)?;
    // Every part of the variant denominator must be ingested: a part that is
    // not ingested leaves its paths uncovered, so the follow-up stays pending
    // and names the missing parts.
    let all_parts: Vec<u32> = packets
        .iter()
        .map(|(_, work)| work.part().map_or(1, |part| part.number))
        .collect();
    let ingested = recomputed
        .ingested
        .iter()
        .any(|id| id == VARIANT_PROVIDER_ID);
    let missing: Vec<u32> = if ingested {
        recomputed
            .lens_parts
            .get(VARIANT_PROVIDER_ID)
            .map_or_else(Vec::new, |progress| progress.pending.clone())
    } else {
        all_parts.clone()
    };
    if !missing.is_empty() {
        return Ok(FollowupState::Pending(parts_pending_reason(
            &missing,
            all_parts.len(),
        )));
    }
    if !recomputed.pending.is_empty() || !recomputed.report.gaps.is_empty() {
        return Ok(FollowupState::Pending(format!(
            "the follow-up is incomplete: {}",
            recomputed.report.gaps.join("; ")
        )));
    }
    let variant_ledger = match fs::read(dir.join(VARIANT_LEDGER_FILE)) {
        Ok(bytes) => {
            let ledger: VariantLedger = serde_json::from_slice(&bytes)
                .map_err(|error| invalid(format!("variant ledger is invalid: {error}")))?;
            ledger.verify_binding(
                &parent_digest,
                &digest,
                &digest_of_confirmed,
                expected_analysis_paths.len() as u64,
            )?;
            let (confirmed_receipts, rejected_receipts, _) = variant_receipt_counts(dir)?;
            if ledger.confirmed != confirmed_receipts || ledger.rejected != rejected_receipts {
                return Err(invalid(
                    "variant ledger disagrees with the authenticated variant receipts",
                ));
            }
            match ledger.assess() {
                LedgerAssessment::Complete => Some(ledger),
                LedgerAssessment::Incomplete(reason) => {
                    return Ok(FollowupState::Pending(format!(
                        "variant pass incomplete: {reason}"
                    )));
                }
                LedgerAssessment::Inconsistent(reason) => {
                    return Err(invalid(format!("variant ledger is inconsistent: {reason}")));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if VARIANT_LEDGER_REQUIRED {
                return Ok(FollowupState::Pending(
                    "variant pass incomplete: no variant ledger recorded".into(),
                ));
            }
            None
        }
        Err(error) => return Err(io(error, "could not read the variant ledger")),
    };
    Ok(FollowupState::Complete(FollowupDone {
        variant_ledger,
        plan_digest: digest,
        parent_plan_digest: parent_digest,
        confirmed_paths: paths,
        analysis_paths: expected_analysis_paths,
        findings: recomputed.report.findings,
    }))
}

/// True when `<run>/followup` exists (compiled or not yet verified).
pub fn exists(run_dir: &Path) -> bool {
    fs::metadata(run_dir.join(FOLLOWUP_DIR).join("plan.json")).is_ok()
}
