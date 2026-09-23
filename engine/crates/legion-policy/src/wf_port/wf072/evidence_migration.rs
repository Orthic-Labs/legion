//! Faithful port of `src/lib/verification/arcane/evidence-migration.mjs`.
//!
//! S05 — batch legacy-evidence migration receipt. Runs
//! `import_legacy_evidence` over a whole batch, registering every import as
//! untrusted, quarantining what cannot be read rather than aborting, and
//! emitting one deterministic migration receipt.
//!
//! Deviation from JS: `migrateLegacyEvidence` registers every import into a
//! `DependencyLedger` (`invalidation.mjs`, owned by a different chunk / not
//! yet ported here). This port takes a `ledger_register: impl FnMut(&str)`
//! callback in its place — the caller wires it to a real ledger once one
//! exists; wf072's own unit tests use a no-op / recording closure. This
//! preserves the exact "every import registered exactly once, before being
//! pushed to `imported`" ordering and side effect shape without requiring
//! wf072 to own or depend on the ledger's not-yet-wired module.

use super::evidence_envelope::{import_legacy_evidence, EnvelopeError, ImportedLegacyEvidence, LegacyEnvelope};
use super::support::{digest_value, Json};

#[derive(Debug, Clone)]
pub struct ParityRecord {
    pub record_id: String,
    pub status: &'static str, // "imported" | "quarantined" | "rejected"
    pub source_digest: String,
    pub destination_digest: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub record_id: String,
    pub source_digest: String,
    pub code: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct MigrationReceipt {
    pub schema: &'static str,
    pub deliverable: &'static str,
    pub lane: &'static str,
    pub destructive: bool,
    pub mapping_version: String,
    pub captured_at: String,
    pub source_record_count: usize,
    pub source_digest: String,
    pub destination_count: usize,
    pub destination_digest: String,
    pub record_count_matches: bool,
    pub per_record: Vec<ParityRecord>,
    pub quarantine: Vec<QuarantineEntry>,
    pub rejected: Vec<QuarantineEntry>,
    pub trust_granted: usize,
    pub receipt_digest: String,
}

#[derive(Debug, Clone)]
pub struct MigrationResult {
    pub receipt: MigrationReceipt,
    pub imported: Vec<(String, ImportedLegacyEvidence)>, // (recordId, envelope)
    pub quarantined: Vec<QuarantineEntry>,
    pub rejected: Vec<QuarantineEntry>,
}

fn legacy_envelope_json(l: &LegacyEnvelope) -> Json {
    Json::Obj(vec![
        ("kind".into(), Json::str(l.kind.clone())),
        ("legacyKind".into(), Json::str(l.legacy_kind.clone())),
        ("payload".into(), l.payload.clone()),
        ("authenticated".into(), Json::Bool(l.authenticated)),
        ("sourceRevision".into(), l.source_revision.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("source".into(), Json::str(l.source.clone())),
        ("capturedAt".into(), Json::str(l.captured_at.clone())),
    ])
}

/// Deterministic projection of an imported record for parity/digest
/// purposes: drops the volatile minted `evidenceId`, keeps everything else
/// (including the position-stable `recordId`). Mirrors JS
/// `projectForParity`.
fn project_for_parity(record_id: &str, envelope: &ImportedLegacyEvidence) -> Json {
    Json::Obj(vec![
        ("recordId".into(), Json::str(record_id)),
        ("runId".into(), envelope.run_id.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("legacyKind".into(), Json::str(envelope.legacy_kind.clone())),
        ("capability".into(), Json::str(envelope.capability.clone())),
        ("observation".into(), envelope.observation.clone()),
        ("evidenceClass".into(), Json::str(envelope.evidence_class.clone())),
        ("sourceRevision".into(), envelope.source_revision.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("authenticationIssuerIdentity".into(), Json::str(envelope.authentication_issuer_identity.clone())),
        ("trustClass".into(), Json::str(envelope.trust_class.clone())),
        ("neverQualifying".into(), Json::Bool(envelope.never_qualifying)),
        ("provisionalMappingRef".into(), envelope.provisional_mapping_ref.clone().map(Json::Str).unwrap_or(Json::Null)),
        ("observedAt".into(), Json::str(envelope.observed_at.clone())),
        ("stale".into(), Json::Bool(envelope.stale)),
    ])
}

/// Mirrors JS `migrateLegacyEvidence`. `mint_evidence_id` supplies what
/// `mintKernelId('evidenceReceipt')` would (see evidence_envelope's module
/// doc); `register_import` is the DependencyLedger substitution described in
/// this module's doc, called once per successfully imported record with
/// that record's assigned evidence id.
pub fn migrate_legacy_evidence(
    records: &[LegacyEnvelope],
    captured_at: &str,
    mapping_version: &str,
    mut mint_evidence_id: impl FnMut(usize) -> String,
    mut register_import: impl FnMut(&str),
) -> MigrationResult {
    let mut imported = Vec::new();
    let mut quarantined = Vec::new();
    let mut rejected = Vec::new();
    let mut per_record = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let record_id = format!("legacy-evidence#{index}");
        let source_digest = digest_value(&legacy_envelope_json(record));

        let evidence_id = mint_evidence_id(index);
        match import_legacy_evidence(record, evidence_id, None, Some("legacy-migration".into()), Some(captured_at.to_string())) {
            Ok(envelope) => {
                register_import(&envelope.evidence_id);
                let destination_digest = digest_value(&project_for_parity(&record_id, &envelope));
                per_record.push(ParityRecord {
                    record_id: record_id.clone(),
                    status: "imported",
                    source_digest: source_digest.clone(),
                    destination_digest: Some(destination_digest),
                    code: None,
                });
                imported.push((record_id, envelope));
            }
            Err(EnvelopeError { code, message }) => {
                let entry = QuarantineEntry {
                    record_id: record_id.clone(),
                    source_digest: source_digest.clone(),
                    code: Some(code.as_str().to_string()),
                    reason: message,
                };
                if code.as_str() == "ARC_AUTH_LEGACY_DIGEST" {
                    per_record.push(ParityRecord {
                        record_id: record_id.clone(),
                        status: "rejected",
                        source_digest,
                        destination_digest: None,
                        code: Some("ARC_AUTH_LEGACY_DIGEST".into()),
                    });
                    rejected.push(entry);
                } else {
                    per_record.push(ParityRecord {
                        record_id: record_id.clone(),
                        status: "quarantined",
                        source_digest,
                        destination_digest: None,
                        code: Some(code.as_str().to_string()),
                    });
                    quarantined.push(entry);
                }
            }
        }
    }

    let source_digest_agg = digest_value(&Json::Arr(per_record.iter().map(|r| Json::str(r.source_digest.clone())).collect()));
    let destination_digest_agg = digest_value(&Json::Arr(
        imported.iter().map(|(rid, env)| project_for_parity(rid, env)).collect(),
    ));

    // Trust tally: must always read 0. Recomputed from what was actually
    // imported (not hardcoded).
    let trust_granted = imported
        .iter()
        .filter(|(_, e)| e.trust_class != "legacy-unauthenticated" || !e.never_qualifying)
        .count();

    let record_count_matches = records.len() == imported.len() + quarantined.len() + rejected.len();

    let receipt_core = Json::Obj(vec![
        ("schema".into(), Json::str("arcane.evidence-migration-receipt.v1")),
        ("deliverable".into(), Json::str("S05")),
        ("lane".into(), Json::str("E-ARCANE")),
        ("destructive".into(), Json::Bool(false)),
        ("mappingVersion".into(), Json::str(mapping_version)),
        ("capturedAt".into(), Json::str(captured_at)),
        ("source".into(), Json::Obj(vec![
            ("recordCount".into(), Json::I64(records.len() as i64)),
            ("digest".into(), Json::str(source_digest_agg.clone())),
        ])),
        ("destination".into(), Json::Obj(vec![
            ("namespace".into(), Json::str("arcane")),
            ("count".into(), Json::I64(imported.len() as i64)),
            ("digest".into(), Json::str(destination_digest_agg.clone())),
        ])),
        ("parity".into(), Json::Obj(vec![
            ("recordCountMatches".into(), Json::Bool(record_count_matches)),
        ])),
        ("quarantine".into(), Json::Obj(vec![
            ("count".into(), Json::I64(quarantined.len() as i64)),
            ("ids".into(), Json::Arr(quarantined.iter().map(|q| Json::str(q.record_id.clone())).collect())),
        ])),
        ("rejected".into(), Json::Obj(vec![
            ("count".into(), Json::I64(rejected.len() as i64)),
            ("ids".into(), Json::Arr(rejected.iter().map(|r| Json::str(r.record_id.clone())).collect())),
        ])),
        ("trust".into(), Json::Obj(vec![("trustGranted".into(), Json::I64(trust_granted as i64))])),
        ("rollback".into(), Json::Obj(vec![
            ("method".into(), Json::str("migration performs no destructive rewrite")),
            ("reversible".into(), Json::Bool(true)),
        ])),
    ]);
    let receipt_digest = digest_value(&receipt_core);

    let receipt = MigrationReceipt {
        schema: "arcane.evidence-migration-receipt.v1",
        deliverable: "S05",
        lane: "E-ARCANE",
        destructive: false,
        mapping_version: mapping_version.to_string(),
        captured_at: captured_at.to_string(),
        source_record_count: records.len(),
        source_digest: source_digest_agg,
        destination_count: imported.len(),
        destination_digest: destination_digest_agg,
        record_count_matches,
        per_record,
        quarantine: quarantined.clone(),
        rejected: rejected.clone(),
        trust_granted,
        receipt_digest,
    };

    MigrationResult { receipt, imported, quarantined, rejected }
}

#[derive(Debug, Clone)]
pub struct Mismatch {
    pub field: String,
    pub record_id: Option<String>,
}

/// Re-run the migration projection over `records` and diff against a
/// previously issued `receipt`. Never trusts the receipt's own claims —
/// recomputes from scratch. Mirrors JS `verifyMigration`.
pub fn verify_migration(
    receipt: &MigrationReceipt,
    records: &[LegacyEnvelope],
    captured_at: &str,
    mapping_version: &str,
    mint_evidence_id: impl FnMut(usize) -> String,
) -> Vec<Mismatch> {
    let fresh = migrate_legacy_evidence(records, captured_at, mapping_version, mint_evidence_id, |_| {});
    let mut mismatches = Vec::new();

    if receipt.source_record_count != fresh.receipt.source_record_count {
        mismatches.push(Mismatch { field: "source.recordCount".into(), record_id: None });
    }
    if receipt.source_digest != fresh.receipt.source_digest {
        mismatches.push(Mismatch { field: "source.digest".into(), record_id: None });
    }
    if receipt.destination_count != fresh.receipt.destination_count {
        mismatches.push(Mismatch { field: "destination.count".into(), record_id: None });
    }
    if receipt.destination_digest != fresh.receipt.destination_digest {
        mismatches.push(Mismatch { field: "destination.digest".into(), record_id: None });
    }

    for fresh_rec in &fresh.receipt.per_record {
        let orig = receipt.per_record.iter().find(|r| r.record_id == fresh_rec.record_id);
        match orig {
            None => mismatches.push(Mismatch { field: "parity.perRecord".into(), record_id: Some(fresh_rec.record_id.clone()) }),
            Some(orig) => {
                if orig.status != fresh_rec.status
                    || orig.source_digest != fresh_rec.source_digest
                    || orig.destination_digest != fresh_rec.destination_digest
                {
                    mismatches.push(Mismatch { field: "parity.perRecord".into(), record_id: Some(fresh_rec.record_id.clone()) });
                }
            }
        }
    }

    mismatches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy(authenticated: bool) -> LegacyEnvelope {
        LegacyEnvelope {
            kind: "legion-legacy-envelope".into(),
            legacy_kind: "k".into(),
            payload: Json::str("p"),
            authenticated,
            source_revision: Some("git:1".into()),
            source: "legacy-tool".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            provisional_mapping_ref: None,
        }
    }

    fn malformed() -> LegacyEnvelope {
        LegacyEnvelope {
            kind: "not-legacy".into(),
            legacy_kind: "k".into(),
            payload: Json::Null,
            authenticated: false,
            source_revision: None,
            source: "s".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            provisional_mapping_ref: None,
        }
    }

    #[test]
    fn migrate_imports_valid_records_and_trust_granted_is_always_zero() {
        let records = vec![legacy(false), legacy(false)];
        let mut registered = Vec::new();
        let result = migrate_legacy_evidence(&records, "2026-01-01T00:00:00Z", "v1", |i| format!("ev-{i}"), |id| registered.push(id.to_string()));
        assert_eq!(result.imported.len(), 2);
        assert_eq!(result.receipt.trust_granted, 0);
        assert_eq!(registered.len(), 2);
        assert!(result.receipt.record_count_matches);
    }

    #[test]
    fn migrate_quarantines_malformed_records_without_aborting_batch() {
        let records = vec![legacy(false), malformed(), legacy(false)];
        let result = migrate_legacy_evidence(&records, "2026-01-01T00:00:00Z", "v1", |i| format!("ev-{i}"), |_| {});
        assert_eq!(result.imported.len(), 2);
        assert_eq!(result.quarantined.len(), 1);
        assert_eq!(result.quarantined[0].record_id, "legacy-evidence#1");
        assert!(result.receipt.record_count_matches);
    }

    #[test]
    fn migrate_rejects_authenticated_true_records_separately_from_quarantine() {
        let records = vec![legacy(true)];
        let result = migrate_legacy_evidence(&records, "2026-01-01T00:00:00Z", "v1", |i| format!("ev-{i}"), |_| {});
        assert_eq!(result.rejected.len(), 1);
        assert_eq!(result.quarantined.len(), 0);
        assert_eq!(result.rejected[0].code.as_deref(), Some("ARC_AUTH_LEGACY_DIGEST"));
    }

    #[test]
    fn verify_migration_detects_no_mismatch_for_identical_rerun() {
        let records = vec![legacy(false), malformed()];
        let result = migrate_legacy_evidence(&records, "2026-01-01T00:00:00Z", "v1", |i| format!("ev-{i}"), |_| {});
        let mismatches = verify_migration(&result.receipt, &records, "2026-01-01T00:00:00Z", "v1", |i| format!("ev-{i}"));
        assert!(mismatches.is_empty(), "{mismatches:?}");
    }

    #[test]
    fn verify_migration_detects_digest_mismatch_when_records_change() {
        let records = vec![legacy(false)];
        let result = migrate_legacy_evidence(&records, "2026-01-01T00:00:00Z", "v1", |i| format!("ev-{i}"), |_| {});
        let changed_records = vec![legacy(false), legacy(false)];
        let mismatches = verify_migration(&result.receipt, &changed_records, "2026-01-01T00:00:00Z", "v1", |i| format!("ev-{i}"));
        assert!(!mismatches.is_empty());
    }
}
