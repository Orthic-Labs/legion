//! Faithful port of `src/lib/verification/arcane/adversarial-ai-reconstruction.mjs`.
//!
//! Runtime controls for two adversarial architecture cases. Both accept
//! structured operator evidence, compute their own verdict, and expose an
//! observation validator which recomputes it instead of trusting supplied
//! output.

use std::collections::BTreeSet;

pub const AI_RECONSTRUCTION_BINDING_IDS: [&str; 2] = ["AE-ADVERSARIAL-009", "AE-ADVERSARIAL-010"];

// Mirrors JS `AI_REQUIRED`, which is declared but likewise unused there —
// `assess_ai_readiness` inlines the same four checks.
#[allow(dead_code)]
const AI_REQUIRED: [&str; 4] = ["provenance", "evaluation", "fallback", "humanAuthority"];
const RECONSTRUCTION_REQUIRED: [&str; 4] = ["topology", "runtime", "deployment", "ownership"];

fn non_empty(value: Option<&str>) -> bool {
    matches!(value, Some(v) if !v.trim().is_empty())
}

/// Parses an RFC3339-ish timestamp the same way `Date.parse` would for the
/// ISO strings this module actually receives (`YYYY-MM-DDTHH:MM:SSZ` and
/// with fractional seconds / explicit offsets). Returns epoch millis.
fn parse_iso(value: &str) -> Option<i64> {
    // Minimal, dependency-free ISO-8601 parser sufficient for the fixed-offset
    // and 'Z'-suffixed timestamps these modules exchange.
    let (date_part, rest) = value.split_once('T')?;
    let mut date_it = date_part.split('-');
    let year: i64 = date_it.next()?.parse().ok()?;
    let month: i64 = date_it.next()?.parse().ok()?;
    let day: i64 = date_it.next()?.parse().ok()?;
    if date_it.next().is_some() {
        return None;
    }

    let (offset_sign, offset_min, time_str) = if let Some(stripped) = rest.strip_suffix('Z') {
        (0i64, 0i64, stripped)
    } else if let Some(pos) = rest.rfind(['+', '-']) {
        // Only treat as an offset if it comes after any time component.
        if pos == 0 {
            return None;
        }
        let (t, off) = rest.split_at(pos);
        let sign = if &off[0..1] == "-" { -1 } else { 1 };
        let off = &off[1..];
        let mut it = off.split(':');
        let oh: i64 = it.next()?.parse().ok()?;
        let om: i64 = it.next().unwrap_or("0").parse().ok()?;
        (sign, oh * 60 + om, t)
    } else {
        (0i64, 0i64, rest)
    };

    let mut time_it = time_str.split(':');
    let hour: i64 = time_it.next()?.parse().ok()?;
    let minute: i64 = time_it.next()?.parse().ok()?;
    let sec_str = time_it.next()?;
    let (sec, millis) = if let Some((s, frac)) = sec_str.split_once('.') {
        let s: i64 = s.parse().ok()?;
        let mut frac = frac.to_string();
        frac.truncate(3);
        while frac.len() < 3 {
            frac.push('0');
        }
        (s, frac.parse::<i64>().ok()?)
    } else {
        (sec_str.parse().ok()?, 0)
    };

    let days = days_from_civil(year, month, day)?;
    let millis_of_day = ((hour * 60 + minute) * 60 + sec) * 1000 + millis;
    let total = days * 86_400_000 + millis_of_day - offset_sign * offset_min * 60_000;
    Some(total)
}

/// Howard Hinnant's `days_from_civil`, days since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn iso_time(value: Option<&str>) -> bool {
    non_empty(value) && parse_iso(value.unwrap()).is_some()
}

#[derive(Debug, Default, Clone)]
pub struct ProvenanceEntry {
    pub source_ref: Option<String>,
    pub digest: Option<String>,
}

fn valid_provenance(entry: &ProvenanceEntry) -> bool {
    non_empty(entry.source_ref.as_deref()) && non_empty(entry.digest.as_deref())
}

#[derive(Debug, Default, Clone)]
pub struct Evaluation {
    pub status: Option<String>,
    pub report_ref: Option<String>,
    pub evaluated_at: Option<String>,
    pub has_metrics: bool,
}

fn valid_evaluation(value: Option<&Evaluation>) -> bool {
    match value {
        Some(v) => {
            v.status.as_deref() == Some("PASS")
                && non_empty(v.report_ref.as_deref())
                && iso_time(v.evaluated_at.as_deref())
                && v.has_metrics
        }
        None => false,
    }
}

#[derive(Debug, Default, Clone)]
pub struct Fallback {
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub tested_at: Option<String>,
}

fn valid_fallback(value: Option<&Fallback>) -> bool {
    match value {
        Some(v) => {
            non_empty(v.mode.as_deref()) && non_empty(v.owner.as_deref()) && iso_time(v.tested_at.as_deref())
        }
        None => false,
    }
}

#[derive(Debug, Default, Clone)]
pub struct HumanAuthority {
    pub role: Option<String>,
    pub authority_ref: Option<String>,
    pub approved_at: Option<String>,
}

fn valid_human_authority(value: Option<&HumanAuthority>) -> bool {
    match value {
        Some(v) => {
            non_empty(v.role.as_deref())
                && non_empty(v.authority_ref.as_deref())
                && iso_time(v.approved_at.as_deref())
        }
        None => false,
    }
}

#[derive(Debug, Default, Clone)]
pub struct AiReadinessInput {
    pub system_id: Option<String>,
    pub provenance: Vec<ProvenanceEntry>,
    pub evaluation: Option<Evaluation>,
    pub fallback: Option<Fallback>,
    pub human_authority: Option<HumanAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiReadinessResult {
    pub system_id: Option<String>,
    pub disposition: &'static str,
    pub readiness: bool,
    pub missing: Vec<&'static str>,
    pub provenance_records: usize,
    pub evaluation_verified: bool,
    pub fallback_tested: bool,
    pub human_authority_bound: bool,
}

/// Return a readiness verdict for an AI-containing system. Readiness is
/// strictly conjunctive: provenance, evaluated behavior, tested fallback, and
/// a named human authority must each be present in caller-supplied evidence.
pub fn assess_ai_readiness(input: &AiReadinessInput) -> AiReadinessResult {
    let mut missing = Vec::new();
    let provenance_ok = !input.provenance.is_empty() && input.provenance.iter().all(valid_provenance);
    if !provenance_ok {
        missing.push("provenance");
    }
    let evaluation_ok = valid_evaluation(input.evaluation.as_ref());
    if !evaluation_ok {
        missing.push("evaluation");
    }
    let fallback_ok = valid_fallback(input.fallback.as_ref());
    if !fallback_ok {
        missing.push("fallback");
    }
    let human_ok = valid_human_authority(input.human_authority.as_ref());
    if !human_ok {
        missing.push("humanAuthority");
    }

    let readiness = missing.is_empty();
    AiReadinessResult {
        system_id: input.system_id.clone(),
        disposition: if readiness { "READY" } else { "NOT_READY" },
        readiness,
        missing,
        provenance_records: input.provenance.iter().filter(|e| valid_provenance(e)).count(),
        evaluation_verified: evaluation_ok,
        fallback_tested: fallback_ok,
        human_authority_bound: human_ok,
    }
}

#[derive(Debug, Default, Clone)]
pub struct EvidenceEntry {
    pub scope: Option<String>,
    pub source_ref: Option<String>,
    pub observed_at: Option<String>,
    pub expires_at: Option<String>,
}

fn current_evidence(entry: &EvidenceEntry, as_of_millis: i64) -> bool {
    non_empty(entry.scope.as_deref())
        && non_empty(entry.source_ref.as_deref())
        && iso_time(entry.observed_at.as_deref())
        && iso_time(entry.expires_at.as_deref())
        && parse_iso(entry.observed_at.as_deref().unwrap()).unwrap() <= as_of_millis
        && parse_iso(entry.expires_at.as_deref().unwrap()).unwrap() >= as_of_millis
}

#[derive(Debug, Default, Clone)]
pub struct ArchitectureReconstructionInput {
    pub as_of: Option<String>,
    pub required_scopes: Vec<String>,
    pub evidence: Vec<EvidenceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchitectureReconstructionResult {
    pub as_of: Option<String>,
    pub disposition: &'static str,
    pub conclusion_allowed: bool,
    pub clean_allowed: bool,
    pub required_scopes: Vec<String>,
    pub observed_scopes: Vec<String>,
    pub missing_scopes: Vec<String>,
    pub stale_scopes: Vec<String>,
    pub uncertainty_present: bool,
    pub uncertainty_reason: Option<&'static str>,
}

/// Assess a reconstruction from actual evidence coverage. Any required scope
/// that is missing, malformed, or expired makes the result explicitly
/// uncertain; callers cannot claim a broad clean conclusion from that result.
pub fn assess_architecture_reconstruction(
    input: &ArchitectureReconstructionInput,
) -> ArchitectureReconstructionResult {
    let as_of_valid = input.as_of.as_deref().map(iso_time_str).unwrap_or(false);
    let as_of = if as_of_valid { input.as_of.clone() } else { None };
    let as_of_millis = as_of.as_deref().and_then(parse_iso);

    let required_scopes: BTreeSet<String> = if !input.required_scopes.is_empty() {
        input
            .required_scopes
            .iter()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .collect()
    } else {
        RECONSTRUCTION_REQUIRED.iter().map(|s| s.to_string()).collect()
    };
    let mut required_scopes: Vec<String> = required_scopes.into_iter().collect();
    required_scopes.sort();

    let mut fresh_scopes: BTreeSet<String> = BTreeSet::new();
    let mut stale_scopes: BTreeSet<String> = BTreeSet::new();
    if let Some(as_of_ms) = as_of_millis {
        for entry in &input.evidence {
            if current_evidence(entry, as_of_ms) {
                if let Some(scope) = &entry.scope {
                    fresh_scopes.insert(scope.clone());
                }
            }
        }
        for entry in &input.evidence {
            if let (Some(scope), Some(expires_at)) = (&entry.scope, &entry.expires_at) {
                if !scope.trim().is_empty() {
                    if let Some(exp) = parse_iso(expires_at) {
                        if exp < as_of_ms {
                            stale_scopes.insert(scope.clone());
                        }
                    }
                }
            }
        }
    }

    let missing_scopes: Vec<String> = required_scopes
        .iter()
        .filter(|scope| !fresh_scopes.contains(*scope))
        .cloned()
        .collect();
    let uncertainty = as_of_millis.is_none() || !missing_scopes.is_empty();

    ArchitectureReconstructionResult {
        as_of,
        disposition: if uncertainty { "UNCERTAINTY_REPORTED" } else { "RECONSTRUCTION_READY" },
        conclusion_allowed: !uncertainty,
        clean_allowed: !uncertainty,
        required_scopes,
        observed_scopes: fresh_scopes.into_iter().collect(),
        missing_scopes: missing_scopes.clone(),
        stale_scopes: stale_scopes.into_iter().collect(),
        uncertainty_present: uncertainty,
        uncertainty_reason: if as_of_millis.is_none() {
            Some("INVALID_AS_OF")
        } else if !missing_scopes.is_empty() {
            Some("INCOMPLETE_OR_STALE_EVIDENCE")
        } else {
            None
        },
    }
}

fn iso_time_str(value: &str) -> bool {
    iso_time(Some(value))
}

/// Executor-friendly production binding, mirroring
/// `executeAdversarialAiReconstructionCase`.
pub enum ReconstructionCase {
    AiReadiness(AiReadinessResult),
    ArchitectureReconstruction(ArchitectureReconstructionResult),
    UnknownCase,
}

pub fn execute_adversarial_ai_reconstruction_case(
    id: &str,
    readiness_input: Option<&AiReadinessInput>,
    reconstruction_input: Option<&ArchitectureReconstructionInput>,
) -> ReconstructionCase {
    match id {
        "AE-ADVERSARIAL-009" => ReconstructionCase::AiReadiness(assess_ai_readiness(
            readiness_input.cloned_or_default(),
        )),
        "AE-ADVERSARIAL-010" => ReconstructionCase::ArchitectureReconstruction(
            assess_architecture_reconstruction(reconstruction_input.cloned_or_default()),
        ),
        _ => ReconstructionCase::UnknownCase,
    }
}

// Small helper trait so `execute_adversarial_ai_reconstruction_case` can
// accept `Option<&T>` and fall back to `T::default()` the way the JS
// `input = {}` default parameter does.
trait OrDefaultRef<T> {
    fn cloned_or_default(self) -> T;
}
impl OrDefaultRef<AiReadinessInput> for Option<&AiReadinessInput> {
    fn cloned_or_default(self) -> AiReadinessInput {
        self.cloned().unwrap_or_default()
    }
}
impl OrDefaultRef<ArchitectureReconstructionInput> for Option<&ArchitectureReconstructionInput> {
    fn cloned_or_default(self) -> ArchitectureReconstructionInput {
        self.cloned().unwrap_or_default()
    }
}

/// Validate output by recalculating it from recorded structured input. This
/// rejects a forged verdict even if its text resembles expected corpus prose.
pub fn validate_ai_readiness_observation(input: &AiReadinessInput, observed: &AiReadinessResult) -> bool {
    &assess_ai_readiness(input) == observed
}

pub fn validate_architecture_reconstruction_observation(
    input: &ArchitectureReconstructionInput,
    observed: &ArchitectureReconstructionResult,
) -> bool {
    &assess_architecture_reconstruction(input) == observed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_input() -> AiReadinessInput {
        AiReadinessInput {
            system_id: Some("sys-1".into()),
            provenance: vec![ProvenanceEntry { source_ref: Some("repo@sha".into()), digest: Some("sha256:aa".into()) }],
            evaluation: Some(Evaluation {
                status: Some("PASS".into()),
                report_ref: Some("report-1".into()),
                evaluated_at: Some("2026-01-01T00:00:00Z".into()),
                has_metrics: true,
            }),
            fallback: Some(Fallback {
                mode: Some("manual".into()),
                owner: Some("ops".into()),
                tested_at: Some("2026-01-01T00:00:00Z".into()),
            }),
            human_authority: Some(HumanAuthority {
                role: Some("lead".into()),
                authority_ref: Some("charter-1".into()),
                approved_at: Some("2026-01-01T00:00:00Z".into()),
            }),
        }
    }

    #[test]
    fn ai_readiness_ready_when_all_evidence_present() {
        let result = assess_ai_readiness(&ready_input());
        assert!(result.readiness);
        assert_eq!(result.disposition, "READY");
        assert!(result.missing.is_empty());
        assert_eq!(result.provenance_records, 1);
    }

    #[test]
    fn ai_readiness_not_ready_when_evidence_missing() {
        let result = assess_ai_readiness(&AiReadinessInput::default());
        assert!(!result.readiness);
        assert_eq!(result.disposition, "NOT_READY");
        assert_eq!(result.missing, vec!["provenance", "evaluation", "fallback", "humanAuthority"]);
    }

    #[test]
    fn ai_readiness_validator_recomputes_rather_than_trusts() {
        let input = ready_input();
        let mut forged = assess_ai_readiness(&input);
        forged.readiness = true;
        forged.disposition = "READY";
        // Tamper independent of input: validator must recompute, not trust.
        let mut bad_input = input.clone();
        bad_input.human_authority = None;
        assert!(!validate_ai_readiness_observation(&bad_input, &forged));
        assert!(validate_ai_readiness_observation(&input, &assess_ai_readiness(&input)));
    }

    fn evidence(scope: &str, observed_at: &str, expires_at: &str) -> EvidenceEntry {
        EvidenceEntry {
            scope: Some(scope.into()),
            source_ref: Some("src".into()),
            observed_at: Some(observed_at.into()),
            expires_at: Some(expires_at.into()),
        }
    }

    #[test]
    fn reconstruction_ready_when_all_scopes_fresh() {
        let input = ArchitectureReconstructionInput {
            as_of: Some("2026-06-01T00:00:00Z".into()),
            required_scopes: vec![],
            evidence: vec![
                evidence("topology", "2026-05-01T00:00:00Z", "2026-12-01T00:00:00Z"),
                evidence("runtime", "2026-05-01T00:00:00Z", "2026-12-01T00:00:00Z"),
                evidence("deployment", "2026-05-01T00:00:00Z", "2026-12-01T00:00:00Z"),
                evidence("ownership", "2026-05-01T00:00:00Z", "2026-12-01T00:00:00Z"),
            ],
        };
        let result = assess_architecture_reconstruction(&input);
        assert_eq!(result.disposition, "RECONSTRUCTION_READY");
        assert!(result.conclusion_allowed);
        assert!(result.clean_allowed);
        assert!(result.missing_scopes.is_empty());
    }

    #[test]
    fn reconstruction_uncertain_when_as_of_invalid() {
        let input = ArchitectureReconstructionInput { as_of: None, required_scopes: vec![], evidence: vec![] };
        let result = assess_architecture_reconstruction(&input);
        assert_eq!(result.disposition, "UNCERTAINTY_REPORTED");
        assert!(!result.conclusion_allowed);
        assert_eq!(result.uncertainty_reason, Some("INVALID_AS_OF"));
    }

    #[test]
    fn reconstruction_uncertain_when_scope_stale() {
        let input = ArchitectureReconstructionInput {
            as_of: Some("2026-06-01T00:00:00Z".into()),
            required_scopes: vec!["topology".into()],
            evidence: vec![evidence("topology", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")],
        };
        let result = assess_architecture_reconstruction(&input);
        assert_eq!(result.disposition, "UNCERTAINTY_REPORTED");
        assert_eq!(result.uncertainty_reason, Some("INCOMPLETE_OR_STALE_EVIDENCE"));
        assert_eq!(result.stale_scopes, vec!["topology".to_string()]);
        assert_eq!(result.missing_scopes, vec!["topology".to_string()]);
    }

    #[test]
    fn execute_case_dispatches_by_id() {
        let ready = ready_input();
        match execute_adversarial_ai_reconstruction_case("AE-ADVERSARIAL-009", Some(&ready), None) {
            ReconstructionCase::AiReadiness(r) => assert!(r.readiness),
            _ => panic!("expected AiReadiness case"),
        }
        match execute_adversarial_ai_reconstruction_case("AE-ADVERSARIAL-999", None, None) {
            ReconstructionCase::UnknownCase => {}
            _ => panic!("expected unknown case"),
        }
    }

    #[test]
    fn binding_ids_match_js_constant() {
        assert_eq!(AI_RECONSTRUCTION_BINDING_IDS, ["AE-ADVERSARIAL-009", "AE-ADVERSARIAL-010"]);
    }
}
