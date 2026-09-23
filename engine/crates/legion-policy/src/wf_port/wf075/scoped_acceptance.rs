//! Faithful port of `src/lib/verification/arcane/scoped-acceptance.mjs`.
//!
//! Uses wf070's `CanonVal`/`digest_value` (`crate::wf_port::wf070::canon`)
//! rather than introducing a JSON-value dependency of its own — see this
//! packet's report for why (`legion-policy`'s `Cargo.toml` is not this
//! owner's file).

use std::collections::{BTreeMap, BTreeSet};

use crate::wf_port::wf070::canon::{digest_value, CanonVal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedAcceptanceError(pub String);
impl std::fmt::Display for ScopedAcceptanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ScopedAcceptanceError {}

fn fail<T>(message: impl Into<String>) -> Result<T, ScopedAcceptanceError> {
    Err(ScopedAcceptanceError(message.into()))
}

/// Mirrors `ITEM_FIELDS`: the exact key set `pick()` projects out of an
/// acceptance item before fingerprinting it.
const ITEM_FIELDS: &[&str] = &[
    "acceptance_id", "id", "disposition", "source", "requirement", "outcome",
    "source_files", "owner", "producer", "dependencies",
    "observable_acceptance_surface", "observable_surface", "observable_exit",
    "positive_test", "negative_test", "evidence_producer", "exclusions",
    "adoption_stage", "verification_method", "revisit_trigger",
];

/// Mirrors `pick(value, fields)`: keeps a field only when the source object
/// *has* the key — `undefined` (absent key) is dropped, but an explicit
/// `null` value is kept, exactly like the JS `value[field] !== undefined`
/// check.
fn pick(value: &CanonVal, fields: &[&str]) -> CanonVal {
    let mut out = BTreeMap::new();
    if let Some(map) = value.as_obj() {
        for field in fields {
            if let Some(v) = map.get(*field) {
                out.insert((*field).to_string(), v.clone());
            }
        }
    }
    CanonVal::Obj(out)
}

/// Mirrors `itemId(item) = item.acceptance_id ?? item.id` — nullish
/// coalescing, so an explicit `null` `acceptance_id` still falls through to
/// `id`.
fn item_id(item: &CanonVal) -> Option<String> {
    let obj = item.as_obj()?;
    let acceptance_id = obj.get("acceptance_id").filter(|v| !matches!(v, CanonVal::Null));
    let candidate = acceptance_id.or_else(|| obj.get("id"));
    candidate.and_then(CanonVal::as_str).map(str::to_string)
}

/// Mirrors `fingerprintAcceptanceItem`.
pub fn fingerprint_acceptance_item(item: &CanonVal) -> Result<String, ScopedAcceptanceError> {
    if item_id(item).is_none() {
        return fail("acceptance item requires acceptance_id or id");
    }
    Ok(digest_value(&pick(item, ITEM_FIELDS)))
}

fn stage_id(stage: &CanonVal) -> Option<String> {
    stage.get("stage_id").and_then(CanonVal::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

fn required_items(stage: &CanonVal) -> Vec<CanonVal> {
    stage.get("required_items").and_then(CanonVal::as_arr).cloned().unwrap_or_default()
}

fn dependencies(stage: &CanonVal) -> Vec<CanonVal> {
    stage.get("dependencies").and_then(CanonVal::as_arr).cloned().unwrap_or_default()
}

/// Mirrors `fingerprintAcceptanceStage`.
pub fn fingerprint_acceptance_stage(stage: &CanonVal) -> Result<String, ScopedAcceptanceError> {
    let Some(sid) = stage_id(stage) else {
        return fail("acceptance stage requires stage_id");
    };
    let mut required_item_fps = Vec::new();
    for item in required_items(stage) {
        let Some(id) = item_id(&item) else {
            return fail("acceptance item requires acceptance_id or id");
        };
        let fp = fingerprint_acceptance_item(&item)?;
        required_item_fps.push(
            CanonVal::obj().set("acceptance_id", CanonVal::Str(id)).set("contract_fingerprint", CanonVal::Str(fp)),
        );
    }
    let owner = stage.get("owner").cloned().unwrap_or(CanonVal::Null);
    let value = CanonVal::obj()
        .set("stage_id", CanonVal::Str(sid))
        .set("owner", owner)
        .set("dependencies", CanonVal::Arr(dependencies(stage)))
        .set("required_items", CanonVal::Arr(required_item_fps));
    Ok(digest_value(&value))
}

/// Mirrors `fingerprintExecutionSchedule`.
pub fn fingerprint_execution_schedule(schedule: &CanonVal) -> String {
    let schedule_version = schedule.get("schedule_version").cloned().unwrap_or(CanonVal::Null);
    let waves = schedule.get("waves").cloned().unwrap_or(CanonVal::Null);
    digest_value(&CanonVal::obj().set("schedule_version", schedule_version).set("waves", waves))
}

#[derive(Debug, Clone)]
pub struct CompiledScopedAcceptance {
    pub stage_fingerprints: BTreeMap<String, String>,
    pub acceptance_manifest_fingerprint: String,
    pub schedule_fingerprint: String,
}

/// Mirrors `compileScopedAcceptance`.
pub fn compile_scoped_acceptance(
    stages: &[CanonVal],
    schedule: &CanonVal,
) -> Result<CompiledScopedAcceptance, ScopedAcceptanceError> {
    let mut stage_fingerprints = BTreeMap::new();
    for stage in stages {
        let Some(sid) = stage_id(stage) else {
            return fail("acceptance stage requires stage_id");
        };
        stage_fingerprints.insert(sid, fingerprint_acceptance_stage(stage)?);
    }
    let manifest_value = CanonVal::Obj(
        stage_fingerprints.iter().map(|(k, v)| (k.clone(), CanonVal::Str(v.clone()))).collect(),
    );
    Ok(CompiledScopedAcceptance {
        acceptance_manifest_fingerprint: digest_value(&manifest_value),
        schedule_fingerprint: fingerprint_execution_schedule(schedule),
        stage_fingerprints,
    })
}

/// Mirrors `descendants`: the transitive closure of every stage that
/// depends (directly or indirectly) on a stage in `changed_ids`.
fn descendants(stages: &[CanonVal], changed_ids: &BTreeSet<String>) -> BTreeSet<String> {
    let mut affected = changed_ids.clone();
    loop {
        let mut grew = false;
        for stage in stages {
            let Some(sid) = stage_id(stage) else { continue };
            if affected.contains(&sid) {
                continue;
            }
            let deps: BTreeSet<String> =
                dependencies(stage).iter().filter_map(CanonVal::as_str).map(str::to_string).collect();
            if deps.iter().any(|d| affected.contains(d)) {
                affected.insert(sid);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    affected
}

#[derive(Debug, Clone)]
pub struct ScopedAcceptanceSpec<'a> {
    pub stages: &'a [CanonVal],
    pub schedule: &'a CanonVal,
}

#[derive(Debug, Clone)]
pub struct ScopedAcceptanceDiff {
    pub schedule_changed: bool,
    pub acceptance_changed: bool,
    pub directly_changed_stage_ids: Vec<String>,
    pub invalidated_stage_ids: Vec<String>,
    pub preserved_stage_ids: Vec<String>,
    pub before: CompiledScopedAcceptance,
    pub after: CompiledScopedAcceptance,
}

/// Mirrors `diffScopedAcceptance`.
pub fn diff_scoped_acceptance(
    previous: &ScopedAcceptanceSpec,
    next: &ScopedAcceptanceSpec,
) -> Result<ScopedAcceptanceDiff, ScopedAcceptanceError> {
    let before = compile_scoped_acceptance(previous.stages, previous.schedule)?;
    let after = compile_scoped_acceptance(next.stages, next.schedule)?;

    let mut all_ids: BTreeSet<String> = before.stage_fingerprints.keys().cloned().collect();
    all_ids.extend(after.stage_fingerprints.keys().cloned());

    let directly_changed_stage_ids: BTreeSet<String> = all_ids
        .iter()
        .filter(|id| before.stage_fingerprints.get(*id) != after.stage_fingerprints.get(*id))
        .cloned()
        .collect();

    let mut invalidated: BTreeSet<String> = descendants(previous.stages, &directly_changed_stage_ids);
    invalidated.extend(descendants(next.stages, &directly_changed_stage_ids));

    let preserved: Vec<String> = all_ids.iter().filter(|id| !invalidated.contains(*id)).cloned().collect();

    Ok(ScopedAcceptanceDiff {
        schedule_changed: before.schedule_fingerprint != after.schedule_fingerprint,
        acceptance_changed: !directly_changed_stage_ids.is_empty(),
        directly_changed_stage_ids: directly_changed_stage_ids.into_iter().collect(),
        invalidated_stage_ids: invalidated.into_iter().collect(),
        preserved_stage_ids: preserved,
        before,
        after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str) -> CanonVal {
        CanonVal::obj().set("id", CanonVal::Str(id.to_string())).set("disposition", CanonVal::Str("accepted".into()))
    }

    fn stage(id: &str, deps: &[&str], items: &[&str]) -> CanonVal {
        CanonVal::obj()
            .set("stage_id", CanonVal::Str(id.to_string()))
            .set("owner", CanonVal::Str("owner-a".to_string()))
            .set("dependencies", CanonVal::Arr(deps.iter().map(|d| CanonVal::Str(d.to_string())).collect()))
            .set("required_items", CanonVal::Arr(items.iter().map(|i| item(i)).collect()))
    }

    fn schedule(version: i64) -> CanonVal {
        CanonVal::obj().set("schedule_version", CanonVal::Int(version)).set("waves", CanonVal::Arr(vec![]))
    }

    #[test]
    fn fingerprint_item_requires_id() {
        let bad = CanonVal::obj().set("disposition", CanonVal::Str("accepted".into()));
        assert!(fingerprint_acceptance_item(&bad).is_err());
    }

    #[test]
    fn fingerprint_item_is_deterministic() {
        let a = fingerprint_acceptance_item(&item("i1")).unwrap();
        let b = fingerprint_acceptance_item(&item("i1")).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn compile_and_diff_no_change() {
        let stages = vec![stage("s1", &[], &["i1"])];
        let sched = schedule(1);
        let spec = ScopedAcceptanceSpec { stages: &stages, schedule: &sched };
        let diff = diff_scoped_acceptance(&spec, &spec).unwrap();
        assert!(!diff.acceptance_changed);
        assert!(!diff.schedule_changed);
        assert!(diff.directly_changed_stage_ids.is_empty());
        assert!(diff.invalidated_stage_ids.is_empty());
        assert_eq!(diff.preserved_stage_ids, vec!["s1".to_string()]);
    }

    #[test]
    fn diff_propagates_to_dependents() {
        let prev_stages = vec![stage("s1", &[], &["i1"]), stage("s2", &["s1"], &["i2"])];
        let next_stages = vec![stage("s1", &[], &["i1-changed"]), stage("s2", &["s1"], &["i2"])];
        let sched = schedule(1);
        let prev = ScopedAcceptanceSpec { stages: &prev_stages, schedule: &sched };
        let next = ScopedAcceptanceSpec { stages: &next_stages, schedule: &sched };
        let diff = diff_scoped_acceptance(&prev, &next).unwrap();
        assert!(diff.acceptance_changed);
        assert_eq!(diff.directly_changed_stage_ids, vec!["s1".to_string()]);
        assert_eq!(diff.invalidated_stage_ids, vec!["s1".to_string(), "s2".to_string()]);
        assert!(diff.preserved_stage_ids.is_empty());
    }

    #[test]
    fn diff_detects_schedule_change_only() {
        let stages = vec![stage("s1", &[], &["i1"])];
        let prev = ScopedAcceptanceSpec { stages: &stages, schedule: &schedule(1) };
        let sched2 = schedule(2);
        let next = ScopedAcceptanceSpec { stages: &stages, schedule: &sched2 };
        let diff = diff_scoped_acceptance(&prev, &next).unwrap();
        assert!(diff.schedule_changed);
        assert!(!diff.acceptance_changed);
        assert_eq!(diff.preserved_stage_ids, vec!["s1".to_string()]);
    }

    #[test]
    fn missing_stage_id_errors() {
        let stages = vec![CanonVal::obj().set("owner", CanonVal::Str("x".into()))];
        let sched = schedule(1);
        assert!(compile_scoped_acceptance(&stages, &sched).is_err());
    }
}
