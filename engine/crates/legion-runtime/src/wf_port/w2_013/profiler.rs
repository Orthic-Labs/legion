//! Port of `skills/designer/engine/scripts/detector/profile/profiler.mjs`.
//!
//! `profileNow()` (perf-timer selection between `performance.now()` and
//! `Date.now()`) is a JS-runtime concern with no Rust equivalent needed;
//! callers here pass elapsed milliseconds directly (as
//! `std::time::Instant::elapsed()` would produce), which is what every
//! call site in the JS module ultimately measures.

/// One recorded profiling event, mirroring `recordProfileEvent`'s
/// `normalized` object shape.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileEvent {
    pub engine: String,
    pub phase: String,
    pub rule_id: String,
    pub target: String,
    pub ms: f64,
    pub findings: u32,
    pub detail: Option<String>,
    pub finding_ids: Vec<String>,
}

/// Metadata passed alongside a callback, mirroring the JS `meta` object
/// (`{ engine, phase, ruleId, target, detail? }`). `ms` and `findings` are
/// filled in by the profiling wrappers, not supplied by the caller.
#[derive(Clone, Debug, Default)]
pub struct ProfileMeta {
    pub engine: String,
    pub phase: String,
    pub rule_id: String,
    pub target: String,
    pub detail: Option<String>,
}

impl ProfileMeta {
    pub fn new(engine: &str, phase: &str, rule_id: &str, target: &str) -> Self {
        Self {
            engine: engine.to_string(),
            phase: phase.to_string(),
            rule_id: rule_id.to_string(),
            target: target.to_string(),
            detail: None,
        }
    }
}

/// Port of `createDetectorProfile()`.
#[derive(Clone, Debug, Default)]
pub struct DetectorProfile {
    pub events: Vec<ProfileEvent>,
}

impl DetectorProfile {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }
}

/// Port of `recordProfileEvent(profile, event)`. The JS version accepts a
/// function, an object with `.record`, an object with `.events`, or a bare
/// array; `legion-runtime` only needs the `{ events: [] }` shape
/// ([`DetectorProfile`]), which every call site in this port uses, so this
/// mirrors just that branch (`Array.isArray(profile.events)`).
pub fn record_profile_event(
    profile: &mut DetectorProfile,
    meta: &ProfileMeta,
    ms: f64,
    findings: u32,
    finding_ids: Vec<String>,
) {
    let ms = if ms.is_finite() { ms } else { 0.0 };
    let event = ProfileEvent {
        engine: if meta.engine.is_empty() {
            "unknown".to_string()
        } else {
            meta.engine.clone()
        },
        phase: if meta.phase.is_empty() {
            "unknown".to_string()
        } else {
            meta.phase.clone()
        },
        rule_id: if meta.rule_id.is_empty() {
            "unknown".to_string()
        } else {
            meta.rule_id.clone()
        },
        target: meta.target.clone(),
        ms,
        findings,
        detail: meta.detail.clone(),
        finding_ids,
    };
    profile.events.push(event);
}

/// Port of `extractFindingIds(findings)`: unique, order-preserving,
/// non-empty ids extracted from a findings list. Callers supply the
/// already-extracted id per finding (`f.id || f.type || f.antipattern` in
/// JS); this takes `&[String]` of those already-resolved ids and dedupes
/// them the way `[...new Set(...)]` does (first occurrence kept, insertion
/// order preserved).
pub fn extract_finding_ids(ids: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for id in ids {
        if id.is_empty() {
            continue;
        }
        if seen.insert(id.clone()) {
            out.push(id.clone());
        }
    }
    out
}

/// Port of `profileFindings(profile, meta, callback)`: runs `callback`,
/// records elapsed time and finding count/ids against `profile` (when
/// `Some`), and returns the callback's findings either way. `finding_ids`
/// is supplied by the caller (already computed, e.g. via
/// [`extract_finding_ids`]) since Rust has no `f?.id || f?.type ||
/// f?.antipattern` structural fallback to perform generically here.
pub fn profile_findings<T, F>(
    profile: Option<&mut DetectorProfile>,
    meta: &ProfileMeta,
    finding_ids: impl FnOnce(&T) -> Vec<String>,
    callback: F,
) -> T
where
    F: FnOnce() -> T,
    T: FindingsCount,
{
    match profile {
        None => callback(),
        Some(profile) => {
            let started = std::time::Instant::now();
            let findings = callback();
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            let ids = finding_ids(&findings);
            record_profile_event(profile, meta, ms, findings.findings_count(), ids);
            findings
        }
    }
}

/// Port of `profileStep(profile, meta, callback)`: like
/// [`profile_findings`] but always records `findings: 0` (no finding-count
/// tracking), matching the JS `finally` block that always fires even on
/// callback error/panic being out of scope for a pure Rust closure.
pub fn profile_step<T, F>(profile: Option<&mut DetectorProfile>, meta: &ProfileMeta, callback: F) -> T
where
    F: FnOnce() -> T,
{
    match profile {
        None => callback(),
        Some(profile) => {
            let started = std::time::Instant::now();
            let result = callback();
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            record_profile_event(profile, meta, ms, 0, Vec::new());
            result
        }
    }
}

/// Anything a `profile_findings` callback can return that we can count
/// findings for. Implemented for `Vec<T>` (the common case, mirroring
/// `Array.isArray(findings) ? findings.length : 0`).
pub trait FindingsCount {
    fn findings_count(&self) -> u32;
}

impl<T> FindingsCount for Vec<T> {
    fn findings_count(&self) -> u32 {
        self.len() as u32
    }
}

/// Port of `percentile(sortedValues, pct)`. `sorted_values` must already be
/// sorted ascending, matching the JS contract.
pub fn percentile(sorted_values: &[f64], pct: f64) -> f64 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    let len = sorted_values.len() as f64;
    let raw_idx = ((pct / 100.0) * len).ceil() - 1.0;
    let idx = raw_idx.max(0.0).min(len - 1.0) as usize;
    sorted_values[idx]
}

/// One summarized group, mirroring `summarizeDetectorProfile`'s output
/// objects.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileSummary {
    pub engine: String,
    pub phase: String,
    pub rule_id: String,
    pub target: String,
    pub calls: u32,
    pub total_ms: f64,
    pub avg_ms: f64,
    pub p50: f64,
    pub p95: f64,
    pub findings: u32,
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Port of `summarizeDetectorProfile(profile)`: groups events by
/// `(engine, phase, ruleId, target)`, aggregates call count/total time/
/// findings, and computes p50/p95 over per-call durations. Groups are
/// returned sorted by `totalMs` descending, matching the JS `.sort((a, b)
/// => b.totalMs - a.totalMs)`.
pub fn summarize_detector_profile(profile: &DetectorProfile) -> Vec<ProfileSummary> {
    struct Group {
        engine: String,
        phase: String,
        rule_id: String,
        target: String,
        calls: u32,
        total_ms: f64,
        findings: u32,
        samples: Vec<f64>,
    }

    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Group> = std::collections::HashMap::new();

    for event in &profile.events {
        let key = format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            event.engine, event.phase, event.rule_id, event.target
        );
        let ms = if event.ms.is_finite() { event.ms } else { 0.0 };
        let group = groups.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Group {
                engine: event.engine.clone(),
                phase: event.phase.clone(),
                rule_id: event.rule_id.clone(),
                target: event.target.clone(),
                calls: 0,
                total_ms: 0.0,
                findings: 0,
                samples: Vec::new(),
            }
        });
        group.calls += 1;
        group.total_ms += ms;
        group.findings += event.findings;
        group.samples.push(ms);
    }

    let mut out: Vec<ProfileSummary> = order
        .into_iter()
        .map(|key| {
            let mut group = groups.remove(&key).expect("group present for recorded key");
            group.samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let avg_ms = group.total_ms / group.calls as f64;
            ProfileSummary {
                engine: group.engine,
                phase: group.phase,
                rule_id: group.rule_id,
                target: group.target,
                calls: group.calls,
                total_ms: round3(group.total_ms),
                avg_ms: round3(avg_ms),
                p50: round3(percentile(&group.samples, 50.0)),
                p95: round3(percentile(&group.samples, 95.0)),
                findings: group.findings,
            }
        })
        .collect();

    out.sort_by(|a, b| b.total_ms.partial_cmp(&a.total_ms).unwrap());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_matches_js_ceil_formula() {
        let sorted = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        // JS: Math.ceil((50/100)*5)-1 = Math.ceil(2.5)-1 = 3-1 = 2 -> sorted[2] = 3
        assert_eq!(percentile(&sorted, 50.0), 3.0);
        // p95: ceil(0.95*5)-1 = ceil(4.75)-1 = 5-1 = 4 -> sorted[4] = 5
        assert_eq!(percentile(&sorted, 95.0), 5.0);
    }

    #[test]
    fn percentile_empty_is_zero() {
        assert_eq!(percentile(&[], 50.0), 0.0);
    }

    #[test]
    fn extract_finding_ids_dedupes_preserving_order() {
        let ids = vec![
            "a".to_string(),
            "b".to_string(),
            "a".to_string(),
            "".to_string(),
            "c".to_string(),
        ];
        assert_eq!(extract_finding_ids(&ids), vec!["a", "b", "c"]);
    }

    #[test]
    fn record_profile_event_defaults_unknown_fields() {
        let mut profile = DetectorProfile::new();
        let meta = ProfileMeta::default();
        record_profile_event(&mut profile, &meta, 12.5, 2, vec!["x".to_string()]);
        let e = &profile.events[0];
        assert_eq!(e.engine, "unknown");
        assert_eq!(e.phase, "unknown");
        assert_eq!(e.rule_id, "unknown");
        assert_eq!(e.ms, 12.5);
        assert_eq!(e.findings, 2);
    }

    #[test]
    fn record_profile_event_nan_ms_becomes_zero() {
        let mut profile = DetectorProfile::new();
        let meta = ProfileMeta::new("static-html", "element", "rule", "file.html");
        record_profile_event(&mut profile, &meta, f64::NAN, 0, vec![]);
        assert_eq!(profile.events[0].ms, 0.0);
    }

    #[test]
    fn profile_findings_records_event_and_returns_callback_result() {
        let mut profile = DetectorProfile::new();
        let meta = ProfileMeta::new("static-html", "element", "rule-a", "file.html");
        let result = profile_findings(
            Some(&mut profile),
            &meta,
            |v: &Vec<String>| v.clone(),
            || vec!["f1".to_string(), "f2".to_string()],
        );
        assert_eq!(result, vec!["f1", "f2"]);
        assert_eq!(profile.events.len(), 1);
        assert_eq!(profile.events[0].findings, 2);
        assert_eq!(profile.events[0].finding_ids, vec!["f1", "f2"]);
    }

    #[test]
    fn profile_findings_with_no_profile_skips_recording() {
        let meta = ProfileMeta::new("static-html", "element", "rule-a", "file.html");
        let result = profile_findings(
            None,
            &meta,
            |v: &Vec<String>| v.clone(),
            || vec!["f1".to_string()],
        );
        assert_eq!(result, vec!["f1"]);
    }

    #[test]
    fn profile_step_always_records_zero_findings() {
        let mut profile = DetectorProfile::new();
        let meta = ProfileMeta::new("static-html", "setup", "read-html", "file.html");
        let html = profile_step(Some(&mut profile), &meta, || "<html></html>".to_string());
        assert_eq!(html, "<html></html>");
        assert_eq!(profile.events[0].findings, 0);
    }

    #[test]
    fn summarize_groups_by_key_and_sorts_by_total_ms_desc() {
        let mut profile = DetectorProfile::new();
        let meta_a = ProfileMeta::new("static-html", "element", "rule-a", "f.html");
        let meta_b = ProfileMeta::new("static-html", "element", "rule-b", "f.html");
        record_profile_event(&mut profile, &meta_a, 10.0, 1, vec!["x".into()]);
        record_profile_event(&mut profile, &meta_a, 20.0, 2, vec!["y".into()]);
        record_profile_event(&mut profile, &meta_b, 5.0, 0, vec![]);

        let summary = summarize_detector_profile(&profile);
        assert_eq!(summary.len(), 2);
        assert_eq!(summary[0].rule_id, "rule-a");
        assert_eq!(summary[0].calls, 2);
        assert_eq!(summary[0].total_ms, 30.0);
        assert_eq!(summary[0].avg_ms, 15.0);
        assert_eq!(summary[0].findings, 3);
        assert_eq!(summary[1].rule_id, "rule-b");
        assert_eq!(summary[1].total_ms, 5.0);
    }
}
