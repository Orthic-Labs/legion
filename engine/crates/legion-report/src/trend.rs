//! Cohort-aware Audit trend rendering (A15).
//!
//! A trend step is only a comparison when both runs measured the same thing:
//! same profile, targets, rules, qualification and scope. Anything else is an
//! explicit `Incomparable` step with reasons, never an "improvement". Missing
//! measurements stay `unknown`; nothing here invents age, precision, cost or
//! performance. Pure functions over caller-supplied points; no I/O.

use crate::escape;
use serde_json::{json, Value};

/// What a run measured. A `None` field was not recorded and therefore can
/// never prove comparability.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Cohort {
    pub profile: Option<String>,
    pub targets_digest: Option<String>,
    pub rules_digest: Option<String>,
    pub qualification_digest: Option<String>,
    pub scope_digest: Option<String>,
    /// Benchmark environment; required only for duration/cost comparison.
    pub hardware: Option<String>,
    pub dataset: Option<String>,
}

/// One completed run's summary. Counts are `None` when unknown.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrendPoint {
    pub run_id: String,
    pub at: Option<String>,
    pub cohort: Cohort,
    /// Items the plan intended to examine (files, obligations, routes).
    pub denominator: Option<u64>,
    pub examined: Option<u64>,
    pub excluded: Option<u64>,
    pub open_findings: Option<u64>,
    /// Obligations/items left in an unknown or unexamined state.
    pub unknown: Option<u64>,
    /// Measured values only (never estimated).
    pub duration_ms: Option<u64>,
    pub cost_micros: Option<u64>,
    /// False when the run was incomplete; such a point is never a baseline.
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Delta {
    Known(i64),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Comparison {
    Comparable {
        open_findings: Delta,
        unknown: Delta,
        examined: Delta,
        /// Present only when hardware and dataset are recorded and equal.
        duration_ms: Option<Delta>,
        cost_micros: Option<Delta>,
    },
    Incomparable {
        reasons: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrendStep {
    pub from: String,
    pub to: String,
    pub comparison: Comparison,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Trend {
    pub points: Vec<TrendPoint>,
    pub steps: Vec<TrendStep>,
}

fn same(label: &str, a: &Option<String>, b: &Option<String>, reasons: &mut Vec<String>) {
    match (a, b) {
        (Some(x), Some(y)) if x == y => {}
        (Some(_), Some(_)) => reasons.push(format!("{label} changed")),
        _ => reasons.push(format!("{label} not recorded in both runs")),
    }
}

fn delta(a: Option<u64>, b: Option<u64>) -> Delta {
    match (a, b) {
        (Some(a), Some(b)) => Delta::Known(b as i64 - a as i64),
        _ => Delta::Unknown,
    }
}

/// Compares two consecutive runs. Incomplete runs, cohort drift, shrinking
/// examined coverage or growing exclusions make the step `Incomparable`.
pub fn compare(previous: &TrendPoint, current: &TrendPoint) -> Comparison {
    let mut reasons = Vec::new();
    if !previous.complete {
        reasons.push("previous run incomplete".to_owned());
    }
    if !current.complete {
        reasons.push("current run incomplete".to_owned());
    }
    let (a, b) = (&previous.cohort, &current.cohort);
    same("profile", &a.profile, &b.profile, &mut reasons);
    same("targets", &a.targets_digest, &b.targets_digest, &mut reasons);
    same("rules", &a.rules_digest, &b.rules_digest, &mut reasons);
    same(
        "qualification",
        &a.qualification_digest,
        &b.qualification_digest,
        &mut reasons,
    );
    same("scope", &a.scope_digest, &b.scope_digest, &mut reasons);
    match (previous.denominator, current.denominator) {
        (Some(x), Some(y)) if x == y => {}
        (Some(_), Some(_)) => reasons.push("denominator changed".to_owned()),
        _ => reasons.push("denominator unknown".to_owned()),
    }
    match (previous.excluded, current.excluded) {
        (Some(x), Some(y)) if y <= x => {}
        (Some(_), Some(_)) => reasons.push("excluded items increased".to_owned()),
        _ => reasons.push("excluded count unknown".to_owned()),
    }
    match (previous.examined, current.examined) {
        (Some(x), Some(y)) if y >= x => {}
        (Some(_), Some(_)) => reasons.push("examined coverage decreased".to_owned()),
        _ => reasons.push("examined count unknown".to_owned()),
    }
    if !reasons.is_empty() {
        return Comparison::Incomparable { reasons };
    }
    let bench_ok = matches!((&a.hardware, &b.hardware), (Some(x), Some(y)) if x == y)
        && matches!((&a.dataset, &b.dataset), (Some(x), Some(y)) if x == y);
    Comparison::Comparable {
        open_findings: delta(previous.open_findings, current.open_findings),
        unknown: delta(previous.unknown, current.unknown),
        examined: delta(previous.examined, current.examined),
        duration_ms: bench_ok.then(|| delta(previous.duration_ms, current.duration_ms)),
        cost_micros: bench_ok.then(|| delta(previous.cost_micros, current.cost_micros)),
    }
}

/// Orders points as given (caller supplies chronological order) and compares
/// each consecutive pair. Never compares across a gap of skipped runs.
pub fn build(points: Vec<TrendPoint>) -> Trend {
    let steps = points
        .windows(2)
        .map(|pair| TrendStep {
            from: pair[0].run_id.clone(),
            to: pair[1].run_id.clone(),
            comparison: compare(&pair[0], &pair[1]),
        })
        .collect();
    Trend { points, steps }
}

fn known(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |v| v.to_string())
}

fn show_delta(delta: &Delta) -> String {
    match delta {
        Delta::Known(v) => format!("{v:+}"),
        Delta::Unknown => "unknown".to_owned(),
    }
}

/// Markdown table of runs (with denominators) plus a step list that states
/// why a step is incomparable.
pub fn render_markdown(trend: &Trend) -> String {
    let mut out = String::from("## Audit trend\n\n");
    out.push_str(
        "| Run | Complete | Examined / denominator | Excluded | Open findings | Unknown | Duration ms | Cost (micros) |\n",
    );
    out.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for p in &trend.points {
        out.push_str(&format!(
            "| {} | {} | {} / {} | {} | {} | {} | {} | {} |\n",
            escape::markdown(&p.run_id),
            if p.complete { "yes" } else { "no" },
            known(p.examined),
            known(p.denominator),
            known(p.excluded),
            known(p.open_findings),
            known(p.unknown),
            known(p.duration_ms),
            known(p.cost_micros),
        ));
    }
    out.push_str("\n### Comparisons\n\n");
    if trend.steps.is_empty() {
        out.push_str("No comparable pair of runs.\n");
    }
    for step in &trend.steps {
        let (from, to) = (escape::markdown(&step.from), escape::markdown(&step.to));
        match &step.comparison {
            Comparison::Comparable {
                open_findings,
                unknown,
                examined,
                duration_ms,
                cost_micros,
            } => {
                out.push_str(&format!(
                    "- {from} -> {to}: comparable cohort; open findings {}, unknown {}, examined {}; duration {}; cost {}\n",
                    show_delta(open_findings),
                    show_delta(unknown),
                    show_delta(examined),
                    duration_ms.as_ref().map_or("not comparable (environment not recorded or changed)".to_owned(), show_delta),
                    cost_micros.as_ref().map_or("not comparable (environment not recorded or changed)".to_owned(), show_delta),
                ));
            }
            Comparison::Incomparable { reasons } => {
                out.push_str(&format!(
                    "- {from} -> {to}: incomparable, no trend claimed ({})\n",
                    escape::markdown(&reasons.join("; "))
                ));
            }
        }
    }
    out
}

/// Machine-readable form of [`render_markdown`]'s content.
pub fn to_value(trend: &Trend) -> Value {
    fn opt(value: Option<u64>) -> Value {
        value.map_or(Value::Null, |v| json!(v))
    }
    fn delta_value(delta: &Delta) -> Value {
        match delta {
            Delta::Known(v) => json!(v),
            Delta::Unknown => Value::Null,
        }
    }
    json!({
        "points": trend.points.iter().map(|p| json!({
            "runId": p.run_id, "at": p.at, "complete": p.complete,
            "denominator": opt(p.denominator), "examined": opt(p.examined),
            "excluded": opt(p.excluded), "openFindings": opt(p.open_findings),
            "unknown": opt(p.unknown), "durationMs": opt(p.duration_ms),
            "costMicros": opt(p.cost_micros),
        })).collect::<Vec<_>>(),
        "steps": trend.steps.iter().map(|s| match &s.comparison {
            Comparison::Comparable { open_findings, unknown, examined, duration_ms, cost_micros } => json!({
                "from": s.from, "to": s.to, "comparable": true,
                "openFindings": delta_value(open_findings),
                "unknown": delta_value(unknown),
                "examined": delta_value(examined),
                "durationMs": duration_ms.as_ref().map(delta_value),
                "costMicros": cost_micros.as_ref().map(delta_value),
            }),
            Comparison::Incomparable { reasons } => json!({
                "from": s.from, "to": s.to, "comparable": false, "reasons": reasons,
            }),
        }).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(id: &str) -> TrendPoint {
        let s = |v: &str| Some(v.to_owned());
        TrendPoint {
            run_id: id.into(),
            cohort: Cohort {
                profile: s("p"),
                targets_digest: s("t"),
                rules_digest: s("r"),
                qualification_digest: s("q"),
                scope_digest: s("s"),
                hardware: s("hw"),
                dataset: s("ds"),
            },
            denominator: Some(100),
            examined: Some(100),
            excluded: Some(0),
            open_findings: Some(5),
            unknown: Some(0),
            duration_ms: Some(1000),
            cost_micros: Some(10),
            complete: true,
            ..TrendPoint::default()
        }
    }

    #[test]
    fn excluded_scope_is_not_improvement() {
        let a = point("a");
        let mut b = point("b");
        b.open_findings = Some(0);
        b.excluded = Some(40);
        b.examined = Some(60);
        assert!(matches!(compare(&a, &b), Comparison::Incomparable { .. }));
    }

    #[test]
    fn hardware_change_hides_performance_delta() {
        let a = point("a");
        let mut b = point("b");
        b.cohort.hardware = Some("other".into());
        b.duration_ms = Some(10);
        match compare(&a, &b) {
            Comparison::Comparable { duration_ms, .. } => assert!(duration_ms.is_none()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_counts_stay_unknown() {
        let a = point("a");
        let mut b = point("b");
        b.open_findings = None;
        match compare(&a, &b) {
            Comparison::Comparable { open_findings, .. } => {
                assert_eq!(open_findings, Delta::Unknown)
            }
            other => panic!("{other:?}"),
        }
    }
}
