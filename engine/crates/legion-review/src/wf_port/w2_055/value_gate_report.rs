//! Port of `src/lib/review/value_gate_report.py` (frozen value-gate human
//! adjudication page generator, dated 2026-07-19).
//!
//! **Ported faithfully (pure, filesystem/network-free):**
//! - the finding-row comparison (`_sample`'s `rows` construction: pairing a
//!   blind and peer disposition per `finding_id`, flagging `flipped` when
//!   the `action` differs) — [`FindingRow`], [`compare_findings`]
//! - the finding-card and full-page HTML rendering (`_finding_card`,
//!   `render`), byte-for-byte including the inline CSS and copy — [`render`]
//! - Python's `html.escape` semantics (`&`, `<`, `>`, `"`, `'`) used
//!   throughout the original templates — [`html_escape`]
//!
//! **Not ported (depends on `dual_review.py`/`review_evidence.py`, neither
//! of which exists in this workspace, and on the fixed, dated
//! `gate-*-20260719-{blind,peer}` run directories under `RUNS_ROOT`):**
//! `_dispositions`, `_sample`'s disk reads, `_branch_outcome`,
//! `_inflation_ratio`, `_material_changes`, `_peer_round_accounting`,
//! `pin_run_evidence`, and `main()`. A caller wiring this to live evidence
//! loads `blind`/`peer` outcomes and per-finding dispositions from those
//! (unported) helpers, builds a [`Sample`] with [`compare_findings`], and
//! renders the page with [`render`].

use std::fmt::Write as _;

/// Port of Python's `html.escape(s, quote=True)` (the default `html.escape`
/// call used throughout the source template f-strings).
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// Port of one disposition record read from `review.disposition.json`'s
/// `advisory_dispositions` (only the fields the report reads).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Disposition {
    pub action: String,
    pub rationale: String,
}

/// Port of one entry from `_finding_records(council.advisory.json)` (only
/// the fields the report reads).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingRecord {
    pub finding_id: String,
    pub claim: String,
    pub author_seat: String,
}

/// Port of one row appended to `_sample`'s `rows` list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingRow {
    pub finding_id: String,
    pub claim: String,
    pub author_seat: String,
    pub blind: Disposition,
    pub peer: Disposition,
    pub flipped: bool,
}

/// Port of the `for finding_id, finding in findings.items(): ... rows.append(...)`
/// loop in `_sample`. `findings` order is preserved (Python dicts are
/// insertion-ordered, mirrored here by iterating `findings` in the order
/// given). Panics if a `finding_id` present in `findings` is missing from
/// `blind_disp`/`peer_disp`, matching the Python `KeyError` on a missing
/// disposition (the source has no fallback).
pub fn compare_findings(
    findings: &[FindingRecord],
    blind_disp: &std::collections::HashMap<String, Disposition>,
    peer_disp: &std::collections::HashMap<String, Disposition>,
) -> Vec<FindingRow> {
    findings
        .iter()
        .map(|finding| {
            let before = blind_disp
                .get(&finding.finding_id)
                .unwrap_or_else(|| panic!("missing blind disposition for {}", finding.finding_id));
            let after = peer_disp
                .get(&finding.finding_id)
                .unwrap_or_else(|| panic!("missing peer disposition for {}", finding.finding_id));
            FindingRow {
                finding_id: finding.finding_id.clone(),
                claim: finding.claim.clone(),
                author_seat: finding.author_seat.clone(),
                blind: before.clone(),
                peer: after.clone(),
                flipped: before.action != after.action,
            }
        })
        .collect()
}

/// Port of `_branch_outcome`'s fields the report reads (`jury_verdict_tier`,
/// `blockers`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchOutcome {
    pub jury_verdict_tier: String,
    pub blockers: Vec<String>,
}

/// Port of `_peer_round_accounting`'s `escalation_rate` field, the only one
/// the report reads.
#[derive(Clone, Debug, PartialEq)]
pub struct RoomAccounting {
    pub escalation_rate: f64,
}

/// Port of the `_sample` return dict, minus the fields sourced from unported
/// helpers (`blind_dir`/`peer_dir` are omitted; they are never read by
/// `render`).
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub label: String,
    pub blind: BranchOutcome,
    pub peer: BranchOutcome,
    pub changes: Vec<String>,
    pub inflation: f64,
    pub room: RoomAccounting,
    pub findings: Vec<FindingRow>,
}

fn finding_card(row: &FindingRow) -> String {
    let flip_class = if row.flipped { " flip" } else { "" };
    let flip_label = if row.flipped { "ACTION FLIP" } else { "same action" };
    format!(
        "\n    <article class=\"finding{flip}\">\n      <header><code>{fid}</code><span>{flabel}</span></header>\n      <p class=\"claim\">{claim}</p>\n      <div class=\"branches\">\n        <section><h4>Blind · {ba}</h4><p>{br}</p></section>\n        <section><h4>PeerDebate · {pa}</h4><p>{pr}</p></section>\n      </div>\n    </article>",
        flip = flip_class,
        fid = html_escape(&row.finding_id),
        flabel = flip_label,
        claim = html_escape(&row.claim),
        ba = html_escape(&row.blind.action),
        br = html_escape(&row.blind.rationale),
        pa = html_escape(&row.peer.action),
        pr = html_escape(&row.peer.rationale),
    )
}

/// Port of `render(samples)`. Byte-for-byte the same output shape as the
/// Python f-string template, including the inline CSS.
pub fn render(samples: &[Sample]) -> String {
    let mut sections = String::new();
    for (index, sample) in samples.iter().enumerate() {
        let inflation_ok = sample.inflation <= 1.1;
        let findings: String = sample.findings.iter().map(finding_card).collect();
        let flips = sample.findings.iter().filter(|r| r.flipped).count();
        let _ = write!(
            sections,
            "\n        <section class=\"sample\" id=\"sample-{index}\">\n          <div class=\"sample-head\">\n            <div><p class=\"eyebrow\">SAMPLE {sample_num}</p><h2>{label}</h2></div>\n            <div class=\"metrics\">\n              <span>Jury <b>{jury_from} → {jury_to}</b></span>\n              <span class=\"{inflation_class}\">Inflation <b>{inflation:.3}×</b></span>\n              <span>Escalation <b>{escalation:.0}%</b></span>\n            </div>\n          </div>\n          <p class=\"changes\">Material change: {changes}</p>\n          <details open><summary>Disposition comparison ({flips} flips)</summary>{findings}</details>\n          <p class=\"pass\"><b>Final delegated assessment: No correct minority position erased.</b></p>\n        </section>",
            index = index,
            sample_num = index + 1,
            label = html_escape(&sample.label),
            jury_from = html_escape(&sample.blind.jury_verdict_tier),
            jury_to = html_escape(&sample.peer.jury_verdict_tier),
            inflation_class = if inflation_ok { "pass" } else { "fail" },
            inflation = sample.inflation,
            escalation = sample.room.escalation_rate * 100.0,
            changes = html_escape(&sample.changes.join(", ")),
            flips = flips,
            findings = findings,
        );
    }
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Agent Room · Frozen Value Gate</title>\n<style>\n:root{{--bg:#0a0d12;--panel:#121722;--line:#283246;--text:#edf2fb;--muted:#93a3bb;--accent:#7dd3fc;--good:#6ee7b7;--bad:#fb7185}}\n*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,Segoe UI,sans-serif}}\nmain{{max-width:1240px;margin:auto;padding:40px 24px 80px}} h1{{font-size:clamp(32px,5vw,64px);line-height:1;margin:8px 0 16px}}\n.eyebrow{{letter-spacing:.16em;color:var(--accent);font-size:12px;font-weight:700}} .lede,.changes{{color:var(--muted)}}\n.verdict{{border:1px solid var(--bad);background:#2a1118;padding:16px 20px;border-radius:12px;margin:24px 0 32px}}\n.sample{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;margin:20px 0}}\n.sample-head,.metrics,.branches{{display:flex;gap:14px;justify-content:space-between}} h2{{margin:0}} .metrics{{flex-wrap:wrap;align-items:center}}\n.metrics span{{border:1px solid var(--line);border-radius:999px;padding:7px 11px}} .pass{{color:var(--good)}} .fail{{color:var(--bad)}}\ndetails{{border-top:1px solid var(--line);padding-top:16px}} summary{{cursor:pointer;font-weight:700;margin-bottom:12px}}\n.finding{{border:1px solid var(--line);border-radius:12px;padding:14px;margin:10px 0}} .finding.flip{{border-color:var(--accent)}}\n.finding header{{display:flex;justify-content:space-between;color:var(--muted);font-size:12px}} .finding.flip header span{{color:var(--accent);font-weight:800}}\n.claim{{font-weight:650}} .branches section{{width:50%;background:#0d121b;border-radius:8px;padding:10px 12px}} h4{{margin:0 0 6px;text-transform:capitalize}}\nfieldset{{margin-top:20px;border:1px solid var(--line);border-radius:12px;padding:16px}} fieldset label{{margin-right:22px}}\ntextarea{{display:block;width:100%;min-height:74px;margin-top:12px;background:#0d121b;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:10px}}\nbutton{{margin-top:24px;background:var(--accent);color:#071018;border:0;border-radius:9px;padding:12px 18px;font-weight:800;cursor:pointer}}\n#status{{color:var(--muted);margin-left:12px}} @media(max-width:760px){{.sample-head,.branches{{display:block}}.branches section{{width:100%;margin-top:8px}}}}\n</style></head><body><main>\n<p class=\"eyebrow\">AGENT ROOM · P-1 EXPERIMENT</p><h1>Frozen value gate</h1>\n<p class=\"lede\">Three matched, pinned reviews with the delegated Fable + Codex adjudication recorded.</p>\n<div class=\"verdict\" style=\"border-color:var(--good);background:#0d271f\"><b>Frozen gate: PASS.</b> All samples have material change, blocker inflation ≤1.10, escalation below 50%, and no correct-minority erasure. the operator explicitly delegated the final judgment to Fable and Codex; both assessed No/No/No.</div>\n{sections}\n</main></body></html>",
        sections = sections,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn html_escape_matches_python_default_quote_true() {
        assert_eq!(
            html_escape("<a href=\"x\">it's & fun</a>"),
            "&lt;a href=&quot;x&quot;&gt;it&#x27;s &amp; fun&lt;/a&gt;"
        );
    }

    #[test]
    fn compare_findings_flags_action_change() {
        let findings = vec![FindingRecord {
            finding_id: "f1".into(),
            claim: "claim text".into(),
            author_seat: "security".into(),
        }];
        let mut blind = HashMap::new();
        blind.insert(
            "f1".to_string(),
            Disposition { action: "raised".into(), rationale: "why".into() },
        );
        let mut peer = HashMap::new();
        peer.insert(
            "f1".to_string(),
            Disposition { action: "dropped".into(), rationale: "why not".into() },
        );
        let rows = compare_findings(&findings, &blind, &peer);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].flipped);
    }

    #[test]
    fn compare_findings_no_flip_when_action_matches() {
        let findings = vec![FindingRecord {
            finding_id: "f1".into(),
            claim: "c".into(),
            author_seat: "ux".into(),
        }];
        let mut blind = HashMap::new();
        blind.insert("f1".to_string(), Disposition { action: "raised".into(), rationale: "a".into() });
        let mut peer = HashMap::new();
        peer.insert("f1".to_string(), Disposition { action: "raised".into(), rationale: "b".into() });
        let rows = compare_findings(&findings, &blind, &peer);
        assert!(!rows[0].flipped);
    }

    fn sample_fixture() -> Sample {
        Sample {
            label: "Skills as Membrane provider".into(),
            blind: BranchOutcome { jury_verdict_tier: "block".into(), blockers: vec!["a".into()] },
            peer: BranchOutcome { jury_verdict_tier: "pass".into(), blockers: vec![] },
            changes: vec!["material change".into()],
            inflation: 1.05,
            room: RoomAccounting { escalation_rate: 0.25 },
            findings: vec![FindingRow {
                finding_id: "f1".into(),
                claim: "claim <b>text</b>".into(),
                author_seat: "security".into(),
                blind: Disposition { action: "raised".into(), rationale: "r1".into() },
                peer: Disposition { action: "dropped".into(), rationale: "r2".into() },
                flipped: true,
            }],
        }
    }

    #[test]
    fn render_includes_escaped_content_and_metrics() {
        let html = render(&[sample_fixture()]);
        assert!(html.contains("<title>Agent Room · Frozen Value Gate</title>"));
        assert!(html.contains("SAMPLE 1"));
        assert!(html.contains("Skills as Membrane provider"));
        // claim's angle brackets are escaped, never rendered as markup
        assert!(html.contains("claim &lt;b&gt;text&lt;/b&gt;"));
        assert!(html.contains("block → pass"));
        assert!(html.contains("1.050×"));
        assert!(html.contains("25%"));
        assert!(html.contains("(1 flips)"));
        assert!(html.contains("ACTION FLIP"));
        assert!(html.contains("Frozen gate: PASS."));
    }

    #[test]
    fn render_inflation_class_fails_above_threshold() {
        let mut sample = sample_fixture();
        sample.inflation = 1.2;
        let html = render(&[sample]);
        assert!(html.contains("class=\"fail\">Inflation <b>1.200×</b>"));
    }

    #[test]
    fn render_multiple_samples_concatenate_in_order() {
        let mut second = sample_fixture();
        second.label = "Membrane link-graph recall".into();
        let html = render(&[sample_fixture(), second]);
        let first_idx = html.find("Skills as Membrane provider").unwrap();
        let second_idx = html.find("Membrane link-graph recall").unwrap();
        assert!(first_idx < second_idx);
        assert!(html.contains("SAMPLE 1"));
        assert!(html.contains("SAMPLE 2"));
    }
}
