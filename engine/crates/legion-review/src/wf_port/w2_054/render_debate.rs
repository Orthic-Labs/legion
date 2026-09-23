//! Port of `src/lib/review/render_debate.py` — renders a council debate
//! (from `council.advisory.json`) as a threaded-conversation HTML page.
//!
//! SCOPE (carried over from the Python docstring): this is a *visual
//! reference* for the P0 room watch page, not a component it is imported
//! by. The P0 page is Rust-served with a live SSE data source; what
//! carries over is the thread layout, seat-card shape, and audit-strip
//! vocabulary, deliberately reimplemented there.
//!
//! GAP: the Python CLI entry point (`main`, argv parsing, file I/O) is not
//! ported — `render_html` below is the pure `payload -> String` function;
//! wiring a bin (reading `council.advisory.json`, writing `debate.html`)
//! is a caller/integration concern outside this module's owned paths.

use serde_json::Value;

fn blocker_text(blocker: &Value) -> String {
    match blocker {
        Value::Object(map) => map
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn blocker_tier(blocker: &Value) -> String {
    match blocker {
        Value::Object(map) => map
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

fn esc(value: &str) -> String {
    // Mirrors Python's `html.escape`: & < > first, then quotes.
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn esc_value(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => esc(""),
        Some(Value::String(s)) => esc(s),
        Some(Value::Bool(b)) => esc(if *b { "True" } else { "False" }),
        Some(other) => esc(&other.to_string()),
    }
}

/// Population standard deviation, mirroring `statistics.pstdev`.
fn pstdev(values: &[f64]) -> f64 {
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    variance.sqrt()
}

fn dispersion(seats: &[Value]) -> f64 {
    let scores: Vec<f64> = seats
        .iter()
        .filter(|j| j.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false))
        .map(|j| j.get("score").and_then(Value::as_f64).unwrap_or(0.0))
        .collect();
    if scores.len() > 1 {
        (pstdev(&scores) * 100.0).round() / 100.0
    } else {
        0.0
    }
}

#[derive(PartialEq, Eq, Debug)]
enum Kind {
    Contest,
    Concede,
    Sustain,
    Response,
    Finding,
}

impl Kind {
    fn as_str(&self) -> &'static str {
        match self {
            Kind::Contest => "contest",
            Kind::Concede => "concede",
            Kind::Sustain => "sustain",
            Kind::Response => "response",
            Kind::Finding => "finding",
        }
    }
}

fn kind_of(blocker: &Value) -> Kind {
    if let Value::Object(map) = blocker {
        if map.get("contest").is_some_and(Value::is_object) {
            return Kind::Contest;
        }
        if let Some(resolution) = map.get("resolution").filter(|v| v.is_object()) {
            return match resolution.get("choice").and_then(Value::as_str) {
                Some("concede") => Kind::Concede,
                Some("sustain") => Kind::Sustain,
                _ => Kind::Response,
            };
        }
    }
    let text = blocker_text(blocker);
    let upper = text.trim().to_uppercase();
    if upper.starts_with("CONTEST:") {
        return Kind::Contest;
    }
    if upper.starts_with("RESPONSE:") {
        if upper.contains("CONCEDE") {
            return Kind::Concede;
        }
        if upper.contains("SUSTAIN") {
            return Kind::Sustain;
        }
        return Kind::Response;
    }
    Kind::Finding
}

fn blocker_list(juror: &Value) -> String {
    let mut rows = Vec::new();
    if let Some(blockers) = juror.get("blockers").and_then(Value::as_array) {
        for blocker in blockers {
            let text = blocker_text(blocker);
            let tier = blocker_tier(blocker);
            let kind = kind_of(blocker);
            let tier_html = if !tier.is_empty() {
                format!("<span class=\"tier\">{}</span>", esc(&tier))
            } else {
                String::new()
            };
            rows.push(format!(
                "<li class=\"b {}\">{tier_html}{}</li>",
                kind.as_str(),
                esc(&text)
            ));
        }
    }
    if let Some(discarded) = juror
        .get("discarded_adoptions")
        .and_then(Value::as_array)
    {
        for text in discarded {
            let text = text.as_str().unwrap_or("");
            rows.push(format!(
                "<li class=\"b discarded\"><span class=\"tier\">cut</span>{}\
<span class=\"note\">unsupported adoption — discarded before synthesis</span></li>",
                esc(text)
            ));
        }
    }
    if rows.is_empty() {
        "<li class=\"b empty\">(none)</li>".to_string()
    } else {
        rows.concat()
    }
}

/// One message bubble in the thread. Mirrors `_msg`.
fn msg(seat: &str, phase: &str, juror: &Value, meta: &str) -> String {
    let parsed_ok = juror.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false);
    if !parsed_ok {
        let err = juror
            .get("error")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("unparsed response");
        return format!(
            "<article class=\"msg failed\"><header><b>{}</b>\
<span class=\"phase\">{}</span>\
<span class=\"badge err\">no position</span></header>\
<p class=\"err-text\">{}</p>\
<p class=\"note\">This seat is silent, not agreeing — its objections, if any, \
were never raised.</p></article>",
            esc(seat),
            esc(phase),
            esc(err)
        );
    }
    format!(
        "<article class=\"msg\"><header><b>{}</b>\
<span class=\"phase\">{}</span>\
<span class=\"verdict\">{}</span>\
<span class=\"score\">{}</span>{meta}</header>\
<p class=\"concern\">{}</p>\
<ul>{}</ul></article>",
        esc(seat),
        esc(phase),
        esc_value(juror.get("verdict")),
        esc_value(juror.get("score")),
        esc_value(juror.get("top_concern")),
        blocker_list(juror)
    )
}

const CSS: &str = r#":root{--bg:#F7F3EC;--fg:#211C18;--muted:#6E665F;--line:#E2DAD1;--card:#FFFDF8;
--accent:#0C6AA5;--warn:#B3261E;--ok:#1B5E20;--cut:#8A8070}
@media(prefers-color-scheme:dark){:root{--bg:#111722;--fg:#F4EFE7;--muted:#A39A91;
--line:#2D3037;--card:#171E2B;--accent:#3FA3DE;--warn:#F2B8B5;--ok:#7DD37D;--cut:#7A736B}}
*{box-sizing:border-box}body{margin:0;padding:2rem;background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;max-width:60rem}
h1{font-size:1.35rem;margin:0 0 .25rem}.sub{color:var(--muted);margin:0 0 1.25rem}
.strip{display:flex;flex-wrap:wrap;gap:.6rem;margin-bottom:1.5rem}
.metric{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:.6rem .9rem;min-width:10rem}
.metric b{display:block;font-size:1.35rem;line-height:1.15}
.metric span{color:var(--muted);font-size:.78rem}
.metric.flag{border-color:var(--warn)}.metric.flag b{color:var(--warn)}
.metric.good{border-color:var(--ok)}.metric.good b{color:var(--ok)}
h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
margin:1.75rem 0 .6rem;border-top:1px solid var(--line);padding-top:.9rem}
.msg{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:.85rem 1.1rem;margin:0 0 .7rem}
.msg.reply{margin-left:2rem;border-left:3px solid var(--accent)}
.msg.failed{border-style:dashed;opacity:.85}
.msg header{display:flex;align-items:baseline;gap:.6rem;flex-wrap:wrap;margin-bottom:.4rem}
.msg header b{font-size:.95rem}
.phase{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.05em}
.verdict{font-size:.8rem}.score{color:var(--accent);font-size:.8rem}
.badge{font-size:.72rem;border:1px solid var(--line);border-radius:99px;padding:.05rem .5rem}
.badge.err{border-color:var(--warn);color:var(--warn)}
.badge.to{border-color:var(--accent);color:var(--accent)}
.concern{margin:.2rem 0 .5rem}
ul{margin:0;padding-left:1.15rem}li{margin:.22rem 0}
.tier{display:inline-block;min-width:1.8rem;color:var(--muted);font-size:.75rem}
.b.contest{color:var(--accent);font-weight:500}
.b.concede{color:var(--ok);font-weight:500}
.b.sustain{color:var(--warn);font-weight:500}
.b.discarded{color:var(--cut);text-decoration:line-through}
.b.discarded .note{display:block;text-decoration:none;font-size:.72rem;color:var(--muted)}
.b.empty,.note{color:var(--muted)}
.err-text{color:var(--warn);margin:.2rem 0}
.note{font-size:.78rem;margin:.2rem 0 0}
footer{margin-top:2rem;color:var(--muted);font-size:.78rem;border-top:1px solid var(--line);padding-top:1rem}
"#;

fn text_upper_starts_contest(blocker: &Value) -> bool {
    blocker_text(blocker).trim().to_uppercase().starts_with("CONTEST:")
}

/// Use the persisted audit; recompute for runs predating it. Mirrors
/// `_audit`. A missing measurement must never render as compliance.
fn audit(payload: &Value, reb_jurors: &[Value]) -> Value {
    if let Some(a) = payload.get("contest_audit") {
        if a.get("answering_seats").is_some() {
            return a.clone();
        }
    }
    let answering: Vec<&Value> = reb_jurors
        .iter()
        .filter(|j| j.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false))
        .collect();
    let contesting = answering
        .iter()
        .filter(|j| {
            j.get("blockers")
                .and_then(Value::as_array)
                .map(|bs| {
                    bs.iter().any(|b| {
                        matches!(b, Value::Object(m) if m.get("contest").is_some_and(Value::is_object))
                            || text_upper_starts_contest(b)
                    })
                })
                .unwrap_or(false)
        })
        .count();
    let failed_seats: Vec<Value> = reb_jurors
        .iter()
        .filter(|j| !j.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false))
        .map(|j| j.get("juror_id").cloned().unwrap_or(Value::Null))
        .collect();
    serde_json::json!({
        "contesting_seats": contesting,
        "answering_seats": answering.len(),
        "total_seats": reb_jurors.len(),
        "failed_seats": failed_seats,
        "herding_suspected": !answering.is_empty() && contesting < answering.len(),
        "fully_compliant": !answering.is_empty() && contesting == answering.len() && answering.len() == reb_jurors.len(),
    })
}

fn juror_id_str(j: &Value) -> String {
    j.get("juror_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Render `council.advisory.json`'s parsed `payload` (identified by
/// `review_dir_name`, used only for the title/footer text) as the full
/// debate HTML page. Mirrors `render(review_dir)` minus the file read.
pub fn render_html(payload: &Value, review_dir_name: &str) -> String {
    let blind: Vec<Value> = payload
        .get("jurors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let reb: Vec<Value> = payload
        .get("rebuttal")
        .and_then(|r| r.get("jurors"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let resp: Vec<Value> = payload
        .get("response")
        .and_then(|r| r.get("jurors"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let reb_by: std::collections::HashMap<String, &Value> =
        reb.iter().map(|j| (juror_id_str(j), j)).collect();

    let audit_v = audit(payload, &reb);
    let res_audit = payload
        .get("resolution_audit")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));
    let n_blind: i64 = blind
        .iter()
        .filter(|j| j.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false))
        .map(|j| j.get("blockers").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0) as i64)
        .sum();
    let n_reb: i64 = reb
        .iter()
        .filter(|j| j.get("parsed_ok").and_then(Value::as_bool).unwrap_or(false))
        .map(|j| j.get("blockers").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0) as i64)
        .sum();
    let inflation = if n_blind != 0 {
        n_reb as f64 / n_blind as f64
    } else {
        0.0
    };
    let failed: Vec<Value> = audit_v
        .get("failed_seats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let open_contests = res_audit.get("open_contests").cloned();

    struct Metric {
        label: String,
        value: String,
        note: String,
        cls: Option<&'static str>,
    }

    let mut metrics = vec![
        Metric {
            label: "Dispersion".into(),
            value: format!("{} &rarr; {}", dispersion(&blind), dispersion(&reb)),
            note: "score spread, blind &rarr; PeerDebate".into(),
            cls: None,
        },
        Metric {
            label: "Contested".into(),
            value: format!(
                "{} / {}",
                display_or_q(audit_v.get("contesting_seats")),
                display_or_q(audit_v.get("answering_seats")),
            ),
            note: "seats that contested a peer".into(),
            cls: if audit_v.get("herding_suspected").and_then(Value::as_bool).unwrap_or(false) {
                Some("flag")
            } else {
                Some("good")
            },
        },
        Metric {
            label: "Inflation".into(),
            value: format!("&times;{inflation:.2}"),
            note: "blocker count vs blind".into(),
            cls: if inflation > 1.15 { Some("flag") } else { None },
        },
    ];
    if !resp.is_empty() {
        metrics.push(Metric {
            label: "Resolved".into(),
            value: format!(
                "{}c / {}s",
                display_or_zero(res_audit.get("conceded_count")),
                display_or_zero(res_audit.get("sustained_count")),
            ),
            note: "contests conceded / sustained".into(),
            cls: if open_contests.as_ref().is_some_and(truthy) {
                Some("flag")
            } else {
                Some("good")
            },
        });
    }
    if !failed.is_empty() {
        let joined = failed
            .iter()
            .map(|f| match f {
                Value::String(s) => s.clone(),
                Value::Null => "null".to_string(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        metrics.push(Metric {
            label: "Failed seats".into(),
            value: failed.len().to_string(),
            note: esc(&joined),
            cls: Some("flag"),
        });
    }
    if let Some(oc) = open_contests.as_ref().filter(|v| truthy(v)) {
        metrics.push(Metric {
            label: "Open contests".into(),
            value: value_str(oc),
            note: "unanswered — blocks seal under the two-exit rule".into(),
            cls: Some("flag"),
        });
    }

    let strip: String = metrics
        .iter()
        .map(|m| {
            let cls_attr = m
                .cls
                .map(|c| format!(" {c}"))
                .unwrap_or_default();
            format!(
                "<div class=\"metric{cls_attr}\"><b>{}</b><span>{} — {}</span></div>",
                m.value, m.label, m.note
            )
        })
        .collect();

    let mut thread: Vec<String> =
        vec!["<h2>Round 1 — blind positions (seats could not see each other)</h2>".to_string()];
    thread.extend(
        blind
            .iter()
            .map(|j| msg(&juror_id_str(j), "position", j, "")),
    );

    if !reb.is_empty() {
        thread.push("<h2>Round 2 — PeerDebate (peers revealed)</h2>".to_string());
        let blind_ids: std::collections::HashSet<String> =
            blind.iter().map(juror_id_str).collect();
        for j in &blind {
            let seat = juror_id_str(j);
            if let Some(rj) = reb_by.get(&seat) {
                thread.push(msg(&seat, "PeerDebate", rj, ""));
            }
        }
        for j in &reb {
            let seat = juror_id_str(j);
            if !blind_ids.contains(&seat) {
                thread.push(msg(&seat, "PeerDebate", j, ""));
            }
        }
    }

    if !resp.is_empty() {
        thread.push("<h2>Round 3 — PeerDebate replies</h2>".to_string());
        for j in &resp {
            let targets = j
                .get("answering_contests")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(value_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let badge = if !targets.is_empty() {
                format!("<span class=\"badge to\">answering {}</span>", esc(&targets))
            } else {
                String::new()
            };
            let rendered = msg(&juror_id_str(j), "PeerDebateReply", j, &badge);
            let rendered = replace_once(&rendered, "<article class=\"msg\"", "<article class=\"msg reply\"");
            let rendered = replace_once(
                &rendered,
                "<article class=\"msg failed\"",
                "<article class=\"msg reply failed\"",
            );
            thread.push(rendered);
        }
    }

    let n_seats = blind.len();
    let rounds = if !resp.is_empty() {
        "3 rounds"
    } else if !reb.is_empty() {
        "2 rounds"
    } else {
        "1 round"
    };
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Council debate — {}</title>\
<style>{CSS}</style><h1>Council debate</h1>\
<p class=\"sub\">{} · {} · {n_seats} seats · {rounds}</p>\
<div class=\"strip\">{strip}</div>{}\
<footer>Batch review, not a live room: seats never saw each other in real time. Each was \
re-run once per round with the relevant peer material appended, so no seat's later \
reasoning leaked into another's. Live rooms are P0/P1 in \
docs/plans/2026-07-14-agent-room-architecture.md.</footer>",
        esc(review_dir_name),
        esc_value(payload.get("skill")),
        esc(review_dir_name),
        thread.concat(),
    )
}

fn replace_once(haystack: &str, from: &str, to: &str) -> String {
    if let Some(idx) = haystack.find(from) {
        let mut out = String::with_capacity(haystack.len() - from.len() + to.len());
        out.push_str(&haystack[..idx]);
        out.push_str(to);
        out.push_str(&haystack[idx + from.len()..]);
        out
    } else {
        haystack.to_string()
    }
}

fn value_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn display_or_q(v: Option<&Value>) -> String {
    match v {
        Some(Value::Null) | None => "?".to_string(),
        Some(other) => value_str(other),
    }
}

fn display_or_zero(v: Option<&Value>) -> String {
    match v {
        Some(Value::Null) | None => "0".to_string(),
        Some(other) => value_str(other),
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn esc_escapes_html_specials() {
        assert_eq!(esc("<b>&\"'"), "&lt;b&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn kind_of_reads_dict_contest() {
        let b = json!({"contest": {"x": 1}});
        assert_eq!(kind_of(&b), Kind::Contest);
    }

    #[test]
    fn kind_of_reads_legacy_prefixes() {
        assert_eq!(kind_of(&json!("CONTEST: no")), Kind::Contest);
        assert_eq!(kind_of(&json!("RESPONSE: I CONCEDE")), Kind::Concede);
        assert_eq!(kind_of(&json!("RESPONSE: I SUSTAIN")), Kind::Sustain);
        assert_eq!(kind_of(&json!("RESPONSE: other")), Kind::Response);
        assert_eq!(kind_of(&json!("plain finding")), Kind::Finding);
    }

    #[test]
    fn dispersion_single_score_is_zero() {
        let seats = vec![json!({"parsed_ok": true, "score": 5})];
        assert_eq!(dispersion(&seats), 0.0);
    }

    #[test]
    fn dispersion_multi_score_matches_pstdev() {
        let seats = vec![
            json!({"parsed_ok": true, "score": 2}),
            json!({"parsed_ok": true, "score": 4}),
        ];
        assert_eq!(dispersion(&seats), 1.0);
    }

    #[test]
    fn render_html_blind_only_smoke() {
        let payload = json!({
            "skill": "review",
            "jurors": [
                {"juror_id": "j1", "parsed_ok": true, "verdict": "APPROVE", "score": 8,
                 "top_concern": "none", "blockers": []},
            ],
        });
        let html = render_html(&payload, "run-1");
        assert!(html.contains("Council debate"));
        assert!(html.contains("1 round"));
        assert!(html.contains("j1"));
        assert!(!html.contains("Round 2"));
    }

    #[test]
    fn render_html_failed_seat_shown_silent() {
        let payload = json!({
            "skill": "review",
            "jurors": [
                {"juror_id": "j1", "parsed_ok": false, "error": "boom"},
            ],
        });
        let html = render_html(&payload, "run-1");
        assert!(html.contains("no position"));
        assert!(html.contains("boom"));
    }

    #[test]
    fn render_html_reply_class_swapped() {
        let payload = json!({
            "skill": "review",
            "jurors": [{"juror_id": "j1", "parsed_ok": true, "verdict": "A", "score": 1, "blockers": []}],
            "rebuttal": {"jurors": [{"juror_id": "j1", "parsed_ok": true, "verdict": "A", "score": 1, "blockers": []}]},
            "response": {"jurors": [{"juror_id": "j1", "parsed_ok": true, "verdict": "A", "score": 1, "blockers": [], "answering_contests": ["c1"]}]},
        });
        let html = render_html(&payload, "run-1");
        assert!(html.contains("class=\"msg reply\""));
        assert!(html.contains("answering c1"));
    }
}
