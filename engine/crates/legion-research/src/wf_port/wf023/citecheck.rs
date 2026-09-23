//! Port of `research-core/citecheck.py`: citation-to-sentence binding and
//! source-support verification.
//!
//! Faithful port of `_sentences`, `_norm_words`, `_support_blob`, `_verdict`,
//! and `check`. The CLI wrapper (`main`) is not ported: this crate is a
//! library, and its I/O (`--draft`/`--evidence`/`--out`, exit code 0/2) is
//! plumbing for the retired Python entry point.

use std::collections::BTreeMap;

use regex::Regex;
use serde_json::Value;

fn cite_re() -> Regex {
    Regex::new(r"\[\+\s*([A-Za-z0-9_.:-]+)\s*\]").expect("static regex")
}

fn number_re() -> Regex {
    Regex::new(r"[-+]?\d[\d,]*(?:\.\d+)?%?").expect("static regex")
}

fn word_re() -> Regex {
    Regex::new(r"[A-Za-z0-9]{3,}").expect("static regex")
}

fn confidence_status_re() -> Regex {
    Regex::new(r"(?i)\[(?:confidence|status):[^\]]+\]").expect("static regex")
}

fn leading_tag_re() -> Regex {
    Regex::new(r"^\[[A-Z][A-Z-]*\]\s*").expect("static regex")
}

fn only_tags_re() -> Regex {
    Regex::new(r"(?i)^(?:(?:\[+?[^\]]+\]|\[(?:confidence|status):[^\]]+\]\s*))+$")
        .expect("static regex")
}

fn factual_verb_re() -> Regex {
    Regex::new(r"(?i)\b(is|are|was|were|has|have|causes?|reduces?|increases?|requires?|prohibits?)\b")
        .expect("static regex")
}

const STOP_WORDS: &[&str] = &[
    "the", "and", "that", "with", "from", "this", "have", "were", "been", "into", "than", "for",
];

/// One binding candidate: a sentence chunk with an `index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentenceRow {
    pub index: usize,
    pub text: String,
}

/// One citation-to-evidence pairing, mirroring the dicts the Python builds
/// by spreading `row` and adding `evidence_id`/`verdict`(/`reason`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CitePair {
    pub index: usize,
    pub text: String,
    pub evidence_id: String,
    pub verdict: String,
    pub reason: Option<String>,
}

/// Mirrors the dict `check()` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiteCheckResult {
    pub ok: bool,
    pub pairs_count: usize,
    pub unbound_count: usize,
    pub dangling_count: usize,
    pub unsupported_or_partial_count: usize,
    pub pairs: Vec<CitePair>,
    pub unbound: Vec<SentenceRow>,
    pub dangling: Vec<CitePair>,
    pub unsupported: Vec<CitePair>,
}

fn norm_words(text: &str) -> Vec<String> {
    word_re()
        .find_iter(text)
        .map(|m| m.as_str().to_lowercase())
        .filter(|w| !STOP_WORDS.contains(&w.as_str()))
        .collect()
}

/// `_sentences`: split markdown into sentence/bullet chunks, skipping
/// headings, blank lines, `sources`/`references` sections, and `_as of`
/// lines. Reattaches a trailing citation-only chunk to the previous one, and
/// splits non-bullet lines on sentence boundaries before an uppercase letter
/// or `[`.
fn sentences(markdown: &str) -> Vec<SentenceRow> {
    let bullet_re = Regex::new(r"^[-*]\s+").expect("static regex");
    // `(?<=[.!?])\s+(?=[A-Z\[])` needs lookaround, which the `regex` crate
    // does not support; we scan manually for the same split points instead.
    let mut rows = Vec::new();
    let mut section = String::new();
    let mut idx = 0usize;
    let only_tags = only_tags_re();

    for raw_line in markdown.lines() {
        let line = raw_line.trim();
        if let Some(stripped) = line.strip_prefix('#') {
            section = stripped.trim_start_matches('#').trim().to_lowercase();
            continue;
        }
        if line.is_empty()
            || section == "sources"
            || section == "references"
            || line.starts_with("_as of")
        {
            continue;
        }
        let is_bullet = bullet_re.is_match(line);
        let text = bullet_re.replace(line, "").to_string();
        let chunks: Vec<String> = if is_bullet {
            vec![text]
        } else {
            split_sentences(&text)
        };
        let mut merged: Vec<String> = Vec::new();
        for chunk in chunks {
            let trimmed = chunk.trim();
            if !merged.is_empty() && only_tags.is_match(trimmed) {
                let last = merged.last_mut().expect("checked non-empty");
                last.push(' ');
                last.push_str(trimmed);
            } else {
                merged.push(chunk);
            }
        }
        for chunk in merged {
            let trimmed = chunk.trim();
            if !trimmed.is_empty() {
                rows.push(SentenceRow {
                    index: idx,
                    text: trimmed.to_string(),
                });
                idx += 1;
            }
        }
    }
    rows
}

/// Splits `text` on `(?<=[.!?])\s+(?=[A-Z\[])`: after `.`, `!`, or `?`,
/// across whitespace, before an uppercase letter or `[`.
fn split_sentences(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if matches!(chars[i], '.' | '!' | '?') {
            let mut j = i + 1;
            let ws_start = j;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j > ws_start && j < chars.len() && (chars[j].is_uppercase() || chars[j] == '[') {
                out.push(chars[start..j].iter().collect::<String>());
                // Trim leading whitespace from the next chunk's start marker.
                start = j;
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out.push(chars[start..].iter().collect::<String>());
    // Each pushed chunk (except the first) begins with the whitespace that
    // was consumed by the split; the caller trims per-chunk, so leave as-is
    // except drop it here to match Python's re.split which excludes the
    // whitespace from both sides.
    out.into_iter()
        .map(|s| s.trim_start().to_string())
        .collect()
}

fn support_blob(ev: &Value) -> String {
    ["quote_or_paraphrase", "evidence_text", "body_plain", "title", "locator"]
        .iter()
        .map(|key| ev.get(*key).and_then(Value::as_str).unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `_verdict`: returns (verdict, reason).
fn verdict(sentence: &str, ev: &Value) -> (String, String) {
    let mut clean = cite_re().replace_all(sentence, "").to_string();
    clean = confidence_status_re().replace_all(&clean, "").to_string();
    clean = leading_tag_re().replace(&clean, "").to_string();

    let numbers: Vec<String> = number_re()
        .find_iter(&clean)
        .map(|m| m.as_str().replace(',', ""))
        .collect();
    let blob = support_blob(ev);
    let blob_numbers = blob.replace(',', "");
    if !numbers.is_empty() && !numbers.iter().all(|n| blob_numbers.contains(n.as_str())) {
        return (
            "unsupported".to_string(),
            format!("sentence numbers {numbers:?} are not all present in evidence"),
        );
    }
    let words = norm_words(&clean);
    let evidence_words: std::collections::BTreeSet<String> = norm_words(&blob).into_iter().collect();
    if words.is_empty() {
        return ("supported".to_string(), "citation-only or metadata sentence".to_string());
    }
    let content_words: std::collections::BTreeSet<String> = words
        .iter()
        .filter(|w| w.parse::<f64>().is_err())
        .cloned()
        .collect();
    let denom = content_words.len().max(1) as f64;
    let overlap_count = content_words.intersection(&evidence_words).count() as f64;
    let overlap = overlap_count / denom;
    if overlap >= 0.55 || (!numbers.is_empty() && overlap >= 0.25) {
        return ("supported".to_string(), format!("lexical overlap={overlap:.2}"));
    }
    if overlap >= 0.30 {
        return ("partially-supported".to_string(), format!("lexical overlap={overlap:.2}"));
    }
    ("unsupported".to_string(), format!("lexical overlap={overlap:.2}"))
}

/// Production entry point: port of `check(markdown, evidence)`.
///
/// `evidence` rows must each carry an `id` field (matches Python's
/// `{str(e['id']): e for e in evidence}`; a row without `id` is dropped
/// rather than panicking, since Rust has no KeyError equivalent here).
pub fn check(markdown: &str, evidence: &[Value]) -> CiteCheckResult {
    let by_id: BTreeMap<String, &Value> = evidence
        .iter()
        .filter_map(|e| e.get("id").map(|id| (value_as_id_string(id), e)))
        .collect();

    let citer = cite_re();
    let numberer = number_re();
    let factual_verb = factual_verb_re();

    let mut pairs = Vec::new();
    let mut unbound = Vec::new();
    let mut dangling = Vec::new();
    let mut unsupported = Vec::new();

    for row in sentences(markdown) {
        let ids: Vec<String> = citer
            .captures_iter(&row.text)
            .map(|c| c[1].to_string())
            .collect();
        let factual = numberer.is_match(&row.text) || factual_verb.is_match(&row.text);
        if ids.is_empty() {
            if factual {
                unbound.push(row);
            }
            continue;
        }
        for eid in ids {
            match by_id.get(&eid) {
                None => {
                    let item = CitePair {
                        index: row.index,
                        text: row.text.clone(),
                        evidence_id: eid,
                        verdict: "dangling".to_string(),
                        reason: None,
                    };
                    pairs.push(item.clone());
                    dangling.push(item);
                }
                Some(ev) => {
                    let (v, reason) = verdict(&row.text, ev);
                    let item = CitePair {
                        index: row.index,
                        text: row.text.clone(),
                        evidence_id: eid,
                        verdict: v.clone(),
                        reason: Some(reason),
                    };
                    pairs.push(item.clone());
                    if v == "unsupported" || v == "partially-supported" {
                        unsupported.push(item);
                    }
                }
            }
        }
    }

    CiteCheckResult {
        ok: unbound.is_empty() && dangling.is_empty() && unsupported.is_empty(),
        pairs_count: pairs.len(),
        unbound_count: unbound.len(),
        dangling_count: dangling.len(),
        unsupported_or_partial_count: unsupported.len(),
        pairs,
        unbound,
        dangling,
        unsupported,
    }
}

fn value_as_id_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(id: &str, text: &str) -> Value {
        json!({"id": id, "quote_or_paraphrase": text})
    }

    #[test]
    fn supported_sentence_with_matching_numbers_and_words() {
        let evidence = vec![ev("E1", "Vendor X charges 12 dollars per seat per month")];
        let markdown = "Vendor X charges 12 dollars per seat per month. [+E1]\n";
        let result = check(markdown, &evidence);
        assert!(result.ok, "{result:?}");
        assert_eq!(result.pairs_count, 1);
        assert_eq!(result.pairs[0].verdict, "supported");
    }

    #[test]
    fn unsupported_when_sentence_number_absent_from_evidence() {
        let evidence = vec![ev("E1", "Vendor X charges a flat monthly fee")];
        let markdown = "Vendor X charges 12 dollars per seat. [+E1]\n";
        let result = check(markdown, &evidence);
        assert!(!result.ok);
        assert_eq!(result.unsupported_or_partial_count, 1);
        assert_eq!(result.unsupported[0].verdict, "unsupported");
    }

    #[test]
    fn dangling_citation_id_not_in_evidence() {
        let evidence: Vec<Value> = vec![];
        let markdown = "Vendor X charges 12 dollars per seat. [+E404]\n";
        let result = check(markdown, &evidence);
        assert!(!result.ok);
        assert_eq!(result.dangling_count, 1);
        assert_eq!(result.dangling[0].evidence_id, "E404");
    }

    #[test]
    fn unbound_factual_sentence_without_citation() {
        let evidence: Vec<Value> = vec![];
        let markdown = "Vendor X requires an annual contract.\n";
        let result = check(markdown, &evidence);
        assert!(!result.ok);
        assert_eq!(result.unbound_count, 1);
        assert_eq!(result.unbound[0].text, "Vendor X requires an annual contract.");
    }

    #[test]
    fn non_factual_sentence_without_citation_is_ignored() {
        let evidence: Vec<Value> = vec![];
        let markdown = "Some background color for the reader.\n";
        let result = check(markdown, &evidence);
        assert!(result.ok);
        assert_eq!(result.pairs_count, 0);
        assert_eq!(result.unbound_count, 0);
    }

    #[test]
    fn sources_section_is_skipped() {
        let evidence: Vec<Value> = vec![];
        let markdown = "# Sources\nVendor X requires an annual contract.\n";
        let result = check(markdown, &evidence);
        assert!(result.ok);
        assert_eq!(result.unbound_count, 0);
    }

    #[test]
    fn bullet_lines_are_treated_as_single_chunks() {
        let evidence = vec![ev("E1", "Vendor X ships weekly updates")];
        let markdown = "- Vendor X ships weekly updates. [+E1]\n";
        let result = check(markdown, &evidence);
        assert_eq!(result.pairs_count, 1);
        assert_eq!(result.pairs[0].verdict, "supported");
    }

    #[test]
    fn citation_only_chunk_is_treated_as_supported_metadata() {
        let evidence = vec![ev("E1", "Vendor X reports growth")];
        let markdown = "Vendor X reports strong growth this year. [+E1] [confidence:high]\n";
        let result = check(markdown, &evidence);
        assert!(result.ok, "{result:?}");
    }
}
