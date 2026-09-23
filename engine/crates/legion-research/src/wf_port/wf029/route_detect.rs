//! Port of `src/lib/research-core/router/route_detect.py`: detection
//! primitives for the least-privilege `ResearchRoute`.
//!
//! Pure text-heuristic functions, no I/O. `re.search` with `re.I` maps to
//! `regex::RegexBuilder::new(..).case_insensitive(true)`; the exact
//! alternation lists and `\b` word-boundary patterns are preserved
//! character-for-character so the compiled patterns match the same inputs.

use std::sync::OnceLock;

use regex::Regex;

pub const DOMAIN_VALUES: &[&str] = &["general", "market", "technical", "scientific", "medical", "legal"];
pub const OPERATIONS: &[&str] = &[
    "discover", "compare", "verify", "analyze", "advise", "review", "draft", "procedure",
    "manage-corpus", "generate-artifact",
];
pub const METHODS: &[&str] = &[
    "web", "competitor", "reddit", "audience", "trends", "scholarly", "document", "authority",
];
pub const PROVIDERS: &[&str] = &["browser", "local-corpus", "notebooklm", "domain-default"];
pub const ASSURANCE: &[&str] = &["quick", "standard", "verified"];
pub const SCALE: &[&str] = &["focused", "broad", "dossier"];
pub const SENSITIVITY: &[&str] = &["public", "private", "highly-sensitive"];

fn re<'a>(cell: &'a OnceLock<Regex>, pattern: &str) -> &'a Regex {
    cell.get_or_init(|| {
        regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .expect("static regex must compile")
    })
}

macro_rules! static_regex {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            re(&CELL, $pattern)
        }
    };
}

static_regex!(
    personal_first_person,
    r"\b(my|mine|i\s+(?:am|have|take|use|was|were|got)|i'm|i've|me)\b"
);
static_regex!(
    other_patient,
    r"\b(my\s+(?:wife|husband|mother|father|friend|child|son|daughter)|his|her)\b"
);

static_regex!(medical_signals, r"\b(medical|doctor|patient|drug|dose|dosing|medicine|medication|interaction|side effect|lab|blood test|diagnosis|symptom|semaglutide|trt|testosterone|\w*statin|thyroid|insulin|hba1c|ldl|apo(?:b|a)|peptide|supplement|clinical trial)\b");
static_regex!(legal_signals, r"\b(legal|law|court|judgment|statute|regulation|consumer|criminal|bail|fir|contract|clause|lawsuit|complaint|appeal|tribunal|police|refund|trademark|copyright|tax)\b");
static_regex!(scientific_signals, r"\b(study|paper|doi|pubmed|trial|meta-analysis|systematic review|scientific literature)\b");
static_regex!(technical_signals, r"\b(benchmark|latency|throughput|architecture|framework|library|runtime|compiler|api)\b");
static_regex!(market_signals, r"\b(market|competitor|positioning|pricing|audience|customer|icp|jtbd|lead|trend|reddit)\b");

fn country_patterns() -> &'static [(&'static str, fn() -> &'static Regex)] {
    static_regex!(country_in, r"\b(india|indian|ipc|bns|bnss|crpc|e-?jagriti|e-?daakhil|consumer commission|ncdrc|rbi|sebi|mca)\b");
    static_regex!(country_us, r"\b(united states|u\.s\.|usa|federal court|ftc|sec|fda)\b");
    static_regex!(country_gb, r"\b(united kingdom|u\.k\.|england|wales|scotland|cma|fca uk)\b");
    static_regex!(country_eu, r"\b(european union|eu law|gdpr|european commission|ecj|cjeu)\b");
    &[
        ("IN", country_in as fn() -> &'static Regex),
        ("US", country_us as fn() -> &'static Regex),
        ("GB", country_gb as fn() -> &'static Regex),
        ("EU", country_eu as fn() -> &'static Regex),
    ]
}

fn legal_area_patterns() -> &'static [(&'static str, fn() -> &'static Regex)] {
    static_regex!(area_criminal, r"\b(criminal|fir|bail|chargesheet|charge sheet|ipc|bns|bnss|crpc|offence|accused|arrest|quash)\b");
    static_regex!(area_consumer, r"\b(consumer|refund|defective product|deficiency in service|unfair trade|e-?jagriti|e-?daakhil|consumer commission)\b");
    static_regex!(area_contract, r"\b(contract|agreement|msa|nda|terms|clause|redline|indemnity|limitation of liability)\b");
    static_regex!(area_employment, r"\b(employment|employee|employer|termination|severance|workplace|labour|labor law)\b");
    static_regex!(area_tax, r"\b(tax|gst|income tax|irs|assessment)\b");
    static_regex!(area_ip, r"\b(trademark|copyright|patent|intellectual property)\b");
    static_regex!(area_privacy, r"\b(privacy|gdpr|dpdp|data protection|personal data)\b");
    static_regex!(area_family, r"\b(divorce|custody|maintenance|alimony|family law)\b");
    static_regex!(area_immigration, r"\b(visa|immigration|citizenship|residency permit)\b");
    static_regex!(area_corporate, r"\b(company law|corporate|shareholder|director|mca|sebi)\b");
    static_regex!(area_regulatory, r"\b(regulatory|regulator|compliance|licence|license|notification)\b");
    static_regex!(area_civil, r"\b(civil suit|injunction|damages|decree|plaintiff|defendant|tort)\b");
    &[
        ("criminal", area_criminal as fn() -> &'static Regex),
        ("consumer", area_consumer as fn() -> &'static Regex),
        ("contract", area_contract as fn() -> &'static Regex),
        ("employment", area_employment as fn() -> &'static Regex),
        ("tax", area_tax as fn() -> &'static Regex),
        ("ip", area_ip as fn() -> &'static Regex),
        ("privacy", area_privacy as fn() -> &'static Regex),
        ("family", area_family as fn() -> &'static Regex),
        ("immigration", area_immigration as fn() -> &'static Regex),
        ("corporate", area_corporate as fn() -> &'static Regex),
        ("regulatory", area_regulatory as fn() -> &'static Regex),
        ("civil", area_civil as fn() -> &'static Regex),
    ]
}

/// `route_detect._unique`.
pub fn unique(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        if !out.contains(value) {
            out.push(value.clone());
        }
    }
    out
}

/// `route_detect.detect_domain`.
pub fn detect_domain(text: &str) -> &'static str {
    if medical_signals().is_match(text) {
        return "medical";
    }
    if legal_signals().is_match(text) {
        return "legal";
    }
    if scientific_signals().is_match(text) {
        return "scientific";
    }
    if technical_signals().is_match(text) {
        return "technical";
    }
    if market_signals().is_match(text) {
        return "market";
    }
    "general"
}

/// `route_detect.detect_operation`.
pub fn detect_operation(text: &str) -> &'static str {
    let lower = text.to_lowercase();
    let checks: &[(&str, &[&str])] = &[
        ("generate-artifact", &["podcast", "audio overview", "slide deck", "quiz", "flashcards", "infographic"]),
        ("manage-corpus", &["create notebook", "add these sources", "upload these", "index these documents"]),
        ("procedure", &["how do i file", "help me file", "filing pack", "consumer complaint", "procedure"]),
        ("draft", &["draft ", "write a notice", "write a complaint", "prepare a memo", "redline"]),
        ("review", &["review ", "audit ", "check this agreement", "review this document"]),
        ("verify", &["verify", "fact-check", "fact check", "are these claims accurate"]),
        ("compare", &["compare", " versus ", " vs ", "alternative to"]),
        ("discover", &["find ", "look up", "discover", "what is out there"]),
        ("advise", &["what should i do", "recommend", "advise"]),
    ];
    for (operation, needles) in checks {
        if needles.iter().any(|needle| lower.contains(needle)) {
            return operation;
        }
    }
    "analyze"
}

/// `route_detect.detect_methods`.
pub fn detect_methods(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut found: Vec<String> = Vec::new();
    let mapping: &[(&str, &[&str])] = &[
        ("reddit", &["reddit", "subreddit"]),
        ("competitor", &["competitor", " vs ", " versus ", "alternative"]),
        (
            "audience",
            &[
                "audience", "pain point", "exact words", "comments", "customer", "customers",
                "customer interview", "jtbd", "jobs to be done", "voc", "survey",
            ],
        ),
        ("trends", &["trend", "last 30 days", "last30days", "gaining traction"]),
        ("scholarly", &["paper", "study", "doi", "pubmed", "trial", "meta-analysis", "scientific literature"]),
        ("document", &["document", "pdf", "transcript", "agreement", "contract", "report"]),
        ("authority", &["law", "statute", "regulation", "judgment", "court", "official source", "guideline", "regulator"]),
    ];
    for (method, needles) in mapping {
        if needles.iter().any(|needle| lower.contains(needle)) {
            found.push((*method).to_string());
        }
    }
    if found.is_empty() || ["web", "online", "search"].iter().any(|x| lower.contains(x)) {
        found.push("web".to_string());
    }
    unique(&found)
}

/// `route_detect.detect_provider`.
pub fn detect_provider(text: &str, _domain: &str, methods: &[String]) -> &'static str {
    let lower = text.to_lowercase();
    if lower.contains("notebooklm") {
        return "notebooklm";
    }
    let only_document = methods.len() == 1 && methods[0] == "document";
    let has_document_not_web = methods.iter().any(|m| m == "document") && !methods.iter().any(|m| m == "web");
    if only_document || has_document_not_web {
        return "local-corpus";
    }
    if ["force browser", "browser provider", "live browser"].iter().any(|x| lower.contains(x)) {
        return "browser";
    }
    "domain-default"
}

/// `route_detect.detect_assurance`.
pub fn detect_assurance(text: &str, domain: &str, operation: &str) -> &'static str {
    let lower = text.to_lowercase();
    if ["quick", "quickly", "brief answer", "rough scan", "triage only"].iter().any(|x| lower.contains(x)) {
        return "quick";
    }
    if [
        "verified", "fact-check", "fact check", "publication", "cite every", "court filing", "doctor-ready",
    ]
    .iter()
    .any(|x| lower.contains(x))
    {
        return "verified";
    }
    if matches!(domain, "medical" | "legal") || matches!(operation, "verify" | "procedure") {
        return "verified";
    }
    "standard"
}

/// `route_detect.detect_scale`.
pub fn detect_scale(text: &str) -> &'static str {
    let lower = text.to_lowercase();
    if ["dossier", "dissertation", "chaptered", "full investigation"].iter().any(|x| lower.contains(x)) {
        return "dossier";
    }
    if ["landscape", "broad", "comprehensive", "across the market", "all competitors"]
        .iter()
        .any(|x| lower.contains(x))
    {
        return "broad";
    }
    "focused"
}

/// `route_detect.detect_sensitivity`. `patient_kind` mirrors the Python
/// `str | None` default of `None`.
pub fn detect_sensitivity(text: &str, _domain: &str, patient_kind: Option<&str>) -> &'static str {
    let lower = text.to_lowercase();
    if ["confidential", "privileged", "highly sensitive", "patient id"].iter().any(|x| lower.contains(x)) {
        return "highly-sensitive";
    }
    let personal_kind = matches!(patient_kind, Some("self") | Some("other-identified"));
    if personal_kind || ["my private", "my clinic", "my case", "my contract"].iter().any(|x| lower.contains(x)) {
        return "private";
    }
    "public"
}

/// `route_detect._country`: exactly one distinct country code hit, else
/// `None`.
pub fn country(text: &str) -> Option<&'static str> {
    let hits: Vec<&'static str> = country_patterns()
        .iter()
        .filter(|(_, pattern)| pattern().is_match(text))
        .map(|(code, _)| *code)
        .collect();
    let unique_codes: std::collections::BTreeSet<&str> = hits.iter().copied().collect();
    if unique_codes.len() == 1 {
        Some(hits[0])
    } else {
        None
    }
}

/// `route_detect._legal_area`: exactly one distinct legal-area hit, else
/// `None`.
pub fn legal_area(text: &str) -> Option<&'static str> {
    let hits: Vec<&'static str> = legal_area_patterns()
        .iter()
        .filter(|(_, pattern)| pattern().is_match(text))
        .map(|(area, _)| *area)
        .collect();
    let unique_areas: std::collections::BTreeSet<&str> = hits.iter().copied().collect();
    if unique_areas.len() == 1 {
        Some(hits[0])
    } else {
        None
    }
}

/// `route_detect._issue`: collapse whitespace, trim, cap at 500 chars.
/// Python slices `[:500]` by Unicode code point; `chars().take(500)`
/// matches that (not by byte, which would risk splitting a multi-byte
/// char).
pub fn issue(text: &str) -> String {
    static_regex!(whitespace, r"\s+");
    let collapsed = whitespace().replace_all(text, " ");
    let trimmed = collapsed.trim();
    trimmed.chars().take(500).collect()
}

/// `PERSONAL_FIRST_PERSON` search, exposed for `route_resolve::build_subject`.
pub fn is_personal_first_person(text: &str) -> bool {
    personal_first_person().is_match(text)
}

/// `OTHER_PATIENT` search, exposed for `route_resolve::build_subject`.
pub fn is_other_patient(text: &str) -> bool {
    other_patient().is_match(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_domain_priority_matches_python_order() {
        // medical beats legal beats scientific beats technical beats market
        assert_eq!(detect_domain("what dose of a drug for my patient"), "medical");
        assert_eq!(detect_domain("court judgment on a contract clause"), "legal");
        assert_eq!(detect_domain("a systematic review paper"), "scientific");
        assert_eq!(detect_domain("api latency benchmark"), "technical");
        assert_eq!(detect_domain("competitor pricing trend"), "market");
        assert_eq!(detect_domain("hello there"), "general");
    }

    #[test]
    fn detect_operation_checks_in_order() {
        assert_eq!(detect_operation("generate a podcast"), "generate-artifact");
        assert_eq!(detect_operation("please review this document"), "review");
        assert_eq!(detect_operation("compare a vs b"), "compare");
        assert_eq!(detect_operation("nothing matches here"), "analyze");
    }

    #[test]
    fn detect_methods_falls_back_to_web() {
        assert_eq!(detect_methods("just search the web"), vec!["web".to_string()]);
        assert_eq!(detect_methods("reddit thread about this"), vec!["reddit".to_string()]);
        assert_eq!(detect_methods("no signal words"), vec!["web".to_string()]);
    }

    #[test]
    fn detect_provider_local_corpus_requires_document_only() {
        let doc_only = vec!["document".to_string()];
        assert_eq!(detect_provider("read this pdf", "general", &doc_only), "local-corpus");
        let doc_and_web = vec!["document".to_string(), "web".to_string()];
        assert_eq!(detect_provider("read this pdf online", "general", &doc_and_web), "domain-default");
        assert_eq!(detect_provider("use notebooklm please", "general", &doc_only), "notebooklm");
    }

    #[test]
    fn country_and_legal_area_require_unique_hit() {
        assert_eq!(country("filing in india under ipc"), Some("IN"));
        assert_eq!(country("india and united states both apply"), None);
        assert_eq!(legal_area("my employment termination dispute"), Some("employment"));
    }

    #[test]
    fn issue_collapses_whitespace_and_caps_length() {
        assert_eq!(issue("  a   b\n\tc  "), "a b c");
        let long = "x".repeat(600);
        assert_eq!(issue(&long).chars().count(), 500);
    }
}
