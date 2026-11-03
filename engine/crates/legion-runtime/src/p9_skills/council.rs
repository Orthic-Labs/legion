//! Packet P9-skill-scripts: Rust port of `skills/council/lib/contracts.mjs` (the deterministic
//! half of the Council packet engine: canonical digesting and the field-level validation rules
//! that do not require loading the JSON Schema files), evolved to the v2 Council shape.
//!
//! v2 Council is ONE round of blind seats run in parallel (three HELPFUL seats: advice only;
//! three CHALLENGING seats: position + score) plus ONE adjudicator who verifies findings, rules
//! contested ones (the user may override), and gives the verdict. There is no debate round and no
//! separate Jury. `BLOCKER_CONSULT` runs three seats (improvement-path, red-team, security-ops).
//!
//! `skills/council/lib/flows.mjs` provider-IO orchestration is not ported here. The pure pieces
//! that need no provider IO are: the contract-boundary list (`CONTRACT_BOUNDARIES`) and the v2
//! verdict rule (`decide_verdict`, enforced on records by `validate_record_fields`).

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// `CONTRACT_BOUNDARIES` from flows.mjs.
pub const CONTRACT_BOUNDARIES: &[&str] = &[
    "changesSealedDecision",
    "changesLockedInvariant",
    "changesAcceptance",
    "expandsScope",
    "addsMaterialDependency",
    "changesPublicBehavior",
    "altersSecurity",
    "exceedsEffectClass",
];

const FORBIDDEN_AUTHORITY_TOKENS: &[&str] = &["DECISION_SEALED", "CONTROL_PASS"];

/// Canonical JSON serialization used for digesting: object keys sorted, arrays preserved
/// in order, matching `contracts.mjs`'s `canonical()`.
pub fn canonical(value: &Value) -> String {
    match value {
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: BTreeSet<&String> = BTreeSet::new();
            for k in map.keys() {
                keys.insert(k);
            }
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonical(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".to_string()),
    }
}

/// `digestValue()`: `sha256:<hex>` over the canonical serialization.
pub fn digest_value(value: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical(value).as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Digest a Council request while excluding its own top-level `packetDigest` field.
/// Nested fields with the same name remain part of the request and affect the digest.
pub fn request_digest(request: &Value) -> String {
    let mut projection = request.clone();
    if let Value::Object(fields) = &mut projection {
        fields.remove("packetDigest");
    }
    digest_value(&projection)
}

/// Mirrors `findForbiddenToken`: recursively scans strings for the forbidden authority tokens.
pub fn find_forbidden_token(value: &Value) -> Option<&'static str> {
    match value {
        Value::String(s) => FORBIDDEN_AUTHORITY_TOKENS
            .iter()
            .find(|t| s.contains(**t))
            .copied(),
        Value::Array(items) => items.iter().find_map(find_forbidden_token),
        Value::Object(map) => map.values().find_map(find_forbidden_token),
        _ => None,
    }
}

/// The mode -> allowed outcome sets from `REQUEST_OUTCOMES`.
pub fn allowed_outcomes(mode: &str) -> Option<&'static [&'static str]> {
    match mode {
        "DECISION_CHALLENGE" => Some(&["SUPPORTED", "REVISE", "UNRESOLVED"]),
        "BLOCKER_CONSULT" => Some(&[
            "CONTRACT_SAFE",
            "AMENDMENT_REQUIRED",
            "INSUFFICIENT_EVIDENCE",
        ]),
        _ => None,
    }
}

const HELPFUL_STANCES: &[&str] = &["improvement-path", "scope-alternatives", "user-outcome"];
const CHALLENGING_STANCES: &[&str] = &["red-team", "security-ops", "minimize"];
const BLOCKER_HELPFUL: &[&str] = &["improvement-path"];
const BLOCKER_CHALLENGING: &[&str] = &["red-team", "security-ops"];

/// `(supported, revise, unresolved)` outcome names for a record mode.
fn outcome_triple(mode: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match mode {
        "DECISION_CHALLENGE" => Some(("SUPPORTED", "REVISE", "UNRESOLVED")),
        "BLOCKER_CONSULT" => Some((
            "CONTRACT_SAFE",
            "AMENDMENT_REQUIRED",
            "INSUFFICIENT_EVIDENCE",
        )),
        _ => None,
    }
}

/// The v2 verdict rule, as a pure function.
///
/// * any CHALLENGING seat FAILED -> unresolved
/// * adjudication missing (`adjudicator_verdict` is `None`) -> unresolved
/// * `forced_revise` (a merged P0 finding or an adjudicator requirementTrace MISSING) turns a
///   supported verdict into revise
/// * otherwise the adjudicator's verdict stands
///
/// Returns `None` only for a mode with no outcome set (for example `PACKET_ONLY`).
pub fn decide_verdict(
    mode: &str,
    challenging_seat_failed: bool,
    adjudicator_verdict: Option<&str>,
    forced_revise: bool,
) -> Option<&'static str> {
    let (supported, revise, unresolved) = outcome_triple(mode)?;
    if challenging_seat_failed {
        return Some(unresolved);
    }
    let Some(verdict) = adjudicator_verdict else {
        return Some(unresolved);
    };
    Some(if verdict == supported {
        if forced_revise {
            revise
        } else {
            supported
        }
    } else if verdict == revise {
        revise
    } else {
        unresolved
    })
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn is_present(v: &Value, key: &str) -> bool {
    v.get(key).is_some_and(|x| !x.is_null())
}

fn seats_of(record: &Value) -> &[Value] {
    record
        .get("seats")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn adjudication_of(record: &Value) -> Option<&Value> {
    record.get("adjudication").filter(|a| a.is_object())
}

fn challenging_seat_failed(record: &Value) -> bool {
    seats_of(record)
        .iter()
        .any(|s| str_field(s, "side") == "CHALLENGING" && str_field(s, "status") != "RETURNED")
}

/// A merged finding at tier P0, or an adjudicator requirementTrace row that is MISSING.
fn adjudication_blocks_support(adjudication: &Value) -> bool {
    let p0 = adjudication
        .get("findings")
        .and_then(Value::as_array)
        .is_some_and(|f| f.iter().any(|x| str_field(x, "tier") == "P0"));
    let missing = adjudication
        .get("requirementTrace")
        .and_then(Value::as_array)
        .is_some_and(|t| t.iter().any(|r| str_field(r, "status") == "MISSING"));
    p0 || missing
}

/// Field-level validation from `validateCouncilRecord`, minus the generic JSON-Schema structural
/// pass (done separately through `validate_against_schema` with the v2 record schema).
pub fn validate_record_fields(record: &Value, request: Option<&Value>) -> Vec<String> {
    let mut errors = Vec::new();
    // A plain fn (rather than a closure) so the borrow's lifetime is tied to
    // each call site's argument, not fixed to one inferred signature.
    fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
        v.get(k)
    }

    let mode = record.get("mode").and_then(Value::as_str).unwrap_or("");
    if mode == "PACKET_ONLY" {
        errors.push("$.mode PACKET_ONLY cannot produce a CouncilRecord".to_string());
    }

    if let Some(request) = request {
        if get(record, "requestId") != get(request, "requestId") {
            errors.push("$.requestId does not match request".to_string());
        }
        if get(record, "mode") != get(request, "mode") {
            errors.push("$.mode does not match request".to_string());
        }
        let computed_digest = request_digest(request);
        let request_digest_matches = get(request, "packetDigest")
            .and_then(Value::as_str)
            .is_some_and(|digest| digest == computed_digest);
        let record_digest_matches = get(record, "packetDigest")
            .and_then(Value::as_str)
            .is_some_and(|digest| digest == computed_digest);
        if !request_digest_matches {
            errors.push("$.packetDigest does not match request content".to_string());
        }
        if !record_digest_matches {
            errors.push("$.packetDigest does not match computed request digest".to_string());
        }
        if get(record, "sourceRevision") != get(request, "sourceRevision") {
            errors.push("$.sourceRevision does not match request".to_string());
        }
        if get(record, "round") != get(request, "round") {
            errors.push("$.round does not match request".to_string());
        }
    }

    // One round by default; a second round only when the user asks, on a revised artifact.
    if let Some(round_no) = record.get("round") {
        if !matches!(round_no.as_i64(), Some(1 | 2)) {
            errors.push("$.round must be 1 or 2".to_string());
        }
    }

    if let Some(allowed) = allowed_outcomes(mode) {
        let outcome = record.get("outcome").and_then(Value::as_str).unwrap_or("");
        if !allowed.contains(&outcome) {
            errors.push(format!("$.outcome is invalid for {mode}"));
        }
    }

    if let Some(token) = find_forbidden_token(record) {
        errors.push(format!("$ contains forbidden authority token {token}"));
    }

    let digest_verified_flag = record
        .pointer("/integrity/digestVerified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let request_digest_verified = request.is_some_and(|request| {
        let computed_digest = request_digest(request);
        request
            .get("packetDigest")
            .and_then(Value::as_str)
            .is_some_and(|digest| digest == computed_digest)
            && record
                .get("packetDigest")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest == computed_digest)
    });
    if request.is_none() {
        errors.push("$.request is required to verify packet digest".to_string());
    }
    if !digest_verified_flag {
        errors.push("$.integrity.digestVerified must be true".to_string());
    } else if !request_digest_verified {
        errors.push(
            "$.integrity.digestVerified cannot be accepted without a matching request digest"
                .to_string(),
        );
    }
    let mutation_detected = record
        .pointer("/integrity/mutationDetected")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if mutation_detected {
        errors.push("$.integrity.mutationDetected invalidates review".to_string());
    }

    validate_seats(record, mode, &mut errors);
    validate_adjudication_and_outcome(record, mode, &mut errors);

    errors
}

/// Seat-level rules: panel shape per mode, distinct lenses, one card per side, helpful seats
/// advisory only, challenging seats scored, returned seats carry their trace and framing check.
fn validate_seats(record: &Value, mode: &str, errors: &mut Vec<String>) {
    let seats = seats_of(record);
    let mut lenses: BTreeSet<&str> = BTreeSet::new();
    let mut cards: BTreeSet<(&str, &str)> = BTreeSet::new();
    let mut helpful_stances: Vec<&str> = Vec::new();
    let mut challenging_stances: Vec<&str> = Vec::new();

    for seat in seats {
        let lens = str_field(seat, "lens").trim();
        let side = str_field(seat, "side");
        let stance = str_field(seat, "stance");
        let status = str_field(seat, "status");
        let label = if lens.is_empty() { "<no lens>" } else { lens };

        if seat.get("isolated").and_then(Value::as_bool) != Some(true) {
            errors.push(format!("$.seats {label} must be isolated"));
        }
        if lens.is_empty() {
            errors.push("$.seats every seat needs a lens id".to_string());
        } else {
            if !lenses.insert(lens) {
                errors.push(format!("$.seats lens {lens} is used by more than one seat"));
            }
            let card = lens.split_once('/').map_or(lens, |(_, card)| card);
            if !cards.insert((side, card)) {
                errors.push(format!(
                    "$.seats card {card} appears more than once on the {side} side"
                ));
            }
            if !stance.is_empty() && !lens.starts_with(&format!("{stance}/")) {
                errors.push(format!(
                    "$.seats lens {lens} does not start with its stance {stance}/"
                ));
            }
        }

        match side {
            "HELPFUL" => {
                helpful_stances.push(stance);
                if !HELPFUL_STANCES.contains(&stance) {
                    errors.push(format!(
                        "$.seats {label} stance {stance} is not a HELPFUL stance"
                    ));
                }
                for key in ["position", "score", "scores"] {
                    if is_present(seat, key) {
                        errors.push(format!(
                            "$.seats {label} is HELPFUL and must not carry {key} (advice only)"
                        ));
                    }
                }
            }
            "CHALLENGING" => {
                challenging_stances.push(stance);
                if !CHALLENGING_STANCES.contains(&stance) {
                    errors.push(format!(
                        "$.seats {label} stance {stance} is not a CHALLENGING stance"
                    ));
                }
                if status == "RETURNED" {
                    validate_challenging_scores(seat, label, errors);
                }
            }
            _ => errors.push(format!(
                "$.seats {label} side must be HELPFUL or CHALLENGING"
            )),
        }

        match status {
            "RETURNED" => {
                if !seat.get("requirementTrace").is_some_and(Value::is_array) {
                    errors.push(format!(
                        "$.seats {label} RETURNED seat needs requirementTrace"
                    ));
                }
                if !seat.get("framingCheck").is_some_and(Value::is_object) {
                    errors.push(format!("$.seats {label} RETURNED seat needs framingCheck"));
                }
            }
            "FAILED" => {}
            _ => errors.push(format!("$.seats {label} status must be RETURNED or FAILED")),
        }
    }

    let (expect_total, helpful_allowed, challenging_allowed) = match mode {
        "DECISION_CHALLENGE" => (6, HELPFUL_STANCES, CHALLENGING_STANCES),
        "BLOCKER_CONSULT" => (3, BLOCKER_HELPFUL, BLOCKER_CHALLENGING),
        _ => return,
    };
    if seats.len() != expect_total {
        errors.push(format!(
            "$.seats {mode} needs exactly {expect_total} seats, found {}",
            seats.len()
        ));
    }
    for (side, stances, allowed) in [
        ("HELPFUL", &helpful_stances, helpful_allowed),
        ("CHALLENGING", &challenging_stances, challenging_allowed),
    ] {
        let distinct: BTreeSet<&str> = stances.iter().copied().collect();
        if distinct.len() != stances.len() {
            errors.push(format!("$.seats {side} seats need distinct stances"));
        }
        for want in allowed {
            if !distinct.contains(want) {
                errors.push(format!(
                    "$.seats {mode} is missing the {side} stance {want}"
                ));
            }
        }
        if stances.len() != allowed.len() {
            errors.push(format!(
                "$.seats {mode} needs exactly {} {side} seats, found {}",
                allowed.len(),
                stances.len()
            ));
        }
    }
}

fn validate_challenging_scores(seat: &Value, label: &str, errors: &mut Vec<String>) {
    match seat.get("position").and_then(Value::as_str) {
        Some("SUPPORTED" | "REVISE" | "UNRESOLVED") => {}
        _ => errors.push(format!(
            "$.seats {label} CHALLENGING seat needs position SUPPORTED|REVISE|UNRESOLVED"
        )),
    }
    match seat.get("score").and_then(Value::as_i64) {
        Some(1..=10) => {}
        _ => errors.push(format!(
            "$.seats {label} CHALLENGING seat needs an integer score 1-10"
        )),
    }
    match seat.get("scores").and_then(Value::as_object) {
        Some(map) if !map.is_empty() => {
            if map
                .values()
                .any(|v| !v.as_f64().is_some_and(|n| (1.0..=10.0).contains(&n)))
            {
                errors.push(format!("$.seats {label} scores must each be a number 1-10"));
            }
        }
        _ => errors.push(format!(
            "$.seats {label} CHALLENGING seat needs per-dimension scores"
        )),
    }
}

/// Adjudication rules and the verdict rule: the record's `outcome` must be what
/// [`decide_verdict`] derives, and an ADJUDICATOR-ruled verdict may not claim SUPPORTED over a
/// merged P0 finding or a MISSING requirement.
fn validate_adjudication_and_outcome(record: &Value, mode: &str, errors: &mut Vec<String>) {
    let adjudication = adjudication_of(record);
    let mut adjudicator_verdict: Option<&str> = None;
    let mut forced_revise = false;

    if let Some(adj) = adjudication {
        let verdict = str_field(adj, "verdict");
        adjudicator_verdict = Some(verdict);
        if let Some(allowed) = allowed_outcomes(mode) {
            if !allowed.contains(&verdict) {
                errors.push(format!("$.adjudication.verdict is invalid for {mode}"));
            }
        }
        let ruled_by = str_field(adj, "ruledBy");
        let override_present = is_present(adj, "userOverride");
        match ruled_by {
            "ADJUDICATOR" => {
                if override_present {
                    errors.push("$.adjudication.userOverride requires ruledBy USER".to_string());
                }
            }
            "USER" => {
                if !override_present {
                    errors.push("$.adjudication ruledBy USER requires userOverride".to_string());
                }
            }
            _ => errors.push("$.adjudication.ruledBy must be ADJUDICATOR or USER".to_string()),
        }

        if ruled_by != "USER" && adjudication_blocks_support(adj) {
            forced_revise = true;
            if let Some((supported, revise, _)) = outcome_triple(mode) {
                if verdict == supported {
                    errors.push(format!(
                        "$.adjudication.verdict {supported} conflicts with a merged P0 finding or a MISSING requirement; the verdict must be {revise}"
                    ));
                }
            }
        }

        validate_adjudication_findings(record, adj, errors);
    }

    if let Some(expected) = decide_verdict(
        mode,
        challenging_seat_failed(record),
        adjudicator_verdict,
        forced_revise,
    ) {
        let outcome = str_field(record, "outcome");
        if outcome != expected && allowed_outcomes(mode).is_some_and(|a| a.contains(&outcome)) {
            errors.push(format!(
                "$.outcome {outcome} does not follow the verdict rule (expected {expected})"
            ));
        }
    }
}

fn validate_adjudication_findings(record: &Value, adj: &Value, errors: &mut Vec<String>) {
    let empty = Vec::new();
    let lenses: BTreeSet<&str> = seats_of(record)
        .iter()
        .map(|s| str_field(s, "lens"))
        .collect();
    let rulings = adj
        .get("findingRulings")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let ruled_ids: BTreeSet<&str> = rulings.iter().map(|r| str_field(r, "findingId")).collect();
    let merged = adj
        .get("findings")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for finding in merged {
        let id = str_field(finding, "findingId");
        if !ruled_ids.contains(id) {
            errors.push(format!(
                "$.adjudication.findingRulings missing ruling for {id}"
            ));
        }
        let raised_by = finding
            .get("raisedBy")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        if raised_by.is_empty() {
            errors.push(format!(
                "$.adjudication.findings {id} needs raisedBy seat lenses"
            ));
        }
        for lens in raised_by.iter().filter_map(Value::as_str) {
            if !lenses.contains(lens) {
                errors.push(format!(
                    "$.adjudication.findings {id} raisedBy {lens} is not a seat in this record"
                ));
            }
        }
    }
}

/// Minimal structural JSON-Schema check (subset used by the council schemas: `type`, `const`,
/// `enum`, `required`, `properties`, `additionalProperties: false`, `items`, `pattern`,
/// `minLength`, `minimum`, `maximum`). Returns one defect string per violation.
pub fn validate_against_schema(value: &Value, schema: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    schema_walk(value, schema, "$", &mut errors);
    errors
}

fn type_matches(value: &Value, name: &str) -> bool {
    match name {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn schema_walk(value: &Value, schema: &Value, path: &str, errors: &mut Vec<String>) {
    if let Some(t) = schema.get("type") {
        let ok = match t {
            Value::String(n) => type_matches(value, n),
            Value::Array(ns) => ns
                .iter()
                .filter_map(Value::as_str)
                .any(|n| type_matches(value, n)),
            _ => true,
        };
        if !ok {
            errors.push(format!("{path} has the wrong type"));
            return;
        }
    }
    if let Some(c) = schema.get("const") {
        if c != value {
            errors.push(format!("{path} must equal {c}"));
        }
    }
    if let Some(Value::Array(options)) = schema.get("enum") {
        if !options.contains(value) {
            errors.push(format!("{path} is not an allowed value"));
        }
    }
    if let Some(s) = value.as_str() {
        if let Some(n) = schema.get("minLength").and_then(Value::as_u64) {
            if (s.chars().count() as u64) < n {
                errors.push(format!("{path} is shorter than {n}"));
            }
        }
        if let Some(p) = schema.get("pattern").and_then(Value::as_str) {
            if let Ok(re) = regex::Regex::new(p) {
                if !re.is_match(s) {
                    errors.push(format!("{path} does not match {p}"));
                }
            }
        }
    }
    if let Some(n) = value.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
            if n < min {
                errors.push(format!("{path} is below {min}"));
            }
        }
        if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
            if n > max {
                errors.push(format!("{path} is above {max}"));
            }
        }
    }
    if let Some(obj) = value.as_object() {
        if let Some(Value::Array(req)) = schema.get("required") {
            for k in req.iter().filter_map(Value::as_str) {
                if !obj.contains_key(k) {
                    errors.push(format!("{path}.{k} is required"));
                }
            }
        }
        let props = schema.get("properties").and_then(Value::as_object);
        for (k, v) in obj {
            match props.and_then(|p| p.get(k)) {
                Some(sub) => schema_walk(v, sub, &format!("{path}.{k}"), errors),
                None => {
                    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                        errors.push(format!("{path}.{k} is not an allowed property"));
                    }
                }
            }
        }
    }
    if let (Some(items), Some(sub)) = (value.as_array(), schema.get("items")) {
        for (i, v) in items.iter().enumerate() {
            schema_walk(v, sub, &format!("{path}[{i}]"), errors);
        }
    }
}
