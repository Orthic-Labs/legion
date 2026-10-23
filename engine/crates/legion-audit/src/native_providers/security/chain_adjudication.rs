//! Chain adjudication (SEC 8.3, 9.4): the single canonical owner of the rule that
//! decides whether an attack-path hypothesis becomes an established chain.
//!
//! Design rule: synthesis proposes compositions; only independent adjudication
//! establishes them. A chain is `PROVEN` only when every member step carries an
//! independently adjudicated verdict at the required strength, every join was
//! verified, blocking controls were evaluated, a typed negative control exists,
//! terminal impact and proof are bound, and the adjudicating context is neither
//! the synthesizing provider nor the synthesizing context. Every failed gate
//! fails closed to `UNPROVEN` with explicit reasons; a member verdict is never
//! upgraded by this module.
//!
//! Hypotheses, member verdicts and the adjudicator's raw assessment are JSON
//! (`serde_json::Value`) so the module does not depend on the attack-path
//! synthesis types.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use legion_contracts::canonical_json_bytes;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Registry provider id for this adjudicator.
pub const PROVIDER_ID: &str = "security.chain-adjudication";

pub const CHAIN_VERDICTS: [&str; 5] = [
    "PROVEN",
    "PARTIALLY_SUPPORTED",
    "REFUTED",
    "BLOCKED",
    "UNPROVEN",
];

/// Member verdicts that count as a surviving primitive.
pub const SURVIVING_MEMBER_VERDICTS: [&str; 2] = ["TRUE_POSITIVE", "LIKELY_TRUE_POSITIVE"];

pub const NEGATIVE_CONTROL_KINDS: [&str; 4] = [
    "break-join",
    "remove-precondition",
    "alternate-principal",
    "benign-input",
];

/// The negative control must show the chain failing when the join is broken.
pub const NEGATIVE_CONTROL_OUTCOME: &str = "chain-broken-as-expected";

pub const REQUIRED_ANALYSIS: [&str; 11] = [
    "step usability",
    "identity compatibility",
    "environment compatibility",
    "tenant compatibility",
    "timing and workflow state",
    "join validity",
    "inter-step controls",
    "terminal impact",
    "safe proof",
    "negative control",
    "strongest benign explanation",
];

const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];
const COMPAT_KEYS: [&str; 4] = ["identity", "environment", "tenant", "timing"];

/// Evidence strength, ordered weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    Possible,
    StrongInference,
    Verified,
}

impl Strength {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "possible" => Some(Self::Possible),
            "strong-inference" => Some(Self::StrongInference),
            "verified" => Some(Self::Verified),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Possible => "possible",
            Self::StrongInference => "strong-inference",
            Self::Verified => "verified",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainAdjudicationError {
    #[error("{0} must be an object")]
    NotAnObject(String),
    #[error("{0} must be a non-empty string")]
    NotANonEmptyString(String),
    #[error("{0} must be an array")]
    NotAnArray(String),
    #[error("{0} binding does not match the frozen audit plan")]
    BindingMismatch(String),
    #[error("attack-path synthesizer cannot adjudicate its own path")]
    SelfSynthesis,
    #[error("chain adjudication requires a distinct, present adjudicating context")]
    SameContext,
    #[error("missing candidate or verdict for {0}")]
    MissingCandidateOrVerdict(String),
}

/// Inputs to [`adjudicate_chain`].
pub struct ChainAdjudicationInput<'a> {
    /// Attack-path hypothesis (SEC 9.3): `id`, `memberCandidateIds`, `steps`,
    /// `joins` (`[{id}]`), `objective`, optional `controls`, `binding`.
    pub hypothesis: &'a Value,
    /// Independently adjudicated candidate verdicts (SEC 9.4, security-verdict-v1).
    pub member_verdicts: &'a [Value],
    /// Plan/revision/generation binding the chain must carry.
    pub expected_binding: &'a Value,
    /// `{provider, contextId}` of the attack-path synthesizer.
    pub synthesizer: &'a Value,
    /// `{provider, contextId}` of the chain adjudicator.
    pub adjudicator: &'a Value,
    /// The adjudicator's raw chain assessment.
    pub raw_assessment: &'a Value,
    /// Minimum member and chain evidence strength. Clamped to at least
    /// `StrongInference`; `Possible` can never establish a chain.
    pub required_strength: Strength,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainVerdict {
    /// One of [`CHAIN_VERDICTS`].
    pub verdict: String,
    /// Why the claim was not accepted as asserted (empty only when accepted).
    pub reasons: Vec<String>,
    /// The `security-chain-verdict` artifact (SEC 9.4).
    pub value: Value,
}

fn non_empty<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn same_json(left: &Value, right: &Value) -> bool {
    match (canonical_json_bytes(left), canonical_json_bytes(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn binding_matches(artifact: &Value, expected: &Value) -> bool {
    expected.is_object()
        && artifact
            .get("binding")
            .map(|binding| binding.is_object() && same_json(binding, expected))
            .unwrap_or(false)
}

/// The `security-model.json` binding is a richer object than the plan binding
/// (`repositoryId`, `inventoryDigest`, ... versus `{repositoryRevision, digest}`),
/// so it is checked on the fields both carry: `repositoryRevision` and
/// `inventoryDigest` (plan `digest`). Exact equality still passes; a model whose
/// binding shares no comparable field with the plan binding fails closed.
pub fn model_binding_matches(model: &Value, expected: &Value) -> bool {
    if binding_matches(model, expected) {
        return true;
    }
    let (Some(binding), true) = (model.get("binding"), expected.is_object()) else {
        return false;
    };
    let mut compared = 0usize;
    for (model_key, plan_key) in [
        ("repositoryRevision", "repositoryRevision"),
        ("inventoryDigest", "digest"),
    ] {
        if let Some(want) = non_empty(expected, plan_key) {
            if non_empty(binding, model_key) != Some(want) {
                return false;
            }
            compared += 1;
        }
    }
    compared > 0
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Member candidate ids declared by the hypothesis (`memberCandidateIds`, and
/// `steps[].candidateId`). Returns the ids plus any consistency reasons.
fn member_ids(hypothesis: &Value) -> (Vec<String>, Vec<String>) {
    let mut reasons = Vec::new();
    let declared = strings(hypothesis, "memberCandidateIds");
    let from_steps: Vec<String> = hypothesis
        .get("steps")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter_map(|step| step.get("candidateId").and_then(Value::as_str))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let ids = if declared.is_empty() {
        from_steps.clone()
    } else {
        declared.clone()
    };
    if !declared.is_empty() && !from_steps.is_empty() {
        let a: BTreeSet<&String> = declared.iter().collect();
        let b: BTreeSet<&String> = from_steps.iter().collect();
        if a != b {
            reasons.push("memberCandidateIds disagree with steps[].candidateId".to_string());
        }
    }
    let unique: HashSet<&String> = ids.iter().collect();
    if unique.len() != ids.len() {
        reasons.push("hypothesis repeats a member candidate id".to_string());
    }
    if ids.iter().any(|id| id.trim().is_empty()) {
        reasons.push("hypothesis has an empty member candidate id".to_string());
    }
    (ids, reasons)
}

fn join_ids(hypothesis: &Value) -> (Vec<String>, Vec<String>) {
    let mut reasons = Vec::new();
    let mut ids = Vec::new();
    if let Some(joins) = hypothesis.get("joins").and_then(Value::as_array) {
        for join in joins {
            match non_empty(join, "id") {
                Some(id) => ids.push(id.to_string()),
                None => reasons.push("hypothesis join has no id".to_string()),
            }
        }
    }
    let unique: HashSet<&String> = ids.iter().collect();
    if unique.len() != ids.len() {
        reasons.push("hypothesis repeats a join id".to_string());
    }
    (ids, reasons)
}

fn hypothesis_control_ids(hypothesis: &Value) -> Vec<String> {
    hypothesis
        .get("controls")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| match item {
                    Value::String(s) => Some(s.clone()),
                    other => other.get("id").and_then(Value::as_str).map(String::from),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Exactly-once coverage of `expected` by `assessments[*][key]`.
fn covers_exactly(assessments: &[Value], key: &str, expected: &[String]) -> bool {
    let mut seen: Vec<&str> = Vec::new();
    for item in assessments {
        match item.get(key).and_then(Value::as_str) {
            Some(id) => seen.push(id),
            None => return false,
        }
    }
    let seen_set: HashSet<&str> = seen.iter().copied().collect();
    let expected_set: HashSet<&str> = expected.iter().map(String::as_str).collect();
    seen.len() == seen_set.len() && seen_set == expected_set
}

/// Adjudicate one attack-path hypothesis. Never errors on a failed gate: the
/// result is `UNPROVEN` (or the adjudicator's validly supported non-proven
/// verdict) with reasons.
pub fn adjudicate_chain(input: ChainAdjudicationInput<'_>) -> ChainVerdict {
    let required = input.required_strength.max(Strength::StrongInference);
    // Integrity failures: the adjudication cannot be trusted for any verdict.
    let mut integrity: Vec<String> = Vec::new();
    // Gates that only a PROVEN claim must satisfy.
    let mut proven_gates: Vec<String> = Vec::new();

    let hypothesis = input.hypothesis;
    let path_id = non_empty(hypothesis, "id").unwrap_or_default().to_string();
    if path_id.is_empty() {
        integrity.push("hypothesis has no id".to_string());
    }
    if !binding_matches(hypothesis, input.expected_binding) {
        integrity.push("hypothesis binding does not match the frozen plan binding".to_string());
    }

    // Independence of the adjudicator from the synthesizer.
    let syn_provider = non_empty(input.synthesizer, "provider");
    let syn_context = non_empty(input.synthesizer, "contextId");
    let adj_provider = non_empty(input.adjudicator, "provider");
    let adj_context = non_empty(input.adjudicator, "contextId");
    match (syn_provider, adj_provider) {
        (Some(s), Some(a)) if s != a => {}
        (Some(_), Some(_)) => integrity
            .push("attack-path synthesizer cannot adjudicate its own path (same provider)".into()),
        _ => integrity.push("synthesizer or adjudicator provider is missing".into()),
    }
    match (syn_context, adj_context) {
        (Some(s), Some(a)) if s != a => {}
        (Some(_), Some(_)) => integrity
            .push("adjudicating context is the synthesizing context (no fresh context)".into()),
        _ => integrity.push("synthesizer or adjudicator context id is missing".into()),
    }
    if let Some(declared) = non_empty(hypothesis, "provider") {
        if Some(declared) != syn_provider {
            integrity.push("hypothesis provider disagrees with the synthesizer".into());
        }
    }
    if let Some(declared) = non_empty(hypothesis, "synthesisContextId") {
        if Some(declared) != syn_context {
            integrity.push("hypothesis synthesisContextId disagrees with the synthesizer".into());
        }
    }

    // Raw assessment identity and shape.
    let raw = input.raw_assessment;
    let raw_ok = raw.is_object();
    if !raw_ok {
        integrity.push("chain assessment is not an object".into());
    }
    if raw_ok {
        if non_empty(raw, "pathId") != Some(path_id.as_str()) || path_id.is_empty() {
            integrity.push("chain assessment pathId does not match the hypothesis".into());
        }
        if non_empty(raw, "contextId") != adj_context || adj_context.is_none() {
            integrity.push("chain assessment contextId does not match the adjudicator".into());
        }
        if raw.get("binding").is_some() && !binding_matches(raw, input.expected_binding) {
            integrity.push("chain assessment binding does not match the frozen plan".into());
        }
    }
    let claimed = non_empty(raw, "verdict").unwrap_or_default().to_string();
    if raw_ok && !CHAIN_VERDICTS.contains(&claimed.as_str()) {
        integrity.push(format!("unsupported chain verdict {claimed:?}"));
    }
    if non_empty(raw, "rationale").is_none() {
        integrity.push("chain assessment has no rationale".into());
    }
    if non_empty(raw, "devilsAdvocate").is_none() {
        integrity.push("chain assessment has no chain-level devil's-advocate challenge".into());
    }

    // Hypothesis structure.
    let (members, member_reasons) = member_ids(hypothesis);
    let (joins, join_reasons) = join_ids(hypothesis);
    integrity.extend(member_reasons);
    integrity.extend(join_reasons);
    if members.len() < 2 {
        integrity.push("a chain needs at least two member steps".into());
    }
    if joins.len() + 1 < members.len() {
        integrity.push("hypothesis declares fewer joins than member steps require".into());
    }

    let step_assessments: Vec<Value> = raw
        .get("stepAssessments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let join_assessments: Vec<Value> = raw
        .get("joinAssessments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !covers_exactly(&step_assessments, "candidateId", &members) {
        integrity.push("chain assessment must assess every member step exactly once".into());
    }
    if !covers_exactly(&join_assessments, "joinId", &joins) {
        integrity.push("chain assessment must assess every join exactly once".into());
    }

    // Member verdicts: independent, surviving, at strength, never upgraded.
    let mut by_candidate: HashMap<&str, &Value> = HashMap::new();
    for verdict in input.member_verdicts {
        if let Some(id) = verdict.get("candidateId").and_then(Value::as_str) {
            if by_candidate.insert(id, verdict).is_some() {
                proven_gates.push(format!("duplicate member verdict for candidate {id}"));
            }
        }
    }
    let mut min_strength: Option<Strength> = None;
    let mut echoed: BTreeMap<String, Value> = BTreeMap::new();
    for id in &members {
        let Some(verdict) = by_candidate.get(id.as_str()) else {
            proven_gates.push(format!("member {id} has no adjudicated verdict"));
            continue;
        };
        echoed.insert(
            id.clone(),
            json!({
                "candidateId": id,
                "verdict": verdict.get("verdict").cloned().unwrap_or(Value::Null),
                "evidenceStrength": verdict.get("evidenceStrength").cloned().unwrap_or(Value::Null),
                "adjudicatorProvider": verdict.get("adjudicatorProvider").cloned().unwrap_or(Value::Null),
                "adjudicatorContextId": verdict.get("adjudicatorContextId").cloned().unwrap_or(Value::Null),
            }),
        );
        let label = non_empty(verdict, "verdict").unwrap_or_default();
        if !SURVIVING_MEMBER_VERDICTS.contains(&label) {
            proven_gates.push(format!(
                "member {id} did not survive adjudication ({label:?})"
            ));
        }
        match non_empty(verdict, "evidenceStrength").and_then(Strength::parse) {
            Some(strength) => {
                if strength < required {
                    proven_gates.push(format!(
                        "member {id} evidence strength {} is below required {}",
                        strength.as_str(),
                        required.as_str()
                    ));
                }
                min_strength = Some(min_strength.map_or(strength, |m| m.min(strength)));
            }
            None => {
                proven_gates.push(format!("member {id} has no recognised evidence strength"));
                min_strength = Some(Strength::Possible);
            }
        }
        let member_provider = non_empty(verdict, "adjudicatorProvider");
        let member_context = non_empty(verdict, "adjudicatorContextId");
        if member_provider.is_none() || member_provider == syn_provider {
            proven_gates.push(format!(
                "member {id} was not independently adjudicated (provider)"
            ));
        }
        if member_context.is_none() || member_context == syn_context {
            proven_gates.push(format!(
                "member {id} was not independently adjudicated (context)"
            ));
        }
    }
    // A chain assessment may not claim a member stronger than its verdict.
    for assessment in &step_assessments {
        if let (Some(id), Some(claimed_strength)) = (
            non_empty(assessment, "candidateId"),
            non_empty(assessment, "evidenceStrength").and_then(Strength::parse),
        ) {
            let member = by_candidate
                .get(id)
                .and_then(|v| non_empty(v, "evidenceStrength"))
                .and_then(Strength::parse);
            if member.map_or(true, |m| claimed_strength > m) {
                proven_gates.push(format!(
                    "step assessment for {id} upgrades the member evidence strength"
                ));
            }
        }
    }

    // PROVEN-only gates.
    let mut terminal_impact = Value::Null;
    let mut proof = Value::Null;
    let mut negative_control = Value::Null;
    let mut severity = Value::Null;
    let mut chain_strength = Value::Null;
    if claimed == "PROVEN" {
        match non_empty(raw, "evidenceStrength").and_then(Strength::parse) {
            Some(strength) => {
                if strength < required {
                    proven_gates.push(format!(
                        "chain evidence strength {} is below required {}",
                        strength.as_str(),
                        required.as_str()
                    ));
                }
                if min_strength.map_or(true, |m| strength > m) {
                    proven_gates
                        .push("chain evidence strength exceeds its weakest member verdict".into());
                }
                chain_strength = json!(strength.as_str());
            }
            None => proven_gates.push("PROVEN chain has no recognised evidenceStrength".into()),
        }
        if step_assessments
            .iter()
            .any(|item| item.get("usableInChain") != Some(&Value::Bool(true)))
        {
            proven_gates.push("every member step must be usable in the chain".into());
        }
        if join_assessments
            .iter()
            .any(|item| non_empty(item, "verdict") != Some("VERIFIED"))
        {
            proven_gates.push("every join must be independently VERIFIED".into());
        }
        let compat = raw.get("compatibility").unwrap_or(&Value::Null);
        for key in COMPAT_KEYS {
            if non_empty(compat, key) != Some("COMPATIBLE") {
                proven_gates.push(format!("{key} compatibility was not established"));
            }
        }
        let controls = raw
            .get("controlAssessments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let assessed: HashSet<&str> = controls
            .iter()
            .filter_map(|c| c.get("controlId").and_then(Value::as_str))
            .collect();
        for id in hypothesis_control_ids(hypothesis) {
            if !assessed.contains(id.as_str()) {
                proven_gates.push(format!("blocking control {id} was not evaluated"));
            }
        }
        if controls
            .iter()
            .any(|c| !matches!(non_empty(c, "status"), Some("INEFFECTIVE") | Some("ABSENT")))
        {
            proven_gates
                .push("a blocking control is effective, unevaluated or unrecognised".into());
        }
        match non_empty(raw, "terminalImpact") {
            Some(_) => terminal_impact = raw["terminalImpact"].clone(),
            None => proven_gates.push("PROVEN chain requires terminalImpact".into()),
        }
        let objective_reached = raw.get("objectiveReached") == Some(&Value::Bool(true));
        if !objective_reached {
            proven_gates.push("terminal objective reachability was not established".into());
        }
        let proof_digest = raw
            .pointer("/proof/digest")
            .and_then(Value::as_str)
            .map(|d| d.starts_with("sha256:") && d.len() > "sha256:".len())
            .unwrap_or(false);
        if proof_digest {
            proof = raw["proof"].clone();
        } else {
            proven_gates.push("PROVEN chain requires a bound proof digest".into());
        }
        let nc = raw.get("negativeControl").unwrap_or(&Value::Null);
        let nc_kind = non_empty(nc, "kind").map_or(false, |k| NEGATIVE_CONTROL_KINDS.contains(&k));
        if nc_kind
            && non_empty(nc, "rationale").is_some()
            && non_empty(nc, "outcome") == Some(NEGATIVE_CONTROL_OUTCOME)
        {
            negative_control = nc.clone();
        } else {
            proven_gates.push(
                "PROVEN chain requires a typed negative control whose outcome shows the chain breaks"
                    .into(),
            );
        }
        match non_empty(raw, "severity") {
            Some(s) if SEVERITIES.contains(&s) => severity = json!(s),
            _ => proven_gates.push("PROVEN chain requires a recognised severity".into()),
        }
    } else if raw.get("severity").map(|v| !v.is_null()).unwrap_or(false) {
        integrity.push(format!("{claimed} chain must not carry final severity"));
    }

    // Verdict selection.
    let mut reasons = integrity;
    let verdict: String = if !reasons.is_empty() {
        "UNPROVEN".to_string()
    } else {
        match claimed.as_str() {
            "PROVEN" => {
                if proven_gates.is_empty() {
                    "PROVEN".to_string()
                } else {
                    reasons.extend(proven_gates.iter().cloned());
                    "UNPROVEN".to_string()
                }
            }
            "BLOCKED" => {
                let effective = raw
                    .get("controlAssessments")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .any(|c| non_empty(c, "status") == Some("EFFECTIVE"))
                    })
                    .unwrap_or(false);
                if effective {
                    "BLOCKED".to_string()
                } else {
                    reasons.push("BLOCKED chain requires an effective blocking control".into());
                    "UNPROVEN".to_string()
                }
            }
            "REFUTED" => {
                let refuted_join = join_assessments
                    .iter()
                    .any(|item| non_empty(item, "verdict") == Some("REFUTED"));
                let unusable = step_assessments
                    .iter()
                    .any(|item| item.get("usableInChain") == Some(&Value::Bool(false)));
                if refuted_join || unusable {
                    "REFUTED".to_string()
                } else {
                    reasons.push("REFUTED chain requires a refuted join or unusable step".into());
                    "UNPROVEN".to_string()
                }
            }
            "PARTIALLY_SUPPORTED" => "PARTIALLY_SUPPORTED".to_string(),
            _ => {
                reasons.push("adjudicator did not establish the chain".into());
                "UNPROVEN".to_string()
            }
        }
    };

    let established = verdict == "PROVEN";
    let mut value = json!({
        "schemaVersion": 1,
        "kind": "security-chain-verdict",
        "providerId": PROVIDER_ID,
        "pathId": path_id,
        "claimedVerdict": if claimed.is_empty() { Value::Null } else { json!(claimed) },
        "verdict": verdict,
        "synthesizerProvider": input.synthesizer.get("provider").cloned().unwrap_or(Value::Null),
        "synthesizerContextId": input.synthesizer.get("contextId").cloned().unwrap_or(Value::Null),
        "adjudicatorProvider": input.adjudicator.get("provider").cloned().unwrap_or(Value::Null),
        "contextId": input.adjudicator.get("contextId").cloned().unwrap_or(Value::Null),
        "binding": input.expected_binding,
        "memberVerdicts": echoed.values().cloned().collect::<Vec<_>>(),
        "evidenceStrength": if established { chain_strength } else { Value::Null },
        "stepAssessments": step_assessments,
        "joinAssessments": join_assessments,
        "controlAssessments": raw.get("controlAssessments").cloned().unwrap_or_else(|| json!([])),
        "terminalImpact": if established { terminal_impact } else { Value::Null },
        "proof": if established { proof } else { Value::Null },
        "negativeControl": if established { negative_control } else { Value::Null },
        "devilsAdvocate": raw.get("devilsAdvocate").cloned().unwrap_or(Value::Null),
        "rationale": raw.get("rationale").cloned().unwrap_or(Value::Null),
        "severity": if established { severity } else { Value::Null },
        "reasons": reasons,
    });
    if let Ok(bytes) = canonical_json_bytes(&value) {
        value["verdictDigest"] = json!(format!("sha256:{}", hex::encode(Sha256::digest(bytes))));
    }
    ChainVerdict {
        verdict,
        reasons,
        value,
    }
}

fn ids_from(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .flat_map(|key| strings(value, key))
        .collect::<Vec<_>>()
}

fn slice_model_for_path(model: &Value, step_packets: &[Value]) -> Value {
    let mut referenced: HashSet<String> = HashSet::new();
    for step in step_packets {
        let candidate = step.get("candidate").unwrap_or(&Value::Null);
        referenced.extend(ids_from(
            candidate,
            &[
                "sources",
                "sinks",
                "assets",
                "requiredControls",
                "observedControls",
            ],
        ));
    }
    let list = |key: &str| -> Vec<Value> {
        model
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    // Candidates cite entities by id, name or evidence path (see
    // `attack_paths` contract), so all three aliases select an entity.
    let evidence_paths: HashMap<String, String> = list("evidence")
        .iter()
        .filter_map(|e| {
            Some((
                e.get("id")?.as_str()?.to_string(),
                e.get("path")?.as_str()?.to_string(),
            ))
        })
        .collect();
    let entities: Vec<Value> = list("entities")
        .into_iter()
        .filter(|e| {
            let by_id = e
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| referenced.contains(id));
            let by_name = e
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| referenced.contains(name));
            let by_path = strings(e, "evidenceRefs").iter().any(|r| {
                evidence_paths
                    .get(r)
                    .is_some_and(|p| referenced.contains(p))
            });
            by_id || by_name || by_path
        })
        .collect();
    let entity_ids: HashSet<String> = entities
        .iter()
        .filter_map(|e| e.get("id").and_then(Value::as_str).map(String::from))
        .collect();
    let relations: Vec<Value> = list("relations")
        .into_iter()
        .filter(|r| {
            let end = |key: &str| {
                r.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            entity_ids.contains(&end("from")) || entity_ids.contains(&end("to"))
        })
        .collect();
    let mut evidence_ids: HashSet<String> = HashSet::new();
    for item in entities.iter().chain(relations.iter()) {
        evidence_ids.extend(strings(item, "evidenceRefs"));
    }
    let evidence: Vec<Value> = list("evidence")
        .into_iter()
        .filter(|e| {
            e.get("id")
                .and_then(Value::as_str)
                .map_or(false, |id| evidence_ids.contains(id))
        })
        .collect();
    json!({ "entities": entities, "relations": relations, "evidence": evidence })
}

/// Build the fresh-context packet handed to the chain adjudicator. Fails
/// closed on binding mismatch, self-synthesis, or a missing/identical context.
pub fn build_adjudication_packet(
    hypothesis: &Value,
    candidates: &[Value],
    member_verdicts: &[Value],
    model: &Value,
    expected_binding: &Value,
    synthesizer: &Value,
    adjudicator: &Value,
) -> Result<Value, ChainAdjudicationError> {
    if !hypothesis.is_object() {
        return Err(ChainAdjudicationError::NotAnObject("hypothesis".into()));
    }
    let path_id = non_empty(hypothesis, "id")
        .ok_or_else(|| ChainAdjudicationError::NotANonEmptyString("hypothesis.id".into()))?;
    if !binding_matches(hypothesis, expected_binding) {
        return Err(ChainAdjudicationError::BindingMismatch("hypothesis".into()));
    }
    if model.get("binding").is_some() && !model_binding_matches(model, expected_binding) {
        return Err(ChainAdjudicationError::BindingMismatch("model".into()));
    }
    let syn_provider = non_empty(synthesizer, "provider")
        .ok_or_else(|| ChainAdjudicationError::NotANonEmptyString("synthesizer.provider".into()))?;
    let adj_provider = non_empty(adjudicator, "provider")
        .ok_or_else(|| ChainAdjudicationError::NotANonEmptyString("adjudicator.provider".into()))?;
    if syn_provider == adj_provider {
        return Err(ChainAdjudicationError::SelfSynthesis);
    }
    match (
        non_empty(synthesizer, "contextId"),
        non_empty(adjudicator, "contextId"),
    ) {
        (Some(s), Some(a)) if s != a => {}
        _ => return Err(ChainAdjudicationError::SameContext),
    }

    let (members, _) = member_ids(hypothesis);
    let candidate_by_id: HashMap<&str, &Value> = candidates
        .iter()
        .filter_map(|c| c.get("id").and_then(Value::as_str).map(|id| (id, c)))
        .collect();
    let verdict_by_id: HashMap<&str, &Value> = member_verdicts
        .iter()
        .filter_map(|v| {
            v.get("candidateId")
                .and_then(Value::as_str)
                .map(|id| (id, v))
        })
        .collect();
    let mut step_packets = Vec::with_capacity(members.len());
    for id in &members {
        match (
            candidate_by_id.get(id.as_str()),
            verdict_by_id.get(id.as_str()),
        ) {
            (Some(candidate), Some(verdict)) => step_packets.push(json!({
                "candidateId": id,
                "candidate": candidate,
                "verdict": verdict,
            })),
            _ => {
                return Err(ChainAdjudicationError::MissingCandidateOrVerdict(
                    id.clone(),
                ))
            }
        }
    }

    let context_id = adjudicator["contextId"].clone();
    let packet_id = {
        let seed =
            json!({ "pathId": path_id, "contextId": context_id, "binding": expected_binding });
        let bytes = canonical_json_bytes(&seed).unwrap_or_default();
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    };
    let model_slice = slice_model_for_path(model, &step_packets);
    Ok(json!({
        "schemaVersion": 1,
        "kind": "security-chain-adjudication-packet",
        "packetId": packet_id,
        "providerId": PROVIDER_ID,
        "pathId": path_id,
        "binding": expected_binding,
        "synthesizer": synthesizer,
        "adjudicator": adjudicator,
        "hypothesis": hypothesis,
        "steps": step_packets,
        "modelSlice": model_slice,
        "requiredAnalysis": REQUIRED_ANALYSIS,
    }))
}

/// Registry entry (providers.json) proposed for this adjudicator. Documented
/// here so the owner of `src/registry/providers.json` can transcribe it.
pub const REGISTRY_ENTRY_NOTE: &str =
    "id=security.chain-adjudication role=adjudicator family=security phase=judgment runner=runtime-script \
     consumes=[security-model,attack-path-hypotheses] produces=[security-chain-verdicts] \
     reasoning={requirement:none,freshContext:true,producerSeparation:true}; registered in src/registry/providers.json";
