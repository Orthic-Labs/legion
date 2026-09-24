//! Port of `src/providers/copy/documentation.mjs` (packet U06).
//!
//! Faithful, deterministic re-implementation of `analyzeDocumentation`.
//! Content items, command contracts, and the claim-proof ledger are all
//! loosely-typed JSON in the original JavaScript, so this port accepts and
//! returns `serde_json::Value` to preserve exact input/output shape parity.

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const PROVIDER: &str = "copy.documentation";
const MEDIA_TYPE: &str = "application/vnd.legion.documentation-analysis+json";

fn digest(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn str_field<'a>(item: &'a Value, key: &str) -> Option<&'a str> {
    item.get(key).and_then(Value::as_str)
}

fn unique(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for v in values {
        if v.is_empty() {
            continue;
        }
        if seen.insert(v.clone()) {
            out.push(v);
        }
    }
    out
}

fn as_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn evidence_refs(item: &Value, extra: &[String]) -> Vec<String> {
    let mut v = as_string_array(item.get("evidenceRefs"));
    v.extend(extra.iter().cloned());
    unique(v)
}

fn schema_refs(item: &Value, contract: Option<&Value>) -> Vec<String> {
    let mut v = as_string_array(item.get("schemaRefs"));
    if let Some(contract) = contract {
        v.extend(as_string_array(contract.get("schemaRefs")));
        if let Some(schema_ref) = str_field(contract, "schemaRef") {
            v.push(schema_ref.to_string());
        }
    }
    unique(v)
}

fn finding(
    item: &Value,
    rule_id: &str,
    claim: &str,
    evidence_refs: Vec<String>,
    binding: &Value,
    mut details: Map<String, Value>,
) -> Value {
    let mut obj = Map::new();
    obj.insert("schemaVersion".into(), json!(1));
    obj.insert("producer".into(), json!(PROVIDER));
    obj.insert("ruleId".into(), json!(rule_id));
    obj.insert("detectorKind".into(), json!("deterministic"));
    obj.insert("category".into(), json!("factual-drift"));
    obj.insert(
        "contentItemIds".into(),
        json!([item.get("id").cloned().unwrap_or(Value::Null)]),
    );
    obj.insert("claim".into(), json!(claim));
    obj.insert("evidenceRefs".into(), json!(evidence_refs));
    obj.insert("binding".into(), binding.clone());
    obj.append(&mut details);
    Value::Object(obj)
}

fn editorial_candidate(item: &Value, span: Value, denominator_digest: &str, binding: &Value) -> Value {
    let mut base = Map::new();
    base.insert("schemaVersion".into(), json!(1));
    base.insert("kind".into(), json!("legion-copy-candidate"));
    base.insert("producer".into(), json!(PROVIDER));
    base.insert("provider".into(), json!(PROVIDER));
    base.insert("providerVersion".into(), json!("1.0.0"));
    base.insert("ruleId".into(), json!("copy.documentation.editorial-density"));
    base.insert("dimension".into(), json!("clarity"));
    base.insert("category".into(), json!("editorial-polish"));
    base.insert(
        "contentItemIds".into(),
        json!([item.get("id").cloned().unwrap_or(Value::Null)]),
    );
    base.insert(
        "claim".into(),
        json!("Editorial preamble delays information without changing documented behavior."),
    );
    base.insert("severityHint".into(), json!("low"));
    base.insert("detectorKind".into(), json!("interpretive"));
    base.insert(
        "evidenceRefs".into(),
        item.get("evidenceRefs").cloned().unwrap_or(json!([])),
    );
    base.insert("proofRefs".into(), json!([]));
    base.insert("uncertainty".into(), json!(["editorial-judgment-required"]));
    base.insert("denominatorDigest".into(), json!(denominator_digest));
    base.insert("binding".into(), binding.clone());
    base.insert("verdict".into(), json!("UNADJUDICATED"));
    base.insert("adjudicationRequired".into(), json!(true));
    base.insert("span".into(), span);
    base.insert(
        "suggestion".into(),
        json!("Review for concision while preserving every prerequisite, side effect, and factual claim."),
    );
    base.insert("mediaType".into(), json!(MEDIA_TYPE));

    let value = Value::Object(base.clone());
    let d = digest(&value);
    base.insert("id".into(), json!(d));
    base.insert("digest".into(), json!(d));
    Value::Object(base)
}

fn flags(example: &str) -> Vec<String> {
    let re = Regex::new(r"--[\w-]+").expect("static regex");
    re.find_iter(example).map(|m| m.as_str().to_string()).collect()
}

fn escape_regex(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn matches_command(example: &str, command: &str) -> bool {
    let escaped = escape_regex(command);
    let pattern = format!(r"^{}(?:\s|$)", escaped);
    Regex::new(&pattern)
        .map(|re| re.is_match(example.trim()))
        .unwrap_or(false)
}

struct ResolvedContract<'a> {
    id: Option<String>,
    contract: Option<&'a Value>,
}

fn resolve_contract<'a>(
    item: &Value,
    contracts_by_id: &'a std::collections::HashMap<String, &'a Value>,
    contracts: &'a [Value],
    examples: &[String],
) -> ResolvedContract<'a> {
    let explicit_id = str_field(item, "commandId")
        .or_else(|| str_field(item, "commandContractId"))
        .map(String::from);
    if let Some(explicit_id) = explicit_id {
        let contract = contracts_by_id.get(&explicit_id).copied();
        return ResolvedContract { id: Some(explicit_id), contract };
    }

    let declared_command = str_field(item, "command").or_else(|| str_field(item, "commandName"));
    if let Some(declared_command) = declared_command {
        if let Some(m) = contracts
            .iter()
            .find(|c| str_field(c, "command") == Some(declared_command))
        {
            return ResolvedContract {
                id: str_field(m, "id").map(String::from),
                contract: Some(m),
            };
        }
    }

    let matches: Vec<&Value> = contracts
        .iter()
        .filter(|c| {
            let command = str_field(c, "command").unwrap_or("");
            examples.iter().any(|example| matches_command(example, command))
        })
        .collect();

    if matches.len() == 1 {
        let m = matches[0];
        ResolvedContract {
            id: str_field(m, "id").map(String::from),
            contract: Some(m),
        }
    } else {
        ResolvedContract { id: None, contract: None }
    }
}

/// Port of `analyzeDocumentation(items, options)`.
pub fn analyze_documentation(items: &[Value], options: &Value) -> Value {
    let binding = options.get("binding").cloned().unwrap_or(json!({}));
    let denominator = json!({
        "kind": "documentation-content-items",
        "expected": items.len(),
        "examined": items.len(),
    });
    let denom_source: Vec<Value> = items
        .iter()
        .map(|item| {
            let id = item.get("id").cloned().unwrap_or(Value::Null);
            let text_digest = item
                .get("textDigest")
                .cloned()
                .unwrap_or_else(|| json!(digest(&item.get("text").cloned().unwrap_or(json!("")))));
            json!([id, text_digest])
        })
        .collect();
    let denominator_digest = digest(&json!(denom_source));

    let contracts: Vec<Value> = options
        .get("commandContracts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let contracts_by_id: std::collections::HashMap<String, &Value> = contracts
        .iter()
        .filter_map(|c| str_field(c, "id").map(|id| (id.to_string(), c)))
        .collect();

    let claims: Vec<Value> = options
        .get("claimProofLedger")
        .and_then(|l| l.get("claims"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let claims_by_id: std::collections::HashMap<String, &Value> = claims
        .iter()
        .filter_map(|c| str_field(c, "id").map(|id| (id.to_string(), c)))
        .collect();

    let terms: Vec<Value> = options.get("terms").and_then(Value::as_array).cloned().unwrap_or_default();

    let mut findings: Vec<Value> = Vec::new();
    let mut candidates: Vec<Value> = Vec::new();
    let mut command_bindings: Vec<Value> = Vec::new();
    let mut release_notes: Vec<Value> = Vec::new();
    let mut coverage_gaps: Vec<String> = Vec::new();

    for item in items {
        let authority = str_field(item, "authority").unwrap_or("").to_lowercase();
        let kind_field = str_field(item, "kind").unwrap_or("");
        let notice_re = Regex::new(r"(?i)(?:legal|security)-notice").expect("static regex");
        let is_authority_text =
            authority == "legal" || authority == "security" || notice_re.is_match(kind_field);
        if is_authority_text {
            let id = str_field(item, "id").unwrap_or("");
            coverage_gaps.push(format!("authority-required:{}", id));
        }

        let examples: Vec<String> = item
            .get("examples")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let has_command_id = item.get("commandId").is_some();
        let has_command_contract_id = item.get("commandContractId").is_some();
        let has_command = item.get("command").is_some();
        let has_command_name = item.get("commandName").is_some();
        let is_command_help = kind_field == "command-help";

        if has_command_id || has_command_contract_id || has_command || has_command_name || is_command_help
            || !examples.is_empty()
        {
            let resolved = resolve_contract(item, &contracts_by_id, &contracts, &examples);
            let item_schema_refs = schema_refs(item, resolved.contract);

            match resolved.contract {
                None => {
                    findings.push(finding(
                        item,
                        "copy.documentation.command-contract-missing",
                        "Command example has no current command contract.",
                        evidence_refs(item, &[]),
                        &binding,
                        Map::from_iter([("schemaRefs".to_string(), json!(item_schema_refs))]),
                    ));
                    command_bindings.push(json!({
                        "contentItemId": item.get("id").cloned().unwrap_or(Value::Null),
                        "commandId": resolved.id,
                        "examples": examples,
                        "status": "unbound",
                        "evidenceRefs": evidence_refs(item, &[]),
                        "schemaRefs": item_schema_refs,
                    }));
                }
                Some(contract) => {
                    let contract_evidence_refs = as_string_array(contract.get("evidenceRefs"));
                    let allowed_flags: Vec<String> = contract
                        .get("options")
                        .or_else(|| contract.get("flags"))
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let unknown_flags: Vec<String> = examples
                        .iter()
                        .flat_map(|e| flags(e))
                        .filter(|f| !allowed_flags.contains(f))
                        .collect();
                    let command = str_field(contract, "command").unwrap_or("");
                    let wrong_command: Vec<String> = examples
                        .iter()
                        .filter(|e| !matches_command(e, command))
                        .cloned()
                        .collect();
                    let prerequisites = as_string_array(contract.get("prerequisites"));
                    let item_prereq_refs = as_string_array(item.get("prerequisiteRefs"));
                    let missing_prerequisites: Vec<String> = prerequisites
                        .into_iter()
                        .filter(|id| !item_prereq_refs.contains(id))
                        .collect();
                    let side_effects: Vec<Value> = contract
                        .get("sideEffects")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let item_side_effect_refs = as_string_array(item.get("sideEffectRefs"));
                    let missing_side_effects: Vec<Value> = side_effects
                        .into_iter()
                        .filter(|se| {
                            let id = se
                                .get("id")
                                .and_then(Value::as_str)
                                .map(String::from)
                                .or_else(|| se.as_str().map(String::from))
                                .unwrap_or_default();
                            !item_side_effect_refs.contains(&id)
                        })
                        .collect();

                    let status = if !unknown_flags.is_empty()
                        || !wrong_command.is_empty()
                        || !missing_prerequisites.is_empty()
                        || !missing_side_effects.is_empty()
                    {
                        "drift"
                    } else {
                        "bound"
                    };

                    command_bindings.push(json!({
                        "contentItemId": item.get("id").cloned().unwrap_or(Value::Null),
                        "commandId": contract.get("id").cloned().unwrap_or(Value::Null),
                        "examples": examples,
                        "status": status,
                        "evidenceRefs": evidence_refs(item, &contract_evidence_refs),
                        "schemaRefs": item_schema_refs,
                    }));

                    if status == "drift" {
                        findings.push(finding(
                            item,
                            "copy.documentation.command-contract-drift",
                            "Command example does not map to current syntax, options, prerequisites, or documented side effects.",
                            evidence_refs(item, &contract_evidence_refs),
                            &binding,
                            Map::from_iter([
                                ("unknownFlags".to_string(), json!(unknown_flags)),
                                ("wrongCommand".to_string(), json!(wrong_command)),
                                ("missingPrerequisites".to_string(), json!(missing_prerequisites)),
                                ("missingSideEffects".to_string(), json!(missing_side_effects)),
                                ("schemaRefs".to_string(), json!(item_schema_refs)),
                            ]),
                        ));
                    }
                }
            }
        }

        if kind_field == "release-note" {
            let release_state = str_field(item, "releaseState").unwrap_or("unproven").to_string();
            let text = str_field(item, "text").unwrap_or("");
            let shipped_re =
                Regex::new(r"(?i)\b(?:now|already|currently)\s+(?:ships?|available|supports?)\b|\bshipped\b|\breleased\b")
                    .expect("static regex");
            let claims_shipped = item.get("claimsShipped").and_then(Value::as_bool) == Some(true)
                || shipped_re.is_match(text);
            let claim = if claims_shipped {
                "shipped"
            } else if release_state == "planned" {
                "planned"
            } else {
                "unproven"
            };
            release_notes.push(json!({
                "contentItemId": item.get("id").cloned().unwrap_or(Value::Null),
                "state": release_state,
                "claim": claim,
                "evidenceRefs": evidence_refs(item, &[]),
                "schemaRefs": schema_refs(item, None),
            }));
            if claims_shipped && release_state != "shipped" {
                findings.push(finding(
                    item,
                    "copy.documentation.planned-as-shipped",
                    "Release note presents behavior as shipped while bound release state is not shipped.",
                    evidence_refs(item, &[]),
                    &binding,
                    Map::from_iter([("releaseState".to_string(), json!(release_state))]),
                ));
            }
        }

        for term in &terms {
            let stale = str_field(term, "stale").unwrap_or("");
            let text = str_field(item, "text").unwrap_or("");
            let pattern = format!(r"(?i)\b{}\b", escape_regex(stale));
            if Regex::new(&pattern).map(|re| re.is_match(text)).unwrap_or(false) {
                let term_evidence = as_string_array(term.get("evidenceRefs"));
                findings.push(finding(
                    item,
                    "copy.documentation.stale-term",
                    &format!("Documentation uses stale term {}.", stale),
                    term_evidence,
                    &binding,
                    Map::from_iter([
                        ("stale".to_string(), json!(stale)),
                        ("current".to_string(), term.get("current").cloned().unwrap_or(Value::Null)),
                    ]),
                ));
            }
        }

        for claim_id in as_string_array(item.get("claimRefs")) {
            let claim = claims_by_id.get(&claim_id).copied();
            let bound = claim
                .and_then(|c| str_field(c, "disposition"))
                .map(|d| d == "bound")
                .unwrap_or(false);
            if !bound {
                let claim_evidence = claim
                    .map(|c| as_string_array(c.get("evidenceRefs")))
                    .unwrap_or_default();
                findings.push(finding(
                    item,
                    "copy.documentation.unsupported-claim",
                    "Documentation claim lacks current bound proof.",
                    claim_evidence,
                    &binding,
                    Map::from_iter([("claimId".to_string(), json!(claim_id))]),
                ));
            }
        }

        let text = str_field(item, "text").unwrap_or("");
        let preamble_re =
            Regex::new(r"(?i)\b(?:it should be noted that|it is important to note that|in order to)\b")
                .expect("static regex");
        if let Some(m) = preamble_re.find(text) {
            if !is_authority_text {
                let start = text[..m.start()].chars().count();
                let matched_chars = m.as_str().chars().count();
                let span = json!({
                    "text": m.as_str(),
                    "start": start,
                    "end": start + matched_chars,
                });
                candidates.push(editorial_candidate(item, span, &denominator_digest, &binding));
            }
        }
    }

    let status = if !findings.is_empty() {
        "findings"
    } else if !candidates.is_empty() {
        "candidates"
    } else if !coverage_gaps.is_empty() {
        "unproven"
    } else {
        "pass"
    };

    let mut base = Map::new();
    base.insert("schemaVersion".into(), json!(1));
    base.insert("producer".into(), json!(PROVIDER));
    base.insert("provider".into(), json!(PROVIDER));
    base.insert("status".into(), json!(status));
    base.insert("denominator".into(), denominator);
    base.insert("denominatorDigest".into(), json!(denominator_digest));
    base.insert("findings".into(), json!(findings));
    base.insert("candidates".into(), json!(candidates));
    base.insert("commandBindings".into(), json!(command_bindings));
    base.insert("releaseNotes".into(), json!(release_notes));
    base.insert("coverageGaps".into(), json!(coverage_gaps));
    base.insert("binding".into(), binding);
    base.insert("mediaType".into(), json!(MEDIA_TYPE));

    let value = Value::Object(base.clone());
    let d = digest(&value);
    base.insert("digest".into(), json!(d));
    Value::Object(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Value {
        json!({"repository": "sha256:fixture-repository"})
    }

    #[test]
    fn binds_command_examples_and_flags_drift_and_planned_as_shipped() {
        let items = vec![
            json!({
                "id": "docs:command-current",
                "text": "Run `legion scan --dry-run`.",
                "kind": "command-help",
                "commandId": "scan",
                "examples": ["legion scan --dry-run"],
                "prerequisiteRefs": ["config:legion"],
                "audience": "operators",
                "evidenceRefs": ["contract:scan"],
                "binding": binding(),
            }),
            json!({
                "id": "docs:command-stale",
                "text": "Run `legion scan --legacy`.",
                "kind": "command-help",
                "commandId": "scan",
                "examples": ["legion scan --legacy"],
                "audience": "operators",
                "binding": binding(),
            }),
            json!({
                "id": "docs:release-planned",
                "text": "Legion now ships remote mutation.",
                "kind": "release-note",
                "releaseState": "planned",
                "claimsShipped": true,
                "audience": "customers",
                "binding": binding(),
            }),
        ];
        let options = json!({
            "commandContracts": [{
                "id": "scan",
                "command": "legion scan",
                "options": ["--dry-run"],
                "prerequisites": ["config:legion"],
                "evidenceRefs": ["contract:scan"],
            }],
            "binding": binding(),
        });

        let result = analyze_documentation(&items, &options);

        assert_eq!(result["commandBindings"][0]["status"], "bound");
        assert_eq!(
            result["commandBindings"][0]["examples"],
            json!(["legion scan --dry-run"])
        );

        let findings = result["findings"].as_array().unwrap();
        assert!(findings.iter().any(|f| f["ruleId"] == "copy.documentation.command-contract-drift"
            && f["contentItemIds"] == json!(["docs:command-stale"])));
        assert!(findings.iter().any(|f| f["ruleId"] == "copy.documentation.planned-as-shipped"
            && f["contentItemIds"] == json!(["docs:release-planned"])));
        assert_eq!(result["candidates"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn keeps_editorial_polish_separate_from_legal_notices() {
        let items = vec![
            json!({
                "id": "docs:editorial",
                "text": "It should be noted that the command writes the report.",
                "kind": "tutorial",
                "audience": "operators",
                "purpose": "explain command side effects",
                "binding": binding(),
            }),
            json!({
                "id": "docs:legal",
                "text": "It should be noted that all rights are reserved.",
                "kind": "legal-notice",
                "authority": "legal",
                "audience": "customers",
                "binding": binding(),
            }),
        ];
        let options = json!({"binding": binding()});

        let result = analyze_documentation(&items, &options);
        let candidates = result["candidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0]["contentItemIds"], json!(["docs:editorial"]));
        assert!(result["coverageGaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == "authority-required:docs:legal"));
    }

    #[test]
    fn missing_contract_and_unsupported_claim_produce_findings() {
        let items = vec![json!({
            "id": "docs:unbound",
            "text": "Run `legion ghost --now`.",
            "kind": "command-help",
            "examples": ["legion ghost --now"],
            "claimRefs": ["claim:x"],
            "binding": binding(),
        })];
        let options = json!({
            "claimProofLedger": {"claims": [{"id": "claim:x", "disposition": "unproven"}]},
            "binding": binding(),
        });
        let result = analyze_documentation(&items, &options);
        let findings = result["findings"].as_array().unwrap();
        assert!(findings
            .iter()
            .any(|f| f["ruleId"] == "copy.documentation.command-contract-missing"));
        assert!(findings
            .iter()
            .any(|f| f["ruleId"] == "copy.documentation.unsupported-claim"));
        assert_eq!(result["status"], "findings");
    }
}
