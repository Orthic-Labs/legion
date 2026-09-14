use super::{CommandError, CommandResult};
use clap::Args;
use legion_audit::{AuditError, AuditProvider, InventoryEnvelope, ProviderExecutor};
use legion_contracts::{
    Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use legion_rules::{Confidence, RuleCompiler, Severity, SourceFile};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    #[arg(long = "blueprint-packet")]
    pub blueprint_packet: Option<PathBuf>,
    #[arg(long = "expected-generation")]
    pub expected_generation: Option<String>,
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub provider: Option<String>,
    #[arg(long, default_value = r#"{"op":"always"}"#)]
    pub selector: String,
    #[arg(long = "pack")]
    pub packs: Vec<String>,
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_bytes: u64,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct NativeRuleProviderExecutor {
    root: PathBuf,
    manifest: PathBuf,
    max_file_bytes: u64,
}

impl NativeRuleProviderExecutor {
    pub fn new(root: PathBuf, manifest: PathBuf, max_file_bytes: u64) -> Result<Self, AuditError> {
        if max_file_bytes == 0 {
            return Err(AuditError::Invalid(
                "max-file-bytes must be positive".into(),
            ));
        }
        Ok(Self {
            root,
            manifest,
            max_file_bytes,
        })
    }
}

impl ProviderExecutor for NativeRuleProviderExecutor {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let runner = provider
            .configuration
            .get("runner")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                AuditError::Provider(format!("provider {} has no runner", provider.id))
            })?;
        if runner.get("kind").and_then(Value::as_str) != Some("built-in")
            || runner.get("implementation").and_then(Value::as_str) != Some("native-rule-manifest")
        {
            return Err(AuditError::Provider(format!(
                "provider {} is not bound to native-rule-manifest",
                provider.id
            )));
        }
        let selector = provider
            .configuration
            .get("selector")
            .cloned()
            .ok_or_else(|| {
                AuditError::Provider(format!("provider {} has no selector", provider.id))
            })?;
        let packs = runner
            .get("packs")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| {
                        value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                            AuditError::Provider(format!(
                                "provider {} has invalid pack id",
                                provider.id
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        evaluate_native_rules(
            &self.root,
            &self.manifest,
            &provider.id,
            provider.required,
            &selector,
            &packs,
            self.max_file_bytes,
            inventory,
        )
    }
}

fn evaluate_native_rules(
    root: &Path,
    manifest_path: &Path,
    provider_id: &str,
    required: bool,
    selector: &Value,
    packs: &[String],
    max_file_bytes: u64,
    inventory: &InventoryEnvelope,
) -> Result<ProviderResult, AuditError> {
    let provider = ProviderId::new(provider_id).map_err(AuditError::from)?;
    let manifest = std::fs::read_to_string(manifest_path).map_err(|error| {
        AuditError::Provider(format!("native rule manifest unavailable: {error}"))
    })?;
    let compiled = RuleCompiler::compile_manifest_json(&manifest)
        .map_err(|error| AuditError::Provider(error.to_string()))?;
    let selected =
        select_packs(compiled, packs).map_err(|error| AuditError::Provider(error.message))?;
    let denominator = inventory.denominator_entries(selector)?;

    let mut files = Vec::new();
    let mut gaps = Vec::new();
    if denominator.entries.is_empty() {
        gaps.push("repository-inventory-empty".into());
    }
    for entry in &denominator.entries {
        let path = root.join(&entry.path);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                gaps.push(format!("source-unavailable:{}:{error}", entry.path));
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            gaps.push(format!("source-not-regular-file:{}", entry.path));
            continue;
        }
        if metadata.len() > max_file_bytes {
            gaps.push(format!("source-byte-bound-exceeded:{}", entry.path));
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => files.push(SourceFile {
                path: entry.path.clone(),
                bytes,
            }),
            Err(error) => gaps.push(format!("source-unavailable:{}:{error}", entry.path)),
        }
    }

    let mut spans = Vec::new();
    for pack in selected.values() {
        let Some(evaluation) = pack.evaluate_lexical(&files) else {
            gaps.push(format!("pack-not-lexical:{}", pack.pack_id));
            continue;
        };
        gaps.extend(evaluation.coverage.gaps);
        spans.extend(evaluation.findings);
    }
    spans.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then(left.path.cmp(&right.path))
            .then(left.byte_start.cmp(&right.byte_start))
            .then(left.byte_end.cmp(&right.byte_end))
    });
    gaps.sort();
    gaps.dedup();

    let mut findings = Vec::with_capacity(spans.len());
    let mut evidence = Map::new();
    let mut locations = Map::new();
    let mut titles = Map::new();
    let mut messages = Map::new();
    for (index, span) in spans.into_iter().enumerate() {
        let finding_id = FindingId::new(format!(
            "{}:{}:{index}",
            span.rule_id,
            span.evidence_hash.trim_start_matches("sha256:")
        ))
        .map_err(AuditError::from)?;
        findings.push(FindingRef {
            id: finding_id.clone(),
            severity: severity_name(span.severity).to_owned(),
        });
        evidence.insert(
            finding_id.to_string(),
            json!({
                "ruleId": span.rule_id,
                "path": span.path,
                "byteStart": span.byte_start,
                "byteEnd": span.byte_end,
                "evidenceHash": span.evidence_hash,
                "confidence": confidence_name(span.confidence),
                "authority": span.authority,
                "uncertainty": span.uncertainty,
                "remediation": span.remediation,
            }),
        );
        locations.insert(finding_id.to_string(), json!([span.path]));
        titles.insert(finding_id.to_string(), json!(span.rule_id));
        messages.insert(
            finding_id.to_string(),
            json!("Declarative native rule matched source evidence"),
        );
    }

    let complete = gaps.is_empty() && files.len() == denominator.entries.len();
    let result = ProviderResult {
        schema_version: 1,
        provider,
        applicable: true,
        required,
        status: if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        coverage: Some(Coverage {
            denominator_digest: denominator.digest,
            expected: denominator.entries.len() as u64,
            examined: files.len() as u64,
            gaps: gaps.clone(),
        }),
        findings,
        coverage_gaps: gaps.clone(),
        degradation: gaps,
        details: [
            ("findingEvidence".into(), Value::Object(evidence)),
            ("findingLocations".into(), Value::Object(locations)),
            ("findingTitles".into(), Value::Object(titles)),
            ("findingMessages".into(), Value::Object(messages)),
            ("selector".into(), selector.clone()),
            ("blueprintDegradations".into(), json!([])),
            (
                "packs".into(),
                json!(selected.keys().cloned().collect::<Vec<_>>()),
            ),
        ]
        .into_iter()
        .collect(),
    };
    result.validate().map_err(AuditError::from)?;
    Ok(result)
}

pub fn run(args: RulesArgs) -> CommandResult {
    if args.max_file_bytes == 0 {
        return Err(CommandError::usage("max-file-bytes must be positive"));
    }
    if args.command.first().map(String::as_str) == Some("compile") {
        return compile_policy(&args);
    }
    if !args.command.is_empty() {
        return Err(CommandError::usage(format!("unknown option: {}", args.command[0])));
    }
    let Some(manifest) = args.manifest.as_ref() else {
        return Ok(json!({ "rules": packaged_rules()? }));
    };
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let manifest_path = std::fs::canonicalize(manifest).map_err(super::io_error)?;
    let provider = ProviderId::new(args.provider.ok_or_else(|| CommandError::usage("rules requires --provider when --manifest is supplied"))?)
        .map_err(|error| CommandError::usage(error.to_string()))?;
    let selector: Value = serde_json::from_str(&args.selector)
        .map_err(|error| CommandError::usage(format!("selector must be JSON: {error}")))?;
    let manifest = std::fs::read_to_string(&manifest_path).map_err(super::io_error)?;
    let compiled = RuleCompiler::compile_manifest_json(&manifest)
        .map_err(|error| CommandError::usage(error.to_string()))?;
    let selected = select_packs(compiled, &args.packs)?;
    let repository_id = root.to_string_lossy().into_owned();
    let (source, context_notices) = super::audit_inventory_source(
        &root,
        args.blueprint_packet.as_deref(),
        args.expected_generation,
    )?;
    let inventory = source
        .inventory(&repository_id)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let denominator = inventory
        .denominator_entries(&selector)
        .map_err(|error| CommandError::usage(error.to_string()))?;

    let mut files = Vec::new();
    let mut gaps = Vec::new();
    if denominator.entries.is_empty() {
        gaps.push("repository-inventory-empty".into());
    }
    for entry in &denominator.entries {
        let path = root.join(&entry.path);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                gaps.push(format!("source-unavailable:{}:{error}", entry.path));
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            gaps.push(format!("source-not-regular-file:{}", entry.path));
            continue;
        }
        if metadata.len() > args.max_file_bytes {
            gaps.push(format!("source-byte-bound-exceeded:{}", entry.path));
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => files.push(SourceFile {
                path: entry.path.clone(),
                bytes,
            }),
            Err(error) => gaps.push(format!("source-unavailable:{}:{error}", entry.path)),
        }
    }

    let mut spans = Vec::new();
    for pack in selected.values() {
        let Some(evaluation) = pack.evaluate_lexical(&files) else {
            gaps.push(format!("pack-not-lexical:{}", pack.pack_id));
            continue;
        };
        gaps.extend(evaluation.coverage.gaps);
        spans.extend(evaluation.findings);
    }
    spans.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then(left.path.cmp(&right.path))
            .then(left.byte_start.cmp(&right.byte_start))
            .then(left.byte_end.cmp(&right.byte_end))
    });
    gaps.sort();
    gaps.dedup();

    let mut findings = Vec::with_capacity(spans.len());
    let mut evidence = Map::new();
    let mut locations = Map::new();
    let mut titles = Map::new();
    let mut messages = Map::new();
    for (index, span) in spans.into_iter().enumerate() {
        let finding_id = FindingId::new(format!(
            "{}:{}:{index}",
            span.rule_id,
            span.evidence_hash.trim_start_matches("sha256:")
        ))
        .map_err(|error| CommandError::internal(error.to_string()))?;
        let severity = severity_name(span.severity).to_owned();
        findings.push(FindingRef {
            id: finding_id.clone(),
            severity,
        });
        evidence.insert(
            finding_id.to_string(),
            json!({
                "ruleId": span.rule_id,
                "path": span.path,
                "byteStart": span.byte_start,
                "byteEnd": span.byte_end,
                "evidenceHash": span.evidence_hash,
                "confidence": confidence_name(span.confidence),
                "authority": span.authority,
                "uncertainty": span.uncertainty,
                "remediation": span.remediation,
            }),
        );
        locations.insert(finding_id.to_string(), json!([span.path]));
        titles.insert(finding_id.to_string(), json!(span.rule_id));
        messages.insert(
            finding_id.to_string(),
            json!("Declarative native rule matched source evidence"),
        );
    }

    let complete = gaps.is_empty() && files.len() == denominator.entries.len();
    // Rules consumes the read-only filesystem inventory directly; it is not an
    // explicitly Blueprint-dependent operation, so context absence cannot
    // degrade its provider result.
    let degradations: Vec<Value> = Vec::new();
    let result = ProviderResult {
        schema_version: 1,
        provider,
        applicable: true,
        required: true,
        status: if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        coverage: Some(Coverage {
            denominator_digest: denominator.digest.clone(),
            expected: denominator.entries.len() as u64,
            examined: files.len() as u64,
            gaps: gaps.clone(),
        }),
        findings,
        coverage_gaps: gaps.clone(),
        degradation: gaps.clone(),
        details: [
            ("findingEvidence".into(), Value::Object(evidence)),
            ("findingLocations".into(), Value::Object(locations)),
            ("findingTitles".into(), Value::Object(titles)),
            ("findingMessages".into(), Value::Object(messages)),
            ("selector".into(), selector.clone()),
            ("blueprintDegradations".into(), json!(degradations)),
            (
                "packs".into(),
                json!(selected.keys().cloned().collect::<Vec<_>>()),
            ),
        ]
        .into_iter()
        .collect(),
    };
    result
        .validate()
        .map_err(|error| CommandError::internal(error.to_string()))?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-native-rule-result",
        "status": if complete { "complete" } else { "incomplete" },
        "repository": repository_id,
        "generation": inventory.generation,
        "inventoryDigest": inventory.digest,
        "selector": selector,
        "denominatorDigest": denominator.digest,
        "contextNotices": context_notices,
        "blueprintDegradations": degradations,
        "providerResult": result,
    }))
}

fn select_packs(
    compiled: std::collections::BTreeMap<String, legion_rules::CompiledRules>,
    requested: &[String],
) -> Result<std::collections::BTreeMap<String, legion_rules::CompiledRules>, CommandError> {
    if requested.is_empty() {
        return Ok(compiled);
    }
    let requested = requested.iter().cloned().collect::<BTreeSet<_>>();
    let missing = requested
        .iter()
        .filter(|pack| !compiled.contains_key(*pack))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CommandError::usage(format!(
            "unknown native rule packs: {}",
            missing.join(", ")
        )));
    }
    Ok(compiled
        .into_iter()
        .filter(|(pack, _)| requested.contains(pack))
        .collect())
}

fn packaged_rules() -> Result<Vec<String>, CommandError> {
    fn walk(path: &Path, out: &mut BTreeSet<String>) -> Result<(), CommandError> {
        for entry in std::fs::read_dir(path).map_err(super::io_error)? {
            let entry = entry.map_err(super::io_error)?;
            let path = entry.path();
            if path.is_dir() { walk(&path, out)?; }
            else if path.extension().and_then(|x| x.to_str()) == Some("json") {
                let value: Value = serde_json::from_slice(&std::fs::read(&path).map_err(super::io_error)?)
                    .map_err(|e| CommandError::internal(e.to_string()))?;
                if let Some(rules) = value.get("rules").and_then(Value::as_array) {
                    for rule in rules {
                        if let Some(id) = rule.get("id").and_then(Value::as_str).or_else(|| rule.as_str()) {
                            out.insert(id.to_owned());
                        }
                    }
                }
            }
        }
        Ok(())
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../src/registry/rules");
    let mut rules = BTreeSet::new();
    walk(&root, &mut rules)?;
    Ok(rules.into_iter().collect())
}

fn compile_policy(args: &RulesArgs) -> CommandResult {
    let command = &args.command;
    if command.len() < 2 { return Err(CommandError::usage("Usage: legion rules compile <source> --base <policy> [--out <output>]")); }
    let source = std::fs::read_to_string(&command[1]).map_err(|e| CommandError::usage(format!("rule source unreadable: {} ({e})", command[1])))?;
    let mut base_path = None;
    let mut out_path = None;
    let mut index = 2;
    while index < command.len() {
        let flag = &command[index];
        let Some(value) = command.get(index + 1) else { return Err(CommandError::usage("Usage: legion rules compile <source> --base <policy> [--out <output>]")); };
        match flag.as_str() {
            "--base" if base_path.is_none() => base_path = Some(value),
            "--out" if out_path.is_none() => out_path = Some(value),
            "--base" => return Err(CommandError::usage("duplicate --base")),
            "--out" => return Err(CommandError::usage("duplicate --out")),
            _ => return Err(CommandError::usage("Usage: legion rules compile <source> --base <policy> [--out <output>]")),
        }
        index += 2;
    }
    let Some(base_path) = base_path else { return Err(CommandError::usage("Usage: legion rules compile <source> --base <policy> [--out <output>]")); };
    let mut base: Value = serde_json::from_slice(&std::fs::read(base_path).map_err(|e| CommandError::usage(format!("base policy unreadable: {base_path} ({e})")))?)
        .map_err(|e| CommandError::usage(format!("base policy unreadable: {base_path} ({e})")))?;
    let classes = base.get("effectRules").and_then(Value::as_array).ok_or_else(|| CommandError::usage("base policy has no effectRules"))?
        .iter().filter_map(|r| r.get("effectClass").and_then(Value::as_str)).map(str::to_owned).collect::<Vec<_>>();
    let mut parsed = Vec::new();
    for (line_no, raw) in source.lines().enumerate() {
        let line = raw.trim(); if line.is_empty() || line.starts_with('#') { continue; }
        let (head, note): (&str, Option<&str>) = if let Some((h, n)) = line.split_once(" note=\"") {
            (h, Some(n.strip_suffix('"').ok_or_else(|| CommandError::usage(format!("line {}: invalid note string", line_no + 1)))?))
        } else { (line, None) };
        let fields = head.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 5 || !matches!(fields[0], "allow"|"deny") || !fields[1].starts_with("approval=") || !fields[2].starts_with("trust=") || !fields[3].starts_with("enforcement=") || fields[4].is_empty() {
            return Err(CommandError::usage(format!("line {}: invalid rule", line_no + 1)));
        }
        let effect = fields[1];
        let mut rule = json!({"effectClass": effect, "rule": fields[0], "approvalRequired": fields[2]=="approval=required", "trustMinimum": fields[3].trim_start_matches("trust="), "requiredEnforcement": fields[4].trim_start_matches("enforcement=")});
        if let Some(note) = note {
            let decoded: String = serde_json::from_str(&format!("\"{}\"", note)).map_err(|_| CommandError::usage(format!("line {}: invalid note string", line_no + 1)))?;
            rule["note"] = Value::String(decoded);
        }
        if !classes.iter().any(|c| c == effect) { return Err(CommandError::usage(format!("unknown effect class: {effect}"))); }
        if parsed.iter().any(|(c, _): &(String, Value)| c == effect) { return Err(CommandError::usage(format!("duplicate effect class: {effect}"))); }
        parsed.push((effect.to_owned(), rule));
    }
    let missing = classes.iter().filter(|c| !parsed.iter().any(|(p, _)| p == *c)).cloned().collect::<Vec<_>>();
    if !missing.is_empty() { return Err(CommandError::usage(format!("missing effect class(es): {}", missing.join(", ")))); }
    base["effectRules"] = Value::Array(classes.iter().map(|c| parsed.iter().find(|(p, _)| p == c).unwrap().1.clone()).collect());
    let bytes = serde_json::to_vec_pretty(&base).map_err(|e| CommandError::internal(e.to_string()))?;
    if let Some(out) = out_path {
        let output = std::path::absolute(out).map_err(super::io_error)?;
        if let Some(parent) = output.parent() { std::fs::create_dir_all(parent).map_err(super::io_error)?; }
        std::fs::write(&output, format!("{}\n", String::from_utf8_lossy(&bytes))).map_err(super::io_error)?;
        Ok(json!({"output": output}))
    } else {
        Ok(json!({"__raw": format!("{}\n", String::from_utf8_lossy(&bytes))}))
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Note => "note",
        Severity::Info => "info",
    }
}

fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}
