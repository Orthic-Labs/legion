use legion_audit::InventorySource as _;
use super::{CommandError, CommandResult};
use clap::Args;
use legion_audit::{AuditError, AuditProvider, InventoryEnvelope, ProviderExecutor};
use legion_contracts::{
    Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use legion_rules::{Confidence, RuleCompiler, Severity, SourceFile};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[arg(long)]
    pub manifest: Option<PathBuf>,
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
    if args.command.iter().any(|argument| argument == "--help") {
        return Ok(json!({"__raw":"Usage: legion rules [compile <source> --base <policy> [--out <output>]]\n"}));
    }
    if args.command.first().map(String::as_str) == Some("compile") {
        return compile_policy(&args);
    }
    if !args.command.is_empty() {
        return Err(CommandError::usage(format!(
            "unknown option: {}",
            args.command[0]
        )));
    }
    let Some(manifest) = args.manifest.as_ref() else {
        let output = json!({ "rules": packaged_rules()? });
        let raw = serde_json::to_string(&output)
            .map_err(|error| CommandError::internal(error.to_string()))?;
        return Ok(json!({ "__raw": format!("{raw}\n") }));
    };
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let manifest_path = std::fs::canonicalize(manifest).map_err(super::io_error)?;
    let provider = ProviderId::new(args.provider.ok_or_else(|| {
        CommandError::usage("rules requires --provider when --manifest is supplied")
    })?)
    .map_err(|error| CommandError::usage(error.to_string()))?;
    let selector: Value = serde_json::from_str(&args.selector)
        .map_err(|error| CommandError::usage(format!("selector must be JSON: {error}")))?;
    let manifest = std::fs::read_to_string(&manifest_path).map_err(super::io_error)?;
    let compiled = RuleCompiler::compile_manifest_json(&manifest)
        .map_err(|error| CommandError::usage(error.to_string()))?;
    let selected = select_packs(compiled, &args.packs)?;
    let repository_id = root.to_string_lossy().into_owned();
    let source = super::audit_inventory_source(&root)?;
    let context_notices: Vec<String> = Vec::new();
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
    // Rules consumes Legion's own read-only filesystem inventory directly —
    // its sole and only source, not a fallback from an external context
    // engine — so there is no degradation concept to report.
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
    // Prefer release-owned native packs. The compile-time registry is used by
    // developer binaries so command behavior never discovers a source checkout
    // beside its executable.
    fn collect_rule_ids(value: &Value, out: &mut BTreeSet<String>) {
        if let Some(rules) = value.get("rules").and_then(Value::as_array) {
            for rule in rules {
                if let Some(id) = rule
                    .get("id")
                    .and_then(Value::as_str)
                    .or_else(|| rule.as_str())
                {
                    out.insert(id.to_owned());
                }
            }
        }
        if let Some(packs) = value.get("packs").and_then(Value::as_array) {
            for pack in packs {
                collect_rule_ids(pack, out);
            }
        }
    }

    let mut rules = BTreeSet::new();
    for source in EMBEDDED_RULE_FILES {
        let value: Value = serde_json::from_str(source)
            .map_err(|error| CommandError::internal(format!("embedded rule registry invalid: {error}")))?;
        collect_rule_ids(&value, &mut rules);
    }
    Ok(rules.into_iter().collect())
}

const EMBEDDED_RULE_FILES: &[&str] = &[
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/ast-grep/structural-core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/code/architecture/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/code/ast-grep/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/code/docs-contract/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/code/maintainability/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/code/test-quality/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/compatibility/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/copy/anti-slop.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/copy/clarity.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/copy/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/copy/documentation.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/data-integrity/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/discoverability/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/governance/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/narrative/chronology.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/privacy/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/requirements/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/safety/hazards.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/abuse-observability.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/ai.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/boundaries.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/browser-http.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/creator-derived.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/crypto-data-privacy.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/enums.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/injection-output.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/specialist.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/supply-developer-machine.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/security/opengrep/core.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/ux/designer-derived.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/rules/visual/designer-derived.json")),
];

fn compile_policy(args: &RulesArgs) -> CommandResult {
    const USAGE: &str = "Usage: legion rules compile <source> --base <policy> [--out <output>]";
    let command = &args.command;
    if command.len() < 2 || command[0] != "compile" {
        return Err(CommandError::usage(USAGE));
    }
    let mut base_path = None;
    let mut out_path = None;
    let mut index = 2;
    while index < command.len() {
        let flag = &command[index];
        let Some(value) = command.get(index + 1) else {
            return Err(CommandError::usage(USAGE));
        };
        if value.is_empty() {
            return Err(CommandError::usage(USAGE));
        }
        match flag.as_str() {
            "--base" if base_path.is_none() => base_path = Some(value.clone()),
            "--out" if out_path.is_none() => out_path = Some(value.clone()),
            "--base" => return Err(CommandError::usage("duplicate --base")),
            "--out" => return Err(CommandError::usage("duplicate --out")),
            _ => return Err(CommandError::usage(USAGE)),
        }
        index += 2;
    }
    let Some(base_path) = base_path else {
        return Err(CommandError::usage(USAGE));
    };
    let source_path = resolve_cli_path(&command[1]).map_err(super::io_error)?;
    let base_path = resolve_cli_path(&base_path).map_err(super::io_error)?;
    let base_text = std::fs::read_to_string(&base_path).map_err(|error| {
        CommandError::usage(format!(
            "base policy unreadable: {} ({error})",
            base_path.display()
        ))
    })?;
    let mut base = parse_ordered_json(&base_text).map_err(|error| {
        CommandError::usage(format!(
            "base policy unreadable: {} ({error})",
            base_path.display()
        ))
    })?;
    let source = std::fs::read_to_string(&source_path).map_err(|error| {
        CommandError::usage(format!(
            "rule source unreadable: {} ({error})",
            source_path.display()
        ))
    })?;
    let classes = base
        .object_field("effectRules")
        .and_then(OrderedJson::as_array)
        .ok_or_else(|| CommandError::usage("base policy has no effectRules"))?
        .iter()
        .map(|rule| {
            rule.object_field("effectClass")
                .and_then(OrderedJson::as_str)
                .map(str::to_owned)
                .ok_or_else(|| CommandError::usage("base policy has no effectRules"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut parsed = Vec::new();
    for (line_no, raw) in source.split('\n').enumerate() {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (head, note) = if let Some((head, note)) = line.split_once(" note=\"") {
            let note = note.strip_suffix('"').ok_or_else(|| {
                CommandError::usage(format!("line {}: invalid note string", line_no + 1))
            })?;
            (head, Some(note))
        } else {
            (line, None)
        };
        let fields = head.split_whitespace().collect::<Vec<_>>();
        let valid_effect = fields.get(1).is_some_and(|effect| {
            !effect.is_empty()
                && effect
                    .bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_uppercase())
        });
        let valid = fields.len() == 5
            && matches!(fields.first(), Some(&"allow") | Some(&"deny"))
            && valid_effect
            && fields
                .get(2)
                .is_some_and(|field| matches!(*field, "approval=required" | "approval=none"))
            && fields.get(3) == Some(&"trust=capability-signature")
            && fields.get(4).is_some_and(|field| {
                matches!(
                    *field,
                    "enforcement=strong"
                        | "enforcement=observed"
                        | "enforcement=read_only"
                        | "enforcement=advisory"
                        | "enforcement=unsupported"
                        | "enforcement=degraded"
                )
            });
        if !valid {
            return Err(CommandError::usage(format!(
                "line {}: invalid rule",
                line_no + 1
            )));
        }
        let effect = fields[1];
        let approval = fields[2] == "approval=required";
        let trust = &fields[3]["trust=".len()..];
        let enforcement = &fields[4]["enforcement=".len()..];
        let mut rule = OrderedJson::Object(vec![
            ("effectClass".into(), OrderedJson::String(effect.into())),
            ("rule".into(), OrderedJson::String(fields[0].into())),
            ("approvalRequired".into(), OrderedJson::Bool(approval)),
            ("trustMinimum".into(), OrderedJson::String(trust.into())),
            (
                "requiredEnforcement".into(),
                OrderedJson::String(enforcement.into()),
            ),
        ]);
        if let Some(note) = note {
            let decoded: String = serde_json::from_str(&format!("\"{note}\"")).map_err(|_| {
                CommandError::usage(format!("line {}: invalid note string", line_no + 1))
            })?;
            rule.object_set("note", OrderedJson::String(decoded));
        }
        if !classes.iter().any(|class| class == effect) {
            return Err(CommandError::usage(format!(
                "unknown effect class: {effect}"
            )));
        }
        if parsed
            .iter()
            .any(|(class, _): &(String, OrderedJson)| class == effect)
        {
            return Err(CommandError::usage(format!(
                "duplicate effect class: {effect}"
            )));
        }
        parsed.push((effect.to_owned(), rule));
    }
    let missing = classes
        .iter()
        .filter(|class| {
            !parsed
                .iter()
                .any(|(parsed_class, _)| parsed_class == *class)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CommandError::usage(format!(
            "missing effect class(es): {}",
            missing.join(", ")
        )));
    }
    let effect_rules = classes
        .iter()
        .map(|class| {
            parsed
                .iter()
                .find(|(parsed_class, _)| parsed_class == class)
                .unwrap()
                .1
                .clone()
        })
        .collect();
    if parsed.iter().any(|(_, rule)| {
        matches!(
            rule.object_field("requiredEnforcement")
                .and_then(OrderedJson::as_str),
            Some("advisory" | "degraded")
        )
    }) {
        return Err(CommandError::usage("compiled policy failed validation"));
    }
    base.object_set("effectRules", OrderedJson::Array(effect_rules));
    let bytes = format!("{}\n", base.render_pretty());
    if let Some(out) = out_path {
        let output = resolve_cli_path(&out).map_err(super::io_error)?;
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).map_err(super::io_error)?;
        }
        let temporary = PathBuf::from(format!("{}.tmp-{}", output.display(), std::process::id()));
        std::fs::write(&temporary, bytes.as_bytes()).map_err(super::io_error)?;
        std::fs::rename(&temporary, &output).map_err(super::io_error)?;
        let receipt = json!({"output": output});
        let raw = serde_json::to_string(&receipt)
            .map_err(|error| CommandError::internal(error.to_string()))?;
        Ok(json!({"__raw": format!("{raw}\n")}))
    } else {
        Ok(json!({"__raw": bytes}))
    }
}

#[derive(Clone, Debug)]
enum OrderedJson {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<OrderedJson>),
    Object(Vec<(String, OrderedJson)>),
}

impl OrderedJson {
    fn as_array(&self) -> Option<&[OrderedJson]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn object_field(&self, name: &str) -> Option<&OrderedJson> {
        match self {
            Self::Object(entries) => entries
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn object_set(&mut self, name: &str, value: OrderedJson) {
        if let Self::Object(entries) = self {
            if let Some((_, current)) = entries.iter_mut().find(|(key, _)| key == name) {
                *current = value;
            } else {
                entries.push((name.into(), value));
            }
        }
    }

    fn render_pretty(&self) -> String {
        self.render_at(0)
    }

    fn render_at(&self, depth: usize) -> String {
        match self {
            Self::Null => "null".into(),
            Self::Bool(value) => value.to_string(),
            Self::Number(value) => value.to_string(),
            Self::String(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into()),
            Self::Array(values) => {
                if values.is_empty() {
                    return "[]".into();
                }
                let indent = "  ".repeat(depth + 1);
                let close_indent = "  ".repeat(depth);
                let body = values
                    .iter()
                    .map(|value| format!("{indent}{}", value.render_at(depth + 1)))
                    .collect::<Vec<_>>()
                    .join(",\n");
                format!("[\n{body}\n{close_indent}]")
            }
            Self::Object(entries) => {
                if entries.is_empty() {
                    return "{}".into();
                }
                let indent = "  ".repeat(depth + 1);
                let close_indent = "  ".repeat(depth);
                let body = entries
                    .iter()
                    .map(|(key, value)| {
                        format!(
                            "{indent}{}: {}",
                            serde_json::to_string(key).unwrap_or_else(|_| "\"\"".into()),
                            value.render_at(depth + 1)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",\n");
                format!("{{\n{body}\n{close_indent}}}")
            }
        }
    }
}

impl<'de> Deserialize<'de> for OrderedJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct OrderedVisitor;
        impl<'de> Visitor<'de> for OrderedVisitor {
            type Value = OrderedJson;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedJson::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedJson::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedJson::Number(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(OrderedJson::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedJson::String(value.into()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedJson::String(value))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedJson::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedJson::Null)
            }

            fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = access.next_element()? {
                    values.push(value);
                }
                Ok(OrderedJson::Array(values))
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some((key, value)) = access.next_entry()? {
                    entries.push((key, value));
                }
                Ok(OrderedJson::Object(entries))
            }
        }
        deserializer.deserialize_any(OrderedVisitor)
    }
}

fn parse_ordered_json(input: &str) -> Result<OrderedJson, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = OrderedJson::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

fn resolve_cli_path(path: &str) -> std::io::Result<PathBuf> {
    let path = Path::new(path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
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
