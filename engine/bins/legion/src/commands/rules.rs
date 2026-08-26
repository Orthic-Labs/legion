use super::{CommandError, CommandResult};
use clap::Args;
use legion_contracts::{
    Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use legion_rules::{Confidence, RuleCompiler, Severity, SourceFile};
use serde_json::{json, Map, Value};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[arg(long)]
    pub manifest: PathBuf,
    #[arg(long = "blueprint-packet")]
    pub blueprint_packet: Option<PathBuf>,
    #[arg(long = "expected-generation")]
    pub expected_generation: Option<String>,
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub provider: String,
    #[arg(long, default_value = r#"{"op":"always"}"#)]
    pub selector: String,
    #[arg(long = "pack")]
    pub packs: Vec<String>,
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_bytes: u64,
}

pub fn run(args: RulesArgs) -> CommandResult {
    if args.max_file_bytes == 0 {
        return Err(CommandError::usage("max-file-bytes must be positive"));
    }
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let manifest_path = std::fs::canonicalize(&args.manifest).map_err(super::io_error)?;
    let provider =
        ProviderId::new(args.provider).map_err(|error| CommandError::usage(error.to_string()))?;
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
