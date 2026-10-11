//! Rust-owned adapters for security-family provider records.
//!
//! The adapter analyses artifacts; it never spawns a tool itself. Artifacts come
//! from the host (`new`) or, when none were injected and a root was supplied
//! (`with_root`), from the self-sourcing [`ArtifactProducer`]. A missing
//! artifact or receipt is never turned into success.

use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{
    Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    error::AuditError, execution::ProviderExecutor, inventory::InventoryEnvelope,
    plan::AuditProvider,
};

use super::{
    ast_grep, container_iac, dependency_osv, imported_sarif, opengrep, packs,
    producer::{ArtifactProducer, Production},
    secrets, supply_chain,
};

#[derive(Clone, Debug, Default)]
pub struct SecurityProviderExecutor {
    /// Keyed by provider id; values are immutable host-produced projections.
    pub artifacts: BTreeMap<String, Value>,
    /// Used only for providers with no injected artifact.
    pub producer: Option<ArtifactProducer>,
    /// The audited root, read directly by the heuristic packs
    /// (`security.credentials` and its four siblings; see [`packs`]).
    pub root: Option<std::path::PathBuf>,
}

impl SecurityProviderExecutor {
    pub fn new(artifacts: BTreeMap<String, Value>) -> Self {
        Self {
            artifacts,
            producer: None,
            root: None,
        }
    }

    /// Source artifacts for the audited `root` when the host injected none.
    /// The heuristic packs read `root` directly.
    pub fn with_root(self, root: impl Into<std::path::PathBuf>) -> Self {
        let root = root.into();
        let mut executor = self.with_producer(ArtifactProducer::new(root.clone()));
        executor.root = Some(root);
        executor
    }

    pub fn with_producer(mut self, producer: ArtifactProducer) -> Self {
        self.producer = Some(producer);
        self
    }

    pub fn analyze(&self, provider: &AuditProvider) -> Option<Value> {
        let input = self
            .artifacts
            .get(&provider.id)
            .cloned()
            .unwrap_or_else(|| json!({}));
        Self::analyze_input(provider, &input)
    }

    /// The provider's frozen selector denominator as (digest, count): the plan's
    /// recorded values when present, else recomputed from the inventory.
    fn frozen_denominator(
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Option<(String, u64)> {
        let selector = provider.configuration.get("selector")?;
        let computed = inventory.denominator_entries(selector).ok()?;
        let digest = provider
            .configuration
            .get("denominatorDigest")
            .and_then(Value::as_str)
            .map_or(computed.digest, str::to_owned);
        let count = provider
            .configuration
            .get("denominatorCount")
            .and_then(Value::as_u64)
            .unwrap_or(computed.entries.len() as u64);
        Some((digest, count))
    }

    /// The provider's frozen selector denominator paths, if the selector
    /// resolves against the inventory.
    fn frozen_paths(
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Option<Vec<String>> {
        let selector = provider.configuration.get("selector")?;
        let computed = inventory.denominator_entries(selector).ok()?;
        Some(
            computed
                .entries
                .into_iter()
                .map(|entry| entry.path)
                .collect(),
        )
    }

    /// What the audit can observe without any scanner output: the frozen
    /// selector paths. An unavailable provider is analysed against this so its
    /// denominator reports what was selected (and examined as zero) instead of
    /// an empty projection that reads as "no inputs exist".
    fn observed_input(inventory: &InventoryEnvelope, paths: &[String]) -> Value {
        json!({
            "plan": {
                "binding": {"repositoryRevision": inventory.generation, "digest": inventory.digest},
                "denominator": {"pathCount": paths.len()},
            },
            "projection": {"files": paths.iter().map(|path| json!({"path": path})).collect::<Vec<_>>()},
            "artifacts": {},
        })
    }

    fn analyze_input(provider: &AuditProvider, input: &Value) -> Option<Value> {
        let input = input.clone();
        Some(match provider.id.as_str() {
            "container.iac" => container_iac::analyze(&input),
            "dependency.osv" => dependency_osv::analyze(&input),
            "secrets.current-history" => secrets::analyze(&input),
            "security.opengrep" => opengrep::analyze(&input),
            "structural.ast-grep" => ast_grep::analyze(&input),
            "supply-chain.license-sbom-provenance" => supply_chain::analyze(&input),
            "imported.sarif" => imported_sarif::analyze(&input),
            _ => return None,
        })
    }
}

impl ProviderExecutor for SecurityProviderExecutor {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        // The five heuristic packs read the frozen selector paths themselves
        // and raise candidates only; they have no scanner artifact.
        if let Some(pack) = packs::pack_for(&provider.id) {
            return packs::execute(
                provider,
                pack,
                self.root.as_deref(),
                Self::frozen_denominator(provider, inventory),
                Self::frozen_paths(provider, inventory),
            );
        }
        let mut unavailable_reason = None;
        let mut produced = None;
        if !self.artifacts.contains_key(&provider.id) {
            if let Some(producer) = &self.producer {
                match producer.produce(provider, inventory) {
                    Production::Artifact(value) => produced = Some(value),
                    Production::Unavailable(reason) => unavailable_reason = Some(reason),
                }
            }
        }
        let input = self.artifacts.get(&provider.id).or(produced.as_ref());
        let frozen_paths = Self::frozen_paths(provider, inventory);
        let observed;
        let analysis_input = match input {
            Some(value) => value,
            None => {
                observed =
                    Self::observed_input(inventory, frozen_paths.as_deref().unwrap_or_default());
                &observed
            }
        };
        let Some(analysis) = Self::analyze_input(provider, analysis_input) else {
            return Err(AuditError::Provider(format!(
                "unsupported security provider {}",
                provider.id
            )));
        };
        let provider_id = ProviderId::new(provider.id.clone())?;
        let expected = analysis
            .get("denominator")
            .and_then(|d| d.get("expected"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let examined = analysis
            .get("denominator")
            .and_then(|d| d.get("examined"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let gaps = analysis
            .get("coverageGaps")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        // Coverage must be bound to the provider's frozen denominator. Host-injected
        // artifacts keep their own counts (the host froze them); a produced
        // artifact is scoped by the producer, so it is reconciled to the frozen
        // selector denominator and only complete when both agree exactly.
        let produced_artifact = produced.is_some();
        let frozen = Self::frozen_denominator(provider, inventory);
        let analysis_expected = analysis
            .get("denominator")
            .and_then(|d| d.get("expected"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // Dependency and SBOM analysis count manifests and packages, not
        // selector paths. The producer scans every selected path to find them,
        // so when the analysis reconciled fully in its own unit the frozen path
        // denominator is examined in full; a partial reconciliation stays partial.
        let own_unit = matches!(
            analysis
                .get("denominator")
                .and_then(|d| d.get("kind"))
                .and_then(Value::as_str),
            Some("lockfile-packages" | "dependency-manifests")
        );
        let unit_reconciled = own_unit
            && examined >= expected
            && !gaps.iter().any(|gap| {
                matches!(
                    gap.get("kind").and_then(Value::as_str),
                    Some(
                        "sbom-package-missing"
                            | "dependency-manifest-unparsed"
                            | "dependency-receipt-invalid"
                            | "dependency-inventory-missing"
                    )
                )
            });
        let (expected, examined) = match (&frozen, produced_artifact) {
            (Some((_, count)), true) if expected > 0 && unit_reconciled => (*count, *count),
            (Some((_, count)), true) if expected > 0 => (*count, examined.min(*count)),
            // An unavailable provider still reports what was selected, with
            // nothing examined.
            (Some((_, count)), false) if input.is_none() && *count > 0 => (*count, 0),
            _ => (expected, examined),
        };
        let reconciled = !produced_artifact
            || own_unit
            || frozen
                .as_ref()
                .is_some_and(|(_, count)| *count == analysis_expected);
        let complete = analysis.get("complete").and_then(Value::as_bool) == Some(true)
            && reconciled
            && expected == examined
            && expected > 0
            && gaps.is_empty();
        let status_text = analysis
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unproven");
        let applicable = analysis
            .get("applicable")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        // `failed` means a scanner ran and broke or the result is invalid. An
        // analysis that ran (including one that found something) or one whose
        // scanner or input is simply absent is partial, with typed gaps.
        let status = if complete {
            ProviderStatus::Complete
        } else if matches!(status_text, "pass" | "candidates" | "fail" | "unproven") {
            ProviderStatus::Partial
        } else {
            ProviderStatus::Failed
        };
        let denominator_digest = provider
            .configuration
            .get("denominatorDigest")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| frozen.as_ref().map(|(digest, _)| digest.clone()))
            .unwrap_or_default();
        let coverage = (expected > 0).then_some(Coverage {
            denominator_digest,
            expected,
            examined,
            gaps: gaps
                .iter()
                .map(|gap| serde_json::to_string(gap).unwrap_or_else(|_| "coverage-gap".into()))
                .collect(),
        });
        let located = locate_findings(
            &provider.id,
            analysis
                .get("findings")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            frozen_paths.as_deref(),
        );
        let findings = located.refs;
        let out_of_scope_count = located.out_of_scope.len();
        let mut candidates = analysis
            .get("candidates")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        // A finding located outside the frozen selector denominator cannot be
        // a finding of this provider's scope; it is kept as an unadjudicated
        // candidate with a typed gap rather than invalidating the result.
        candidates.extend(located.out_of_scope);
        let mut details = BTreeMap::from([
            (String::from("analysis"), analysis.clone()),
            (String::from("candidates"), Value::Array(candidates)),
        ]);
        if !findings.is_empty() {
            details.insert("findingEvidence".into(), Value::Object(located.evidence));
            details.insert("findingLocations".into(), Value::Object(located.locations));
            details.insert("findingTitles".into(), Value::Object(located.titles));
            details.insert("findingMessages".into(), Value::Object(located.messages));
        }
        // Preserve terminal receipts at the contract boundary. The generic
        // Audit executor validates this projection before accepting results.
        if let Some(receipt) = input
            .and_then(|value| value.get("executionReceipt"))
            .or_else(|| analysis.get("executionReceipt"))
        {
            details.insert("executionReceipt".into(), receipt.clone());
        }
        // How the artifact was sourced: `tool` (receipt-bound scanner run),
        // `native-fallback`, or `file` (repository SARIF).
        if let Some(producer) = input.and_then(|value| value.get("producer")) {
            details.insert("producer".into(), producer.clone());
        }
        // With no host-supplied artifact there is nothing to analyze: the
        // plan selected this provider, so it is applicable but unavailable.
        let artifact_supplied = input.is_some();
        let mut result = ProviderResult {
            schema_version: 1,
            provider: provider_id,
            applicable: applicable || !artifact_supplied,
            required: provider.required,
            status,
            complete,
            coverage,
            findings,
            coverage_gaps: gaps
                .iter()
                .map(|gap| serde_json::to_string(gap).unwrap_or_else(|_| "coverage-gap".into()))
                .collect(),
            degradation: Vec::new(),
            details,
        };
        if out_of_scope_count > 0 {
            let gap = format!(
                "{{\"count\":{out_of_scope_count},\"kind\":\"finding-outside-denominator\"}}"
            );
            result.complete = false;
            if matches!(result.status, ProviderStatus::Complete | ProviderStatus::Ok) {
                result.status = ProviderStatus::Partial;
            }
            result.coverage_gaps.push(gap.clone());
            if let Some(coverage) = result.coverage.as_mut() {
                coverage.gaps.push(gap);
            }
        }
        if !artifact_supplied {
            crate::native_providers::availability::mark_unavailable(
                &mut result,
                &unavailable_reason
                    .unwrap_or_else(|| format!("artifact-not-produced:{}", provider.id)),
            );
        }
        Ok(result)
    }
}

/// Findings projected into the shape `validate_result` requires: a unique id,
/// non-empty evidence, and a `path:line` inside the frozen selector denominator.
struct LocatedFindings {
    refs: Vec<FindingRef>,
    evidence: Map<String, Value>,
    locations: Map<String, Value>,
    titles: Map<String, Value>,
    messages: Map<String, Value>,
    out_of_scope: Vec<Value>,
}

fn text_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|key| value.get(*key).and_then(Value::as_str))
        .find(|text| !text.is_empty())
}

/// The repository path a finding is about, as the producers spell it.
fn finding_path(finding: &Value, paths: Option<&BTreeSet<&str>>) -> Option<String> {
    let sarif_uri = finding
        .get("locations")
        .and_then(Value::as_array)
        .and_then(|locations| locations.first())
        .and_then(|location| location.get("physicalLocation"))
        .and_then(|physical| physical.get("artifactLocation"))
        .and_then(|artifact| artifact.get("uri"))
        .and_then(Value::as_str);
    let nested = finding
        .get("location")
        .and_then(|location| text_field(location, &["path", "file"]));
    let candidates = [
        text_field(
            finding,
            &["file", "File", "path", "evidencePath", "manifest"],
        ),
        nested,
        sarif_uri,
        text_field(finding, &["target", "Target"]),
    ];
    let normalized = |raw: &str| {
        let raw = raw.strip_prefix("file://").unwrap_or(raw);
        raw.strip_prefix("./").unwrap_or(raw).replace('\\', "/")
    };
    let mut first = None;
    for raw in candidates.into_iter().flatten() {
        let path = normalized(raw);
        if paths.is_none_or(|set| set.contains(path.as_str())) {
            return Some(path);
        }
        first.get_or_insert(path);
    }
    // A spelled path outside the selection stays outside (the caller demotes
    // it); a finding with no spelled path is attributed to the first selected
    // path so it stays reviewable.
    first.or_else(|| paths.and_then(|set| set.iter().next().map(|path| (*path).to_owned())))
}

fn finding_line(finding: &Value) -> u64 {
    [
        finding.get("line"),
        finding.get("StartLine"),
        finding.get("startLine"),
        finding
            .get("locations")
            .and_then(Value::as_array)
            .and_then(|locations| locations.first())
            .and_then(|location| location.get("physicalLocation"))
            .and_then(|physical| physical.get("region"))
            .and_then(|region| region.get("startLine")),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_u64)
    .filter(|line| *line > 0)
    .unwrap_or(1)
}

fn locate_findings(
    provider: &str,
    findings: &[Value],
    paths: Option<&[String]>,
) -> LocatedFindings {
    let set: Option<BTreeSet<&str>> = paths.map(|paths| paths.iter().map(String::as_str).collect());
    let mut located = LocatedFindings {
        refs: Vec::new(),
        evidence: Map::new(),
        locations: Map::new(),
        titles: Map::new(),
        messages: Map::new(),
        out_of_scope: Vec::new(),
    };
    for finding in findings {
        let rule = text_field(finding, &["ruleId", "RuleID", "rule_id", "id", "kind"])
            .unwrap_or("finding")
            .to_owned();
        let Some(path) = finding_path(finding, set.as_ref()) else {
            located.out_of_scope.push(finding.clone());
            continue;
        };
        if set.as_ref().is_some_and(|set| !set.contains(path.as_str())) {
            located.out_of_scope.push(finding.clone());
            continue;
        }
        let line = finding_line(finding);
        // A redacted excerpt digest, never the matched text: secret findings
        // carry only `secretDigest`, other findings are digested whole.
        let excerpt = finding
            .get("secretDigest")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(
                        serde_json::to_string(finding)
                            .unwrap_or_default()
                            .as_bytes()
                    ))
                )
            });
        let id = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                format!("{provider}\0{rule}\0{path}\0{line}\0{excerpt}").as_bytes()
            ))
        );
        if located.evidence.contains_key(&id) {
            continue;
        }
        let Ok(finding_id) = FindingId::new(id.clone()) else {
            continue;
        };
        located.refs.push(FindingRef {
            id: finding_id,
            severity: finding
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("warning")
                .into(),
        });
        located.evidence.insert(
            id.clone(),
            json!({
                "provider": provider,
                "ruleId": rule,
                "path": path,
                "line": line,
                "excerptDigest": excerpt,
                "redacted": true,
            }),
        );
        located
            .locations
            .insert(id.clone(), json!([format!("{path}:{line}")]));
        located.titles.insert(id.clone(), json!(rule));
        located.messages.insert(
            id,
            json!(format!("{provider} reported {rule} at {path}:{line}")),
        );
    }
    located
}
