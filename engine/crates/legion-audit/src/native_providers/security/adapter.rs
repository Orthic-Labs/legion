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
    scanners, secrets, supply_chain, suppressions,
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

    pub fn with_snapshot_manifest(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        if let Some(producer) = self.producer.take() {
            self.producer = Some(producer.with_snapshot_manifest(path));
        }
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
            id if scanners::tool_for(id).is_some() => scanners::analyze(&input),
            "security.suppression-changes" => suppressions::analyze(&input),
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
        let mut denied_receipts = Vec::new();
        if !self.artifacts.contains_key(&provider.id) {
            if let Some(producer) = &self.producer {
                match producer.produce(provider, inventory) {
                    Production::Artifact(value) => produced = Some(value),
                    Production::Unavailable(reason) => unavailable_reason = Some(reason),
                    Production::AdmissionUnavailable { reason, receipts } => {
                        unavailable_reason = Some(reason);
                        denied_receipts = receipts;
                    }
                }
            }
        }
        let input = self.artifacts.get(&provider.id).or(produced.as_ref());
        if let Some(reason) = input
            .and_then(|value| value.get("executionAdmissionUnavailable"))
            .and_then(Value::as_str)
        {
            unavailable_reason = Some(reason.into());
        }
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
        let mut gaps = analysis
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
        // Only this invocation's self-produced IaC artifact can reconcile
        // configuration observations into frozen selector-path coverage.
        // Host JSON never opts into this conversion.
        let native_iac = produced_artifact && provider.id == "container.iac";
        let native_secrets = produced_artifact && provider.id == "secrets.current-history";
        // Only this producer invocation owns actual SDK receipts/raw streams.
        // Untrusted injected JSON cannot substitute for native history proof.
        if provider.id == "secrets.current-history" && !native_secrets {
            gaps.push(json!({"kind":"secret-native-history-proof-required"}));
        }
        let secret_reconciled = native_secrets
            && frozen.as_ref().is_some_and(|(_, count)| {
                let rows = analysis
                    .pointer("/sourceCoverage/validatedPaths")
                    .and_then(Value::as_array);
                let validated: BTreeSet<&str> = rows
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                let selected: BTreeSet<&str> = frozen_paths
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(String::as_str)
                    .collect();
                rows.is_some_and(|rows| rows.len() == validated.len())
                    && validated == selected
                    && validated.len() as u64 == *count
                    && analysis
                        .pointer("/sourceCoverage/currentComplete")
                        .and_then(Value::as_bool)
                        == Some(true)
                    && analysis
                        .pointer("/sourceCoverage/historyComplete")
                        .and_then(Value::as_bool)
                        == Some(true)
                    && super::history::validate_manifest(&analysis["historyProof"]).is_some_and(
                        |manifest| {
                            manifest.inventory_digest == inventory.digest
                                && manifest.repository_id == inventory.repository_id
                                && manifest
                                    .current
                                    .keys()
                                    .map(String::as_str)
                                    .collect::<BTreeSet<_>>()
                                    == selected
                                && manifest.current.iter().all(|(path, hash)| {
                                    inventory.entries.iter().any(|entry| {
                                        entry.path == *path && entry.digest.as_ref() == Some(hash)
                                    })
                                })
                        },
                    )
            });
        if native_secrets && !secret_reconciled {
            gaps.push(json!({"kind":"secret-frozen-path-history-reconciliation-invalid"}));
        }

        let mut iac_examined_paths = 0;
        let mut iac_reconciled = false;
        if native_iac {
            let paths: BTreeSet<&str> = frozen_paths
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(String::as_str)
                .collect();
            let validated = analysis
                .pointer("/sourceCoverage/validatedPaths")
                .and_then(Value::as_array);
            let validated_paths: BTreeSet<&str> = validated
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let scope_valid = frozen.as_ref().is_some_and(|(digest, count)| {
                *count == paths.len() as u64
                    && analysis
                        .pointer("/sourceCoverage/selectedCount")
                        .and_then(Value::as_u64)
                        == Some(*count)
                    && analysis
                        .pointer("/sourceCoverage/frozenDenominatorCount")
                        .and_then(Value::as_u64)
                        == Some(*count)
                    && analysis
                        .pointer("/sourceCoverage/frozenDenominatorDigest")
                        .and_then(Value::as_str)
                        == Some(digest.as_str())
                    && validated.is_some_and(|rows| rows.len() == validated_paths.len())
                    && validated_paths.is_subset(&paths)
            });
            if !scope_valid {
                gaps.push(json!({"kind": "iac-frozen-path-reconciliation-invalid"}));
            }
            iac_examined_paths = validated_paths.intersection(&paths).count() as u64;
            iac_reconciled = scope_valid
                && validated_paths == paths
                && analysis
                    .pointer("/sourceCoverage/complete")
                    .and_then(Value::as_bool)
                    == Some(true)
                && expected == examined
                && gaps.is_empty();
        }
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
            // This count comes only from validated selected paths, never
            // from the infrastructure-resource count. A malformed frozen
            // count is separately gapped & cannot make completion true.
            (Some((_, count)), true) if native_secrets => (
                *count,
                if secret_reconciled {
                    *count
                } else {
                    examined.min(*count)
                },
            ),
            (Some((_, count)), true) if native_iac => (*count, iac_examined_paths.min(*count)),
            (Some((_, count)), true) if expected > 0 && unit_reconciled => (*count, *count),
            (Some((_, count)), true) if expected > 0 => (*count, examined.min(*count)),
            // An unavailable provider still reports what was selected, with
            // nothing examined.
            (Some((_, count)), false) if input.is_none() && *count > 0 => (*count, 0),
            _ => (expected, examined),
        };
        let reconciled = !produced_artifact
            || (native_iac && iac_reconciled)
            || (native_secrets && secret_reconciled)
            || own_unit
            || (!native_iac
                && !native_secrets
                && frozen
                    .as_ref()
                    .is_some_and(|(_, count)| *count == analysis_expected));
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
            (native_secrets && secret_reconciled).then_some(&analysis["historyProof"]),
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
        if let Some(receipts) = input.and_then(|value| value.get("executionReceipts")) {
            details.insert("executionReceipts".into(), receipts.clone());
        }
        if !denied_receipts.is_empty() {
            details.insert("executionReceipt".into(), denied_receipts[0].clone());
            details.insert("executionReceipts".into(), json!(denied_receipts));
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
        if !artifact_supplied || unavailable_reason.is_some() {
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
    history_proof: Option<&Value>,
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
        let historical = provider == "secrets.current-history"
            && finding.get("mode").and_then(Value::as_str) == Some("history")
            && history_proof.is_some_and(|proof| super::history::live_anchor(finding, proof));
        if (provider == "secrets.current-history"
            && finding.get("mode").and_then(Value::as_str) == Some("history")
            && !historical)
            || (set.as_ref().is_some_and(|set| !set.contains(path.as_str())) && !historical)
        {
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
        // Preserve every existing provider ID. Only historical secret findings
        // need commit identity because deleted/branch paths share current names.
        let mut identity = format!("{provider}\0{rule}\0{path}\0{line}\0{excerpt}");
        if historical {
            identity.push_str("\0history\0");
            identity.push_str(
                finding
                    .get("commit")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            );
        }
        let id = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(identity.as_bytes()))
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
        if historical {
            let evidence = located
                .evidence
                .get_mut(&id)
                .expect("inserted finding evidence");
            for field in [
                "commit",
                "mode",
                "blobOid",
                "blobDigest",
                "historyManifestDigest",
            ] {
                evidence[field] = finding[field].clone();
            }
        }
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

#[cfg(test)]
mod history_identity_regression {
    use super::*;

    #[test]
    fn ordinary_history_mode_preserves_existing_provider_identity() {
        let excerpt = format!("sha256:{}", "a".repeat(64));
        let finding = json!({"ruleId":"DS002","file":"Dockerfile","line":1,"secretDigest":excerpt,"mode":"history"});
        let located = locate_findings(
            "container.iac",
            &[finding],
            Some(&["Dockerfile".into()]),
            None,
        );
        assert_eq!(located.refs.len(), 1);
        assert!(located.out_of_scope.is_empty());
        let expected = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                format!("container.iac\0DS002\0Dockerfile\01\0{excerpt}").as_bytes()
            ))
        );
        assert_eq!(
            serde_json::to_value(&located.refs[0]).unwrap()["id"],
            json!(expected)
        );
    }
}
