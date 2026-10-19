//! Opaque observations of actual package-owned Audit report producer/consumer APIs.
//! This capability proves report protocol behavior only; never runtime trust.
use super::{
    common::{gap, Analysis},
    evidence::limit_runtime_evidence,
};
use crate::{AuditProvider, FrozenPlan, InventoryEnvelope, NativeProviderRegistry};
use legion_contracts::{Report, ReportScope, ReportV1};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Component, Path, PathBuf},
};

const LIMIT: usize = 1024 * 1024;
const TOTAL: usize = 128 * 1024 * 1024;
pub const CONTRACT: &str = "legion-audit-report-v1-v2/1";

fn hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Exact producer/consumer implementation compiled into this binary. These are
/// source identities, not signed build provenance or execution attestations.
pub fn implementation() -> Value {
    let sources = BTreeMap::from([
        (
            "engine/crates/legion-audit/src/report.rs",
            hash(include_bytes!("../../report.rs")),
        ),
        (
            "engine/crates/legion-contracts/src/report.rs",
            hash(include_bytes!("../../../../legion-contracts/src/report.rs")),
        ),
        (
            "engine/crates/legion-report/src/lib.rs",
            hash(include_bytes!("../../../../legion-report/src/lib.rs")),
        ),
        (
            "engine/crates/legion-report/src/json.rs",
            hash(include_bytes!("../../../../legion-report/src/json.rs")),
        ),
    ]);
    json!({"contract":CONTRACT,"producer":{"crate":"legion-audit","version":env!("CARGO_PKG_VERSION"),"schemas":[1,2]},
        "consumer":{"crate":"legion-contracts+legion-report","version":env!("CARGO_PKG_VERSION"),"schemas":[1,2]},
        "platform":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH},"sources":sources})
}

fn snapshot(
    root: &Path,
    inventory: &InventoryEnvelope,
) -> Result<BTreeMap<String, String>, String> {
    inventory.validate().map_err(|e| e.to_string())?;
    if inventory.entries.is_empty() {
        return Err("report-protocol-empty-denominator".into());
    }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let mut files = BTreeMap::new();
    let mut total = 0;
    for entry in &inventory.entries {
        if entry.path.is_empty()
            || entry.path.contains(['\\', ':', '\0'])
            || entry
                .path
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err("report-protocol-path-invalid".into());
        }
        let mut path = root.clone();
        for part in Path::new(&entry.path).components() {
            if !matches!(part, Component::Normal(_)) {
                return Err("report-protocol-path-invalid".into());
            }
            path.push(part.as_os_str());
            if std::fs::symlink_metadata(&path)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("report-protocol-source-symlink".into());
            }
        }
        let mut bytes = vec![];
        std::fs::File::open(&path)
            .map_err(|e| e.to_string())?
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        total += bytes.len();
        if bytes.len() > LIMIT
            || total > TOTAL
            || !path
                .canonicalize()
                .map_err(|e| e.to_string())?
                .starts_with(&root)
        {
            return Err("report-protocol-source-limit-or-escape".into());
        }
        let digest = hash(&bytes);
        if entry.digest.as_deref() != Some(digest.as_str()) {
            return Err(format!("report-protocol-source-drift:{}", entry.path));
        }
        if files.insert(entry.path.clone(), digest).is_some() {
            return Err("report-protocol-source-duplicate".into());
        }
    }
    Ok(files)
}

/// Semantic fields promised to survive supported report-reader/render round trips.
/// v2-only evidence keys are intentionally excluded from this v1 core contract.
fn core(report: &ReportV1) -> Value {
    let mut findings = report
        .findings
        .iter()
        .map(|f| {
            let mut evidence = f.evidence.clone();
            evidence.remove(legion_contracts::V2_FINDING_EVIDENCE_KEY);
            json!({"id":f.id,"severity":f.severity,"title":f.title,"message":f.message,
            "provider":f.provider,"locations":f.locations,"evidence":evidence})
        })
        .collect::<Vec<_>>();
    findings.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    json!({"reportId":report.report_id,"status":report.status,"findings":findings,
        "gaps":report.gaps,"claims":report.claims,"targets":report.targets})
}

/// No Deserialize, public fields, or constructor accepting claimed observations.
/// Minting always executes real frozen native providers & product report APIs.
#[derive(Clone, Debug)]
pub struct NativeReportObservation {
    root: PathBuf,
    inventory_digest: String,
    provider_digest: String,
    files: BTreeMap<String, String>,
    document: Value,
}

impl NativeReportObservation {
    pub fn capture(
        root: &Path,
        plan: &FrozenPlan,
        inventory: &InventoryEnvelope,
    ) -> Result<Self, String> {
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        let files = snapshot(&root, inventory)?;
        // This in-process protocol probe cannot introduce executable tasks.
        if plan.providers().iter().any(|p| {
            p.configuration.contains_key("input")
                || p.kind != crate::ProviderKind::RustAlgorithm
                || !matches!(
                    p.id.as_str(),
                    "compatibility.core"
                        | "architecture.core"
                        | "docs.contract"
                        | "test-quality.core"
                        | "requirements.traceability"
                        | "framework.frontend"
                        | "framework.data"
                        | "framework.backend"
                )
        }) {
            return Err("report-protocol-non-source-provider".into());
        }
        let provider = plan
            .provider("compatibility.core")
            .ok_or("report-protocol-provider-missing")?;
        if provider.configuration.contains_key("input") {
            return Err("report-protocol-injected-input".into());
        }
        let denominator = inventory
            .denominator_entries(&provider.configuration["selector"])
            .map_err(|e| e.to_string())?;
        if provider.configuration["denominatorDigest"] != json!(denominator.digest)
            || provider.configuration["denominatorCount"] != json!(denominator.entries.len())
        {
            return Err("report-protocol-denominator-drift".into());
        }
        // Fresh baseline registry has no opaque observation, so capture cannot recurse.
        let execution = crate::execute(plan, inventory, &NativeProviderRegistry::new(&root))
            .map_err(|e| e.to_string())?;
        let report = crate::report::canonical_report(&root.to_string_lossy(), &execution)
            .map_err(|e| e.to_string())?;
        let v2 = crate::report::lift_report_v2(
            &report,
            ReportScope {
                spec: "whole".into(),
                base_ref_oid: None,
                merge_base_oid: None,
                head: inventory.generation.clone(),
                snapshot_key: None,
                index_schema_version: None,
            },
        )
        .map_err(|e| e.to_string())?;
        let mut cases = BTreeMap::new();
        for schema in [1, 2] {
            // Both producer forms are exactly those consumed by the real report CLI.
            let produced = if schema == 1 {
                legion_report::render_json(&report)
            } else {
                legion_report::render_json_schema(&v2, 2)
            }
            .map_err(|e| e.to_string())?;
            let wire: Value = serde_json::from_str(&produced).map_err(|e| e.to_string())?;
            let consumed = Report::read_any(&wire).map_err(|e| e.to_string())?;
            let rendered =
                legion_report::render_json_schema(&consumed, schema).map_err(|e| e.to_string())?;
            let reread = Report::read_any(
                &serde_json::from_str::<Value>(&rendered).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let expected = if schema == 1 {
                core(&report)
            } else {
                core(&v2.v1_core())
            };
            let observed = core(&reread.v1_core());
            if expected != observed {
                return Err(format!("report-protocol-roundtrip-mismatch:{schema}"));
            }
            cases.insert(format!("schema-{schema}"), json!({"schema":schema,"producedBytes":produced,"producedDigest":hash(produced.as_bytes()),
                "renderedBytes":rendered,"renderedDigest":hash(rendered.as_bytes()),"expected":expected,"observed":observed,"status":"compatible"}));
        }
        let base: Value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
        let mut controls = BTreeMap::new();
        for name in ["unsupported-schema", "missing-schema", "malformed-findings"] {
            let mut wire = base.clone();
            match name {
                "unsupported-schema" => wire["schema_version"] = json!(3),
                "missing-schema" => {
                    wire.as_object_mut().unwrap().remove("schema_version");
                }
                _ => wire["findings"] = json!("malformed"),
            }
            let error = Report::read_any(&wire)
                .err()
                .ok_or("report-protocol-control-accepted")?;
            controls.insert(
                name,
                json!({"input":wire,"status":"incompatible","error":error.to_string()}),
            );
        }
        if snapshot(&root, inventory)? != files {
            return Err("report-protocol-source-drift".into());
        }
        let document = json!({"schema":"legion-native-report-compatibility-observation/1","contract":CONTRACT,
            "claimScope":"native-report-v1-v2-v1-core-preservation","protocolComplete":true,"certificationClaim":false,
            "preservationScope":"v1-core-only; excludes v2-only fields & extensions",
            "protocolDenominator":{"kind":"report-schema-contracts","expected":2,"examined":cases.len()},
            "implementation":implementation(),"planDigest":plan.digest(),"inventoryDigest":inventory.digest,
            "denominatorDigest":denominator.digest,"denominatorCount":denominator.entries.len(),"files":files,
            "execution":execution,"reportV1":report,"reportV2":v2,"cases":cases,"controls":controls});
        Ok(Self {
            root,
            inventory_digest: inventory.digest.clone(),
            provider_digest: crate::digest(provider).map_err(|e| e.to_string())?,
            files,
            document,
        })
    }

    pub fn summary(&self) -> Value {
        self.document.clone()
    }

    pub(super) fn analyze(
        &self,
        root: &Path,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Analysis {
        let valid = root.canonicalize().is_ok_and(|root| root == self.root)
            && inventory.digest == self.inventory_digest
            && crate::digest(provider).is_ok_and(|digest| digest == self.provider_digest)
            && snapshot(root, inventory).is_ok_and(|files| files == self.files);
        let mut result = Analysis::new(
            "unproven",
            false,
            json!({"kind":"source-files",
            "expected":inventory.entries.len(),"examined":if valid {inventory.entries.len()} else {0}}),
        );
        result.extras.insert(
            "protocolDenominator".into(),
            json!({"kind":"report-schema-contracts","expected":2,"examined":if valid {2} else {0}}),
        );
        if valid {
            result
                .extras
                .insert("nativeReportCompatibility".into(), self.summary());
        } else {
            result
                .coverage_gaps
                .push(gap("report-protocol-observation-binding-invalid"));
        }
        limit_runtime_evidence(&mut result);
        result
    }
}
