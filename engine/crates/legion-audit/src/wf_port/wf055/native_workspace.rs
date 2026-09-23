//! Port of `src/providers/security/model-extractors/native-workspace.mjs`.
//!
//! Native-workspace extractor per Security Appendix §11.7: config
//! discovery, `.env` loading, workspace trust, plugin/hook/tool/MCP
//! discovery, process execution sinks, updater config, desktop boundaries,
//! IPC, credential stores.

use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

use crate::wf_port::wf052::contracts::stable_id;
use crate::wf_port::wf055::common::{entity, relation};

static FILE_PATH_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.env|config\.|plugin|hook|mcp|skill|extension|\.agent/").expect("valid regex"));
static TEXT_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.env|loadConfig|plugin|hook|mcp").expect("valid regex"));
static EXEC_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:exec|spawn|child_process|Command::new|subprocess)").expect("valid regex"));
static UPDATER_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"updater|autoUpdater|update").expect("valid regex"));

#[derive(Default, Clone)]
pub struct NativeWorkspaceExtraction {
    pub entities: Vec<Value>,
    pub relations: Vec<Value>,
    pub evidence: Vec<Value>,
    pub initial_facts: Vec<Value>,
    pub coverage_gaps: Vec<Value>,
}

/// Port of `extractNativeWorkspace({ root, plan, projection, files, lensRegistry })`.
pub fn extract_native_workspace(files: &[(String, String)]) -> NativeWorkspaceExtraction {
    let mut out = NativeWorkspaceExtraction::default();

    for (file, text) in files {
        if text.is_empty() {
            continue;
        }
        if FILE_PATH_MARKER.is_match(file) || TEXT_MARKER.is_match(text) {
            let evidence_ref = stable_id("workspace-evidence", &json!({ "file": file }));
            let entrypoint = entity(
                "entrypoint",
                &format!("workspace config {file}"),
                json!({ "entrypointType": "workspace-open" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            let artifact = entity(
                "repository-artifact",
                &format!("config artifact {file}"),
                json!({ "trust": "workspace-controlled" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            let entrypoint_id = entrypoint["id"].as_str().unwrap_or_default().to_string();
            let artifact_id = artifact["id"].as_str().unwrap_or_default().to_string();
            out.entities.push(entrypoint);
            out.entities.push(artifact);
            out.relations.push(relation(
                "loads",
                &entrypoint_id,
                &artifact_id,
                &[evidence_ref.clone()],
                json!({}),
                None,
                None,
            ));
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Workspace config",
            }));
        }
        if EXEC_MARKER.is_match(text) {
            let evidence_ref = stable_id("exec-evidence", &json!({ "file": file }));
            let sink = entity(
                "sink",
                &format!("process execution {file}"),
                json!({ "sinkKind": "process" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            out.entities.push(sink);
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Process execution sink",
            }));
        }
        if UPDATER_MARKER.is_match(text) {
            let evidence_ref = stable_id("updater-evidence", &json!({ "file": file }));
            let asset = entity(
                "repository-artifact",
                &format!("updater config {file}"),
                json!({ "assetKind": "updater" }),
                &[evidence_ref.clone()],
                None,
                None,
            );
            out.entities.push(asset);
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Updater config",
            }));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_is_skipped_entirely() {
        let out = extract_native_workspace(&[("src/.env.example".into(), String::new())]);
        assert!(out.entities.is_empty());
    }

    #[test]
    fn env_file_path_alone_produces_workspace_config_and_loads_relation() {
        let out = extract_native_workspace(&[(".env".into(), "SECRET=1".into())]);
        assert_eq!(out.entities.len(), 2);
        let entrypoint = out.entities.iter().find(|e| e["kind"] == "entrypoint").expect("entrypoint present");
        assert_eq!(entrypoint["attributes"]["entrypointType"], "workspace-open");
        let artifact = out
            .entities
            .iter()
            .find(|e| e["kind"] == "repository-artifact")
            .expect("artifact present");
        assert_eq!(artifact["attributes"]["trust"], "workspace-controlled");
        assert_eq!(out.relations.len(), 1);
        assert_eq!(out.relations[0]["kind"], "loads");
    }

    #[test]
    fn text_marker_alone_without_matching_file_path_also_triggers_workspace_config() {
        let out = extract_native_workspace(&[("src/setup.js".into(), "loadConfig('./settings.json')".into())]);
        assert!(out.entities.iter().any(|e| e["kind"] == "entrypoint"));
    }

    #[test]
    fn process_execution_sink_detected() {
        let out = extract_native_workspace(&[("src/runner.js".into(), "child_process.exec('ls')".into())]);
        let sink = out.entities.iter().find(|e| e["kind"] == "sink").expect("sink present");
        assert_eq!(sink["attributes"]["sinkKind"], "process");
    }

    #[test]
    fn updater_config_detected() {
        let out = extract_native_workspace(&[("src/updater.js".into(), "autoUpdater.checkForUpdates()".into())]);
        let asset = out
            .entities
            .iter()
            .find(|e| e["attributes"]["assetKind"] == "updater")
            .expect("updater asset present");
        assert_eq!(asset["kind"], "repository-artifact");
    }

    #[test]
    fn one_file_can_trigger_all_three_rules_independently() {
        let out = extract_native_workspace(&[(
            "plugin/updater.js".into(),
            "loadConfig(); child_process.spawn('x'); autoUpdater.on('x', () => {})".into(),
        )]);
        assert!(out.entities.iter().any(|e| e["kind"] == "entrypoint"));
        assert!(out.entities.iter().any(|e| e["kind"] == "sink"));
        assert!(out.entities.iter().any(|e| e["attributes"]["assetKind"] == "updater"));
    }

    #[test]
    fn irrelevant_file_produces_nothing() {
        let out = extract_native_workspace(&[("src/math.js".into(), "export const add = (a, b) => a + b;".into())]);
        assert!(out.entities.is_empty());
        assert!(out.relations.is_empty());
        assert!(out.evidence.is_empty());
    }
}
