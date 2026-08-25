//! LEG-I01 host detection and ownership-safe projection acceptance corpus.

use legion_host::{
    detect, project_mcp, DetectionRule, HostDescriptor, Mechanism, SurfaceDescriptor,
};
use serde_json::Value;
use std::collections::BTreeMap;

fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../migration/native-rust/fixtures/host-cases.v1.json"
    ))
    .expect("LEG-001 host fixtures remain valid JSON")
}

fn codex_descriptor() -> HostDescriptor {
    HostDescriptor {
        schema_version: 1,
        kind: "legion-host-descriptor".into(),
        id: "codex".into(),
        display_name: "Codex".into(),
        install_owner: "adapter".into(),
        detect: DetectionRule {
            any_of: vec![".codex/config.toml".into()],
            env: Vec::new(),
        },
        surfaces: BTreeMap::from([(
            String::from("mcp"),
            SurfaceDescriptor {
                fidelity: "strong".into(),
                mechanism: Mechanism {
                    kind: "json".into(),
                    path: None,
                    table: None,
                    key: Some("mcpServers".into()),
                },
                note: None,
            },
        )]),
    }
}

#[test]
fn host_detection_does_not_use_cross_harness_instruction_files() {
    let descriptor = codex_descriptor();
    let evidence = legion_host::HostEvidence::with_files(["AGENTS.md".into()]);
    assert!(!detect(&descriptor, &evidence).unwrap());
    assert_eq!(fixtures()["cases"].as_array().unwrap().len(), 4);
}

#[test]
fn mcp_projection_preserves_foreign_servers_and_records_ownership() {
    let descriptor = codex_descriptor();
    let existing = br#"{"mcpServers":{"mine":{"command":"mine"}}}"#;
    let item = project_mcp(
        &descriptor,
        ".codex/config.json",
        Some(existing),
        "legion-mcp",
        &["serve".into()],
        "fixture-generation",
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&item.bytes).unwrap();
    assert_eq!(value["mcpServers"]["mine"]["command"], "mine");
    assert_eq!(value["mcpServers"]["legion"]["command"], "legion-mcp");
    assert!(value["mcpServers"]["legion"]["_legionOwnership"].is_object());
}

#[test]
fn malformed_mcp_json_fails_closed() {
    let result = project_mcp(
        &codex_descriptor(),
        ".codex/config.json",
        Some(b"<<<<<<< HEAD"),
        "legion-mcp",
        &[],
        "fixture-generation",
    );
    assert!(result.is_err());
}
