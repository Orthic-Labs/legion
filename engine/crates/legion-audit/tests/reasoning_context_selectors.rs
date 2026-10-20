use legion_audit::{FilesystemInventorySource, InventorySource};
use serde_json::Value;
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn temp_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "legion-reasoning-context-selectors-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn shipped_doc_and_schema_selectors_include_real_context_without_global_source_reclassification() {
    let root = temp_dir();
    for (path, text) in [
        ("lib.rs", "pub struct Request { pub count: u64 }"),
        ("README.md", "count is inclusive"),
        ("schema.json", r#"{"type":"string"}"#),
        ("image.svg", "<svg/>"),
    ] {
        std::fs::write(root.join(path), text).unwrap();
    }
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory("regression")
        .unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .find(|e| e.path == "README.md")
            .unwrap()
            .source_file
    );
    assert!(
        !inventory
            .entries
            .iter()
            .find(|e| e.path == "schema.json")
            .unwrap()
            .source_file
    );
    let registry: Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/registry/providers.json"),
        )
        .unwrap(),
    )
    .unwrap();
    for (id, context, excluded) in [
        ("reasoning.doc-drift", "README.md", "schema.json"),
        ("reasoning.schema", "schema.json", "README.md"),
    ] {
        let spec = registry["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .unwrap();
        let denominator = inventory.denominator_entries(&spec["selector"]).unwrap();
        let paths: Vec<_> = denominator
            .entries
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(paths.len(), 2, "{id}: {paths:?}");
        assert!(
            paths.contains(&"lib.rs") && paths.contains(&context),
            "{id}: {paths:?}"
        );
        assert!(!paths.contains(&excluded) && !paths.contains(&"image.svg"));
    }
    std::fs::remove_dir_all(root).unwrap();
}
