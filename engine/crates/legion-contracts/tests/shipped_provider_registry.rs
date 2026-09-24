//! The installed `legion audit` loads `src/registry/providers.json` into
//! `ProviderSpec` and refuses to run if any entry fails. 0.3.15 shipped 15
//! reasoning lens providers without the required execution fields, so every
//! audit exited 4 before scanning. Load the shipped registry exactly as the
//! production path does.

use legion_contracts::ProviderSpec;
use std::path::Path;

#[test]
fn every_shipped_provider_deserializes_and_validates() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/registry/providers.json");
    let bytes = std::fs::read(&path).expect("read shipped provider registry");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("registry is JSON");
    let providers = value["providers"].as_array().expect("registry has providers");
    assert!(!providers.is_empty());
    for provider in providers {
        let id = provider["id"].as_str().unwrap_or("<no id>");
        let spec: ProviderSpec = serde_json::from_value(provider.clone())
            .unwrap_or_else(|error| panic!("provider {id} does not deserialize: {error}"));
        spec.validate()
            .unwrap_or_else(|error| panic!("provider {id} does not validate: {error:?}"));
    }
}
