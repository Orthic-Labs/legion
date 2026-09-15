use crate::assets::resolve_legion_root;
use crate::descriptor::{
    adapter_by_id, adapter_ids, builtin_adapters, capabilities_value, resolve_descriptor,
    HarnessDescriptor,
};
use crate::engine::{detect, install, uninstall, verify};
use crate::error::HarnessError;
use serde_json::{json, Value};
use std::path::Path;

pub struct HarnessRegistry {
    adapters: Vec<HarnessDescriptor>,
}

impl HarnessRegistry {
    pub fn load() -> Result<Self, HarnessError> {
        Ok(Self {
            adapters: builtin_adapters()?,
        })
    }

    pub fn adapter_ids(&self) -> Vec<String> {
        adapter_ids(&self.adapters)
    }

    pub fn detect_harnesses(&self, root: &Path) -> Vec<String> {
        self.adapters
            .iter()
            .filter(|adapter| adapter.id != "generic" && detect(adapter, root))
            .map(|adapter| adapter.id.clone())
            .collect()
    }

    pub fn fidelity_matrix(&self, root: &Path) -> Result<Vec<Value>, HarnessError> {
        let legion_root = resolve_legion_root()?;
        let _ = legion_root;
        Ok(self
            .adapters
            .iter()
            .map(|adapter| {
                let descriptor = if adapter.id == "generic" {
                    resolve_descriptor(&self.adapters, &adapter.id, root)?
                } else {
                    adapter.clone()
                };
                capabilities_value(&descriptor)
            })
            .collect::<Result<Vec<_>, HarnessError>>()?)
    }

    pub fn capabilities(&self, id: &str, root: &Path) -> Result<Value, HarnessError> {
        let descriptor = resolve_descriptor(&self.adapters, id, root)?;
        capabilities_value(&descriptor)
    }

    pub fn install(&self, id: &str, root: &Path) -> Result<Value, HarnessError> {
        adapter_by_id(&self.adapters, id)?;
        let descriptor = resolve_descriptor(&self.adapters, id, root)?;
        let legion_root = resolve_legion_root()?;
        install(&descriptor, root, &legion_root, None)
    }

    pub fn verify(&self, id: &str, root: &Path) -> Result<Value, HarnessError> {
        adapter_by_id(&self.adapters, id)?;
        let descriptor = resolve_descriptor(&self.adapters, id, root)?;
        let legion_root = resolve_legion_root()?;
        verify(&descriptor, root, &legion_root)
    }

    pub fn uninstall(&self, id: &str, root: &Path) -> Result<Value, HarnessError> {
        adapter_by_id(&self.adapters, id)?;
        let descriptor = resolve_descriptor(&self.adapters, id, root)?;
        let legion_root = resolve_legion_root()?;
        uninstall(&descriptor, root, &legion_root)
    }
}

pub fn list_value(registry: &HarnessRegistry) -> Value {
    json!({
        "kind": "legion-harness-list",
        "adapters": registry.adapter_ids(),
    })
}

pub fn detect_value(registry: &HarnessRegistry, root: &Path) -> Value {
    json!({
        "kind": "legion-harness-detect",
        "detected": registry.detect_harnesses(root),
    })
}

pub fn matrix_value(registry: &HarnessRegistry, root: &Path) -> Result<Value, HarnessError> {
    Ok(json!({
        "kind": "legion-harness-matrix",
        "harnesses": registry.fidelity_matrix(root)?,
    }))
}

pub fn capabilities_response(registry: &HarnessRegistry, id: &str, root: &Path) -> Result<Value, HarnessError> {
    let value = registry.capabilities(id, root)?;
    Ok(json!({
        "kind": "legion-harness-capabilities",
        "id": value.get("id").cloned().unwrap_or(Value::Null),
        "displayName": value.get("displayName").cloned().unwrap_or(Value::Null),
        "installOwner": value.get("installOwner").cloned().unwrap_or(Value::Null),
        "surfaces": value.get("surfaces").cloned().unwrap_or(Value::Null),
    }))
}

pub fn install_response(registry: &HarnessRegistry, id: &str, root: &Path) -> Result<Value, HarnessError> {
    let value = registry.install(id, root)?;
    let mut response = serde_json::Map::new();
    response.insert("kind".into(), json!("legion-harness-install"));
    response.insert("id".into(), value.get("id").cloned().unwrap_or(Value::Null));
    response.insert("installOwner".into(), value.get("installOwner").cloned().unwrap_or(Value::Null));
    response.insert("wrote".into(), value.get("wrote").cloned().unwrap_or(Value::Null));
    if let Some(skipped) = value.get("skipped") {
        response.insert("skipped".into(), skipped.clone());
    }
    response.insert("surfaces".into(), value.get("surfaces").cloned().unwrap_or(Value::Null));
    Ok(Value::Object(response))
}

pub fn verify_response(registry: &HarnessRegistry, id: &str, root: &Path) -> Result<(Value, bool), HarnessError> {
    let value = registry.verify(id, root)?;
    let ok = value.get("ok").and_then(Value::as_bool) == Some(true);
    Ok((
        json!({
            "kind": "legion-harness-verify",
            "id": value.get("id").cloned().unwrap_or(Value::Null),
            "installOwner": value.get("installOwner").cloned().unwrap_or(Value::Null),
            "ok": ok,
            "problems": value.get("problems").cloned().unwrap_or(Value::Null),
            "surfaces": value.get("surfaces").cloned().unwrap_or(Value::Null),
        }),
        ok,
    ))
}

pub fn uninstall_response(registry: &HarnessRegistry, id: &str, root: &Path) -> Result<Value, HarnessError> {
    let value = registry.uninstall(id, root)?;
    Ok(json!({
        "kind": "legion-harness-uninstall",
        "id": value.get("id").cloned().unwrap_or(Value::Null),
        "removed": value.get("removed").cloned().unwrap_or(Value::Null),
        "kept": value.get("kept").cloned().unwrap_or(Value::Null),
    }))
}
