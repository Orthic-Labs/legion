use serde_json::Value;
use std::path::Path;

pub fn load_control_packs(assets_root: &Path) -> Vec<Value> {
    let index_path = assets_root.join("registry/controls/packs/index.json");
    let bytes = match std::fs::read(index_path) {
        Ok(bytes) => bytes,
        Err(_) => return Vec::new(),
    };
    let index = match serde_json::from_slice::<Value>(&bytes) {
        Ok(index) => index,
        Err(_) => return Vec::new(),
    };
    if index.get("schemaVersion") != Some(&Value::from(1)) {
        return Vec::new();
    }
    let packs = index
        .get("packs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    packs
        .into_iter()
        .filter_map(|path| {
            let relative = path.as_str().unwrap_or_default();
            let pack_path = assets_root.join(relative);
            let bytes = std::fs::read(pack_path).ok()?;
            serde_json::from_slice(&bytes).ok()
        })
        .collect()
}
