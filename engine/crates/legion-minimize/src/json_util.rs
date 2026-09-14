use crate::error::MinimizeError;
use serde_json::{Map, Value};
use std::path::Path;

pub fn read_json(path: &Path) -> Result<Value, MinimizeError> {
    let bytes = std::fs::read(path).map_err(|error| {
        MinimizeError::new(format!("cannot read {}: {}", path.display(), error))
    })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        MinimizeError::new(format!("cannot read {}: {}", path.display(), error))
    })?;
    if !value.is_object() {
        return Err(MinimizeError::new(format!(
            "cannot read {}: not an object",
            path.display()
        )));
    }
    Ok(value)
}

pub fn write_json(path: &Path, value: &Value) -> Result<(), MinimizeError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|error| {
                MinimizeError::new(format!("cannot write {}: {}", path.display(), error))
            })?;
        }
    }
    let sorted = sort_keys_deep(value);
    let rendered = serde_json::to_string_pretty(&sorted).map_err(|error| {
        MinimizeError::new(format!("cannot write {}: {}", path.display(), error))
    })?;
    std::fs::write(path, format!("{rendered}\n")).map_err(|error| {
        MinimizeError::new(format!("cannot write {}: {}", path.display(), error))
    })?;
    Ok(())
}

pub fn sort_keys_deep(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sort_keys_deep).collect()),
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                sorted.insert(key.clone(), sort_keys_deep(&map[key]));
            }
            Value::Object(sorted)
        }
        _ => value.clone(),
    }
}

pub fn sha256_file(path: &Path) -> Result<String, MinimizeError> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|error| {
        MinimizeError::new(format!("cannot hash {}: {}", path.display(), error))
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn file_exists(path: &Path) -> bool {
    path.is_file()
}
