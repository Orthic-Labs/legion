use legion_contracts::canonical_digest;
use serde_json::json;
use std::path::{Path, PathBuf};

pub fn state_root(workspace: &Path) -> PathBuf {
    workspace.join(".audit").join("arcane")
}

pub fn key_hex(domain: &str, values: &[String]) -> Result<String, legion_contracts::canonical::CanonicalError> {
    let digest = canonical_digest(&json!({ "domain": domain, "values": values }))?;
    Ok(digest
        .strip_prefix("sha256:")
        .unwrap_or(digest.as_str())
        .to_owned())
}

pub fn state_file(
    dir: &Path,
    domain: &str,
    values: &[String],
) -> Result<PathBuf, legion_contracts::canonical::CanonicalError> {
    Ok(dir.join(format!("{}.json", key_hex(domain, values)?)))
}
