//! Port of `research-core/query.py`: canonical query persistence and
//! wrapper-contract separation.

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Mirrors the dict returned by `query.persist(...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistResult {
    pub query_sha256: String,
    pub query_path: String,
}

/// Production entry point — writes `query.md` (and, if given,
/// `request-contract.md`) under `run_dir`, both with a trailing newline and
/// trailing-whitespace stripped from the input, matching
/// `text.rstrip() + '\n'`.
pub fn persist(run_dir: &Path, query: &str, wrapper_contract: Option<&str>) -> std::io::Result<PersistResult> {
    let text = format!("{}\n", query.trim_end());
    fs::create_dir_all(run_dir)?;
    let query_path = run_dir.join("query.md");
    fs::write(&query_path, &text)?;
    if let Some(contract) = wrapper_contract {
        let contract_text = format!("{}\n", contract.trim_end());
        fs::write(run_dir.join("request-contract.md"), contract_text)?;
    }
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    Ok(PersistResult {
        query_sha256: hex::encode(hasher.finalize()),
        query_path: query_path.to_string_lossy().into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_writes_query_with_trailing_newline_and_matching_digest() {
        let dir = std::env::temp_dir().join(format!("legion-research-port-query-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let result = persist(&dir, "What is the price?   \n\n", None).unwrap();
        let content = fs::read_to_string(dir.join("query.md")).unwrap();
        assert_eq!(content, "What is the price?\n");
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        assert_eq!(result.query_sha256, hex::encode(hasher.finalize()));
        assert!(!dir.join("request-contract.md").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_writes_wrapper_contract_when_given() {
        let dir = std::env::temp_dir().join(format!("legion-research-port-query-contract-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        persist(&dir, "query text", Some("contract text  ")).unwrap();
        let contract = fs::read_to_string(dir.join("request-contract.md")).unwrap();
        assert_eq!(contract, "contract text\n");
        let _ = fs::remove_dir_all(&dir);
    }
}
