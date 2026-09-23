//! Partial port of `src/lib/dispatch-validator/validate-tasklist.py`.
//!
//! The Python script is a thin CLI that shells out to `validate-dispatch.py
//! <packet> --packet-type <type> --<mode>-receipt <receipt>` and forwards
//! its stdout/stderr/exit code unchanged; the full `validate()` entry point
//! it delegates to is not ported (see `wf_port::w2_044`'s module doc). This
//! chunk ports the one observable contract both `validate-tasklist.py`'s
//! own smoke test (`test_validate_tasklist.py`) and its default
//! `--packet-type authority --receipt-mode write` path exercise, which is
//! fully inside the ported `authority_packet_errors` surface: run the
//! packet through `authority_packet_errors`, and on success write a
//! `<packet-stem>.receipt.json` sidecar recording the packet's digest.
//!
//! `--receipt-mode verify` and `--packet-type worker` are **not ported**:
//! they are handled entirely inside the unported `validate()` function.

use super::authority_packet::authority_packet_errors;
use super::digest::sha256_digest;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Result of [`validate_and_write_receipt`].
#[derive(Debug)]
pub enum TasklistResult {
    /// Port of the Python script's `return 0` path: packet is structurally
    /// valid and a receipt was written at `receipt_path`.
    Pass { receipt_path: PathBuf },
    /// Port of the Python script's `return 1` path: packet failed
    /// structural validation; no receipt is written.
    Fail { errors: Vec<String> },
}

/// Port of `validate-tasklist.py`'s default (`--packet-type authority
/// --receipt-mode write`) path.
///
/// `packet_path` must be readable JSON; on success a
/// `<stem>.receipt.json` file is written next to it (or under
/// `receipt_dir`, matching the Python script's `--receipt-dir` override)
/// containing `{"packet": <canonical path>, "sha256": <digest>}`.
pub fn validate_and_write_receipt(
    packet_path: &Path,
    receipt_dir: Option<&Path>,
) -> std::io::Result<TasklistResult> {
    let bytes = std::fs::read(packet_path)?;
    let packet: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return Ok(TasklistResult::Fail {
                errors: vec!["packet unreadable".to_string()],
            })
        }
    };
    let (errors, _) = authority_packet_errors(&packet, packet_path);
    if !errors.is_empty() {
        return Ok(TasklistResult::Fail { errors });
    }
    let dir = receipt_dir
        .map(Path::to_path_buf)
        .or_else(|| packet_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = packet_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let receipt_path = dir.join(format!("{stem}.receipt.json"));
    let receipt = serde_json::json!({
        "packet": packet_path.to_string_lossy(),
        "sha256": sha256_digest(&bytes),
    });
    std::fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt)?)?;
    Ok(TasklistResult::Pass { receipt_path })
}
