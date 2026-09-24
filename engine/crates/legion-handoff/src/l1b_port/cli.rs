//! `run(argv)` CLI wrapper mirroring `skills/handoff/scripts/validate-handoff.py`'s
//! `argparse` surface: `<handoff> [--template-self-check] [--write-receipt PATH | --verify-receipt PATH]`.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::validate::{normalized_path, storage_errors, validate};

fn is_windows() -> bool {
    cfg!(windows)
}

/// Python: `main()`. Returns the process exit code; all output goes to
/// `out` (the Python script mixes `print()` to stdout and one `print(...,
/// file=sys.stderr)` for the missing-file case, reproduced here via `err`).
pub fn run(argv: &[String], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let mut handoff: Option<PathBuf> = None;
    let mut template_self_check = false;
    let mut write_receipt: Option<PathBuf> = None;
    let mut verify_receipt: Option<PathBuf> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--template-self-check" => template_self_check = true,
            "--write-receipt" => {
                if verify_receipt.is_some() {
                    let _ = writeln!(
                        err,
                        "FAIL: argument --write-receipt: not allowed with argument --verify-receipt"
                    );
                    return 2;
                }
                i += 1;
                write_receipt = argv.get(i).map(PathBuf::from);
            }
            "--verify-receipt" => {
                if write_receipt.is_some() {
                    let _ = writeln!(
                        err,
                        "FAIL: argument --verify-receipt: not allowed with argument --write-receipt"
                    );
                    return 2;
                }
                i += 1;
                verify_receipt = argv.get(i).map(PathBuf::from);
            }
            other if handoff.is_none() && !other.starts_with("--") => {
                handoff = Some(PathBuf::from(other));
            }
            other => {
                let _ = writeln!(err, "FAIL: unrecognized argument: {other}");
                return 2;
            }
        }
        i += 1;
    }
    let handoff = match handoff {
        Some(h) => h,
        None => {
            let _ = writeln!(err, "FAIL: the following arguments are required: handoff");
            return 2;
        }
    };

    if !handoff.is_file() {
        let _ = writeln!(err, "FAIL: handoff file not found: {}", handoff.display());
        return 2;
    }
    if !template_self_check && write_receipt.is_none() && verify_receipt.is_none() {
        let _ = writeln!(out, "FAIL: exactly one receipt mode is required");
        return 1;
    }

    let raw_bytes = match std::fs::read(&handoff) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(out, "FAIL: {e}");
            return 1;
        }
    };
    let text = match String::from_utf8(raw_bytes.clone()) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(out, "FAIL: handoff is not valid UTF-8: {e}");
            return 1;
        }
    };

    let mut errors = validate(&text, template_self_check);
    if !template_self_check {
        errors.extend(storage_errors(
            &text,
            &handoff,
            write_receipt.as_deref(),
            verify_receipt.as_deref(),
            is_windows(),
        ));
    }
    errors.sort();
    errors.dedup();
    if !errors.is_empty() {
        let _ = writeln!(out, "FAIL: {} handoff defect(s)", errors.len());
        for e in &errors {
            let _ = writeln!(out, "- {e}");
        }
        return 1;
    }

    let digest = hex::encode(Sha256::digest(&raw_bytes));
    if let Some(verify_receipt) = &verify_receipt {
        if !verify_receipt.is_file() {
            let _ = writeln!(out, "FAIL: receipt file not found: {}", verify_receipt.display());
            return 2;
        }
        let receipt_text = match std::fs::read_to_string(verify_receipt) {
            Ok(t) => t,
            Err(e) => {
                let _ = writeln!(out, "FAIL: invalid receipt: {e}");
                return 1;
            }
        };
        let receipt: serde_json::Value = match serde_json::from_str(&receipt_text) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(out, "FAIL: invalid receipt: {e}");
                return 1;
            }
        };
        let get_str = |k: &str| -> String {
            receipt
                .as_object()
                .and_then(|o| o.get(k))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        if get_str("sha256") != digest {
            let _ = writeln!(out, "FAIL: handoff bytes do not match receipt");
            return 1;
        }
        let handoff_name = handoff
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if get_str("artifact_name") != handoff_name {
            let _ = writeln!(out, "FAIL: handoff filename does not match receipt");
            return 1;
        }
        let resolved = resolve(&handoff);
        if normalized_path(&get_str("artifact_path"), is_windows())
            != normalized_path(&resolved.display().to_string(), is_windows())
        {
            let _ = writeln!(out, "FAIL: handoff path does not match receipt");
            return 1;
        }
        let _ = writeln!(out, "RECEIPT_PASS: sha256={digest}");
    }
    if let Some(write_receipt) = &write_receipt {
        let handoff_name = handoff
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let resolved = resolve(&handoff);
        let receipt = serde_json::json!({
            "schema_version": 1,
            "artifact_name": handoff_name,
            "artifact_path": resolved.display().to_string(),
            "sha256": digest,
            "validated_at": iso8601_now_utc(),
            "validator": "legion/lib/handoff/validate-handoff.py",
        });
        if let Some(parent) = write_receipt.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    let _ = writeln!(out, "FAIL: {e}");
                    return 1;
                }
            }
        }
        let body = format!("{}\n", serde_json::to_string_pretty(&receipt).unwrap());
        if let Err(e) = std::fs::write(write_receipt, body) {
            let _ = writeln!(out, "FAIL: {e}");
            return 1;
        }
    }
    let _ = writeln!(out, "PASS: handoff is cold-start complete (sha256={digest})");
    0
}

/// RFC3339 UTC timestamp with a `+00:00` offset, matching Python's
/// `datetime.now(timezone.utc).isoformat()`.
fn iso8601_now_utc() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let micros = now.subsec_micros();
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let (h, m, s) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{micros:06}+00:00"
    )
}

/// Days-since-epoch to (year, month, day), Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn resolve(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}
