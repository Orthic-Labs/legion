//! `run(argv)` CLI wrapper mirroring `skills/handoff/scripts/validate-handoff.py`'s
//! `argparse` surface: `<handoff> [--template-self-check] [--write-receipt PATH | --verify-receipt PATH]`.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::validate::{
    normalized_path, physical_path_string, resolve_physical_existing, resolve_physical_receipt,
    storage_errors, validate,
};

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
                match argv.get(i) {
                    Some(v) => write_receipt = Some(PathBuf::from(v)),
                    None => {
                        let _ =
                            writeln!(err, "FAIL: argument --write-receipt: expected one argument");
                        return 2;
                    }
                }
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
                match argv.get(i) {
                    Some(v) => verify_receipt = Some(PathBuf::from(v)),
                    None => {
                        let _ = writeln!(
                            err,
                            "FAIL: argument --verify-receipt: expected one argument"
                        );
                        return 2;
                    }
                }
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

    // Template self-check skips storage and content-authority gates, so it must
    // never be combined with a receipt mode (it could mint or bless a normal
    // authoritative receipt). Rejected before any artifact I/O.
    if template_self_check && (write_receipt.is_some() || verify_receipt.is_some()) {
        let _ = writeln!(
            err,
            "FAIL: invalid combination: --template-self-check cannot be used with --write-receipt or --verify-receipt"
        );
        return 2;
    }

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
        // Physical identity only; resolution failure is fatal (no lexical
        // fallback). Point-in-time: not a TOCTOU/confinement guarantee.
        let (physical_handoff, physical_receipt) = match physical_identity(&handoff, verify_receipt)
        {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(out, "FAIL: {e}");
                return 1;
            }
        };
        if !physical_receipt.is_file() {
            let _ = writeln!(
                out,
                "FAIL: receipt file not found: {}",
                verify_receipt.display()
            );
            return 2;
        }
        let receipt_text = match std::fs::read_to_string(&physical_receipt) {
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
        let handoff_name = physical_handoff
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if get_str("artifact_name") != handoff_name {
            let _ = writeln!(out, "FAIL: handoff filename does not match receipt");
            return 1;
        }
        if normalized_path(
            &physical_path_string_of(&get_str("artifact_path")),
            is_windows(),
        ) != normalized_path(&physical_path_string(&physical_handoff), is_windows())
        {
            let _ = writeln!(out, "FAIL: handoff path does not match receipt");
            return 1;
        }
        let _ = writeln!(out, "RECEIPT_PASS: sha256={digest}");
    }
    if let Some(write_receipt) = &write_receipt {
        // The receipt parent must already resolve physically (it is the
        // artifact's directory in the non-template path); no directories are
        // created and no lexical fallback is used on resolution failure.
        let (physical_handoff, physical_receipt) = match physical_identity(&handoff, write_receipt)
        {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(out, "FAIL: {e}");
                return 1;
            }
        };
        let handoff_name = physical_handoff
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let receipt = serde_json::json!({
            "schema_version": 1,
            "artifact_name": handoff_name,
            "artifact_path": physical_path_string(&physical_handoff),
            "sha256": digest,
            "validated_at": iso8601_now_utc(),
            "validator": "handoff/validate-handoff",
        });
        let body = format!("{}\n", serde_json::to_string_pretty(&receipt).unwrap());
        if let Err(e) = std::fs::write(&physical_receipt, body) {
            let _ = writeln!(out, "FAIL: {e}");
            return 1;
        }
    }
    let _ = writeln!(
        out,
        "PASS: handoff is cold-start complete (sha256={digest})"
    );
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
    let (h, m, s) = (
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    );
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{micros:06}+00:00")
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

/// Physical (canonical) identity of the handoff artifact and its receipt
/// sidecar: existing artifact canonicalized; receipt canonicalized if present,
/// else canonical parent + basename. Any resolution failure is an error; there
/// is no lexical fallback for authority decisions.
fn physical_identity(handoff: &Path, receipt: &Path) -> Result<(PathBuf, PathBuf), String> {
    let physical_handoff = resolve_physical_existing(handoff)?;
    let physical_receipt = resolve_physical_receipt(receipt)?;
    Ok((physical_handoff, physical_receipt))
}

/// Verbatim-prefix stripping for a path string read from a receipt, so receipts
/// written with `\\?\C:\...` still compare equal to the physical spelling.
fn physical_path_string_of(value: &str) -> String {
    super::validate::strip_verbatim_prefix(value)
}

#[cfg(test)]
mod tests {
    use super::super::validate::test_support::{link_dir, write_file, TestRoot};
    use super::*;

    #[test]
    fn physical_identity_resolves_existing_artifact_and_new_adjacent_receipt() {
        let root = TestRoot::new("cli-normal");
        let artifact = root.join("handoffs/h.md");
        write_file(&artifact, "body");
        let receipt = root.join("handoffs/h.receipt.json");
        let (a, r) = physical_identity(&artifact, &receipt).unwrap();
        assert_eq!(physical_path_string(&a), physical_path_string(&artifact));
        assert_eq!(physical_path_string(&r), physical_path_string(&receipt));
        assert_eq!(a.parent(), r.parent());
    }

    #[test]
    fn physical_identity_follows_symlink_to_forbidden_target() {
        let root = TestRoot::new("cli-link");
        write_file(&root.join("cache/real/h.md"), "body");
        link_dir(&root.join("stable"), &root.join("cache/real"));
        let (a, r) = physical_identity(
            &root.join("stable/h.md"),
            &root.join("stable/h.receipt.json"),
        )
        .unwrap();
        // The identity used for authority is the real location, not the
        // clean-looking link spelling.
        assert_eq!(
            physical_path_string(&a),
            physical_path_string(&root.join("cache/real/h.md"))
        );
        assert_eq!(
            physical_path_string(&r),
            physical_path_string(&root.join("cache/real/h.receipt.json"))
        );
    }

    #[test]
    fn physical_identity_fails_closed_on_missing_artifact_or_receipt_parent() {
        let root = TestRoot::new("cli-missing");
        let artifact = root.join("handoffs/h.md");
        write_file(&artifact, "body");

        let missing_artifact = root.join("handoffs/nope.md");
        let err = physical_identity(&missing_artifact, &root.join("handoffs/nope.receipt.json"))
            .unwrap_err();
        assert!(err.contains("cannot resolve existing path"), "{err}");

        let err =
            physical_identity(&artifact, &root.join("absent-dir/h.receipt.json")).unwrap_err();
        assert!(err.contains("cannot resolve receipt parent"), "{err}");
    }

    #[test]
    fn physical_path_string_of_strips_windows_verbatim_prefix_only() {
        assert_eq!(physical_path_string_of(r"\\?\C:\a\h.md"), r"C:\a\h.md");
        assert_eq!(physical_path_string_of("/a/h.md"), "/a/h.md");
    }

    #[test]
    fn run_rejects_missing_handoff_file_with_exit_2() {
        let root = TestRoot::new("cli-run-missing");
        let argv = vec![root.join("absent.md").to_string_lossy().into_owned()];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run(&argv, &mut out, &mut err), 2);
        assert!(String::from_utf8_lossy(&err).contains("handoff file not found"));
    }

    fn run_capture(argv: &[String]) -> (i32, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(argv, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn template_self_check_with_receipt_flag_is_rejected_before_artifact_io() {
        let root = TestRoot::new("cli-selfcheck-combo");
        let receipt = root.join("h.receipt.json");
        // Artifact intentionally absent: the combination error must win over
        // any file lookup, proving no artifact I/O happened first.
        let missing = root.join("absent.md").to_string_lossy().into_owned();
        for flag in ["--write-receipt", "--verify-receipt"] {
            let argv = vec![
                missing.clone(),
                "--template-self-check".to_string(),
                flag.to_string(),
                receipt.to_string_lossy().into_owned(),
            ];
            let (code, out, err) = run_capture(&argv);
            assert_eq!(code, 2, "{flag}");
            assert!(err.contains("invalid combination"), "{flag}: {err}");
            assert!(!err.contains("not found"), "{flag}: {err}");
            assert!(out.is_empty(), "{flag}: {out}");
            assert!(!receipt.exists(), "{flag}");
        }
    }

    #[test]
    fn template_self_check_combo_never_writes_receipt_for_existing_artifact() {
        let root = TestRoot::new("cli-selfcheck-existing");
        let artifact = root.join("handoffs/h.md");
        let receipt = root.join("handoffs/h.receipt.json");
        write_file(&artifact, "not a handoff");
        // Flag order must not matter.
        let argv = vec![
            "--write-receipt".to_string(),
            receipt.to_string_lossy().into_owned(),
            artifact.to_string_lossy().into_owned(),
            "--template-self-check".to_string(),
        ];
        let (code, _out, err) = run_capture(&argv);
        assert_eq!(code, 2);
        assert!(err.contains("invalid combination"), "{err}");
        assert!(!receipt.exists());
    }

    #[test]
    fn template_self_check_without_receipt_flags_still_runs_validation() {
        let root = TestRoot::new("cli-selfcheck-alone");
        let artifact = root.join("t.md");
        write_file(&artifact, "not a template");
        let argv = vec![
            artifact.to_string_lossy().into_owned(),
            "--template-self-check".to_string(),
        ];
        let (code, out, err) = run_capture(&argv);
        // Reaches validation (defects, exit 1), not the combination guard.
        assert_eq!(code, 1, "{out} {err}");
        assert!(out.contains("handoff defect(s)"), "{out}");
        assert!(!err.contains("invalid combination"), "{err}");
    }

    #[test]
    fn receipt_flag_without_value_is_rejected() {
        let argv = vec![
            "h.md".to_string(),
            "--template-self-check".to_string(),
            "--write-receipt".to_string(),
        ];
        let (code, _out, err) = run_capture(&argv);
        assert_eq!(code, 2);
        assert!(err.contains("expected one argument"), "{err}");
    }

    #[test]
    fn run_non_template_fails_closed_when_storage_is_physically_forbidden() {
        // Content is not a valid handoff, so validation also fails; the point
        // is that the storage defect for the physical cache location is
        // reported and no receipt is written through the clean-looking link.
        let root = TestRoot::new("cli-run-forbidden");
        write_file(&root.join("cache/real/h.md"), "not a handoff");
        link_dir(&root.join("stable"), &root.join("cache/real"));
        let artifact = root.join("stable/h.md");
        let receipt = root.join("stable/h.receipt.json");
        let argv = vec![
            artifact.to_string_lossy().into_owned(),
            "--write-receipt".to_string(),
            receipt.to_string_lossy().into_owned(),
        ];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run(&argv, &mut out, &mut err), 1);
        let stdout = String::from_utf8_lossy(&out);
        assert!(
            stdout.contains("canonical handoff cannot use temporary/cache/review-run storage"),
            "{stdout}"
        );
        assert!(
            stdout.contains("handoff receipt cannot use temporary/cache/review-run storage"),
            "{stdout}"
        );
        assert!(!root.join("cache/real/h.receipt.json").exists());
    }
}
