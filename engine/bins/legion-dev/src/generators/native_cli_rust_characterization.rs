// Port of `scripts/native-cli/run-rust-characterization.mjs`. Native
// characterization gate. By default this is a current-tree gate and
// requires build evidence binding the exact executable, source tree, and
// frozen manifest. `--diagnostic` deliberately produces non-qualifying
// output.

use crate::native_cli_gate as gate;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

fn semantic_oracle(fixture: &Value, observation: &gate::Observation) -> Vec<String> {
    let empty = json!({});
    let expect = fixture.get("rustExpect").unwrap_or(&empty);
    let mut mismatches = Vec::new();
    if let Some(exit) = expect.get("exitCode").and_then(Value::as_i64) {
        if observation.exit_code.map(|c| c as i64) != Some(exit) {
            mismatches.push(format!(
                "expected native exit {exit}, got {}",
                observation.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "null".into())
            ));
        }
    }
    for needle in expect.get("stdoutIncludes").and_then(Value::as_array).into_iter().flatten() {
        if let Some(n) = needle.as_str() {
            if !observation.stdout.contains(n) {
                mismatches.push(format!("native stdout missing: {n}"));
            }
        }
    }
    for needle in expect.get("stderrIncludes").and_then(Value::as_array).into_iter().flatten() {
        if let Some(n) = needle.as_str() {
            if !observation.stderr.contains(n) {
                mismatches.push(format!("native stderr missing: {n}"));
            }
        }
    }
    if let Some(kind) = expect.get("kind").and_then(Value::as_str) {
        match serde_json::from_str::<Value>(&observation.stdout) {
            Ok(parsed) => {
                if parsed.get("kind").and_then(Value::as_str) != Some(kind) {
                    mismatches.push(format!("expected native kind {kind}"));
                }
            }
            Err(_) => mismatches.push("native stdout is not JSON".to_string()),
        }
    }
    mismatches
}

pub fn run(root: &Path, diagnostic: bool) -> bool {
    match run_inner(root, diagnostic) {
        Ok(ok) => ok,
        Err(err) => {
            eprintln!("legion-dev: native-cli-capture-rust: {err}");
            false
        }
    }
}

fn run_inner(root: &Path, diagnostic: bool) -> Result<bool, String> {
    let fixture_index = root.join("tests/native-cli-characterization/fixtures.json");
    let node_baselines_path = root.join("tests/native-cli-characterization/node-baselines.br.json");
    let out_dir = root.join("dist/native-cli/rust-characterization");

    let baselines = gate::read_node_baselines(&node_baselines_path)?;

    let manifest = gate::load_manifest(&fixture_index)?;
    let source = gate::source_identity(root)?;
    let executable = gate::developer_executable_path(std::env::var("LEGION_EXE").ok().as_deref())?;

    let (provenance_executable, provenance_executable_sha256, provenance_value) = if diagnostic {
        let sha = gate::sha256_file(&executable)?;
        (
            executable.clone(),
            sha.clone(),
            json!({ "mode": "diagnostic-developer", "executable": executable.display().to_string(), "evidenceRole": "diagnostic-developer-capture" }),
        )
    } else {
        let evidence_path = gate::resolve_evidence_path(std::env::var("LEGION_NATIVE_BUILD_EVIDENCE").ok().as_deref(), root);
        let provenance = gate::validate_executable_provenance(
            &executable,
            Some(evidence_path.as_path()),
            &manifest.manifest_sha256,
            &source,
            "current-tree",
            None,
        )?;
        let executable_sha = provenance.executable_sha256.clone();
        let executable_path = provenance.executable.clone();
        (
            executable_path,
            executable_sha,
            json!({
                "path": provenance.path.display().to_string(),
                "executable": provenance.executable.display().to_string(),
                "executableSha256": provenance.executable_sha256,
                "mode": provenance.mode,
            }),
        )
    };

    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let mut results = Vec::new();
    for row in &manifest.rows {
        gate::validate_normalization(&row.fixture)?;
        let baseline = baselines.get(&row.id);
        let sandbox = gate::create_sandbox(root, &row.fixture)?;
        let before = gate::snapshot_sandbox(&sandbox);
        let before = match before {
            Ok(v) => v,
            Err(e) => {
                gate::remove_sandbox(&sandbox);
                return Err(e);
            }
        };
        let argv: Vec<String> = row
            .fixture
            .get("argv")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let timeout_ms = row.fixture.get("timeoutMs").and_then(Value::as_u64).unwrap_or(gate::DEFAULT_TIMEOUT_MS);
        let max_output = row.fixture.get("maxOutputBytes").and_then(Value::as_u64).unwrap_or(gate::DEFAULT_MAX_OUTPUT_BYTES as u64) as usize;
        let mut observation = gate::run_bounded(&provenance_executable, &argv, &sandbox.cwd, &sandbox.env, timeout_ms, max_output);
        let after = gate::snapshot_sandbox(&sandbox);
        gate::remove_sandbox(&sandbox);
        let after = after?;
        observation.filesystem = json!({ "before": before, "after": after });
        observation.sandbox_roots = sandbox.temp_roots.clone();

        let baseline_id_digest = baseline.and_then(|b| {
            let id = b.get("id").and_then(Value::as_str)?;
            let digest = b.get("fixtureSha256").and_then(Value::as_str)?;
            Some((id.to_string(), digest.to_string()))
        });
        let mut temp_roots = sandbox.temp_roots.clone();
        if let Some(b) = baseline {
            if let Some(roots) = b.get("sandboxRoots").and_then(Value::as_array) {
                temp_roots.extend(roots.iter().filter_map(|r| r.as_str().map(str::to_string)));
            }
        }
        let mut row_result = gate::evaluate_parity_row(
            &row.fixture,
            &observation,
            baseline,
            baseline_id_digest.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
            &row.fixture_sha256,
            &row.id,
            &temp_roots,
        );
        if row_result.status == "matched" || row_result.status == "mismatched" {
            row_result.mismatch.extend(semantic_oracle(&row.fixture, &observation));
            row_result.status = if row_result.mismatch.is_empty() { "matched" } else { "mismatched" };
        }

        let record = json!({
            "schemaVersion": 2,
            "kind": "legion-rust-characterization-row",
            "id": row.id,
            "fixtureSha256": row.fixture_sha256,
            "manifestSha256": manifest.manifest_sha256,
            "source": { "sourceRevision": source.source_revision, "sourceTreeSha256": source.source_tree_sha256 },
            "executable": provenance_executable.display().to_string(),
            "executableSha256": provenance_executable_sha256,
            "argv": argv,
            "cwd": row.fixture.get("cwd").cloned().unwrap_or(json!(".")),
            "sandboxRoots": sandbox.temp_roots,
            "exitCode": observation.exit_code,
            "stdoutSha256": gate::sha256(observation.stdout.as_bytes()),
            "stderrSha256": gate::sha256(observation.stderr.as_bytes()),
            "stdout": observation.stdout,
            "stderr": observation.stderr,
            "error": observation.error,
            "signal": observation.signal,
            "timedOut": observation.timed_out,
            "outputLimitExceeded": observation.output_limit_exceeded,
            "filesystem": observation.filesystem,
            "mismatch": row_result.mismatch,
            "status": row_result.status,
            "comparison": row_result.comparison,
        });
        fs::write(out_dir.join(format!("{}.json", row.id)), format!("{}\n", serde_json::to_string_pretty(&record).unwrap())).map_err(|e| e.to_string())?;
        results.push(gate::RowSummaryInput {
            id: row.id.clone(),
            status: row_result.status.to_string(),
            mismatch: row_result.mismatch.clone(),
            error: observation.error.clone(),
        });
    }

    let summarized = gate::summarize_results(&results, Some(&manifest.row_ids), Some(manifest.row_count));
    let mut qualifying = summarized.get("qualifying").and_then(Value::as_bool).unwrap_or(false);
    qualifying = !diagnostic && qualifying;

    let summary = json!({
        "schemaVersion": 2,
        "kind": "legion-rust-characterization",
        "evidenceRole": if diagnostic { "diagnostic-developer-capture" } else { "current-tree-qualifying-parity" },
        "qualifying": qualifying,
        "manifest": { "sha256": manifest.manifest_sha256, "rowCount": manifest.row_count, "rowIds": manifest.row_ids },
        "source": { "sourceRevision": source.source_revision, "sourceTreeSha256": source.source_tree_sha256 },
        "executable": executable.display().to_string(),
        "provenance": provenance_value,
        "duplicateIds": summarized["duplicateIds"],
        "invalidIds": summarized["invalidIds"],
        "missingIds": summarized["missingIds"],
        "unexpectedIds": summarized["unexpectedIds"],
        "coverageValid": summarized["coverageValid"],
        "counts": summarized["counts"],
        "results": summarized["resultsNormalized"],
    });
    fs::write(out_dir.join("summary.json"), format!("{}\n", serde_json::to_string_pretty(&summary).unwrap())).map_err(|e| e.to_string())?;
    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    Ok(diagnostic || qualifying)
}
