// Port of `scripts/native-cli/run-installed-parity.mjs`. Installed parity
// gate. The executable is intentionally not overrideable: only the
// installer-owned stable current path (`%LOCALAPPDATA%\Orthic
// Labs\Legion\current\bin\legion.exe`) can qualify installed behavior — so,
// like the Node script's implicit assumption, this only means anything on
// Windows.

use std::path::Path;

#[cfg(not(windows))]
pub fn run(_root: &Path) -> bool {
    eprintln!(
        "legion-dev: native-cli-parity-installed: installed-parity qualifies the Windows installer-owned \
         current `legion.exe`; this gate only runs on Windows."
    );
    false
}

#[cfg(windows)]
pub fn run(root: &Path) -> bool {
    match run_inner(root) {
        Ok(ok) => ok,
        Err(err) => {
            eprintln!("legion-dev: native-cli-parity-installed: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn run_inner(root: &Path) -> Result<bool, String> {
    use crate::native_cli_gate as gate;
    use serde_json::{json, Value};
    use std::fs;

    let fixture_index = root.join("tests/native-cli-characterization/fixtures.json");
    let node_baselines_path = root.join("tests/native-cli-characterization/node-baselines.br.json");
    let out_dir = root.join("dist/native-cli/installed-parity");

    let baselines = gate::read_node_baselines(&node_baselines_path)?;
    let manifest = gate::load_manifest(&fixture_index)?;
    let source = gate::source_identity(root)?;
    let local_app_data = std::env::var("LOCALAPPDATA").ok();
    let stable = gate::installed_executable_path(local_app_data.as_deref())?;
    let installed_plugin_root = fs::canonicalize(stable.current_root.join("plugin")).unwrap_or_else(|_| stable.current_root.join("plugin"));
    let evidence_path = gate::resolve_evidence_path(std::env::var("LEGION_NATIVE_BUILD_EVIDENCE").ok().as_deref(), root);
    let provenance = gate::validate_executable_provenance(
        &stable.executable,
        Some(evidence_path.as_path()),
        &manifest.manifest_sha256,
        &source,
        "installed",
        local_app_data.as_deref(),
    )?;

    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let mut results = Vec::new();
    for row in &manifest.rows {
        gate::validate_normalization(&row.fixture)?;
        let baseline = baselines.get(&row.id);
        let sandbox = gate::create_sandbox(root, &row.fixture)?;
        let before = gate::snapshot_sandbox_hashed(&sandbox);
        let (before, before_sha256) = match before {
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
        let mut observation = gate::run_bounded(&stable.executable, &argv, &sandbox.cwd, &sandbox.env, timeout_ms, max_output);
        let after = gate::snapshot_sandbox_hashed(&sandbox);
        gate::remove_sandbox(&sandbox);
        let (after, after_sha256) = after?;
        observation.filesystem = json!({
            "before": before,
            "after": after,
            "beforeSha256": before_sha256,
            "afterSha256": after_sha256,
        });
        observation.sandbox_roots = sandbox.temp_roots.clone();

        let baseline_id_digest = baseline.and_then(|b| {
            let id = b.get("id").and_then(Value::as_str)?;
            let digest = b.get("fixtureSha256").and_then(Value::as_str)?;
            Some((id.to_string(), digest.to_string()))
        });
        let mut temp_roots = vec![
            root.display().to_string(),
            stable.current_root.join("plugin").display().to_string(),
            installed_plugin_root.display().to_string(),
            format!("\\\\?\\{}", installed_plugin_root.display()),
        ];
        temp_roots.extend(sandbox.temp_roots.clone());
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

        let mut installed_root_assertion = None;
        if row.id == "harness-install-codex" {
            let skills_root = installed_plugin_root.join("skills");
            let problems = gate::validate_installed_skill_links(&observation.filesystem, &skills_root, root);
            installed_root_assertion = Some(json!({
                "requiredRoot": skills_root.display().to_string(),
                "forbiddenRoot": root.display().to_string(),
                "problems": problems.clone(),
            }));
            if !problems.is_empty() {
                row_result.status = "mismatched";
                row_result.mismatch.extend(problems);
            }
        }

        let record = json!({
            "schemaVersion": 2,
            "kind": "legion-installed-parity-row",
            "id": row.id,
            "fixtureSha256": row.fixture_sha256,
            "manifestSha256": manifest.manifest_sha256,
            "source": { "sourceRevision": source.source_revision, "sourceTreeSha256": source.source_tree_sha256 },
            "executable": stable.executable.display().to_string(),
            "executableSha256": provenance.executable_sha256,
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
            "installedRootAssertion": installed_root_assertion,
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
    let qualifying = summarized.get("qualifying").and_then(Value::as_bool).unwrap_or(false);

    let summary = json!({
        "schemaVersion": 2,
        "kind": "legion-installed-parity",
        "evidenceRole": "installed-current-qualifying-parity",
        "qualifying": qualifying,
        "manifest": { "sha256": manifest.manifest_sha256, "rowCount": manifest.row_count, "rowIds": manifest.row_ids },
        "source": { "sourceRevision": source.source_revision, "sourceTreeSha256": source.source_tree_sha256 },
        "executable": stable.executable.display().to_string(),
        "provenance": {
            "path": provenance.path.display().to_string(),
            "executable": provenance.executable.display().to_string(),
            "executableSha256": provenance.executable_sha256,
            "mode": provenance.mode,
        },
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
    Ok(qualifying)
}
