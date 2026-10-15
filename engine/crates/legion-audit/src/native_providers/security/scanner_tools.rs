//! Producer half of named scanner adapters; all processes use parent's effect
//! route. Owned configs prevent repository configuration executing plugins,
//! changing reports, rewriting source or weakening independent scanner policy.
use std::time::Instant;

use super::*;
use crate::native_providers::security::{scanners, suppressions};

const MAX_RUNS: usize = 16;
const ARG_BYTES: usize = 32 * 1024;
const INPUT_BYTES: u64 = 2 * 1024 * 1024;

fn checked_text(root: &Path, relative: &str) -> Result<String, String> {
    let relative = scanners::safe_relative(relative).ok_or("path-outside-root")?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|_| "input-unreadable")?;
    if !metadata.is_file() || metadata.len() > INPUT_BYTES {
        return Err("input-not-regular-or-oversize".into());
    }
    let real = fs::canonicalize(&path).map_err(|_| "input-unreadable")?;
    let root = fs::canonicalize(root).map_err(|_| "root-unreadable")?;
    if !real.starts_with(root) {
        return Err("path-outside-root".into());
    }
    fs::read_to_string(real).map_err(|_| "input-not-text".into())
}

fn module_root(root: &Path, path: &str, marker: &str) -> Option<String> {
    let mut directory = Path::new(path).parent()?;
    loop {
        let relative = directory.join(marker).to_string_lossy().replace('\\', "/");
        if checked_text(root, &relative).is_ok() {
            return Some(directory.to_string_lossy().replace('\\', "/"));
        }
        directory = directory.parent()?;
    }
}

fn kube_input(text: &str) -> Result<bool, &'static str> {
    if text.contains("{{") || text.contains("{%") {
        return Err("kubernetes-template-unrendered");
    }
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return Ok(value.get("apiVersion").is_some() && value.get("kind").is_some());
    }
    let api = text.lines().any(|line| line.starts_with("apiVersion:"));
    let kind = text.lines().any(|line| line.starts_with("kind:"));
    if api != kind {
        return Err("kubernetes-object-identity-incomplete");
    }
    Ok(api && kind)
}

fn glob_literal(path: &str) -> String {
    path.chars()
        .map(|c| {
            if matches!(c, '[' | ']' | '*' | '?') {
                format!("[{c}]")
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Pinned local schemas are content-bound, not trusted because a caller supplied
/// a well-shaped digest. Links, excessive trees & remote templates are refused.
fn schema_location(config: &Value) -> Result<(String, String, String), &'static str> {
    let directory = config
        .get("directory")
        .and_then(Value::as_str)
        .ok_or("scanner-schema-directory-missing")?;
    let expected = config
        .get("digest")
        .and_then(Value::as_str)
        .ok_or("scanner-schema-digest-missing")?;
    let template = config
        .get("template")
        .and_then(Value::as_str)
        .ok_or("scanner-schema-template-missing")?;
    let version = config
        .get("kubernetesVersion")
        .and_then(Value::as_str)
        .ok_or("scanner-schema-version-missing")?;
    if !Path::new(directory).is_absolute()
        || scanners::safe_relative(template).is_none()
        || template.contains("://")
        || !version.chars().all(|c| c.is_ascii_digit() || c == '.')
        || version.split('.').count() != 3
    {
        return Err("scanner-local-schema-location-invalid");
    }
    let root = fs::canonicalize(directory).map_err(|_| "offline-database-missing:kubeconform")?;
    if !root.is_dir() {
        return Err("offline-database-missing:kubeconform");
    }
    let mut entries = Vec::new();
    let mut total = 0u64;
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry.map_err(|_| "scanner-schema-unreadable")?;
        if entry.file_type().is_symlink() {
            return Err("scanner-schema-symlink-refused");
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let metadata = entry.metadata().map_err(|_| "scanner-schema-unreadable")?;
        total = total.saturating_add(metadata.len());
        if total > 32 * 1024 * 1024 || entries.len() >= 4096 {
            return Err("scanner-schema-size-cap");
        }
        let bytes = fs::read(entry.path()).map_err(|_| "scanner-schema-unreadable")?;
        entries.push((
            entry
                .path()
                .strip_prefix(&root)
                .map_err(|_| "scanner-schema-path-invalid")?
                .to_string_lossy()
                .replace('\\', "/"),
            digest(&bytes),
        ));
    }
    entries.sort();
    let actual = digest_json(&json!(entries));
    if entries.is_empty() || actual != expected {
        return Err("scanner-schema-digest-mismatch");
    }
    Ok((
        root.join(template).to_string_lossy().into_owned(),
        version.to_owned(),
        actual,
    ))
}

impl<'a> Run<'a> {
    pub(super) fn named_scanner(&self) -> Production {
        let Some(tool) = scanners::tool_for(&self.provider.id) else {
            return unavailable("scanner-unsupported");
        };
        let Some(selector) = self.provider.configuration.get("selector") else {
            return unavailable("scanner-frozen-selector-missing");
        };
        let Ok(denominator) = self.inventory.denominator_entries(selector) else {
            return unavailable("scanner-frozen-selector-invalid");
        };
        let files: Vec<String> = denominator.entries.iter().map(|e| e.path.clone()).collect();
        let mut gaps = Vec::new();
        let mut examined = BTreeSet::new();
        let mut selected = Vec::new();
        let mut source_digests = BTreeMap::new();
        let mut selection_ledger = Vec::new();
        let source_sides = match crate::inventory::snapshot_source_sides(self.root()) {
            Ok(sides) => sides,
            Err(_) => return unavailable("scanner-frozen-source-sides-invalid"),
        };
        for entry in &denominator.entries {
            if source_sides
                .get(&entry.path)
                .is_some_and(|side| side == "base")
            {
                examined.insert(entry.path.clone());
                selection_ledger.push(json!({"path":entry.path,"sourceSide":"base","disposition":"not-applicable","reason":"deleted-source-has-no-selected-tool-input"}));
                continue;
            }
            let text = match checked_text(self.root(), &entry.path) {
                Ok(text) => text,
                Err(reason) => {
                    gaps.push(json!({"kind":"scanner-input-unreadable","path":entry.path,"reason":reason}));
                    continue;
                }
            };
            let actual = digest(text.as_bytes());
            if entry
                .digest
                .as_ref()
                .is_some_and(|expected| expected != &actual)
            {
                gaps.push(
                    json!({"kind":"scanner-input-changed-since-inventory","path":entry.path}),
                );
                continue;
            }
            source_digests.insert(entry.path.clone(), actual);
            if matches!(tool, "kubeconform" | "kube-linter") {
                match kube_input(&text) {
                    Ok(false) => {
                        examined.insert(entry.path.clone());
                        selection_ledger.push(json!({"path":entry.path,"disposition":"not-applicable","reason":"no-kubernetes-object-identity"}));
                        continue;
                    }
                    Err(reason) => {
                        gaps.push(json!({"kind":reason,"path":entry.path}));
                        continue;
                    }
                    Ok(true) => {}
                }
            }
            selected.push(entry.path.clone());
        }
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for file in &selected {
            let group = match tool {
                "tflint" => Path::new(file)
                    .parent()
                    .map(|p| p.to_string_lossy().replace('\\', "/")),
                "golangci-lint" => module_root(self.root(), file, "go.mod"),
                "brakeman" => {
                    module_root(self.root(), file, "config/application.rb").filter(|app| {
                        let manifest = if app.is_empty() {
                            "Gemfile".to_owned()
                        } else {
                            format!("{app}/Gemfile")
                        };
                        checked_text(self.root(), &manifest).is_ok_and(|text| {
                            text.lines().any(|line| {
                                let text = line.trim_start();
                                text.starts_with("gem ")
                                    && (text.contains("\"rails\"") || text.contains("'rails'"))
                            })
                        })
                    })
                }
                _ => Some(String::new()),
            };
            match group {
                Some(group) => groups.entry(group).or_default().push(file.clone()),
                None => {
                    gaps.push(
                        json!({"kind":"scanner-project-root-unproven","tool":tool,"path":file}),
                    );
                }
            }
        }
        let config = self.scratch.path.join(format!("{tool}-owned-config"));
        let plugin_dir = self.scratch.path.join("empty-plugins");
        if fs::create_dir_all(&plugin_dir).is_err() {
            return unavailable("scanner-scratch-unavailable");
        }
        let body = match tool {
            "squawk" => String::new(),
            "brakeman" => "--- {}\n".into(),
            "tflint" => format!("config {{\n call_module_type = \"none\"\n plugin_dir = {}\n}}\nplugin \"terraform\" {{\n enabled = true\n preset = \"recommended\"\n}}\nrule \"terraform_map_duplicate_keys\" {{ enabled = false }}\n", serde_json::to_string(&plugin_dir.to_string_lossy()).unwrap_or_default()),
            "kube-linter" => "checks:\n  doNotAutoAddDefaults: true\n  include:\n    - privileged-container\n    - privilege-escalation-container\n    - host-network\n    - host-pid\n    - host-ipc\n    - sensitive-host-mounts\n    - wildcard-in-rules\n    - cluster-admin-role-binding\n    - writable-host-mount\n    - unsafe-proc-mount\n    - run-as-non-root\n    - no-read-only-root-fs\n".into(),
            _ => String::new(),
        };
        if fs::write(&config, body.as_bytes()).is_err() {
            return unavailable("scanner-config-unwritable");
        }
        let config = config.to_string_lossy().into_owned();
        let started = Instant::now();
        let mut candidates = Vec::new();
        let mut ledger = Vec::new();
        let mut receipts = Vec::new();
        let mut last_receipt = None;
        let mut output_bytes = 0usize;
        for (index, (base, paths)) in groups.into_iter().enumerate() {
            if index >= MAX_RUNS {
                gaps.push(json!({"kind":"scanner-run-cap","tool":tool,"paths":paths}));
                continue;
            }
            let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let Some(left) = self
                .producer
                .timeout_ms
                .checked_sub(elapsed)
                .filter(|left| *left > 0)
            else {
                gaps.push(json!({"kind":"scanner-deadline-exhausted","tool":tool,"paths":paths}));
                continue;
            };
            let cwd = self.root().join(&base);
            let file_args: Vec<String> = paths.iter().map(|path| format!("./{path}")).collect();
            let config_args = ["--config".to_owned(), config.clone()];
            let mut args: Vec<String> = match tool {
                "squawk" => ["--reporter", "json", "-c", &config, "--"]
                    .into_iter()
                    .map(str::to_owned)
                    .chain(file_args.iter().map(|p| glob_literal(p)))
                    .collect(),
                "zizmor" => [
                    "--offline",
                    "--no-config",
                    "--no-progress",
                    "--no-exit-codes",
                    "--color",
                    "never",
                    "--format",
                    "json-v1",
                    "--",
                ]
                .into_iter()
                .map(str::to_owned)
                .chain(file_args.clone())
                .collect(),
                "shellcheck" => ["--norc", "-f", "json", "--severity=style", "--"]
                    .into_iter()
                    .map(str::to_owned)
                    .chain(file_args.clone())
                    .collect(),
                "tflint" => config_args
                    .into_iter()
                    .chain(
                        [
                            "--format",
                            "json",
                            "--no-color",
                            "--call-module-type",
                            "none",
                            "--force",
                        ]
                        .into_iter()
                        .map(str::to_owned),
                    )
                    .collect(),
                "kube-linter" => ["lint", "--config", &config, "--format", "json", "--"]
                    .into_iter()
                    .map(str::to_owned)
                    .chain(file_args.clone())
                    .collect(),
                "brakeman" => [
                    "-c",
                    &config,
                    "-q",
                    "-f",
                    "json",
                    "--no-progress",
                    "--no-exit-on-warn",
                    "--no-exit-on-error",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                "golangci-lint" => [
                    "run",
                    "--no-config",
                    "--modules-download-mode=readonly",
                    "--path-mode=abs",
                    "--output.json.path=stdout",
                    "--show-stats=false",
                    "--enable=gosec",
                    "./...",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                "kubeconform" => {
                    // A host-pinned local schema tree is mandatory; never use
                    // kubeconform's remote default or ignore missing schemas.
                    let Some(schemas) = self.provider.configuration.get("scannerSchemas") else {
                        gaps.push(
                            json!({"kind":"offline-database-missing:kubeconform","paths":paths}),
                        );
                        continue;
                    };
                    let (location, version, schema_digest) = match schema_location(schemas) {
                        Ok(location) => location,
                        Err(reason) => {
                            gaps.push(json!({"kind":reason,"paths":paths}));
                            continue;
                        }
                    };
                    selection_ledger.push(json!({"kind":"offline-schema-identity","digest":schema_digest,"kubernetesVersion":version}));
                    [
                        "-output",
                        "json",
                        "-strict",
                        "-summary",
                        "-verbose",
                        "-kubernetes-version",
                        &version,
                        "-schema-location",
                        &location,
                        "--",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .chain(file_args.clone())
                    .collect()
                }
                _ => unreachable!(),
            };
            // Direct file-scoped tools run from root; module scanners run in
            // their proven module directory. Positional paths never become flags.
            let module_scanner = matches!(tool, "tflint" | "brakeman" | "golangci-lint");
            if args.iter().map(String::len).sum::<usize>() > ARG_BYTES {
                gaps.push(json!({"kind":"scanner-argument-cap","tool":tool,"paths":paths}));
                continue;
            }
            let mut env = vec![
                ("HOME", self.scratch.path.to_string_lossy().into_owned()),
                (
                    "USERPROFILE",
                    self.scratch.path.to_string_lossy().into_owned(),
                ),
                ("GOTOOLCHAIN", "local".into()),
                ("GOPROXY", "off".into()),
                ("GOSUMDB", "off".into()),
                ("GOWORK", "off".into()),
                ("CGO_ENABLED", "0".into()),
                (
                    "GOCACHE",
                    self.scratch
                        .path
                        .join("go-build")
                        .to_string_lossy()
                        .into_owned(),
                ),
                (
                    "GOLANGCI_LINT_CACHE",
                    self.scratch
                        .path
                        .join("golangci-cache")
                        .to_string_lossy()
                        .into_owned(),
                ),
            ];
            if tool == "tflint" {
                env.push(("PATH", String::new()));
            }
            let accepted: &[i32] = if matches!(
                tool,
                "squawk" | "shellcheck" | "kube-linter" | "kubeconform" | "golangci-lint"
            ) {
                &[0, 1]
            } else {
                &[0]
            };
            let run = match self.run_tool_at(
                &[tool],
                std::mem::take(&mut args),
                accepted,
                &env,
                if module_scanner { &cwd } else { self.root() },
                left,
            ) {
                Ok(run) => run,
                Err(reason) => {
                    gaps.push(json!({"kind":"scanner-run-unavailable","tool":tool,"reason":reason,"paths":paths}));
                    continue;
                }
            };
            output_bytes = output_bytes.saturating_add(run.stdout.len());
            if output_bytes > self.producer.output_limit {
                gaps.push(json!({"kind":"scanner-total-output-cap","tool":tool,"paths":paths}));
                break;
            }
            let output: Value = match serde_json::from_slice(&run.stdout) {
                Ok(output) => output,
                Err(_) => {
                    gaps.push(json!({"kind":"scanner-output-invalid","tool":tool,"stdoutDigest":digest(&run.stdout),"paths":paths}));
                    continue;
                }
            };
            let report = scanners::normalize(
                tool,
                &output,
                self.root(),
                if module_scanner { &base } else { "" },
            );
            if run.receipt["exitCode"] == 1 && report.candidates.is_empty() {
                gaps.push(json!({"kind":"scanner-nonzero-without-candidates","tool":tool,"stdoutDigest":digest(&run.stdout)}));
            }
            let schema_valid = !report
                .gaps
                .iter()
                .any(|gap| gap["kind"] == "scanner-output-schema-invalid");
            let run_receipt = self.execution_receipt(&run);
            receipts.push(json!({"base":base,"paths":paths,"receipt":run_receipt,"ownedConfigDigest":digest(body.as_bytes())}));
            last_receipt = Some(run_receipt);
            if schema_valid {
                for path in &paths {
                    if tool == "kubeconform"
                        && !report
                            .ledger
                            .iter()
                            .any(|row| row["path"].as_str() == Some(path.as_str()))
                    {
                        gaps.push(
                            json!({"kind":"scanner-target-unreported","tool":tool,"path":path}),
                        );
                    } else {
                        examined.insert(path.clone());
                    }
                }
            }
            candidates.extend(report.candidates);
            gaps.extend(report.gaps);
            ledger.extend(report.ledger);
        }
        // Bind reads & scans to source identity even if files changed while a
        // scanner ran. Changed files retain candidates & lose completion.
        for (path, expected) in &source_digests {
            if checked_text(self.root(), path)
                .map(|text| digest(text.as_bytes()))
                .ok()
                .as_ref()
                != Some(expected)
            {
                examined.remove(path);
                gaps.push(json!({"kind":"scanner-input-changed-during-execution","path":path}));
            }
        }
        let evidence = json!({"binding":self.binding(),"tool":tool,"selectedPaths":files,"applicablePaths":selected,"examinedPaths":examined,"sourceDigests":source_digests,"executionReceipt":last_receipt,"runs":receipts,"candidates":candidates,"gaps":gaps,"lossLedger":ledger,"selectionLedger":selection_ledger});
        let mode = if !receipts.is_empty() {
            "tool"
        } else if selected.is_empty() {
            "native-selection"
        } else {
            "unavailable"
        };
        let mut input = self.input(
            &files,
            json!({"scannerEvidence":evidence}),
            json!({"mode":mode,"offline":true,"tool":tool,"runs":receipts}),
        );
        if let Some(receipt) = last_receipt {
            input["executionReceipt"] = receipt;
        }
        Production::Artifact(input)
    }

    pub(super) fn suppression_changes(&self) -> Production {
        let Some(selector) = self.provider.configuration.get("selector") else {
            return unavailable("suppression-selector-missing");
        };
        let Ok(denominator) = self.inventory.denominator_entries(selector) else {
            return unavailable("suppression-selector-invalid");
        };
        let paths: Vec<_> = denominator
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        let snapshot_changes;
        let mut deleted_paths = BTreeSet::new();
        let changes = if let Some(manifest) = &self.producer.snapshot_manifest {
            let snapshot = match crate::snapshot::FrozenSnapshot::open(manifest) {
                Ok(snapshot) => snapshot,
                Err(_) => return unavailable("suppression-frozen-snapshot-invalid"),
            };
            if fs::canonicalize(&snapshot.manifest.execution_root).ok()
                != fs::canonicalize(self.root()).ok()
            {
                return unavailable("suppression-frozen-snapshot-root-mismatch");
            }
            if !snapshot.manifest.scope.spec.is_diff() {
                return unavailable("suppression-baseline-missing");
            }
            let mut changes = Vec::new();
            let mut unchanged = Vec::new();
            let mut snapshot_gaps = Vec::new();
            for path in &paths {
                if snapshot.manifest.scope.changed_paths.contains(path) {
                    let change = match snapshot.changed_source(path, 2 * 1024 * 1024) {
                        Ok(change) => change,
                        Err(_) => {
                            snapshot_gaps.push(
                                json!({"kind":"suppression-snapshot-read-failed","path":path}),
                            );
                            continue;
                        }
                    };
                    let deleted = change.after.is_none() && change.before.is_some();
                    if deleted {
                        deleted_paths.insert(path.clone());
                    }
                    let before = match String::from_utf8(change.before.unwrap_or_default()) {
                        Ok(text) => text,
                        Err(_) => {
                            snapshot_gaps
                                .push(json!({"kind":"suppression-baseline-not-text","path":path}));
                            continue;
                        }
                    };
                    let after = match String::from_utf8(change.after.unwrap_or_default()) {
                        Ok(text) => text,
                        Err(_) => {
                            snapshot_gaps
                                .push(json!({"kind":"suppression-selected-not-text","path":path}));
                            continue;
                        }
                    };
                    changes.push(json!({"path":path,"before":before,"after":after,"sourceSide":if deleted{"base"}else{"selected"}}));
                } else {
                    unchanged.push(path.clone());
                }
            }
            snapshot_changes = json!({"binding":self.binding(),"files":changes,"unchangedPaths":unchanged,"snapshotKey":snapshot.manifest.key,"gaps":snapshot_gaps});
            &snapshot_changes
        } else if let Some(changes) = self.provider.configuration.get("suppressionChanges") {
            changes
        } else {
            return unavailable("suppression-baseline-missing");
        };
        if let Some(files) = changes.get("files").and_then(Value::as_array) {
            for file in files {
                let Some(path) = file.get("path").and_then(Value::as_str) else {
                    return unavailable("suppression-diff-path-invalid");
                };
                let Some(after) = file.get("after").and_then(Value::as_str) else {
                    return unavailable("suppression-diff-content-missing");
                };
                // Scope owner supplies base-side deleted denominator entries.
                // Empty caller text alone never proves a deletion.
                if deleted_paths.contains(path) {
                    let Some(before) = file.get("before").and_then(Value::as_str) else {
                        return unavailable("suppression-deleted-baseline-missing");
                    };
                    if denominator
                        .entries
                        .iter()
                        .find(|e| e.path == path)
                        .and_then(|e| e.digest.as_ref())
                        .is_some_and(|expected| expected != &digest(before.as_bytes()))
                    {
                        return unavailable(format!("suppression-base-inventory-mismatch:{path}"));
                    }
                    continue;
                }
                if checked_text(self.root(), path).ok().as_deref() != Some(after) {
                    return unavailable(format!("suppression-after-snapshot-mismatch:{path}"));
                }
                if let Some(expected) = denominator
                    .entries
                    .iter()
                    .find(|e| e.path == path)
                    .and_then(|e| e.digest.as_ref())
                {
                    if &digest(after.as_bytes()) != expected {
                        return unavailable(format!("suppression-inventory-mismatch:{path}"));
                    }
                }
            }
        }
        // Host supplies immutable before/after records bound to this inventory.
        // No present-tense exclusion is inferred to be a change.
        let evidence = suppressions::changes(changes, &self.binding(), &paths);
        Production::Artifact(self.input(
            &paths,
            json!({"suppressionEvidence":evidence}),
            json!({"mode":"host-diff","offline":true}),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(id: &str, selector: Value) -> AuditProvider {
        serde_json::from_value(json!({"id":id,"version":"1.0.0","role":"candidate-generator","phase":"source","dependencies":[],"kind":"rust-algorithm","configuration":{"selector":selector},"cleanClaim":"evidence-only","benchmarkStatus":"unproven","benchmarkRequiredForCleanClaim":false,"qualificationDigest":null,"required":true})).unwrap()
    }

    fn inventory(path: &str, text: &str) -> InventoryEnvelope {
        InventoryEnvelope::new(
            "test-repository",
            "test-revision",
            vec![InventoryEntry {
                path: path.into(),
                symbols: vec![],
                dependencies: vec![],
                package_scripts: vec![],
                source_file: true,
                digest: Some(digest(text.as_bytes())),
            }],
        )
        .unwrap()
    }
    #[test]
    fn kubernetes_selection_distinguishes_non_objects_and_templates() {
        assert_eq!(kube_input("name: ordinary\n"), Ok(false));
        assert_eq!(kube_input("apiVersion: v1\nkind: Pod\n"), Ok(true));
        assert!(kube_input("apiVersion: v1\nkind: {{ .Values.kind }}\n").is_err());
    }
    #[test]
    fn sql_path_globs_are_literal() {
        assert_eq!(
            glob_literal("./migrations/[1]*?.sql"),
            "./migrations/[[]1[]][*][?].sql"
        );
    }

    #[test]
    fn absent_tool_yields_typed_gap_without_clean_result() {
        let temp = Scratch::create(None).unwrap();
        let root = temp.path.join("repo");
        fs::create_dir_all(&root).unwrap();
        let text = "ALTER TABLE users DROP COLUMN name;\n";
        fs::write(root.join("m.sql"), text).unwrap();
        let producer = ArtifactProducer::new(&root).with_search_path(vec![]);
        let provider = provider("security.scanner-squawk", scanners::selector("squawk"));
        let Production::Artifact(input) = producer.produce(&provider, &inventory("m.sql", text))
        else {
            panic!("expected retained unavailable evidence")
        };
        assert!(input["artifacts"]["scannerEvidence"]["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["reason"] == "tool-missing:squawk"));
        assert_eq!(scanners::analyze(&input)["complete"], false);
    }

    #[test]
    fn secret_fixture_is_retained_and_secret_value_redacted() {
        let temp = Scratch::create(None).unwrap();
        let root = temp.path.join("repo");
        fs::create_dir_all(root.join("fixtures")).unwrap();
        let token = format!("ghp_{}", "A".repeat(36));
        let text = format!("token = '{token}'\n");
        fs::write(root.join("fixtures/token.env"), &text).unwrap();
        let provider = provider("secrets.current-history", json!({"op":"always"}));
        let Production::Artifact(input) = ArtifactProducer::new(&root)
            .with_search_path(vec![])
            .produce(&provider, &inventory("fixtures/token.env", &text))
        else {
            panic!("native fallback expected")
        };
        let findings = input["artifacts"]["secretEvidence"]["findings"]
            .as_array()
            .unwrap();
        assert!(findings
            .iter()
            .any(|finding| finding["File"] == "fixtures/token.env"
                && finding["RuleID"] == "github.token"));
        assert!(!serde_json::to_string(&input).unwrap().contains(&token));
    }
}
