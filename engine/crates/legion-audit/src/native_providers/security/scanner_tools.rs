//! Producer half of named scanner adapters; all processes use parent's effect
//! route. Owned configs prevent repository configuration executing plugins,
//! changing reports, rewriting source or weakening independent scanner policy.
use std::time::Instant;

use serde::Deserialize;

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

/// File anchors settle generator location only. They carry no invented line
/// & do not satisfy downstream adjudication's source-delivery requirements.
fn bind_kube_file_anchors(
    report: &mut scanners::Normalized,
    tool: &str,
    root: &Path,
    paths: &[String],
    frozen_digests: &BTreeMap<String, Option<String>>,
    source_digests: &BTreeMap<String, String>,
) {
    if !matches!(tool, "kube-linter" | "kubeconform") {
        return;
    }
    for candidate in &mut report.candidates {
        if candidate["anchorKind"] != "file" {
            continue;
        }
        let raw_digest = candidate["source"]["rawFindingDigest"].clone();
        let bound = (|| -> Result<String, &'static str> {
            let path = candidate["path"]
                .as_str()
                .ok_or("file-anchor-path-missing")?;
            if !paths.iter().any(|selected| selected == path) {
                return Err("file-anchor-outside-run");
            }
            let frozen = frozen_digests
                .get(path)
                .and_then(Option::as_deref)
                .filter(|digest| super::super::common::valid_digest(Some(&json!(digest))))
                .ok_or("file-anchor-frozen-digest-missing-or-invalid")?;
            if source_digests.get(path).map(String::as_str) != Some(frozen) {
                return Err("file-anchor-source-digest-mismatch");
            }
            let observed = checked_text(root, path).map_err(|_| "file-anchor-source-unreadable")?;
            if digest(observed.as_bytes()) != frozen {
                return Err("file-anchor-source-changed");
            }
            Ok(frozen.to_owned())
        })();
        match bound {
            Ok(source_digest) => {
                candidate["anchorStatus"] = json!("scanner-reported");
                candidate["source"]["sourceDigest"] = json!(source_digest);
                candidate["source"]["frozenSourceDigest"] = json!(source_digest);
                candidate["evidence"][0]["sourceDigest"] = json!(source_digest);
                report.gaps.retain(|gap| {
                    !(gap["kind"] == "scanner-candidate-anchor-unresolved"
                        && gap["tool"] == tool
                        && gap["rawFindingDigest"] == raw_digest)
                });
                for row in &mut report.ledger {
                    if row["candidateId"] == candidate["id"] {
                        row["disposition"] = json!("candidate");
                    }
                }
            }
            Err(reason) => {
                for gap in &mut report.gaps {
                    if gap["kind"] == "scanner-candidate-anchor-unresolved"
                        && gap["tool"] == tool
                        && gap["rawFindingDigest"] == raw_digest
                    {
                        gap["reason"] = json!(reason);
                    }
                }
            }
        }
    }
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

/// Parse every YAML/JSON document before excluding a selected path. Quoted,
/// flow & indented mappings are ordinary YAML; lexical key matching cannot
/// establish that a file lacks Kubernetes objects.
fn kube_input(text: &str) -> Result<bool, &'static str> {
    if text.contains("{{") || text.contains("{%") {
        return Err("kubernetes-template-unrendered");
    }
    fn nested_identity(value: &serde_yaml::Value) -> bool {
        match value {
            serde_yaml::Value::Mapping(mapping) => mapping.iter().any(|(key, value)| {
                matches!(key.as_str(), Some("apiVersion" | "kind" | "<<")) || nested_identity(value)
            }),
            serde_yaml::Value::Sequence(values) => values.iter().any(nested_identity),
            serde_yaml::Value::Tagged(_) => true,
            _ => false,
        }
    }
    let mut documents = 0usize;
    let mut applicable = false;
    for document in serde_yaml::Deserializer::from_str(text) {
        documents += 1;
        let value = serde_yaml::Value::deserialize(document)
            .map_err(|_| "kubernetes-document-parse-unknown")?;
        let serde_yaml::Value::Mapping(mapping) = value else {
            return Err("kubernetes-document-shape-unknown");
        };
        if mapping
            .keys()
            .any(|key| key.as_str().is_none() || key.as_str() == Some("<<"))
        {
            return Err("kubernetes-document-identity-ambiguous");
        }
        let api = mapping.get(&serde_yaml::Value::String("apiVersion".into()));
        let kind = mapping.get(&serde_yaml::Value::String("kind".into()));
        match (api, kind) {
            (Some(api), Some(kind))
                if api.as_str().is_some_and(|s| !s.trim().is_empty())
                    && kind.as_str().is_some_and(|s| !s.trim().is_empty()) =>
            {
                applicable = true
            }
            (None, None) => {
                if mapping.values().any(nested_identity) {
                    return Err("kubernetes-document-identity-ambiguous");
                }
            }
            _ => return Err("kubernetes-object-identity-incomplete"),
        }
    }
    if documents == 0 {
        return Err("kubernetes-document-shape-unknown");
    }
    Ok(applicable)
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
        let frozen_digests = denominator
            .entries
            .iter()
            .map(|entry| (entry.path.clone(), entry.digest.clone()))
            .collect::<BTreeMap<_, _>>();
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
                selection_ledger.push(json!({"path":entry.path,"sourceSide":"base","sourceDigest":entry.digest,"disposition":"not-applicable","reason":"deleted-source-has-no-selected-tool-input"}));
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
            source_digests.insert(entry.path.clone(), actual.clone());
            if matches!(tool, "kubeconform" | "kube-linter") {
                match kube_input(&text) {
                    Ok(false) => {
                        examined.insert(entry.path.clone());
                        selection_ledger.push(json!({"path":entry.path,"sourceSide":"selected","sourceDigest":actual,"classifier":"yaml-document-identity","disposition":"not-applicable","reason":"no-kubernetes-object-identity"}));
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
        // Native config loaders require supported file extensions.
        let config_name = if tool == "kube-linter" {
            "kube-linter-owned-config.yaml".to_owned()
        } else if tool == "tflint" {
            "tflint-owned-config.hcl".to_owned()
        } else {
            format!("{tool}-owned-config")
        };
        let config = self.scratch.path.join(config_name);
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
            let cwd = if base.is_empty() {
                self.root().to_path_buf()
            } else {
                self.root().join(&base)
            };
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
            if tool == "golangci-lint" {
                // Match exact scanner admission without inheriting host Git or
                // Python user configuration into the Go toolchain process tree.
                env.push(("GIT_CONFIG_NOSYSTEM", "1".into()));
                env.push(("PYTHONNOUSERSITE", "1".into()));
            }
            if tool == "tflint" {
                // The producer pins a fresh owned IPC TMPDIR after merging
                // these values. This empty PATH forbids plugin executables;
                // bundled Terraform rules communicate only in that namespace.
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
            // Preserve actual execution identity even if output parsing fails.
            let run_receipt = self.execution_receipt(&run);
            receipts.push(json!({"base":base,"paths":paths,"receipt":run_receipt,"ownedConfigDigest":digest(body.as_bytes())}));
            last_receipt = Some(run_receipt);
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
            let mut report = scanners::normalize(
                tool,
                &output,
                self.root(),
                if module_scanner { &base } else { "" },
            );
            bind_kube_file_anchors(
                &mut report,
                tool,
                self.root(),
                &paths,
                &frozen_digests,
                &source_digests,
            );
            if run.receipt["exitCode"] == 1 && report.candidates.is_empty() {
                gaps.push(json!({"kind":"scanner-nonzero-without-candidates","tool":tool,"stdoutDigest":digest(&run.stdout)}));
            }
            let schema_valid = !report
                .gaps
                .iter()
                .any(|gap| gap["kind"] == "scanner-output-schema-invalid");
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

    fn fixture_producer(root: &Path) -> ArtifactProducer {
        ArtifactProducer::new(root).with_policy_authorizer(Arc::new(legion_effects::StaticPolicy {
            decision: legion_effects::PolicyDecision {
                allowed: true,
                policy_id: "scanner-fixture".into(),
                policy_version: 1,
                policy_digest: format!("sha256:{}", "f".repeat(64)),
                reason: None,
            },
        }))
    }

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
    fn kube_file_anchor_requires_exact_scanned_frozen_source() {
        let temp = Scratch::create(None).unwrap();
        let root = temp.path.join("repo");
        fs::create_dir_all(&root).unwrap();
        let text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: example\n";
        fs::write(root.join("pod.yaml"), text).unwrap();
        let frozen = digest(text.as_bytes());
        for tool in ["kube-linter", "kubeconform"] {
            for change in [
                "valid",
                "outside-run",
                "missing-digest",
                "invalid-digest",
                "wrong-digest",
                "wrong-observed",
                "drift",
                "missing-source",
                "escape",
                "missing-path",
                "missing-message",
            ] {
                fs::write(root.join("pod.yaml"), text).unwrap();
                let mut raw = if tool == "kube-linter" {
                    json!({"Check":"privileged-container","Object":{"Metadata":{"FilePath":"pod.yaml"}},"Diagnostic":{"Message":"privileged"}})
                } else {
                    json!({"filename":"pod.yaml","status":"statusInvalid","msg":"schema mismatch"})
                };
                let path_pointer = if tool == "kube-linter" {
                    "/Object/Metadata/FilePath"
                } else {
                    "/filename"
                };
                if change == "escape" {
                    *raw.pointer_mut(path_pointer).unwrap() = json!("../pod.yaml");
                }
                if change == "missing-path" {
                    *raw.pointer_mut(path_pointer).unwrap() = Value::Null;
                }
                if change == "missing-message" {
                    *raw.pointer_mut(if tool == "kube-linter" {
                        "/Diagnostic/Message"
                    } else {
                        "/msg"
                    })
                    .unwrap() = Value::Null;
                }
                let output = if tool == "kube-linter" {
                    json!({"Reports":[raw]})
                } else {
                    json!({"resources":[raw]})
                };
                let mut report = scanners::normalize(tool, &output, &root, "");
                let original = report.candidates[0].clone();
                let paths = vec![if change == "outside-run" {
                    "other.yaml".into()
                } else {
                    "pod.yaml".into()
                }];
                let mut frozen_digests =
                    BTreeMap::from([("pod.yaml".into(), Some(frozen.clone()))]);
                let mut observed = BTreeMap::from([("pod.yaml".into(), frozen.clone())]);
                match change {
                    "missing-digest" => {
                        frozen_digests.insert("pod.yaml".into(), None);
                    }
                    "invalid-digest" => {
                        frozen_digests.insert("pod.yaml".into(), Some("not-a-digest".into()));
                    }
                    "wrong-digest" => {
                        frozen_digests
                            .insert("pod.yaml".into(), Some(digest(b"other frozen bytes")));
                    }
                    "wrong-observed" => {
                        observed.insert("pod.yaml".into(), digest(b"other observed bytes"));
                    }
                    "drift" => fs::write(root.join("pod.yaml"), "kind: Changed\n").unwrap(),
                    "missing-source" => fs::remove_file(root.join("pod.yaml")).unwrap(),
                    _ => {}
                }
                bind_kube_file_anchors(
                    &mut report,
                    tool,
                    &root,
                    &paths,
                    &frozen_digests,
                    &observed,
                );
                let candidate = &report.candidates[0];
                assert_eq!(candidate["id"], original["id"], "{tool}/{change}");
                assert_eq!(candidate["source"]["raw"], original["source"]["raw"]);
                assert_eq!(
                    candidate["source"]["rawFindingDigest"],
                    original["source"]["rawFindingDigest"]
                );
                assert!(candidate["line"].is_null());
                assert!(candidate["evidence"][0]["line"].is_null());
                assert_eq!(candidate["adjudication"], "required");
                assert_eq!(report.ledger.len(), 1);
                if change == "valid" {
                    assert_eq!(candidate["anchorKind"], "file");
                    assert_eq!(candidate["anchorStatus"], "scanner-reported");
                    assert_eq!(candidate["source"]["sourceDigest"], frozen);
                    assert_eq!(candidate["source"]["frozenSourceDigest"], frozen);
                    assert_eq!(report.ledger[0]["disposition"], "candidate");
                    assert!(report.gaps.is_empty(), "{tool}: {:?}", report.gaps);
                } else {
                    assert_eq!(candidate["anchorStatus"], "unresolved", "{tool}/{change}");
                    assert!(candidate["source"].get("sourceDigest").is_none());
                    assert_eq!(report.ledger[0]["disposition"], "retained-unresolved");
                    assert!(
                        report
                            .gaps
                            .iter()
                            .any(|gap| gap["kind"] == "scanner-candidate-anchor-unresolved"),
                        "{tool}/{change}"
                    );
                }
            }
        }
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
        let producer = fixture_producer(&root).with_search_path(vec![]);
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
        let Production::Artifact(input) = fixture_producer(&root)
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
    #[test]
    fn selected_non_kubernetes_files_are_natively_classified_without_deselecting_provider() {
        let temp = Scratch::create(None).unwrap();
        let root = temp.path.join("repo");
        fs::create_dir_all(&root).unwrap();
        let text = r#"{"name":"ordinary-package"}"#;
        fs::write(root.join("package.json"), text).unwrap();
        for tool in ["kube-linter", "kubeconform"] {
            let provider = provider(
                &format!("security.scanner-{tool}"),
                scanners::selector(tool),
            );
            let Production::Artifact(input) = fixture_producer(&root)
                .with_search_path(vec![])
                .produce(&provider, &inventory("package.json", text))
            else {
                panic!("native classification evidence required")
            };
            let analysis = scanners::analyze(&input);
            assert_eq!(analysis["applicable"], true, "{tool}");
            assert_eq!(analysis["complete"], true, "{tool}");
            assert_eq!(analysis["status"], "classified", "{tool}");
            assert_eq!(analysis["executionMode"], "native-classification");
            assert_eq!(analysis["denominator"]["expected"], 1);
            assert_eq!(analysis["denominator"]["examined"], 1);
            assert_eq!(
                analysis["selectionLedger"][0]["disposition"],
                "not-applicable"
            );
            assert_eq!(
                analysis["selectionLedger"][0]["sourceDigest"],
                digest(text.as_bytes())
            );
            assert!(input["artifacts"]["scannerEvidence"]["runs"]
                .as_array()
                .unwrap()
                .is_empty());
            assert!(input.get("executionReceipt").is_none());
            let mut unproven = input.clone();
            unproven["artifacts"]["scannerEvidence"]["selectionLedger"] = json!([]);
            assert_eq!(scanners::analyze(&unproven)["complete"], false);
        }
    }

    #[test]
    fn mixed_kubernetes_inputs_keep_frozen_denominator_and_require_external_evidence() {
        let temp = Scratch::create(None).unwrap();
        let root = temp.path.join("repo");
        fs::create_dir_all(&root).unwrap();
        let sources = [
            ("package.json", r#"{"name":"ordinary-package"}"#),
            (
                "pod.yaml",
                "apiVersion: v1\nkind: Pod\nmetadata:\n  name: fixture\n",
            ),
        ];
        for (path, text) in sources {
            fs::write(root.join(path), text).unwrap();
        }
        let inventory = InventoryEnvelope::new(
            "test-repository",
            "test-revision",
            sources
                .iter()
                .map(|(path, text)| InventoryEntry {
                    path: (*path).into(),
                    symbols: vec![],
                    dependencies: vec![],
                    package_scripts: vec![],
                    source_file: true,
                    digest: Some(digest(text.as_bytes())),
                })
                .collect(),
        )
        .unwrap();
        for tool in ["kube-linter", "kubeconform"] {
            let provider = provider(
                &format!("security.scanner-{tool}"),
                scanners::selector(tool),
            );
            let Production::Artifact(input) = fixture_producer(&root)
                .with_search_path(vec![])
                .produce(&provider, &inventory)
            else {
                panic!("partial classification evidence required")
            };
            let analysis = scanners::analyze(&input);
            assert_eq!(analysis["applicable"], true, "{tool}");
            assert_eq!(analysis["complete"], false, "{tool}");
            assert_eq!(analysis["classificationOnly"], false);
            assert_eq!(analysis["denominator"]["expected"], 2);
            assert_eq!(analysis["denominator"]["examined"], 1);
            assert_eq!(
                input["artifacts"]["scannerEvidence"]["applicablePaths"],
                json!(["pod.yaml"])
            );
            assert!(analysis["coverageGaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gap| gap["kind"] == "scanner-input-unexamined" && gap["path"] == "pod.yaml"));
            assert!(input["artifacts"]["scannerEvidence"]["runs"]
                .as_array()
                .unwrap()
                .is_empty());
            if tool == "kube-linter" {
                assert!(analysis["coverageGaps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|gap| gap["reason"] == "tool-missing:kube-linter"));
            } else {
                assert!(analysis["coverageGaps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|gap| gap["kind"] == "offline-database-missing:kubeconform"));
            }
        }
    }
    #[test]
    fn yaml_identity_parser_covers_quoted_flow_indented_and_multiple_documents() {
        let positives = [
            "\"apiVersion\": v1\n\"kind\": Pod\nmetadata:\n  name: fixture\n",
            "  apiVersion: v1\n  kind: Pod\n  metadata: {name: fixture}\n",
            "{apiVersion: v1, kind: Pod, metadata: {name: fixture}}\n",
            "name: ordinary\n---\napiVersion: v1\nkind: Pod\n",
            "apiVersion: v1\nkind: Pod\n---\nname: ordinary\n",
            "---\napiVersion: v1\nkind: Pod\n---\napiVersion: apps/v1\nkind: Deployment\n",
        ];
        for text in positives {
            assert_eq!(kube_input(text), Ok(true), "{text}");
        }
        for text in [
            "name: ordinary\n",
            "{name: ordinary, metadata: {name: fixture}}\n",
            "name: ordinary\n---\nname: another\n",
            r#"{"name":"ordinary-package"}"#,
        ] {
            assert_eq!(kube_input(text), Ok(false), "{text}");
        }
        for text in [
            "apiVersion: v1\nkind: Pod\n---\n[invalid\n",
            "name: ordinary\n---\n[invalid\n",
            "apiVersion: v1\nkind: Pod\n---\nkind: Pod\n",
            "apiVersion: v1\nkind: null\n",
            "apiVersion: v1\nkind: Pod\nkind: Deployment\n",
            "items: [{apiVersion: v1, kind: Pod}]\n",
            "- apiVersion: v1\n  kind: Pod\n",
            "apiVersion v1\nkind Pod\n",
            "<<: {apiVersion: v1, kind: Pod}\n",
        ] {
            assert!(kube_input(text).is_err(), "{text}");
        }
    }

    #[test]
    fn quoted_or_unknown_yaml_never_completes_native_classification_without_scanner() {
        let temp = Scratch::create(None).unwrap();
        let root = temp.path.join("repo");
        fs::create_dir_all(&root).unwrap();
        for text in [
            "\"apiVersion\": v1\n\"kind\": Pod\nmetadata:\n  name: fixture\n",
            "  apiVersion: v1\n  kind: Pod\n",
            "{apiVersion: v1, kind: Pod}\n",
            "name: ordinary\n---\napiVersion: v1\nkind: Pod\n",
            "apiVersion: v1\nkind: Pod\n---\n[invalid\n",
        ] {
            fs::write(root.join("pod.yaml"), text).unwrap();
            for tool in ["kube-linter", "kubeconform"] {
                let provider = provider(
                    &format!("security.scanner-{tool}"),
                    scanners::selector(tool),
                );
                let Production::Artifact(input) = fixture_producer(&root)
                    .with_search_path(vec![])
                    .produce(&provider, &inventory("pod.yaml", text))
                else {
                    panic!("selected evidence required")
                };
                let analysis = scanners::analyze(&input);
                assert_eq!(analysis["applicable"], true, "{tool}: {text}");
                assert_eq!(analysis["complete"], false, "{tool}: {text}");
                assert_eq!(analysis["classificationOnly"], false, "{tool}: {text}");
                assert_eq!(analysis["denominator"]["examined"], 0, "{tool}: {text}");
                assert!(!analysis["coverageGaps"].as_array().unwrap().is_empty());
                assert!(
                    !analysis["selectionLedger"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|row| row["disposition"] == "not-applicable"),
                    "{tool}: {text}"
                );
            }
        }
    }
}
