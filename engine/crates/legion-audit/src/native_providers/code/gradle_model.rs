//! Owner-contained Gradle model extraction for `code.android.lint` and typed
//! Kotlin detekt.
//!
//! The extractor runs the audited project's Gradle wrapper *only* when the
//! wrapper jar digest and the `distributionSha256Sum` in
//! `gradle-wrapper.properties` both match host-supplied pins. The wrapper
//! shell script is never executed (it is project code); the pinned JDK's
//! `java` launches the digest-checked wrapper jar directly, through a host
//! owner's contained process (project-executing class, network denied, scratch
//! writable only). Gradle always runs `--offline`; a dependency cache is read
//! only when the pins name one.
//!
//! A Legion-owned init script (`gradle_model.init.gradle`) is written to the
//! output root and emits the model JSON. The JSON is untrusted: provenance is
//! rejected if emitted, source-set digests are recomputed from the frozen
//! inventory, the model digest is bound to the owner receipt, and every
//! failure is an explicit gap, never a partial model.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use legion_effects::owner_process::InvocationClass;
use legion_provider_sdk::{ExecutionState, ExternalProjectTool, ExternalToolRequest};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::{
    android::{compute_source_set_digest, AndroidBuildModel, PROVIDER_ID},
    kotlin_detekt::{typed_evidence_from_model_value, TypedClasspathEvidence, TypedProvenance},
};
use crate::execution_policy::OWNER_POLICY_ID;
use crate::host_owner::OwnerRequestContext;
use crate::inventory::InventoryEntry;

pub const INIT_SCRIPT: &str = include_str!("gradle_model.init.gradle");
pub const INIT_SCRIPT_FILE: &str = "legion-android-model.init.gradle";
pub const MODEL_FILE: &str = "legion-android-model.json";
pub const WRAPPER_JAR: &str = "gradle/wrapper/gradle-wrapper.jar";
pub const WRAPPER_PROPERTIES: &str = "gradle/wrapper/gradle-wrapper.properties";
pub const WRAPPER_MAIN_CLASS: &str = "org.gradle.wrapper.GradleWrapperMain";
const MAX_MODEL_BYTES: u64 = 8 * 1024 * 1024;
const MODEL_TIMEOUT_MS: u64 = 15 * 60 * 1000;
const OUTPUT_LIMIT: usize = 1024 * 1024;

/// Host-supplied pins. None of these may come from the audited tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GradlePins {
    /// Canonical JDK `java` that is also a host-policy tool entry for
    /// `code.android.lint` with class `project-executing`.
    pub java: PathBuf,
    /// Accepted `gradle-wrapper.jar` digests (`sha256:<hex>` or bare hex).
    pub wrapper_jar_sha256: BTreeSet<String>,
    /// Accepted `distributionSha256Sum` values.
    pub distribution_sha256: BTreeSet<String>,
    /// Read-only dependency/distribution cache granted by policy, if any.
    pub dependency_cache_root: Option<PathBuf>,
}

/// A successfully extracted and owner-bound model.
#[derive(Clone, Debug)]
pub struct ExtractedAndroidModel {
    pub model: AndroidBuildModel,
    /// Typed detekt classpaths keyed `"<module path>:<variant>"`.
    pub typed: BTreeMap<String, TypedClasspathEvidence>,
    /// Typed classpaths that failed validation; never fatal for the model.
    pub typed_gaps: Vec<String>,
    /// Program and argv prefix a lint runner must use (task args follow).
    pub runner_program: String,
    pub runner_argv_prefix: Vec<String>,
}

impl ExtractedAndroidModel {
    /// Typed detekt input for the variant Lint covers.
    pub fn typed_classpath(&self, module: &str, variant: &str) -> Option<&TypedClasspathEvidence> {
        self.typed.get(&format!("{module}:{variant}"))
    }
}

fn gap(kind: impl AsRef<str>) -> String {
    format!("{PROVIDER_ID}:{}", kind.as_ref())
}

fn sha_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn normalize(value: &str) -> String {
    let lower = value.trim().to_ascii_lowercase();
    lower.strip_prefix("sha256:").unwrap_or(&lower).to_string()
}

fn pinned(set: &BTreeSet<String>, value: &str) -> bool {
    let value = normalize(value);
    !value.is_empty() && set.iter().any(|pin| normalize(pin) == value)
}

fn regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

fn distribution_sum(properties: &str) -> Option<String> {
    properties.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "distributionSha256Sum").then(|| value.trim().to_string())
    })
}

fn safe_rel(path: &str) -> bool {
    !path.starts_with('/')
        && !path.contains('\\')
        && !path.split('/').any(|part| part == "..")
        && !path.contains(':')
}

/// Run the pinned wrapper through the owner-backed `tool` and extract the
/// model. `plan_id` is the frozen plan digest the owner binds. `Err` carries
/// explicit gaps.
pub async fn extract_android_model(
    ctx: Option<&OwnerRequestContext>,
    tool: Option<&dyn ExternalProjectTool>,
    plan_id: &str,
    project_root: &Path,
    output_root: &Path,
    pins: Option<&GradlePins>,
    entries: &[InventoryEntry],
) -> Result<ExtractedAndroidModel, Vec<String>> {
    let (Some(ctx), Some(executor)) = (ctx, tool) else {
        return Err(vec![gap("gradle-owner-missing")]);
    };
    let Some(pins) = pins else {
        return Err(vec![gap("gradle-pins-missing")]);
    };
    let root = std::fs::canonicalize(project_root)
        .map_err(|error| vec![gap(format!("gradle-project-root-unreadable:{error}"))])?;
    // Wrapper pin check: jar digest and distributionSha256Sum must both match.
    let jar_path = root.join(WRAPPER_JAR);
    let props_path = root.join(WRAPPER_PROPERTIES);
    let unpinned = || vec![gap("gradle-wrapper-unpinned")];
    if !regular_file(&jar_path) || !regular_file(&props_path) {
        return Err(unpinned());
    }
    let jar_bytes = std::fs::read(&jar_path).map_err(|_| unpinned())?;
    if !pinned(&pins.wrapper_jar_sha256, &sha_hex(&jar_bytes)) {
        return Err(unpinned());
    }
    let props = std::fs::read_to_string(&props_path).map_err(|_| unpinned())?;
    match distribution_sum(&props) {
        Some(sum) if pinned(&pins.distribution_sha256, &sum) => {}
        _ => return Err(unpinned()),
    }
    // Host-policy pin for the JDK; never a digest taken from the file itself.
    let java = std::fs::canonicalize(&pins.java)
        .map_err(|_| vec![gap("gradle-java-not-in-host-policy")])?;
    let Some(pin) = ctx.pin_for(PROVIDER_ID, &java).cloned() else {
        return Err(vec![gap("gradle-java-not-in-host-policy")]);
    };
    if pin.class != InvocationClass::ProjectExecuting {
        return Err(vec![gap("gradle-owner-class-not-project-executing")]);
    }
    // Legion-owned script and scratch layout.
    std::fs::create_dir_all(output_root)
        .map_err(|error| vec![gap(format!("gradle-output-root-unwritable:{error}"))])?;
    let out = std::fs::canonicalize(output_root)
        .map_err(|error| vec![gap(format!("gradle-output-root-unwritable:{error}"))])?;
    let script = out.join(INIT_SCRIPT_FILE);
    let model_path = out.join(MODEL_FILE);
    let _ = std::fs::remove_file(&model_path);
    std::fs::write(&script, INIT_SCRIPT)
        .map_err(|error| vec![gap(format!("gradle-init-script-unwritable:{error}"))])?;
    // Gradle's own home is always writable scratch; the policy cache is only
    // ever a read-only dependency cache.
    let gradle_home = out.join("gradle-home");
    let home_dir = out.join("home");
    let tmp_dir = out.join("tmp");
    for dir in [&gradle_home, &home_dir, &tmp_dir] {
        std::fs::create_dir_all(dir)
            .map_err(|error| vec![gap(format!("gradle-output-root-unwritable:{error}"))])?;
    }
    let jar_arg = jar_path.to_string_lossy().into_owned();
    let home_arg = gradle_home.to_string_lossy().into_owned();
    let cache_arg = out.join("project-cache").to_string_lossy().into_owned();
    let prefix: Vec<String> = vec![
        "-classpath".into(),
        jar_arg,
        WRAPPER_MAIN_CLASS.into(),
        "--offline".into(),
        "--no-daemon".into(),
        "--console=plain".into(),
        "-g".into(),
        home_arg,
        "--project-cache-dir".into(),
        cache_arg,
    ];
    let mut args = prefix.clone();
    args.extend([
        "-I".to_string(),
        script.to_string_lossy().into_owned(),
        format!("-Dlegion.model.out={}", model_path.display()),
        "-q".into(),
        "help".into(),
    ]);
    let mut environment = BTreeMap::new();
    for name in &pin.environment_names {
        let value = match name.as_str() {
            "HOME" => Some(home_dir.to_string_lossy().into_owned()),
            "TMPDIR" => Some(tmp_dir.to_string_lossy().into_owned()),
            "GRADLE_RO_DEP_CACHE" => pins
                .dependency_cache_root
                .as_ref()
                .map(|root| root.to_string_lossy().into_owned()),
            _ => None,
        };
        if let Some(value) = value {
            environment.insert(name.clone(), value);
        }
    }
    let environment_allowlist = environment.keys().cloned().collect();
    // One plan binding for every owner request of this run.
    ctx.plan()
        .bind(plan_id)
        .map_err(|error| vec![gap(format!("gradle-owner-plan-binding-conflict:{error}"))])?;
    let request = ExternalToolRequest {
        request_id: format!("audit:{PROVIDER_ID}:{plan_id}:gradle-model"),
        provider_id: PROVIDER_ID.into(),
        plan_id: plan_id.into(),
        policy_id: OWNER_POLICY_ID.into(),
        task_id: Some("gradle-model".into()),
        executable: pin.executable.to_string_lossy().into_owned(),
        args,
        cwd: root.to_string_lossy().into_owned(),
        // The policy's digest, never one computed from the file about to run.
        expected_digest: Some(pin.digest.clone()),
        skip_version_probe: true,
        environment,
        environment_allowlist,
        requires_network_sandbox: true,
        sandbox: Some(ctx.sandbox_receipt()),
        timeout_ms: MODEL_TIMEOUT_MS,
        stdout_limit: OUTPUT_LIMIT,
        stderr_limit: OUTPUT_LIMIT,
        ..ExternalToolRequest::default()
    };
    let receipt = executor.execute(request, CancellationToken::new()).await;
    match receipt.state {
        ExecutionState::Completed => {}
        ExecutionState::Blocked
        | ExecutionState::UnauthorizedEffect
        | ExecutionState::SandboxMissing
        | ExecutionState::MissingExecutable
        | ExecutionState::UnsealedExecutable => {
            return Err(vec![gap(format!(
                "gradle-model-admission-denied:{}:{}",
                receipt.state.as_str(),
                receipt.gaps.join(";")
            ))]);
        }
        ExecutionState::Timeout
        | ExecutionState::Cancelled
        | ExecutionState::OutputLimited
        | ExecutionState::KillFailed => {
            return Err(vec![gap("gradle-model-execution-interrupted")]);
        }
        _ => return Err(vec![gap("gradle-model-execution-failed")]),
    }
    let reaped = receipt.process_tree.started
        && receipt.process_tree.terminated
        && receipt.process_tree.reaped;
    if !receipt.complete || !reaped {
        return Err(vec![gap("gradle-model-execution-interrupted")]);
    }
    if receipt.exit_code != Some(0) {
        return Err(vec![gap("gradle-model-execution-failed")]);
    }
    let meta = std::fs::symlink_metadata(&model_path)
        .map_err(|_| vec![gap("gradle-model-output-missing")])?;
    if !meta.file_type().is_file() || meta.len() > MAX_MODEL_BYTES {
        return Err(vec![gap("gradle-model-output-invalid")]);
    }
    let bytes = std::fs::read(&model_path).map_err(|_| vec![gap("gradle-model-output-missing")])?;
    let artifact_digest = sha_hex(&bytes);
    let receipt_id = receipt.receipt_id.clone();
    let java_program = java.to_string_lossy().into_owned();
    let mut extracted = parse_model(
        &bytes,
        &java_program,
        TypedProvenance::AdmittedBuild {
            receipt_id,
            artifact_digest,
        },
        entries,
    )?;
    extracted.runner_program = java_program;
    // The lint run must redirect build output exactly as the model run did, so
    // the reports sit where the model says; it never re-emits the model.
    let mut runner_prefix = prefix;
    runner_prefix.extend([
        "-I".to_string(),
        script.to_string_lossy().into_owned(),
        format!("-Dlegion.model.out={}", model_path.display()),
        "-Dlegion.model.emit=false".into(),
    ]);
    extracted.runner_argv_prefix = runner_prefix;
    Ok(extracted)
}

/// Validate untrusted model JSON and bind it to `provenance`. Pure; exposed
/// for the extractor and for tests of the malformed-model paths.
pub fn parse_model(
    bytes: &[u8],
    gradle_program: &str,
    provenance: TypedProvenance,
    entries: &[InventoryEntry],
) -> Result<ExtractedAndroidModel, Vec<String>> {
    let malformed = |detail: &str| vec![gap(format!("gradle-model-malformed:{detail}"))];
    let value: Value = serde_json::from_slice(bytes).map_err(|_| malformed("not-json"))?;
    let Some(top) = value.as_object() else {
        return Err(malformed("not-object"));
    };
    if top.keys().any(|k| k != "model" && k != "typedClasspath") {
        return Err(malformed("unknown-top-level-key"));
    }
    let mut model_value = top
        .get("model")
        .cloned()
        .ok_or_else(|| malformed("model-missing"))?;
    let Some(object) = model_value.as_object_mut() else {
        return Err(malformed("model-not-object"));
    };
    if object.contains_key("provenance") {
        return Err(vec![gap("gradle-model-self-attested")]);
    }
    object.insert(
        "provenance".into(),
        serde_json::to_value(&provenance).map_err(|_| malformed("provenance"))?,
    );
    object.insert("gradleProgram".into(), Value::String(gradle_program.into()));
    let mut model =
        AndroidBuildModel::from_value(&model_value).map_err(|error| malformed(&error))?;
    for module in &mut model.modules {
        if module.dir.starts_with('/') || module.dir.split('/').any(|p| p == "..") {
            return Err(vec![gap("gradle-model-path-escape")]);
        }
        for variant in &mut module.variants {
            if !safe_rel(&variant.report_xml_path) {
                return Err(vec![gap("gradle-model-path-escape")]);
            }
            if !variant.report_root.is_empty()
                && variant.report_root != super::android::REPORT_ROOT_OWNER_OUTPUT
            {
                return Err(malformed("report-root-unknown"));
            }
            for set in &mut variant.source_sets {
                if !safe_rel(&set.dir) {
                    return Err(vec![gap("gradle-model-path-escape")]);
                }
                // Legion recomputes; the script's value is never trusted.
                if let Some(actual) = compute_source_set_digest(entries, &set.dir) {
                    set.digest = actual;
                }
            }
        }
    }
    let mut typed = BTreeMap::new();
    let mut typed_gaps = Vec::new();
    if let Some(map) = top.get("typedClasspath") {
        let Some(map) = map.as_object() else {
            return Err(malformed("typed-not-object"));
        };
        for (key, entry) in map {
            match typed_evidence_from_model_value(entry, provenance.clone()) {
                Ok(evidence) => {
                    typed.insert(key.clone(), evidence);
                }
                Err(error) => typed_gaps.push(format!(
                    "code.kotlin.detekt-typed:typed-classpath-malformed:{key}:{error}"
                )),
            }
        }
    }
    typed_gaps.sort();
    Ok(ExtractedAndroidModel {
        model,
        typed,
        typed_gaps,
        runner_program: gradle_program.into(),
        runner_argv_prefix: Vec::new(),
    })
}
