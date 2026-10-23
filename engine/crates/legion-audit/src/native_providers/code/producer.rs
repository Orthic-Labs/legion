//! Dispatch for the assurance-extension `code.*` providers (A04-A07, A16).
//!
//! `code.kotlin.detekt-source`, `code.kotlin.detekt-typed`, `code.android.lint`,
//! `code.apple.targets`, `code.javascript.native` and `code.rust.targets` are
//! planners and parsers: their modules launch nothing themselves. This
//! dispatcher binds each one to the frozen denominator, runs the planner over
//! the frozen inventory (reading only digest-verified bytes), and reports the
//! plan.
//!
//! Boundaries kept deliberately:
//!
//! * Nothing runs unless an active host owner admits it. When the host supplies
//!   an owner context, two launches may start here, and both are typed
//!   `ExternalToolRequest`s submitted through the owner-backed executor, so
//!   every one passes per-request owner admission (plan binding, policy pin and
//!   digest, environment, roots, runtime closure, classification) before any
//!   spawn: the pinned-JDK Gradle model extraction (`gradle_model`, project
//!   executing, network denied) and the Xcode bridge (`xcode_bridge`). An
//!   admission denial or missing pin is an explicit gap, never a raw launch.
//!   Lint and test runners remain plans for the sandboxed `ExternalProjectTool`
//!   route (`OwnerAdmissionRequired` on the installed CLI). Without an owner,
//!   or until a plan-bound runner returns receipts, every provider carries
//!   `unavailable:tool-not-run:<tool>` (or its own typed equivalent) and is
//!   never complete.
//! * Tool pins, Gradle build models, typed classpaths, Xcode obligations and
//!   Rust target matrices are never minted from raw provider configuration
//!   except for declarations that can only add obligations (Xcode obligations,
//!   the Rust matrix, the Apple/JS selections). A missing pin or model is a
//!   named gap from the planner itself.
//! * Every denominator file the dispatcher could not read is a named
//!   `file-skipped` gap; `examined` counts only bytes actually read and
//!   verified against the inventory digest.
//! * Families with nothing selected return the engine's not-applicable shape,
//!   never a pass.

use super::{
    android::{self, AndroidLintOptions, ExecutionRoute},
    gradle_model::{self, ExtractedAndroidModel, GradlePins},
    javascript_native::{self, Linter, NativeLintOptions, NativeLinterPin},
    kotlin_detekt::{self, DetektMode, DetektOptions, DetektToolPin},
    rust_targets::{self, RustObligationKind, RustTargetMatrix},
    xcode_bridge,
    xcode_targets::{self, SnapshotFiles, XcodeObligation},
    ProviderExecutorAdapter,
};
use crate::{
    inventory::InventoryEntry,
    native_providers::{availability, code::applicability},
    profiles::AuditProfile,
    AuditError, AuditProvider, InventoryEnvelope,
};
use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderStatus};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::host_owner::OwnerRequestContext;
use legion_provider_sdk::ExternalProjectTool;

/// Result of one owner-contained Gradle model extraction (cached per plan).
pub(super) type ModelExtraction = Result<ExtractedAndroidModel, Vec<String>>;

/// Host-derived execution facts for one assurance provider run. Exists only
/// when the run's scratch carries an owner request context (an active owner);
/// every field comes from the host (policy, frozen plan, scratch roots), never
/// from repository or provider-configuration input.
pub(super) struct AssuranceHost {
    ctx: Arc<OwnerRequestContext>,
    plan_digest: String,
    output_root: PathBuf,
    /// The owner-backed executor: Gradle extraction is admitted per request.
    tool: Arc<dyn ExternalProjectTool>,
    gradle_pins: Option<GradlePins>,
    apple_bridge: Option<Arc<dyn xcode_targets::AppleTargetBridge + Send + Sync>>,
    model_cache: Arc<Mutex<BTreeMap<String, ModelExtraction>>>,
}

impl AssuranceHost {
    pub(super) fn from_run(
        wiring: &super::HostOwnerWiring,
        root: Option<&Path>,
        plan: &crate::FrozenPlan,
        tool: Arc<dyn ExternalProjectTool>,
        scratch: &crate::native_providers::legacy_checks::AuditScratch,
    ) -> Option<Self> {
        let ctx = scratch.owner_context()?;
        let fallback_root = std::env::current_dir().ok();
        let root = root.or(fallback_root.as_deref());
        let gradle_tool = tool.clone();
        let apple_bridge = wiring.apple_bridge.clone().or_else(|| {
            let bridge = xcode_bridge::OwnedXcodeBridge::new(
                tool,
                ctx.clone(),
                plan.digest(),
                root?,
                scratch.root(),
                &scratch.artifacts_dir(),
            )
            .ok()?;
            Some(Arc::new(bridge) as Arc<dyn xcode_targets::AppleTargetBridge + Send + Sync>)
        });
        Some(Self {
            ctx,
            plan_digest: plan.digest().to_owned(),
            tool: gradle_tool,
            output_root: scratch.root().to_path_buf(),
            gradle_pins: wiring.gradle_pins.clone(),
            apple_bridge,
            model_cache: wiring.model_cache.clone(),
        })
    }
}

/// Run (once per plan) the owner-contained Gradle model extraction. Missing
/// pins or an admission denial yield the extractor's explicit gaps; nothing runs then.
fn extract_model(
    host: &AssuranceHost,
    root: Option<&Path>,
    entries: &[InventoryEntry],
) -> ModelExtraction {
    if let Some(cached) = host
        .model_cache
        .lock()
        .ok()
        .and_then(|cache| cache.get(&host.plan_digest).cloned())
    {
        return cached;
    }
    let result = match root {
        None => Err(vec![format!(
            "{}:gradle-project-root-unreadable:no-root",
            android::PROVIDER_ID
        )]),
        Some(root) => {
            let output = host.output_root.join("gradle-model");
            xcode_bridge::block_on(gradle_model::extract_android_model(
                Some(host.ctx.as_ref()),
                Some(host.tool.as_ref()),
                &host.plan_digest,
                root,
                &output,
                host.gradle_pins.as_ref(),
                entries,
            ))
            .unwrap_or_else(|| {
                Err(vec![format!(
                    "{}:gradle-model-runtime-unavailable",
                    android::PROVIDER_ID
                )])
            })
        }
    };
    if let Ok(mut cache) = host.model_cache.lock() {
        cache.insert(host.plan_digest.clone(), result.clone());
    }
    result
}

/// Largest single file the assurance dispatcher reads.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Total bytes one provider may read.
pub const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SKIP_DETAILS: usize = 50;
const MAX_GAP_DETAIL_CHARS: usize = 240;

/// Provider IDs this module dispatches.
pub const ASSURANCE_PROVIDER_IDS: [&str; 6] = [
    kotlin_detekt::SOURCE_PROVIDER_ID,
    kotlin_detekt::TYPED_PROVIDER_ID,
    android::PROVIDER_ID,
    xcode_targets::PROVIDER_ID,
    javascript_native::PROVIDER_ID,
    rust_targets::PROVIDER_ID,
];

pub fn is_assurance_provider(provider_id: &str) -> bool {
    ASSURANCE_PROVIDER_IDS.contains(&provider_id)
}

/// Bytes read from the frozen denominator, plus a bounded list of
/// `<reason>:<path>` for every file that was not.
#[derive(Debug, Default)]
pub struct FrozenRead {
    pub files: BTreeMap<String, Vec<u8>>,
    pub skips: Vec<String>,
}

/// Reads regular, non-symlink files under `root`, bounded per file and in
/// total, verifying each against its inventory `sha256:` digest when one is
/// recorded. A file that cannot be read becomes a skip, never an omission.
pub fn read_frozen<'a>(
    root: Option<&Path>,
    entries: impl IntoIterator<Item = &'a InventoryEntry>,
    max_file: u64,
    max_total: u64,
) -> FrozenRead {
    let mut out = FrozenRead::default();
    let mut budget = max_total;
    let mut skipped = 0usize;
    for entry in entries {
        match read_one(root, entry, max_file, &mut budget) {
            Ok(bytes) => {
                out.files.insert(entry.path.clone(), bytes);
            }
            Err(reason) => {
                skipped += 1;
                if out.skips.len() < MAX_SKIP_DETAILS {
                    out.skips.push(format!("{reason}:{}", entry.path));
                }
            }
        }
    }
    if skipped > MAX_SKIP_DETAILS {
        out.skips
            .push(format!("+{}-more", skipped - MAX_SKIP_DETAILS));
    }
    out
}

fn read_one(
    root: Option<&Path>,
    entry: &InventoryEntry,
    max_file: u64,
    budget: &mut u64,
) -> Result<Vec<u8>, &'static str> {
    let root = root.ok_or("no-root")?;
    let relative = Path::new(&entry.path);
    if entry.path.is_empty()
        || relative.is_absolute()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("unsafe-path");
    }
    let full = root.join(relative);
    let meta = std::fs::symlink_metadata(&full).map_err(|_| "unreadable")?;
    if meta.file_type().is_symlink() {
        return Err("symlink");
    }
    if !meta.is_file() {
        return Err("not-a-file");
    }
    if meta.len() > max_file {
        return Err("oversize");
    }
    if meta.len() > *budget {
        return Err("byte-budget");
    }
    let bytes = std::fs::read(&full).map_err(|_| "unreadable")?;
    *budget = budget.saturating_sub(bytes.len() as u64);
    if let Some(expected) = entry
        .digest
        .as_deref()
        .filter(|digest| digest.starts_with("sha256:"))
    {
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if actual != expected {
            return Err("drift");
        }
    }
    Ok(bytes)
}

enum Produced {
    NotApplicable {
        subject: &'static str,
        reason: String,
    },
    Done(Outcome),
}

#[derive(Default)]
struct Outcome {
    gaps: Vec<String>,
    /// Reasons passed to `mark_unavailable`.
    unavailable: Vec<String>,
    examined: u64,
    details: BTreeMap<String, Value>,
}

fn input_field<T: DeserializeOwned>(input: &Value, key: &str) -> Result<Option<T>, String> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|error| error.to_string()),
    }
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_GAP_DETAIL_CHARS {
        text.to_owned()
    } else {
        text.chars().take(MAX_GAP_DETAIL_CHARS).collect()
    }
}

fn skip_gaps(provider_id: &str, skips: &[String]) -> Vec<String> {
    skips
        .iter()
        .map(|skip| format!("{provider_id}:file-skipped:{skip}"))
        .collect()
}

/// `{code, detail}` rows (the Apple provider's gap shape) as gap strings.
fn coded_gaps(items: Option<&Value>, prefix: &str, out: &mut Vec<String>) {
    for item in items.and_then(Value::as_array).into_iter().flatten() {
        let code = item.get("code").and_then(Value::as_str).unwrap_or("gap");
        let detail = item.get("detail").and_then(Value::as_str).unwrap_or("");
        out.push(if detail.is_empty() {
            format!("{prefix}:{code}")
        } else {
            format!("{prefix}:{code}:{}", clip(detail))
        });
    }
}

/// Entry point used by [`ProviderExecutorAdapter`]; `None` when the provider
/// is not one of the assurance-extension providers.
pub(super) fn execute_assurance(
    adapter: &ProviderExecutorAdapter,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
) -> Option<Result<ProviderResult, AuditError>> {
    is_assurance_provider(&provider.id).then(|| run(adapter, provider, inventory, None))
}

/// As [`execute_assurance`], with the host-derived execution facts of an
/// active owner (`None` keeps the plan-only, explicit-gap behaviour).
pub(super) fn execute_assurance_hosted(
    adapter: &ProviderExecutorAdapter,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    host: Option<&AssuranceHost>,
) -> Option<Result<ProviderResult, AuditError>> {
    is_assurance_provider(&provider.id).then(|| run(adapter, provider, inventory, host))
}

fn run(
    adapter: &ProviderExecutorAdapter,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    host: Option<&AssuranceHost>,
) -> Result<ProviderResult, AuditError> {
    let selector = provider
        .configuration
        .get("selector")
        .cloned()
        .unwrap_or_else(|| json!({"op": "always"}));
    let denominator = inventory.denominator_entries(&selector)?;
    let frozen_count = provider
        .configuration
        .get("denominatorCount")
        .and_then(Value::as_u64)
        .unwrap_or(denominator.entries.len() as u64);
    let frozen_digest = provider
        .configuration
        .get("denominatorDigest")
        .and_then(Value::as_str)
        .map_or_else(|| denominator.digest.clone(), str::to_owned);
    let root = adapter
        .root
        .clone()
        .or_else(|| std::env::current_dir().ok());
    let root = root.as_deref();
    let input = provider
        .configuration
        .get("input")
        .cloned()
        .or_else(|| adapter.inputs.get(&provider.id).cloned())
        .unwrap_or(Value::Null);

    let produced = match provider.id.as_str() {
        kotlin_detekt::SOURCE_PROVIDER_ID => kotlin(
            DetektMode::Source,
            inventory,
            &denominator.entries,
            root,
            None,
        ),
        kotlin_detekt::TYPED_PROVIDER_ID => kotlin(
            DetektMode::Typed,
            inventory,
            &denominator.entries,
            root,
            host,
        ),
        android::PROVIDER_ID => android_lint(root, inventory, &denominator.entries, &input, host),
        xcode_targets::PROVIDER_ID => {
            apple_targets(root, inventory, &denominator.entries, &input, host)
        }
        javascript_native::PROVIDER_ID => javascript(root, inventory, &denominator.entries, &input),
        rust_targets::PROVIDER_ID => {
            rust_target_matrix(root, inventory, &denominator.entries, &input)
        }
        other => {
            return Err(AuditError::Provider(format!(
                "unsupported native assurance provider: {other}"
            )))
        }
    };
    let mut outcome = match produced {
        Produced::NotApplicable { subject, reason } => {
            return applicability::not_applicable_result(
                &provider.id,
                provider.required,
                subject,
                &reason,
            );
        }
        Produced::Done(outcome) => outcome,
    };
    outcome.gaps.sort();
    outcome.gaps.dedup();
    let examined = outcome.examined.min(frozen_count);
    let gaps = outcome.gaps;
    let mut details = outcome.details;
    details.insert("findingEvidence".into(), Value::Object(Map::new()));
    details.insert("findingLocations".into(), Value::Object(Map::new()));
    let mut result = ProviderResult {
        schema_version: 1,
        provider: ProviderId::new(provider.id.clone())?,
        applicable: true,
        required: provider.required,
        // A planned-but-unexecuted provider can never read as complete.
        status: ProviderStatus::Partial,
        complete: false,
        coverage: Some(Coverage {
            denominator_digest: frozen_digest,
            expected: frozen_count,
            examined,
            gaps: gaps.clone(),
        }),
        findings: Vec::new(),
        coverage_gaps: gaps,
        degradation: Vec::new(),
        details,
    };
    for reason in &outcome.unavailable {
        availability::mark_unavailable(&mut result, reason);
    }
    Ok(result)
}

// ---------------------------------------------------------------- Kotlin

fn kotlin(
    mode: DetektMode,
    inventory: &InventoryEnvelope,
    selected: &[InventoryEntry],
    root: Option<&Path>,
    host: Option<&AssuranceHost>,
) -> Produced {
    if selected.is_empty() {
        return Produced::NotApplicable {
            subject: "kotlin",
            reason: "no-kotlin-files-in-inventory".into(),
        };
    }
    // The pin catalog is root-owned; the unenrolled default has no
    // distribution digest, so the planner names `detekt-distribution-digest-missing`
    // and plans no argv. Typed mode takes its classpath only from an
    // owner-extracted Gradle model (never from repository input).
    let pin = DetektToolPin::pinned();
    let options = DetektOptions::default();
    let mut model_gaps: Vec<String> = Vec::new();
    let plan = match mode {
        DetektMode::Source => kotlin_detekt::plan_source(&inventory.entries, &pin, &options),
        DetektMode::Typed => {
            let android_project = inventory
                .entries
                .iter()
                .any(|entry| name_of(&entry.path) == "AndroidManifest.xml");
            let mut chosen: Option<(kotlin_detekt::TypedClasspathEvidence, String, String)> = None;
            if let (Some(host), true) = (host, android_project) {
                match extract_model(host, root, &inventory.entries) {
                    Err(gaps) => model_gaps.extend(gaps),
                    Ok(extracted) => {
                        model_gaps.extend(extracted.typed_gaps.iter().cloned());
                        match extracted.typed.len() {
                            1 => {
                                if let Some((key, evidence)) = extracted.typed.iter().next() {
                                    // Variant comes from the model key, target from the
                                    // model's SDK identity: both checked against the
                                    // evidence's own claims by `validate_typed_evidence`.
                                    let variant =
                                        key.rsplit(':').next().unwrap_or_default().to_owned();
                                    let target = extracted
                                        .model
                                        .sdk
                                        .as_ref()
                                        .map(|sdk| format!("android-{}", sdk.compile_sdk))
                                        .unwrap_or_default();
                                    chosen = Some((evidence.clone(), target, variant));
                                }
                            }
                            0 => {}
                            count => model_gaps.push(format!(
                                "{}:typed-classpath-ambiguous:{count}-variants",
                                kotlin_detekt::TYPED_PROVIDER_ID
                            )),
                        }
                    }
                }
            }
            match &chosen {
                Some((evidence, target, variant)) => kotlin_detekt::plan_typed(
                    &inventory.entries,
                    &pin,
                    &options,
                    Some(evidence),
                    target,
                    variant,
                ),
                None => kotlin_detekt::plan_typed(&inventory.entries, &pin, &options, None, "", ""),
            }
        }
    };
    let mut out = Outcome {
        gaps: plan.gaps.clone(),
        ..Outcome::default()
    };
    out.gaps.extend(model_gaps);
    out.unavailable
        .push(format!("tool-not-run:{}", kotlin_detekt::TOOL_ID));
    out.details.insert(
        "nativeProducer".into(),
        json!({
            "mode": "plan-only",
            "providerId": plan.provider_id,
            "executed": false,
            "runnable": plan.is_runnable(),
            "pinSource": "unenrolled-default",
            "scopeDigest": plan.scope.scope_digest,
            "scanned": plan.scope.scanned.len(),
            "excluded": plan.scope.excluded.len(),
            "unsupported": plan.scope.unsupported.len(),
            "runnerRecord": plan.runner_record(),
        }),
    );
    Produced::Done(out)
}

// --------------------------------------------------------------- Android

fn android_lint(
    root: Option<&Path>,
    inventory: &InventoryEnvelope,
    selected: &[InventoryEntry],
    input: &Value,
    host: Option<&AssuranceHost>,
) -> Produced {
    if selected.is_empty() {
        return Produced::NotApplicable {
            subject: "android",
            reason: "no-android-files-in-inventory".into(),
        };
    }
    let build_entries: Vec<&InventoryEntry> = inventory
        .entries
        .iter()
        .filter(|entry| matches!(name_of(&entry.path), "build.gradle" | "build.gradle.kts"))
        .collect();
    let read = read_frozen(
        root,
        build_entries.iter().copied(),
        MAX_FILE_BYTES,
        MAX_TOTAL_BYTES,
    );
    let build_texts: BTreeMap<String, String> = read
        .files
        .iter()
        .filter_map(|(path, bytes)| {
            String::from_utf8(bytes.clone())
                .ok()
                .map(|text| (path.clone(), text))
        })
        .collect();
    let profile = input
        .get("profile")
        .and_then(Value::as_str)
        .and_then(AuditProfile::parse)
        .unwrap_or(AuditProfile::Repository);
    // Without an active owner no Gradle model producer is enrolled and no
    // execution is admitted: `None` yields `android-model-missing` for an
    // applicable project. With an owner, the model is extracted under owner
    // containment from host-policy pins (absent pins/process stay gaps).
    let options = AndroidLintOptions::new(profile, ExecutionRoute::NotAdmitted);
    let base = android::plan_lint(&inventory.entries, &build_texts, None, &options);
    if !base.is_applicable() {
        return Produced::NotApplicable {
            subject: "android",
            reason: "no-android-files-in-inventory".into(),
        };
    }
    let extraction = host.map(|host| extract_model(host, root, &inventory.entries));
    let plan = match &extraction {
        Some(Ok(extracted)) => {
            android::plan_with_owner(&inventory.entries, &build_texts, Ok(extracted), &options)
        }
        Some(Err(gaps)) => android::plan_with_owner(
            &inventory.entries,
            &build_texts,
            Err(gaps.as_slice()),
            &options,
        ),
        None => base,
    };
    let mut out = Outcome {
        examined: build_texts.len() as u64,
        ..Outcome::default()
    };
    if let Some(Ok(extracted)) = &extraction {
        out.gaps.extend(extracted.typed_gaps.iter().cloned());
    }
    out.gaps.extend(plan.gaps.iter().cloned());
    out.gaps.extend(plan.applicability.gaps.iter().cloned());
    out.gaps
        .extend(skip_gaps(android::PROVIDER_ID, &read.skips));
    for obligation in &plan.obligations {
        out.gaps.push(format!(
            "{}:lint-not-run:{}",
            android::PROVIDER_ID,
            obligation.id
        ));
        for gap in &obligation.plan_gaps {
            out.gaps.push(if gap.starts_with(android::PROVIDER_ID) {
                gap.clone()
            } else {
                format!("{}:{gap}", android::PROVIDER_ID)
            });
        }
    }
    out.unavailable
        .push(format!("tool-not-run:{}", android::TOOL_ID));
    out.details.insert(
        "nativeProducer".into(),
        json!({
            "mode": "plan-only",
            "executed": false,
            "profile": profile.as_str(),
            "route": "not-admitted",
            "modelExtracted": matches!(extraction, Some(Ok(_))),
            "applicability": plan.applicability.reasons,
            "manifests": plan.applicability.manifests,
            "obligations": plan.obligations.len(),
            "runnerRecords": plan.runner_records(),
        }),
    );
    Produced::Done(out)
}

// ----------------------------------------------------------------- Apple

fn apple_targets(
    root: Option<&Path>,
    inventory: &InventoryEnvelope,
    selected: &[InventoryEntry],
    input: &Value,
    host: Option<&AssuranceHost>,
) -> Produced {
    if selected.is_empty() {
        return Produced::NotApplicable {
            subject: "xcode",
            reason: "no-xcode-files-in-inventory".into(),
        };
    }
    let id = xcode_targets::PROVIDER_ID;
    let mut out = Outcome::default();
    let obligations: Vec<XcodeObligation> =
        match input_field::<Vec<XcodeObligation>>(input, "xcodeObligations") {
            Ok(Some(obligations)) => obligations,
            Ok(None) => Vec::new(),
            Err(_) => {
                out.gaps
                    .push(format!("{id}:input-invalid:xcodeObligations"));
                Vec::new()
            }
        };
    let read = read_frozen(root, selected.iter(), MAX_FILE_BYTES, MAX_TOTAL_BYTES);
    out.examined = read.files.len() as u64;
    out.gaps.extend(skip_gaps(id, &read.skips));
    let files: SnapshotFiles = read.files;
    let mut analysis = xcode_targets::analyze_targets(&files, &obligations);
    // The evidence context is derived on the host. A repository- or
    // configuration-supplied `xcodeEvidenceContext` is never read.
    if input
        .get("xcodeEvidenceContext")
        .is_some_and(|v| !v.is_null())
    {
        out.gaps
            .push(format!("{id}:input-ignored:xcodeEvidenceContext"));
    }
    let discharged = host.is_some_and(|host| {
        discharge_apple_obligations(
            &files,
            &obligations,
            inventory,
            host,
            &mut analysis,
            &mut out,
        )
    });
    coded_gaps(
        analysis
            .get("inventory")
            .and_then(|value| value.get("issues")),
        id,
        &mut out.gaps,
    );
    let empty = |key: &str| {
        analysis
            .get("inventory")
            .and_then(|value| value.get(key))
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    };
    if empty("projects") && empty("workspaces") {
        out.gaps
            .push(format!("{id}:no-xcode-container-in-inventory"));
    }
    if obligations.is_empty() {
        out.gaps.push(format!("{id}:no-declared-xcode-obligations"));
    }
    for row in analysis
        .get("obligations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let obligation_id = row.get("id").and_then(Value::as_str).unwrap_or("?");
        if row.get("status").and_then(Value::as_str) != Some("satisfied") {
            out.gaps
                .push(format!("{id}:obligation-unmet:{obligation_id}"));
        }
        coded_gaps(
            row.get("coverage").and_then(|value| value.get("gaps")),
            id,
            &mut out.gaps,
        );
    }
    if !discharged {
        out.unavailable.push("apple-bridge-unconfigured".into());
    }
    out.details.insert("nativeAnalysis".into(), analysis);
    out.details.insert(
        "nativeProducer".into(),
        json!({
            "mode": if discharged { "host-executed" } else { "static-inventory" },
            "executed": discharged,
            "declaredObligations": obligations.len(),
        }),
    );
    Produced::Done(out)
}

/// Run each declared obligation through the adapter's owner-backed Apple
/// bridge. The expected-evidence context is derived here from the frozen
/// inventory (repository/snapshot digests) and the host-policy xcodebuild pin
/// (toolchain version, executable digest) plus the obligation's own canonical
/// command; repository or configuration input never supplies it. Without a
/// bridge (or without a host pin) nothing runs and `false` is returned so the
/// caller keeps the `apple-bridge-unconfigured` gap. Unmet outcomes keep their
/// bridge gaps.
fn discharge_apple_obligations(
    files: &SnapshotFiles,
    obligations: &[XcodeObligation],
    envelope: &InventoryEnvelope,
    host: &AssuranceHost,
    analysis: &mut Value,
    out: &mut Outcome,
) -> bool {
    use crate::artifact_evidence::{RepositoryBinding, TrustEnrollment, UnconfiguredVerifier};
    let id = xcode_targets::PROVIDER_ID;
    let Some(bridge) = host.apple_bridge.clone() else {
        return false;
    };
    if obligations.is_empty() {
        return false;
    }
    let Some((xcodebuild_version, xcodebuild_digest)) = bridge.host_binding() else {
        out.gaps.push(format!("{id}:xcodebuild-host-pin-missing"));
        return false;
    };
    let binding = xcode_targets::HostEvidenceBinding {
        repositories: vec![RepositoryBinding {
            repository_id: envelope.repository_id.clone(),
            revision: envelope.generation.clone(),
            branch: None,
            snapshot_digest: envelope.digest.clone(),
        }],
        xcodebuild_version,
        xcodebuild_digest,
    };
    let inventory = xcode_targets::inventory_xcode(files);
    let trust = TrustEnrollment {
        schema_version: 1,
        issuers: Vec::new(),
    };
    let now = crate::p12_pipeline::store::utc_now();
    let mut outcomes = BTreeMap::new();
    for obligation in obligations {
        let coverage = xcode_targets::evaluate_static(&inventory, files, obligation);
        let context = match xcode_targets::host_expected_context(obligation, &coverage, &binding) {
            Ok(context) => context,
            Err(gap) => {
                out.gaps
                    .push(format!("{id}:bridge:{}:{}", obligation.id, clip(&gap.code)));
                continue;
            }
        };
        let outcome = xcode_targets::discharge_via_bridge(
            bridge.as_ref(),
            obligation,
            &coverage,
            &context,
            &trust,
            &UnconfiguredVerifier,
            &now,
        );
        for gap in &outcome.gaps {
            out.gaps
                .push(format!("{id}:bridge:{}:{}", obligation.id, clip(&gap.code)));
        }
        outcomes.insert(obligation.id.clone(), outcome);
    }
    if let Some(rows) = analysis
        .get_mut("obligations")
        .and_then(Value::as_array_mut)
    {
        for row in rows {
            let Some(outcome) = row
                .get("id")
                .and_then(Value::as_str)
                .and_then(|row_id| outcomes.get(row_id))
            else {
                continue;
            };
            if let (Some(map), Ok(value)) = (row.as_object_mut(), serde_json::to_value(outcome)) {
                map.insert("status".into(), json!(outcome.status));
                map.insert("bridge".into(), value);
            }
        }
    }
    true
}

// ------------------------------------------------------------ JavaScript

fn javascript(
    root: Option<&Path>,
    inventory: &InventoryEnvelope,
    selected: &[InventoryEntry],
    input: &Value,
) -> Produced {
    if selected.is_empty() {
        return Produced::NotApplicable {
            subject: "javascript",
            reason: "no-javascript-files-in-inventory".into(),
        };
    }
    let id = javascript_native::PROVIDER_ID;
    let linter = match input.get("linter").and_then(Value::as_str) {
        Some("biome") => Linter::Biome,
        _ => Linter::Oxlint,
    };
    // Binary pins are root-owned; unpinned names `<tool>-version-unpinned` and
    // `<tool>-distribution-digest-missing` on every unit.
    let pin = NativeLinterPin::unpinned(linter);
    let options = NativeLintOptions::new(linter, "staged-config");
    let frozen = root.map(|root| javascript_native::frozen_reader(root, &inventory.entries));
    let reader = |path: &str| -> Option<Vec<u8>> { frozen.as_ref().and_then(|read| read(path)) };
    let plan = javascript_native::plan_native_lint(&inventory.entries, &reader, &pin, &options);
    let mut out = Outcome::default();
    out.gaps.extend(plan.gaps.iter().cloned());
    for unit in &plan.units {
        out.gaps.extend(unit.gaps.iter().cloned());
        out.gaps.push(format!(
            "{id}:native-lint-not-run:{}",
            if unit.package_dir.is_empty() {
                "."
            } else {
                unit.package_dir.as_str()
            }
        ));
    }
    if plan.units.is_empty() {
        out.gaps.push(format!("{id}:no-lint-units-planned"));
    }
    if root.is_none() {
        out.gaps.push(format!("{id}:file-skipped:no-root"));
    }
    out.unavailable
        .push(format!("tool-not-run:{}", linter.tool_id()));
    let records: Vec<Value> = plan.units.iter().map(|unit| unit.runner_record()).collect();
    out.details.insert(
        "nativeProducer".into(),
        json!({
            "mode": "plan-only",
            "executed": false,
            "linter": linter.tool_id(),
            "pinSource": "unenrolled-default",
            "units": plan.units.len(),
            "excluded": plan.excluded.len(),
            "unowned": plan.unowned.len(),
            "runnerRecords": records,
            "coverage": javascript_native::coverage_manifest(),
            "noNodeCoverage": javascript_native::no_node_coverage(),
        }),
    );
    Produced::Done(out)
}

// ------------------------------------------------------------ Rust targets

fn rust_target_matrix(
    root: Option<&Path>,
    inventory: &InventoryEnvelope,
    selected: &[InventoryEntry],
    input: &Value,
) -> Produced {
    if selected.is_empty() {
        return Produced::NotApplicable {
            subject: "rust-manifest",
            reason: "no-rust-manifest-in-inventory".into(),
        };
    }
    let id = rust_targets::PROVIDER_ID;
    let mut out = Outcome::default();
    // The matrix is a product declaration (it can only add obligations);
    // evidence for each obligation arrives only as authenticated imports.
    // Repository declaration (`.legion/rust-targets.json`) when the host gave
    // no matrix; read only through the frozen, digest-checked inventory.
    let declarations =
        crate::runtime_obligations::RuntimeDeclarations::from_inventory(inventory, |path| {
            let entry = inventory.entries.iter().find(|entry| entry.path == path)?;
            read_frozen(root, [entry], MAX_FILE_BYTES, MAX_FILE_BYTES)
                .files
                .remove(path)
        });
    out.gaps
        .extend(declarations.gaps_for_stack(crate::runtime_obligations::Stack::RustCore));
    let matrix = match input_field::<RustTargetMatrix>(input, "rustTargetMatrix") {
        Ok(Some(matrix)) => matrix,
        Ok(None) => declarations.rust_matrix.clone().unwrap_or_default(),
        Err(_) => {
            out.gaps
                .push(format!("{id}:input-invalid:rustTargetMatrix"));
            RustTargetMatrix::default()
        }
    };
    let plan = rust_targets::plan_rust_obligations(
        &matrix,
        &[
            RustObligationKind::Build,
            RustObligationKind::Lint,
            RustObligationKind::Test,
            RustObligationKind::Miri,
            RustObligationKind::UnsafeReview,
        ],
    );
    for gap in &plan.gaps {
        out.gaps.push(format!("{id}:{}", clip(gap)));
    }
    let mut unmet = BTreeSet::new();
    for obligation in &plan.obligations {
        unmet.insert(obligation.id.clone());
        for gap in &obligation.plan_gaps {
            out.gaps
                .push(format!("{id}:{}:{}", clip(gap), obligation.id));
        }
    }
    for obligation_id in &unmet {
        out.gaps
            .push(format!("{id}:obligation-unmet:{obligation_id}"));
    }
    out.unavailable
        .push("rust-target-evidence-not-imported".into());
    out.details.insert(
        "nativeProducer".into(),
        json!({
            "mode": "obligation-plan",
            "executed": false,
            "declaredBy": matrix.declared_by,
            "obligations": plan.obligations.len(),
            "targetPlan": serde_json::to_value(&plan).unwrap_or(Value::Null),
        }),
    );
    Produced::Done(out)
}
