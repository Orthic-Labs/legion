//! Genuine SDK matrix. Run only through root integration's admitted CI batch.
#![cfg(target_os = "macos")]
use super::*;
use crate::native_providers::{code, legacy_checks::AuditExternalProjectTool};
use crate::{
    execute_with_cancellation, AuditPlan, FilesystemInventorySource, InventorySource,
    NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ArtifactRecord, PolicyAuthorizer, PolicyDecision};
use std::{
    fs,
    sync::{Arc, Mutex},
};

const ID: &str = "code.dotnet";
const POLICY: &str = "legion-dotnet-sdk-qualification-v1";
const TASKS: [&str; 4] = ["restore", "build", "analyzer", "test"];
const LOOPBACK_APPROVAL: &str = ".NET: approved — qualification-only loopback TCP admission for the VSTest harness process tree, recorded verbatim in code.dotnet’s record; external/non-loopback/UDP stay denied. Include in this batch.";
const LOOPBACK_RULES: &str = "(allow network-bind (require-all (local ip \"localhost:*\") (socket-type SOCK_STREAM)))\n(allow network-inbound (require-all (local ip \"localhost:*\") (socket-type SOCK_STREAM)))\n(allow network-outbound (require-all (remote ip \"localhost:*\") (socket-type SOCK_STREAM)))\n";

fn qualification_profile(stage: &Path, task: &str) -> String {
    let p = string(stage).replace('\\', "\\\\").replace('"', "\\\"");
    let rules = if task == "test" { LOOPBACK_RULES } else { "" };
    format!("(version 1)\n(allow default)\n(deny network*)\n{rules}(allow file-read* file-write* (subpath \"{p}\"))\n")
}
fn sandbox_admission() -> Value {
    json!({"approval":LOOPBACK_APPROVAL,"scope":"qualification-only VSTest harness process tree","provider":ID,"task":"test","transport":"TCP","addresses":["127.0.0.1","::1"],"ports":"dynamic","operations":["bind","inbound","outbound"],"externalNetwork":false,"nonLoopback":false,"udp":false,"productionAdmission":false,"inheritedDescriptorConfinementProven":false})
}

fn qualification_applies(opt_in: bool, provider: &str, task: &str) -> bool {
    opt_in && provider == ID && task == "test"
}

pub(super) fn apply_qualification_environment(
    opt_in: bool,
    provider: &str,
    task: &str,
    environment: &mut BTreeMap<String, String>,
    allowlist: &mut BTreeSet<String>,
) {
    if qualification_applies(opt_in, provider, task) {
        environment.insert("DOTNET_SYSTEM_NET_DISABLEIPV6".into(), "1".into());
        allowlist.insert("DOTNET_SYSTEM_NET_DISABLEIPV6".into());
    }
}

#[test]
fn loopback_admission_requires_explicit_dotnet_test_opt_in() {
    for opt_in in [false, true] {
        for provider in [ID, "code.jvm", "code.python"] {
            for task in TASKS {
                assert_eq!(
                    qualification_applies(opt_in, provider, task),
                    opt_in && provider == ID && task == "test"
                );
                let mut environment = BTreeMap::from([("EXISTING".into(), "value".into())]);
                let mut allowlist = BTreeSet::from(["EXISTING".into()]);
                apply_qualification_environment(
                    opt_in,
                    provider,
                    task,
                    &mut environment,
                    &mut allowlist,
                );
                let mut expected_environment =
                    BTreeMap::from([("EXISTING".into(), "value".into())]);
                let mut expected_allowlist = BTreeSet::from(["EXISTING".into()]);
                if opt_in && provider == ID && task == "test" {
                    expected_environment.insert("DOTNET_SYSTEM_NET_DISABLEIPV6".into(), "1".into());
                    expected_allowlist.insert("DOTNET_SYSTEM_NET_DISABLEIPV6".into());
                }
                assert_eq!(environment, expected_environment);
                assert_eq!(allowlist, expected_allowlist);
            }
        }
    }
    let stage = Path::new("/qualification/stage");
    let baseline = "(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath \"/qualification/stage\"))\n";
    for task in ["restore", "build", "analyzer"] {
        assert_eq!(qualification_profile(stage, task), baseline);
    }
    let test = qualification_profile(stage, "test");
    assert_eq!(
        test,
        baseline.replacen(
            "(deny network*)\n",
            &format!("(deny network*)\n{LOOPBACK_RULES}"),
            1
        )
    );
    assert_eq!(test.matches("(socket-type SOCK_STREAM)").count(), 3);
    assert!(!test.contains("SOCK_DGRAM"));
}

// This module only exists in macOS test builds. Explicit adapter opt-in
// cannot change installed owner admission or another provider/task's profile.
pub(super) fn authenticate_qualification_sandbox(
    ctx: &ToolContext<'_>,
    task: &str,
    executable: &str,
    args: &[String],
    cwd: &str,
) -> Option<Result<legion_effects::SandboxAuthentication, legion_effects::SandboxGap>> {
    if !qualification_applies(ctx.dotnet_qualification_loopback, ctx.provider_id, task) {
        return None;
    }
    Some((|| {
        let wrapper = Path::new("/usr/bin/sandbox-exec");
        if !wrapper.is_file() {
            return Err(legion_effects::SandboxGap::ToolMissing);
        }
        let profile = qualification_profile(Path::new(cwd), task);
        let hash = sha256_text(profile.as_bytes());
        let hash = hash.trim_start_matches("sha256:");
        let path = ctx.scratch.sandbox_dir().join(format!("audit-{hash}.sb"));
        fs::create_dir_all(ctx.scratch.sandbox_dir())
            .map_err(|e| legion_effects::SandboxGap::ProfileWriteFailed(e.to_string()))?;
        fs::write(&path, &profile)
            .map_err(|e| legion_effects::SandboxGap::ProfileWriteFailed(e.to_string()))?;
        let mut wrapped_args = vec!["-f".into(), string(&path), "--".into(), executable.into()];
        wrapped_args.extend_from_slice(args);
        // VSTest propagates diagnostics to testhost; retain both logs in this
        // qualification case's existing control tree, including on failure.
        wrapped_args.extend([
            "--diag".into(),
            string(&ctx.scratch.cache_dir().join("dotnet-control/vstest.log")),
        ]);
        Ok(legion_effects::SandboxAuthentication {
            id: format!("sandbox:macos:{hash}"),
            network: true,
            filesystem_scope: Some(cwd.into()),
            wrapped_executable: string(wrapper),
            wrapped_args,
        })
    })())
}
const CONTROLS: [&str; 11] = [
    "positive",
    "nonempty-clean",
    "test-failure",
    "malformed",
    "missing-tool",
    "rejected-admission",
    "unsupported-framework",
    "unsupported-import",
    "source-drift",
    "package-drift",
    "sdk-drift",
];

fn bytes(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(rows) => json!(rows
                .iter()
                .map(|(k, v)| (k.clone(), ordered(v)))
                .collect::<BTreeMap<_, _>>()),
            Value::Array(rows) => Value::Array(rows.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).unwrap()
}

// Identical large subtrees (the enrollment and installed-closure listings embedded in every native
// input snapshot, tool receipt, and tool evidence run) are stored once under `sharedValues` and
// referenced by `{"$sharedRef": digest}`; the validator verifies each stored value's digest, expands
// every reference after checking the qualification digest, then runs its checks on the full data.
// A stored value is keyed by the digest of its own canonical bytes, which may contain references to
// smaller stored values (children are shared first), so each entry is bound by the digest chain.
const SHARE_THRESHOLD: usize = 32 * 1024;

/// Appends the canonical bytes of `value` (identical to `bytes`) to `out` in one pass and counts the
/// digest of every object of at least `SHARE_THRESHOLD` bytes.
fn count_large(value: &Value, out: &mut Vec<u8>, counts: &mut BTreeMap<String, usize>) {
    let start = out.len();
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let ordered: BTreeMap<&String, &Value> = map.iter().collect();
            for (index, (key, child)) in ordered.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).unwrap();
                out.push(b':');
                count_large(child, out, counts);
            }
            out.push(b'}');
            if out.len() - start >= SHARE_THRESHOLD {
                *counts.entry(sha256_text(&out[start..])).or_insert(0) += 1;
            }
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, child) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                count_large(child, out, counts);
            }
            out.push(b']');
        }
        _ => serde_json::to_writer(&mut *out, value).unwrap(),
    }
}

/// Replaces, children first, every object of at least `SHARE_THRESHOLD` bytes whose original
/// digest occurs at least twice in `counts` by a `$sharedRef` to its stored (child-compacted) value.
/// `out` receives the same canonical bytes of the original value that `count_large` counted;
/// `keys` maps an original digest to the stored value's key so a repeat is not re-serialized.
fn share_repeated(
    value: &mut Value,
    out: &mut Vec<u8>,
    counts: &BTreeMap<String, usize>,
    keys: &mut BTreeMap<String, String>,
    shared: &mut serde_json::Map<String, Value>,
) {
    let start = out.len();
    match &mut *value {
        Value::Object(map) => {
            out.push(b'{');
            let mut names: Vec<String> = map.keys().cloned().collect();
            names.sort();
            for (index, name) in names.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, name).unwrap();
                out.push(b':');
                share_repeated(map.get_mut(name).unwrap(), out, counts, keys, shared);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, child) in items.iter_mut().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                share_repeated(child, out, counts, keys, shared);
            }
            out.push(b']');
        }
        scalar => serde_json::to_writer(&mut *out, &*scalar).unwrap(),
    }
    if !value.is_object() || out.len() - start < SHARE_THRESHOLD {
        return;
    }
    let original = sha256_text(&out[start..]);
    if counts.get(&original).copied().unwrap_or(0) < 2 {
        return;
    }
    if !keys.contains_key(&original) {
        let key = sha256_text(&bytes(value));
        shared.insert(key.clone(), std::mem::take(value));
        keys.insert(original.clone(), key);
    }
    let key = keys[&original].clone();
    *value = json!({"$sharedRef": key});
}

/// Stores each repeated large subtree of `cases` once and returns the table of stored values.
fn share_repeated_values(cases: &mut [Value]) -> serde_json::Map<String, Value> {
    let mut out = Vec::new();
    let mut counts = BTreeMap::new();
    for case in cases.iter() {
        out.clear();
        count_large(case, &mut out, &mut counts);
    }
    let mut keys = BTreeMap::new();
    let mut shared = serde_json::Map::new();
    for case in cases.iter_mut() {
        out.clear();
        share_repeated(case, &mut out, &counts, &mut keys, &mut shared);
    }
    shared
}

#[test]
fn shared_values_round_trip_and_bind_every_reference_by_digest() {
    fn big(tag: &str) -> Value {
        json!({"tag": tag, "listing": "x".repeat(SHARE_THRESHOLD)})
    }
    fn expand(value: &Value, shared: &serde_json::Map<String, Value>) -> Value {
        match value {
            Value::Object(map) if map.len() == 1 && map.contains_key("$sharedRef") => {
                let key = map["$sharedRef"].as_str().unwrap();
                expand(shared.get(key).expect("shared reference resolves"), shared)
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, child)| (key.clone(), expand(child, shared)))
                    .collect(),
            ),
            Value::Array(items) => {
                Value::Array(items.iter().map(|child| expand(child, shared)).collect())
            }
            _ => value.clone(),
        }
    }
    let original = vec![
        json!({"id": 1, "snapshot": big("a"), "again": big("a"), "wrapper": {"nested": big("a"), "own": big("b")}}),
        json!({"unique": big("c"), "id": 2, "snapshot": big("a")}),
        json!({"id": 3, "outer": {"keep": big("d"), "inner": {"deep": big("a")}}, "twin": {"keep": big("d"), "inner": {"deep": big("a")}}}),
    ];
    // The one-pass writer must emit exactly `bytes`, or counted digests drift from stored keys.
    for case in &original {
        let mut out = Vec::new();
        count_large(case, &mut out, &mut BTreeMap::new());
        assert_eq!(out, bytes(case));
    }
    let mut cases = original.clone();
    let shared = share_repeated_values(&mut cases);
    assert!(!shared.is_empty());
    for (key, value) in &shared {
        assert_eq!(*key, sha256_text(&bytes(value)));
    }
    for (case, expected) in cases.iter().zip(&original) {
        assert_eq!(&expand(case, &shared), expected);
    }
    // Repeated subtrees leave only a reference; unique ones stay inline; repeats nest.
    assert!(cases[0]["snapshot"].get("$sharedRef").is_some());
    assert_eq!(cases[0]["snapshot"], cases[0]["again"]);
    assert_eq!(cases[0]["snapshot"], cases[1]["snapshot"]);
    assert_eq!(cases[0]["wrapper"]["own"]["tag"], json!("b"));
    assert_eq!(cases[1]["unique"]["tag"], json!("c"));
    assert_eq!(cases[2]["outer"], cases[2]["twin"]);
    let outer = shared[cases[2]["outer"]["$sharedRef"].as_str().unwrap()].clone();
    assert!(outer["keep"].get("$sharedRef").is_some());
    assert!(bytes(&Value::Array(cases)).len() < 4 * SHARE_THRESHOLD);
}

fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, path: &Path, output: &mut BTreeMap<String, Vec<u8>>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for item in fs::read_dir(path).unwrap() {
                walk(root, &item.unwrap().path(), output);
            }
        } else {
            output.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
                fs::read(path).unwrap(),
            );
        }
    }
    let mut output = BTreeMap::new();
    walk(root, root, &mut output);
    output
}
fn digests(rows: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    rows.iter()
        .map(|(p, b)| (p.clone(), sha256_text(b)))
        .collect()
}
fn file_digests(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), out);
            }
        } else {
            out.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
                sha256_text(&fs::read(path).unwrap()),
            );
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}
fn generated_session_provenance(relative: &Path) -> bool {
    relative.parent()
        == Some(Path::new(
            "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance",
        ))
        && relative
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(|name| {
                name.len() == 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
}

fn bind_source_tree(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
    assert!(!path.is_symlink(), "source binding refuses symlinks");
    if path.is_file() && generated_session_provenance(path.strip_prefix(root).unwrap()) {
        return;
    }
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            bind_source_tree(root, &entry.unwrap().path(), files);
        }
    } else {
        files.insert(
            path.strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/"),
            sha256_text(&fs::read(path).unwrap()),
        );
    }
}

#[test]
fn source_binding_excludes_only_regular_generated_session_receipts() {
    fn snapshot(root: &Path) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        bind_source_tree(root, root, &mut files);
        files
    }
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let base = std::env::var_os("RUNNER_TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let scratch = Scratch(base.join(format!(
        "legion-sdk-source-binding-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    let root = &scratch.0;
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    let source = root.join("engine/crates/legion-audit/src/mod.rs");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, b"pub fn source() {}\n").unwrap();
    let baseline = snapshot(root);
    let receipt = root.join(format!("{prefix}{}.json", "0123456789abcdef".repeat(4)));
    fs::create_dir_all(receipt.parent().unwrap()).unwrap();
    fs::write(&receipt, b"generated receipt").unwrap();
    assert_eq!(snapshot(root), baseline);
    fs::write(&receipt, b"different host receipt").unwrap();
    assert_eq!(snapshot(root), baseline);
    fs::remove_file(&receipt).unwrap();
    fs::create_dir(&receipt).unwrap();
    fs::write(receipt.join("nested.rs"), b"retained child").unwrap();
    assert_eq!(snapshot(root).len(), baseline.len() + 1);
    fs::remove_dir_all(&receipt).unwrap();
    for relative in [
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.JSON", "a".repeat(64)),
        format!("{prefix}{}.json", "A".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}{}.json", "a".repeat(65)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("nested/{prefix}{}.json", "a".repeat(64)),
    ] {
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"must remain bound").unwrap();
        let before = snapshot(root);
        assert_eq!(before.len(), baseline.len() + 1, "{relative}");
        fs::write(&path, b"changed retained bytes").unwrap();
        assert_ne!(snapshot(root), before, "{relative}");
        fs::remove_file(path).unwrap();
    }
    // A Unix backslash is filename data, even when display normalization looks generated.
    #[cfg(unix)]
    for relative in [
        format!(
            r"engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance\{}.json",
            "a".repeat(64)
        ),
        format!(
            r"engine\crates/legion-audit/src/.audit/arcane/receipts/session-provenance/{}.json",
            "a".repeat(64)
        ),
        format!(
            r"engine\crates\legion-audit\src\.audit\arcane\receipts\session-provenance\{}.json",
            "a".repeat(64)
        ),
    ] {
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"literal backslash source").unwrap();
        let before = snapshot(root);
        assert_eq!(before.len(), baseline.len() + 1, "{relative}");
        fs::write(&path, b"changed literal backslash source").unwrap();
        assert_ne!(snapshot(root), before, "{relative}");
        fs::remove_file(path).unwrap();
    }
    assert_eq!(snapshot(root), baseline);
    fs::write(&source, b"pub fn changed_source() {}\n").unwrap();
    assert_ne!(snapshot(root), baseline);
    std::os::unix::fs::symlink(&source, &receipt).unwrap();
    assert!(std::panic::catch_unwind(|| snapshot(root)).is_err());
    fs::remove_file(receipt).unwrap();
}

fn spec() -> Value {
    let registry: Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/registry/providers.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut spec = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == ID)
        .unwrap()
        .clone();
    // Registration is an output of qualification, never an input to its identity.
    spec.as_object_mut().unwrap().remove("benchmark");
    spec
}
fn required_for_clean_claim() -> bool {
    let registry: Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/registry/providers.json"),
        )
        .unwrap(),
    )
    .unwrap();
    registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == ID)
        .unwrap()["benchmark"]["requiredForCleanClaim"]
        .as_bool()
        .unwrap()
}
fn execution_spec() -> ProviderSpec {
    let mut bound = spec();
    bound["benchmark"] = json!({"status":"unproven", "requiredForCleanClaim":required_for_clean_claim(), "qualificationDigest":null});
    serde_json::from_value(bound).unwrap()
}
fn string(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}
struct ExactPolicy {
    plan: String,
    scratch: Arc<AuditScratch>,
    enrollment: Value,
    language: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    decisions: Mutex<Vec<Value>>,
    absent: bool,
}
impl ExactPolicy {
    fn stage(&self) -> PathBuf {
        self.scratch.cache_dir().join("dotnet-source")
    }
    fn control(&self) -> PathBuf {
        self.scratch.cache_dir().join("dotnet-control")
    }
    fn extension(&self) -> &str {
        match self.language.as_str() {
            "csharp" => "csproj",
            "visualBasic" => "vbproj",
            "fsharp" => "fsproj",
            _ => panic!(),
        }
    }
    fn fsharp(&self, task: &str) -> bool {
        task == "analyzer" && self.language == "fsharp"
    }
    fn profile_text(&self, task: &str) -> String {
        qualification_profile(&self.stage(), task)
    }
    fn profile(&self, task: &str) -> PathBuf {
        self.scratch.sandbox_dir().join(format!(
            "audit-{}.sb",
            sha256_text(self.profile_text(task).as_bytes()).trim_start_matches("sha256:")
        ))
    }
    fn prefix(&self, task: &str, args: Vec<String>) -> Vec<String> {
        let mut result = vec![
            "-f".into(),
            string(&self.profile(task)),
            "--".into(),
            format!("{}/dotnet", self.enrollment["sdkRoot"].as_str().unwrap()),
        ];
        result.extend(args);
        result
    }
    fn command(&self, task: &str) -> Vec<String> {
        let control = self.control();
        if self.fsharp(task) {
            return vec![
                format!(
                    "{}/tools/net8.0/any/dotnet-fsharplint.dll",
                    self.enrollment["fsharpAnalyzer"]["root"].as_str().unwrap()
                ),
                "--format".into(),
                "MSBuild".into(),
                "lint".into(),
                string(&self.stage().join(&self.language).join("**/*.fs")),
                "--lint-config".into(),
                string(&self.stage().join("fsharplint.json")),
            ];
        }
        let mut args = vec![
            if task == "analyzer" { "build" } else { task }.into(),
            string(
                &self
                    .stage()
                    .join(&self.language)
                    .join(format!("Fixture.{}", self.extension())),
            ),
        ];
        args.extend([
            "--nologo".into(),
            "--verbosity".into(),
            "normal".into(),
            "--artifacts-path".into(),
            string(&control.join("artifacts-0")),
            "-p:NuGetAudit=false".into(),
            "-p:RestoreIgnoreFailedSources=false".into(),
            "-p:UseSharedCompilation=false".into(),
            "-p:BuildInParallel=false".into(),
            "-nodeReuse:false".into(),
            "-p:ImportDirectoryBuildProps=false".into(),
            "-p:ImportDirectoryBuildTargets=false".into(),
            "-p:ImportDirectoryPackagesProps=false".into(),
        ]);
        match task {
            "restore" => args.extend([
                "--locked-mode".into(),
                "--no-cache".into(),
                "--disable-parallel".into(),
                "--configfile".into(),
                string(&control.join("NuGet.Config")),
                "--packages".into(),
                self.enrollment["packagesRoot"].as_str().unwrap().into(),
            ]),
            "build" => args.extend(["--no-restore".into(), "-p:RunAnalyzers=false".into()]),
            "analyzer" => args.extend([
                "--no-restore".into(),
                "-t:Rebuild".into(),
                "-p:RunAnalyzers=true".into(),
                "-p:RunAnalyzersDuringBuild=true".into(),
                "-p:EnableNETAnalyzers=true".into(),
                "-p:ReportAnalyzer=true".into(),
            ]),
            "test" => args.extend([
                "--no-restore".into(),
                "--no-build".into(),
                "--logger".into(),
                "trx;LogFilePrefix=dotnet-sdk".into(),
                "--results-directory".into(),
                string(&control.join("test-results-0")),
                "--diag".into(),
                string(&control.join("vstest.log")),
            ]),
            _ => panic!(),
        };
        args
    }
    fn environment(&self, task: &str) -> (BTreeMap<String, String>, BTreeSet<String>) {
        let (mut env, mut allowed) = audit_environment(&self.scratch);
        env.insert(
            "PATH".into(),
            self.enrollment["sdkRoot"].as_str().unwrap().into(),
        );
        for name in [
            "CARGO_HOME",
            "RUSTUP_HOME",
            "GOPATH",
            "GOROOT",
            "GOMODCACHE",
        ] {
            if let Ok(value) = std::env::var(name) {
                env.insert(name.into(), value);
                allowed.insert(name.into());
            }
        }
        let c = self.control();
        let values = vec![
            ("NO_COLOR", "1".into()),
            ("CARGO_NET_OFFLINE", "true".into()),
            ("CARGO_TERM_COLOR", "never".into()),
            (
                "DOTNET_ROOT",
                self.enrollment["sdkRoot"].as_str().unwrap().into(),
            ),
            ("DOTNET_MULTILEVEL_LOOKUP", "0".into()),
            ("DOTNET_ROLL_FORWARD", "LatestPatch".into()),
            ("DOTNET_CLI_TELEMETRY_OPTOUT", "1".into()),
            ("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1".into()),
            ("DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE", "true".into()),
            ("DOTNET_NOLOGO", "1".into()),
            ("MSBUILDDISABLENODEREUSE", "1".into()),
            ("MSBuildEnableWorkloadResolver", "false".into()),
            (
                "NUGET_PACKAGES",
                self.enrollment["packagesRoot"].as_str().unwrap().into(),
            ),
            ("NUGET_HTTP_CACHE_PATH", string(&c.join("http-cache"))),
            ("DOTNET_CLI_HOME", string(&c.join("home"))),
            (
                "LEGION_DOTNET_INPUT_MANIFEST",
                string(&c.join("inputs.json")),
            ),
            ("LEGION_DOTNET_FRAMEWORKS", "net8.0".into()),
            (
                "LEGION_DOTNET_TEST_RESULTS",
                string(&c.join("test-results-0")),
            ),
        ];
        for (key, value) in values {
            env.insert(key.into(), value);
            allowed.insert(key.into());
        }
        if task == "test" {
            env.insert("DOTNET_SYSTEM_NET_DISABLEIPV6".into(), "1".into());
            allowed.insert("DOTNET_SYSTEM_NET_DISABLEIPV6".into());
        }
        for (key, path) in [
            ("HOME", "home"),
            ("USERPROFILE", "home"),
            ("XDG_CONFIG_HOME", "home/.config"),
            ("MSBuildUserExtensionsPath", "home/msbuild"),
        ] {
            env.insert(key.into(), string(&c.join(path)));
            allowed.insert(key.into());
        }
        if self.fsharp(task) {
            env.insert(
                "LEGION_DOTNET_FSHARP_FILES".into(),
                serde_json::to_string(&vec!["fsharp/Answer.fs", "fsharp/Tests.fs"]).unwrap(),
            );
            allowed.insert("LEGION_DOTNET_FSHARP_FILES".into());
        }
        (env, allowed)
    }
    fn expected(&self, task: &str, request_id: String) -> ExternalToolRequest {
        let (environment, environment_allowlist) = self.environment(task);
        let version = self.prefix(
            task,
            if self.fsharp(task) {
                vec![self.command(task)[0].clone(), "--version".into()]
            } else {
                vec!["--version".into()]
            },
        );
        ExternalToolRequest {
            request_id,
            provider_id: ID.into(),
            plan_id: self.plan.clone(),
            policy_id: "audit".into(),
            task_id: Some(task.into()),
            executable: string(&self.wrapper),
            args: self.prefix(task, self.command(task)),
            cwd: string(&self.stage()),
            expected_digest: Some(self.wrapper_digest.clone()),
            accepted_exit_codes: if self.fsharp(task) {
                [0, 255, -1].into_iter().collect()
            } else if ["restore", "test"].contains(&task) {
                [0].into_iter().collect()
            } else {
                [0, 1].into_iter().collect()
            },
            version_args: version,
            environment,
            environment_allowlist,
            requires_network_sandbox: true,
            sandbox: if self.absent {
                None
            } else {
                Some(legion_effects::SandboxReceipt {
                    id: format!(
                        "sandbox:macos:{}",
                        sha256_text(self.profile_text(task).as_bytes())
                            .trim_start_matches("sha256:")
                    ),
                    network: true,
                    filesystem_scope: Some(string(&self.stage())),
                })
            },
            stdout_limit: 32 * 1024 * 1024,
            stderr_limit: 32 * 1024 * 1024,
            ..ExternalToolRequest::default()
        }
    }
    fn definition(&self) -> Value {
        json!({"id":POLICY,"provider":ID,"plan":self.plan,"language":self.language,"scratch":self.scratch.root(),"enrollmentDigest":sha256_text(&bytes(&self.enrollment)),"wrapper":self.wrapper,"wrapperDigest":self.wrapper_digest,"profiles":TASKS.iter().map(|task|((*task).to_owned(), self.profile_text(task))).collect::<BTreeMap<_,_>>(),"requests":TASKS.iter().map(|task|request_value(&self.expected(task,"legion-audit/<content-digest>".into()))).collect::<Vec<_>>(),"productionAdmission":false,"absentSandboxControl":self.absent})
    }
}
impl PolicyAuthorizer for ExactPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        let task = r.task_id.as_deref().unwrap_or("");
        let id_ok = r
            .request_id
            .strip_prefix("legion-audit/")
            .is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            });
        let mut rows = self.decisions.lock().unwrap();
        let allowed = TASKS.contains(&task)
            && id_ok
            && *r == self.expected(task, r.request_id.clone())
            && fs::read(&self.wrapper).is_ok_and(|b| sha256_text(&b) == self.wrapper_digest)
            && fs::read(self.profile(task)).is_ok_and(|b| b == self.profile_text(task).as_bytes())
            && !rows.iter().any(|row| row["requestId"] == r.request_id);
        rows.push(json!({"requestId":r.request_id,"allowed":allowed,"request":request_value(r)}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: sha256_text(&bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact frozen .NET fixture request"
                } else {
                    "outside frozen .NET fixture request"
                }
                .into(),
            ),
        }
    }
}
struct Shared(Arc<ExactPolicy>);
impl PolicyAuthorizer for Shared {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(r)
    }
}
fn request_value(r: &ExternalToolRequest) -> Value {
    json!({"schemaVersion":r.schema_version,"requestId":r.request_id,"providerId":r.provider_id,"planId":r.plan_id,"policyId":r.policy_id,"taskId":r.task_id,"executable":r.executable,"args":r.args,"cwd":r.cwd,"origin":format!("{:?}",r.origin),"shell":r.shell,"expectedDigest":r.expected_digest,"acceptedExitCodes":r.accepted_exit_codes,"versionArgs":r.version_args,"skipVersionProbe":r.skip_version_probe,"versionRequirement":r.version_requirement,"environment":r.environment,"environmentAllowlist":r.environment_allowlist,"sensitiveArgumentIndexes":r.sensitive_argument_indexes,"sensitiveEnvironmentNames":r.sensitive_environment_names,"requiresNetworkSandbox":r.requires_network_sandbox,"sandbox":r.sandbox.as_ref().map(|s|json!({"id":s.id,"network":s.network,"filesystemScope":s.filesystem_scope})),"timeoutMs":r.timeout_ms,"stdoutLimit":r.stdout_limit,"stderrLimit":r.stderr_limit})
}
fn artifact(record: Option<&ArtifactRecord>, scratch: &AuditScratch) -> Value {
    let Some(record) = record else {
        return Value::Null;
    };
    let path = Path::new(&record.path);
    assert!(
        !path.is_absolute()
            && path.components().all(|c| matches!(c, Component::Normal(_)))
            && record.immutable
    );
    let root = fs::canonicalize(scratch.artifacts_dir()).unwrap();
    let full = fs::canonicalize(root.join(path)).unwrap();
    assert!(full.starts_with(&root));
    let raw = fs::read(&full).unwrap();
    assert_eq!(record.digest, sha256_text(&raw));
    assert_eq!(record.bytes, raw.len());
    json!({"path":record.path,"absolutePath":full,"digest":record.digest,"bytes":record.bytes,"immutable":record.immutable,"rawBytes":raw})
}
struct Recorder {
    inner: Arc<dyn ExternalProjectTool>,
    scratch: Arc<AuditScratch>,
    rows: Arc<Mutex<Vec<Value>>>,
    requests: Arc<Mutex<Vec<ExternalToolRequest>>>,
    drift: Option<PathBuf>,
}
struct RestoreInput(Option<(PathBuf, Option<Vec<u8>>)>);
impl Drop for RestoreInput {
    fn drop(&mut self) {
        if let Some((path, before)) = self.0.take() {
            if let Some(bytes) = before {
                fs::write(path, bytes).expect("restore deliberate drift");
            } else if path.exists() {
                fs::remove_file(path).expect("remove deliberate drift");
            }
        }
    }
}
#[async_trait::async_trait]
impl ExternalProjectTool for Recorder {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        let first = self.requests.lock().unwrap().is_empty();
        self.requests.lock().unwrap().push(request.clone());
        if first {
            if let Some(path) = &self.drift {
                let mut value = fs::read(path).unwrap_or_default();
                value.extend_from_slice(b"\n");
                fs::write(path, value).unwrap();
            }
        }
        let receipt = self.inner.execute(request.clone(), cancellation).await;
        let row = json!({"request":request_value(&request),"executionReceipt":crate::execution_policy::receipt_json(&receipt),"stdout":artifact(receipt.stdout.as_ref(),&self.scratch),"stderr":artifact(receipt.stderr.as_ref(),&self.scratch)});
        let mut rows = self.rows.lock().unwrap();
        let path = self
            .scratch
            .root()
            .join(format!("sdk-execution-{}.json", rows.len()));
        fs::write(path, serde_json::to_vec_pretty(&row).unwrap()).unwrap();
        rows.push(row);
        receipt
    }
}
fn source_fixture(enrollment: &Value, language: &str, control: &str) -> BTreeMap<String, Vec<u8>> {
    let seeds = Path::new(enrollment["fixturesRoot"].as_str().unwrap());
    let mut rows: BTreeMap<String, Vec<u8>> = ["global.json", ".editorconfig", "fsharplint.json"]
        .into_iter()
        .map(|p| (p.into(), fs::read(seeds.join(p)).unwrap()))
        .collect();
    rows.extend(
        files(&seeds.join(language))
            .into_iter()
            .map(|(p, b)| (format!("{language}/{p}"), b)),
    );
    let extension = match language {
        "csharp" => "cs",
        "visualBasic" => "vb",
        _ => "fs",
    };
    let answer = format!("{language}/Answer.{extension}");
    let tests = format!("{language}/Tests.{extension}");
    let modify = |rows: &mut BTreeMap<String, Vec<u8>>, p: &str, from: &str, to: &str| {
        let s = String::from_utf8(rows[p].clone()).unwrap();
        assert!(s.contains(from));
        rows.insert(p.into(), s.replace(from, to).into_bytes());
    };
    if control == "positive" && language == "fsharp" {
        modify(
            &mut rows,
            &tests,
            "Answer().Double(2)",
            "(new Answer()).Double(2)",
        );
    }
    if control != "positive" {
        if language == "csharp" {
            modify(
                &mut rows,
                &answer,
                "public int Double",
                "public static int Double",
            );
            modify(&mut rows, &tests, "new Answer().Double", "Answer.Double");
        }
        if language == "visualBasic" {
            modify(
                &mut rows,
                &answer,
                "Public Function DoubleValue",
                "Public Shared Function DoubleValue",
            );
            modify(
                &mut rows,
                &tests,
                "New Answer().DoubleValue",
                "Answer.DoubleValue",
            );
        }
    }
    if control == "test-failure" {
        // F# asserts with IsTrue: MSTest 3.8's IEquatable<'T> overloads make AreEqual ambiguous there.
        if language == "fsharp" {
            modify(&mut rows, &tests, "IsTrue(4 =", "IsTrue(5 =");
        } else {
            modify(&mut rows, &tests, "AreEqual(4,", "AreEqual(5,");
        }
    }
    if control == "malformed" {
        rows.get_mut(&answer)
            .unwrap()
            .extend_from_slice(b"\nTHIS IS INVALID SOURCE !!!\n");
    }
    let project = rows.keys().find(|p| p.ends_with("proj")).unwrap().clone();
    if control == "unsupported-framework" {
        modify(&mut rows, &project, "net8.0", "net9.0");
    }
    if control == "unsupported-import" {
        modify(
            &mut rows,
            &project,
            "</Project>",
            "<Import Project=\"/tmp/unfrozen.targets\" /></Project>",
        );
    }
    rows
}
fn case(base: &Path, retained: &Path, enrollment: &Value, language: &str, control: &str) -> Value {
    let name = format!("dotnet-{language}-{control}");
    let root = base.join(&name).join("source");
    fs::create_dir_all(&root).unwrap();
    let sources = source_fixture(enrollment, language, control);
    for (p, b) in &sources {
        let path = root.join(p);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b).unwrap();
    }
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&name)
        .unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[execution_spec()])
        .unwrap()
        .freeze(Some(b"dotnet-sdk-qualification-fixture"))
        .unwrap();
    let scratch = Arc::new(
        AuditScratch::with_scratch_dir(&root, retained.join("cases").join(&name)).unwrap(),
    );
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let policy = Arc::new(ExactPolicy {
        plan: frozen.digest().into(),
        scratch: scratch.clone(),
        enrollment: enrollment.clone(),
        language: language.into(),
        wrapper_digest: sha256_text(&fs::read(&wrapper).unwrap()),
        wrapper,
        decisions: Mutex::new(Vec::new()),
        absent: false,
    });
    let rows = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let drift = match control {
        "source-drift" => Some(
            root.join(
                sources
                    .keys()
                    .find(|p| {
                        p.ends_with("Answer.cs")
                            || p.ends_with("Answer.vb")
                            || p.ends_with("Answer.fs")
                    })
                    .unwrap(),
            ),
        ),
        "package-drift" => Some(
            Path::new(enrollment["packagesRoot"].as_str().unwrap()).join(
                enrollment["packageFiles"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .find(|p| p.ends_with(".nupkg.metadata"))
                    .unwrap(),
            ),
        ),
        "sdk-drift" => Some(
            Path::new(enrollment["sdkRoot"].as_str().unwrap()).join("legion-drift-control.txt"),
        ),
        _ => None,
    };
    let original = drift.as_ref().map(|p| fs::read(p).ok());
    let restoration = RestoreInput(drift.clone().zip(original.clone()));
    let actual: Arc<dyn ExternalProjectTool> = if control == "rejected-admission" {
        Arc::new(legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            crate::execution_policy::OwnerAdmissionRequired,
        ))
    } else {
        Arc::new(legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            Shared(policy.clone()),
        ))
    };
    let recorder = Recorder {
        inner: actual,
        scratch: scratch.clone(),
        rows: rows.clone(),
        requests: requests.clone(),
        drift: drift.clone(),
    };
    let search = if control == "missing-tool" {
        let empty = base.join(&name).join("empty-bin");
        fs::create_dir(&empty).unwrap();
        vec![empty]
    } else {
        vec![PathBuf::from(enrollment["sdkRoot"].as_str().unwrap())]
    };
    let native = NativeProviderRegistry::new(&root)
        .with_scratch(scratch.clone())
        .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(recorder)))
        .with_code(
            code::ProviderExecutorAdapter::new()
                .with_root(&root)
                .with_search_path(search)
                .with_sandbox(SandboxPolicy::Required)
                .with_dotnet_qualification_loopback(),
        );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let report = runtime
        .block_on(execute_with_cancellation(
            &frozen,
            &inventory,
            &native,
            CancellationToken::new(),
        ))
        .unwrap();
    let actual_sources = files(&root);
    let drift_observed = drift.as_ref().map(|p| fs::read(p).ok());
    drop(restoration);
    let result = serde_json::to_value(&report.results[0].result).unwrap();
    let executions = rows.lock().unwrap().clone();
    let receipts = &result["details"]["nativeProducer"]["toolReceipts"];
    let mut record = json!({"caseId":name,"language":language,"control":control,"provider":ID,"fixtureSources":sources,"fixtureDigests":digests(&sources),"sourceAfter":actual_sources,"inventory":inventory,"planDigest":frozen.digest(),"policyDefinition":policy.definition(),"policyDecisions":policy.decisions.lock().unwrap().clone(),"sdkExecutions":executions,"nativeResult":result,"driftBefore":original,"driftObserved":drift_observed,"matched":false});
    if ["positive", "nonempty-clean", "test-failure", "malformed"].contains(&control) {
        assert_eq!(
            executions.len(),
            4,
            "every original task must enter actual SDK execution"
        );
        for task in TASKS {
            let row = executions
                .iter()
                .find(|r| r["request"]["taskId"] == task)
                .unwrap();
            assert_eq!(row["executionReceipt"]["processTree"]["started"], true);
            assert_eq!(row["executionReceipt"]["policy"]["allowed"], true);
            assert!(row["stdout"].is_object() && row["stderr"].is_object());
        }
        if ["positive", "nonempty-clean"].contains(&control) {
            let diagnostics = scratch.cache_dir().join("dotnet-control/vstest.log");
            assert!(!diagnostics.is_symlink());
            assert!(!fs::read(diagnostics).unwrap().is_empty());
            assert_eq!(
                result["complete"], true,
                "incomplete native result; gaps: {}",
                result["coverage_gaps"]
            );
            for row in &executions {
                assert_eq!(row["executionReceipt"]["state"], "completed");
                assert_eq!(row["executionReceipt"]["complete"], true);
            }
            let test = receipts
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["tool"] == "test")
                .unwrap();
            assert!(test["dotnetStandardResults"]["retained"]
                .as_array()
                .is_some_and(|v| !v.is_empty()));
            let analysis = &result["details"]["nativeAnalysis"];
            for tool in analysis["toolEvidence"].as_array().unwrap() {
                assert_eq!(tool["status"], "pass");
            }
            if control == "positive" {
                let serialized = serde_json::to_string(&result).unwrap();
                assert!(serialized.contains(if language == "fsharp" {
                    "fsharplint:FL0014"
                } else {
                    "dotnet:CA1822"
                }));
            } else {
                assert!(result["findings"].as_array().unwrap().is_empty());
            }
        }
        if control == "test-failure" {
            let test = executions
                .iter()
                .find(|r| r["request"]["taskId"] == "test")
                .unwrap();
            assert_ne!(test["executionReceipt"]["exitCode"], 0);
            let retained_test = receipts
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["tool"] == "test")
                .unwrap();
            assert!(
                serde_json::to_string(&retained_test["dotnetStandardResults"])
                    .unwrap()
                    .contains("Failed")
            );
            assert_eq!(result["complete"], false);
        }
        if control == "malformed" {
            let build = executions
                .iter()
                .find(|r| r["request"]["taskId"] == "build")
                .unwrap();
            assert_ne!(build["executionReceipt"]["exitCode"], 0);
            assert_eq!(result["complete"], false);
        }
    } else if [
        "unsupported-framework",
        "unsupported-import",
        "missing-tool",
    ]
    .contains(&control)
    {
        assert!(executions.is_empty());
        assert_eq!(result["complete"], false);
    } else if control == "rejected-admission" {
        assert_eq!(executions.len(), 4);
        for row in &executions {
            assert_eq!(row["executionReceipt"]["processTree"]["started"], false);
            assert_eq!(row["executionReceipt"]["policy"]["allowed"], false);
        }
        assert_eq!(result["complete"], false);
    } else {
        assert_eq!(executions.len(), 1);
        assert_ne!(record["driftBefore"], record["driftObserved"]);
        assert_eq!(result["complete"], false);
        assert!(serde_json::to_string(receipts)
            .unwrap()
            .contains("afterError"));
    }
    if control != "source-drift" {
        assert_eq!(sources, actual_sources);
    }
    if control == "nonempty-clean" {
        record["boundaryControls"] =
            boundary_controls(&runtime, &policy, requests.lock().unwrap().first().unwrap());
    }
    record["matched"] = json!(true);
    record
}
fn boundary_controls(
    runtime: &tokio::runtime::Runtime,
    baseline: &Arc<ExactPolicy>,
    source: &ExternalToolRequest,
) -> Value {
    let mut rows = Vec::new();
    for field in [
        "args",
        "cwd",
        "provider",
        "plan",
        "policy",
        "task",
        "digest",
        "environment",
        "allowlist",
        "version",
        "timeout",
        "output",
        "accepted",
        "shell",
        "origin",
        "sandbox",
    ] {
        let mut request = source.clone();
        match field {
            "args" => request.args.push("--unbound".into()),
            "cwd" => request.cwd.push_str("/unbound"),
            "provider" => request.provider_id = "code.python".into(),
            "plan" => request.plan_id.push('0'),
            "policy" => request.policy_id.push('0'),
            "task" => request.task_id = Some("unbound".into()),
            "digest" => request.expected_digest = Some("sha256:unbound".into()),
            "environment" => {
                request.environment.insert("UNBOUND".into(), "1".into());
            }
            "allowlist" => {
                request.environment_allowlist.insert("UNBOUND".into());
            }
            "version" => request.version_args.push("--unbound".into()),
            "timeout" => request.timeout_ms += 1,
            "output" => request.stdout_limit += 1,
            "accepted" => {
                request.accepted_exit_codes.insert(42);
            }
            "shell" => request.shell = true,
            "origin" => request.origin = legion_effects::ToolOrigin::System,
            "sandbox" => request.sandbox.as_mut().unwrap().network = false,
            _ => panic!(),
        }
        let policy = Arc::new(ExactPolicy {
            plan: baseline.plan.clone(),
            scratch: baseline.scratch.clone(),
            enrollment: baseline.enrollment.clone(),
            language: baseline.language.clone(),
            wrapper: baseline.wrapper.clone(),
            wrapper_digest: baseline.wrapper_digest.clone(),
            decisions: Mutex::new(Vec::new()),
            absent: false,
        });
        let effect = legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(baseline.scratch.artifacts_dir()),
            Shared(policy.clone()),
        );
        let receipt =
            runtime.block_on(effect.execute_with_cancellation(&request, CancellationToken::new()));
        assert!(!receipt.process_tree.started);
        if field == "shell" {
            assert!(receipt.policy.is_none());
            assert_eq!(receipt.state, ExecutionState::UnauthorizedEffect);
        } else {
            assert!(receipt.policy.as_ref().is_some_and(|p| !p.allowed));
        }
        rows.push(json!({"control":format!("request-mutation-{field}"),"sourceRequest":request_value(source),"request":request_value(&request),"policyDefinition":policy.definition(),"executionReceipt":crate::execution_policy::receipt_json(&receipt),"matched":true}));
    }
    let policy = Arc::new(ExactPolicy {
        plan: baseline.plan.clone(),
        scratch: baseline.scratch.clone(),
        enrollment: baseline.enrollment.clone(),
        language: baseline.language.clone(),
        wrapper: baseline.wrapper.clone(),
        wrapper_digest: baseline.wrapper_digest.clone(),
        decisions: Mutex::new(Vec::new()),
        absent: true,
    });
    let mut request = source.clone();
    request.sandbox = None;
    let effect = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(baseline.scratch.artifacts_dir()),
        Shared(policy.clone()),
    );
    let receipt =
        runtime.block_on(effect.execute_with_cancellation(&request, CancellationToken::new()));
    assert!(!receipt.process_tree.started);
    assert_eq!(receipt.state, ExecutionState::SandboxMissing);
    rows.push(json!({"control":"absent-sandbox","request":request_value(&request),"policyDefinition":policy.definition(),"executionReceipt":crate::execution_policy::receipt_json(&receipt),"matched":true}));
    json!(rows)
}

#[test]
#[ignore = "native pinned .NET + frozen offline inputs; root integration CI only"]
fn original_dotnet_sdk_contract_has_real_language_task_and_boundary_controls() {
    let output = PathBuf::from(
        std::env::var_os("LEGION_DOTNET_ACCURACY_OUTPUT")
            .expect("retained scratch output required"),
    );
    let ci_scratch = if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        std::env::var_os("RUNNER_TEMP").map(PathBuf::from)
    } else {
        None
    };
    assert!(
        output.is_absolute()
            && output
                .components()
                .all(|p| !matches!(p, Component::ParentDir))
            && (output.starts_with("/Volumes/D/scratch")
                || ci_scratch.as_ref().is_some_and(|p| output.starts_with(p)))
    );
    fs::create_dir_all(output.parent().unwrap()).unwrap();
    let enrollment_path = PathBuf::from(std::env::var_os("LEGION_DOTNET_ENROLLMENT").unwrap());
    let enrollment_bytes = fs::read(&enrollment_path).unwrap();
    let enrollment: Value = serde_json::from_slice(&enrollment_bytes).unwrap();
    assert_eq!(output.file_name().unwrap(), "code_dotnet.json");
    let base = output.parent().unwrap().join("dotnet-fixture-sources");
    fs::create_dir(&base).unwrap();
    let retained = output.parent().unwrap().join("dotnet-retained");
    fs::create_dir(&retained).unwrap();
    let sdk_before = file_digests(Path::new(enrollment["sdkRoot"].as_str().unwrap()));
    let packages_before = file_digests(Path::new(enrollment["packagesRoot"].as_str().unwrap()));
    assert_eq!(code::dotnet::CONFIG.extensions, &["cs", "fs", "vb"]);
    assert_eq!(code::dotnet::CONFIG.tools, &TASKS);
    assert_eq!(code::dotnet::CONFIG.required_context, &["targetFrameworks"]);
    let mut cases = Vec::new();
    for language in ["csharp", "fsharp", "visualBasic"] {
        for control in CONTROLS {
            cases.push(case(&base, &retained, &enrollment, language, control));
        }
    }
    assert_eq!(
        sdk_before,
        file_digests(Path::new(enrollment["sdkRoot"].as_str().unwrap()))
    );
    assert_eq!(
        packages_before,
        file_digests(Path::new(enrollment["packagesRoot"].as_str().unwrap()))
    );
    assert_eq!(enrollment_bytes, fs::read(&enrollment_path).unwrap());
    // One 0.95 MB enrollment recurs in every native input snapshot, tool receipt, and tool
    // evidence run (244 of the record's 274 MB); the record stores each repeated subtree once.
    let shared_values = share_repeated_values(&mut cases);
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut source_binding = BTreeMap::new();
    for path in [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
        "scripts/ci/provision-dotnet-qualification-tools.py",
        "scripts/ci/audit-dotnet-sdk-accuracy.py",
        "scripts/ci/run-dotnet-sdk-qualification-child.py",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        "engine/Cargo.toml",
        "engine/Cargo.lock",
        "engine/rust-toolchain.toml",
    ] {
        bind_source_tree(&repo, &repo.join(path), &mut source_binding);
    }
    let mut record = json!({"schema":"legion-dotnet-sdk-accuracy/1","kind":"dotnet-code-command-sdk-constructed","provider":ID,"providerVersion":spec()["providerVersion"],"productionQualification":false,"qualificationEligible":true,"claimScope":"known-answer-fixture-cases","supportedSurface":"frozen SDK8 net8.0 simple projects; C#/VB Roslyn CA1822 & frozen-file FSharpLint FL0014; actual MSTest execution","executionPath":"native-sdk-frozen-plan-self-sourced-code","admissionScope":"explicit constructed SDK authorizer; genuine OwnerAdmissionRequired denial; no production owner-admission claim","status":"observed-known-answer-controls","missingControls":[],"executedScope":TASKS,"originalContract":{"variants":["csharp","fsharp","visualBasic"],"extensions":["cs","fs","vb"],"tasks":TASKS,"contexts":["targetFrameworks"]},"modelCalls":0,"providerSpec":spec(),"requiredForCleanClaim":required_for_clean_claim(),"sourceBinding":source_binding,"enrollment":enrollment,"enrollmentDigest":sha256_text(&enrollment_bytes),"sdkFiles":sdk_before,"packageFiles":packages_before,"cases":cases,"metrics":{"cases":33,"matched":33,"mismatched":0,"wholeProviderQualified":false,"boundedSdkAccuracyQualified":true}});
    record["sandboxAdmission"] = sandbox_admission();
    record["sharedValues"] = Value::Object(shared_values);
    record["qualificationDigest"] = json!(sha256_text(&bytes(&record)));
    // Compact: the compacted record is committed, and pretty-printing its retained byte arrays
    // (one line per byte) nearly triples it.
    let raw = serde_json::to_vec(&record).unwrap();
    fs::write(
        output.parent().unwrap().join("dotnet-sdk-enrollment.json"),
        &enrollment_bytes,
    )
    .unwrap();
    fs::write(&output, &raw).unwrap();
    println!("DOTNET_CODE_COMMAND_SDK_ACCURACY_ARTIFACT {}",serde_json::to_string(&json!({"schema":"legion-dotnet-code-command-sdk-artifact/1","provider":ID,"file":"code_dotnet.json","digest":sha256_text(&raw),"bytes":raw.len(),"qualificationDigest":record["qualificationDigest"],"qualificationEligible":true,"productionQualification":false})).unwrap());
}
