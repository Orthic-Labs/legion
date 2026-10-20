//! Constructed real SDK/offline-database/artifact controls for dependency.osv.
//! Does not qualify production admission, self-producer, public osv_command,
//! complete advisory coverage, reachability, or dependency installation.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute,
    native_providers::{legacy_checks::AuditExternalProjectTool, security::dependency_osv},
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision, ToolOrigin};
use legion_provider_sdk::ExternalProjectTool;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const ID: &str = "dependency.osv";
const SOURCE: &str = "engine/crates/legion-audit/tests/osv_accuracy.rs";
const ADVISORY_PATH: &str =
    "engine/crates/legion-audit/tests/fixtures/osv/GHSA-35jh-r3h4-6jhm.json";
const ADVISORY: &[u8] = include_bytes!("fixtures/osv/GHSA-35jh-r3h4-6jhm.json");
const ADVISORY_DIGEST: &str =
    "sha256:3060fadb9a686e5041d53fe5c20c7844b2a0a49ce8d7b3d89d70703be02ec4f1";
const ADVISORY_URL: &str = "https://raw.githubusercontent.com/github/advisory-database/95c688698ee6767a611e157d7329d11f3e0a1f4b/advisories/github-reviewed/2021/05/GHSA-35jh-r3h4-6jhm/GHSA-35jh-r3h4-6jhm.json";
const POLICY: &str = "legion-osv-sdk-offline-artifact-fixture-v1";
const VERSION_REQUIREMENT: &str = "exact-tool:osv-scanner:2.2.2";
const TIMEOUT: u64 = 30_000;
const LIMIT: usize = 4 * 1024 * 1024;
// Requires separate reviewed producer prerequisite: clean packages are absent
// from OSV JSON unless --all-packages is passed.
const ARGV: &[&str] = &[
    "scan",
    "source",
    "--offline",
    "--format",
    "json",
    "--all-packages",
    "-r",
    ".",
];

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
fn pin() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "sha256:f1e1cc84b6e365b79b874cb9028a4f74ac64666094b542f1eb196b10f44b505e"
    } else if cfg!(target_arch = "x86_64") {
        "sha256:5c2a2e2a686e34c0674e0a463aa626467df5d9fba0ed06870a2eb684dc434de3"
    } else {
        panic!("no reviewed native OSV asset for this architecture")
    }
}
fn spec() -> (ProviderSpec, Value) {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    let value = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == ID)
        .unwrap()
        .clone();
    (serde_json::from_value(value.clone()).unwrap(), value)
}
// Generated host receipts are runtime evidence, never implementation inputs.
// Match one exact repository-relative directory & lowercase SHA-256 JSON name.
fn generated_session_provenance(relative: &Path) -> bool {
    // Match filesystem components before display separator normalization.
    if relative.parent()
        != Some(Path::new(
            "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance",
        ))
    {
        return false;
    }
    relative
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

#[test]
fn source_binding_receipt_exclusion_is_exact() {
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    assert!(generated_session_provenance(Path::new(&format!(
        "{prefix}{}.json",
        "0123456789abcdef".repeat(4)
    ))));
    for relative in [
        "engine/crates/legion-audit/src/mod.rs".to_owned(),
        "engine/crates/legion-audit/src/nested/.audit/anything.rs".to_owned(),
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.json", "A".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("nested/{prefix}{}.json", "a".repeat(64)),
    ] {
        assert!(
            !generated_session_provenance(Path::new(&relative)),
            "unexpected exclusion: {relative}"
        );
    }
}

fn source_binding_walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
    assert!(!path.is_symlink(), "source binding refuses symlinks");
    if path.is_file() && generated_session_provenance(path.strip_prefix(root).unwrap()) {
        return;
    }
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            source_binding_walk(root, &entry.unwrap().path(), files);
        }
    } else {
        assert!(path.is_file());
        files.insert(
            path.strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/"),
            digest(&fs::read(path).unwrap()),
        );
    }
}

#[test]
fn source_binding_excludes_only_regular_generated_session_receipts() {
    fn snapshot(root: &Path) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        source_binding_walk(
            root,
            &root.join("engine/crates/legion-audit/src"),
            &mut files,
        );
        files
    }
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let base = std::env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
    let scratch = Scratch(base.join(format!(
        "legion-source-binding-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    let root = &scratch.0;
    let source = root.join("engine/crates/legion-audit/src/mod.rs");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, b"original source\n").unwrap();
    let baseline = snapshot(root);
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    let receipt = root.join(format!("{prefix}{}.json", "0123456789abcdef".repeat(4)));
    fs::create_dir_all(receipt.parent().unwrap()).unwrap();
    fs::write(&receipt, b"generated receipt\n").unwrap();
    assert_eq!(snapshot(root), baseline);
    fs::write(&receipt, b"changed generated receipt\n").unwrap();
    assert_eq!(snapshot(root), baseline);

    // A matching directory remains traversed; only regular files are excluded.
    fs::remove_file(&receipt).unwrap();
    fs::create_dir(&receipt).unwrap();
    let nested = receipt.join("nested.rs");
    fs::write(&nested, b"retained nested source\n").unwrap();
    let nested_key = nested
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    assert_eq!(
        snapshot(root).get(&nested_key),
        Some(&digest(b"retained nested source\n"))
    );
    fs::write(&nested, b"changed nested source\n").unwrap();
    assert_eq!(
        snapshot(root).get(&nested_key),
        Some(&digest(b"changed nested source\n"))
    );
    fs::remove_dir_all(&receipt).unwrap();

    for relative in [
        "engine/crates/legion-audit/src/nested/.audit/anything.rs".to_owned(),
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.JSON", "a".repeat(64)),
        format!("{prefix}{}.json", "A".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}{}.json", "a".repeat(65)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("engine/crates/legion-audit/src/nested/.audit/arcane/receipts/session-provenance/{}.json", "a".repeat(64)),
        // Unix backslashes are literal filesystem name bytes.
        format!("engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance\\{}.json", "a".repeat(64)),
        format!("engine/crates/legion-audit/src/.audit\\arcane/receipts/session-provenance/{}.json", "a".repeat(64)),
        format!(r"engine/crates/legion-audit/src/.audit\arcane\receipts\session-provenance\{}.json", "a".repeat(64)),
    ] {
        let path = root.join(&relative);
        assert!(!generated_session_provenance(path.strip_prefix(root).unwrap()));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"retained source\n").unwrap();
        let key = relative.replace('\\', "/");
        let before = snapshot(root);
        assert_eq!(before.len(), baseline.len() + 1, "{relative}");
        assert_eq!(before.get(&key), Some(&digest(b"retained source\n")), "{relative}");
        fs::write(&path, b"changed retained source\n").unwrap();
        let changed = snapshot(root);
        assert_eq!(changed.get(&key), Some(&digest(b"changed retained source\n")), "{relative}");
        assert_ne!(changed.get(&key), before.get(&key), "{relative}");
        fs::remove_file(path).unwrap();
    }
    assert_eq!(snapshot(root), baseline);
    fs::write(&source, b"changed implementation\n").unwrap();
    assert_ne!(snapshot(root), baseline);

    // Symlink refusal precedes even an exactly matching receipt filename.
    std::os::unix::fs::symlink(&source, &receipt).unwrap();
    assert!(std::panic::catch_unwind(|| snapshot(root)).is_err());
    fs::remove_file(&receipt).unwrap();
    std::os::unix::fs::symlink(source.parent().unwrap(), &receipt).unwrap();
    assert!(std::panic::catch_unwind(|| snapshot(root)).is_err());
    fs::remove_file(&receipt).unwrap();
}

fn source_binding(root: &Path) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    for path in [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
        "engine/Cargo.lock",
        "engine/Cargo.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        SOURCE,
        "engine/crates/legion-audit/tests/fixtures/osv",
    ] {
        source_binding_walk(root, &root.join(path), &mut files);
    }
    files
}

/// One standard uncompressed ZIP entry containing unchanged official JSON.
/// Actual pinned OSV parses this archive; no fabricated tool output/schema.
fn fixture_zip() -> Vec<u8> {
    assert_eq!(digest(ADVISORY), ADVISORY_DIGEST);
    let name = b"GHSA-35jh-r3h4-6jhm.json";
    let mut crc = 0xffff_ffffu32;
    for byte in ADVISORY {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    crc = !crc;
    let mut out = Vec::new();
    fn u16le(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_le_bytes());
    }
    fn u32le(out: &mut Vec<u8>, value: u32) {
        out.extend(value.to_le_bytes());
    }
    u32le(&mut out, 0x0403_4b50);
    for value in [20, 0, 0, 0, 33] {
        u16le(&mut out, value);
    }
    for value in [crc, ADVISORY.len() as u32, ADVISORY.len() as u32] {
        u32le(&mut out, value);
    }
    u16le(&mut out, name.len() as u16);
    u16le(&mut out, 0);
    out.extend(name);
    out.extend(ADVISORY);
    let central = out.len() as u32;
    u32le(&mut out, 0x0201_4b50);
    for value in [20, 20, 0, 0, 0, 33] {
        u16le(&mut out, value);
    }
    for value in [crc, ADVISORY.len() as u32, ADVISORY.len() as u32] {
        u32le(&mut out, value);
    }
    for value in [name.len() as u16, 0, 0, 0, 0] {
        u16le(&mut out, value);
    }
    u32le(&mut out, 0);
    u32le(&mut out, 0);
    out.extend(name);
    let size = out.len() as u32 - central;
    u32le(&mut out, 0x0605_4b50);
    for value in [0, 0, 1, 1] {
        u16le(&mut out, value);
    }
    u32le(&mut out, size);
    u32le(&mut out, central);
    u16le(&mut out, 0);
    out
}

struct ScopedPolicy {
    root: PathBuf,
    run: PathBuf,
    plan: String,
    inventory: String,
    source_digest: String,
    database: PathBuf,
    database_digest: String,
    tool: PathBuf,
    wrapper: PathBuf,
    wrapper_digest: String,
    args: Vec<String>,
    environment: BTreeMap<String, String>,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn definition(&self) -> Value {
        json!({"id":POLICY,"version":1,"provider":ID,"scope":"constructed-native-sdk-offline-artifact-fixture",
            "planDigest":self.plan,"inventoryDigest":self.inventory,"root":self.root,"run":self.run,
            "sourceDigest":self.source_digest,"databaseArchive":self.database,"databaseDigest":self.database_digest,
            "tool":{"path":self.tool,"digest":pin(),"version":"2.2.2"},"wrapper":{"path":self.wrapper,"digest":self.wrapper_digest},
            "args":self.args,"versionRequirement":VERSION_REQUIREMENT,"environment":self.environment,"timeoutMs":TIMEOUT,"outputLimit":LIMIT,
            "profile":self.profile_definition()})
    }
    fn profile_definition(&self) -> Value {
        let escaped = self
            .root
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let text=format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
        let hash = digest(text.as_bytes());
        json!({"path":self.run.join("sandbox").join(format!("audit-{}.sb",hash.trim_start_matches("sha256:"))),
            "text":text,"digest":hash,"receiptId":format!("sandbox:macos:{}",hash.trim_start_matches("sha256:"))})
    }
    fn permits(&self, r: &ExternalToolRequest) -> bool {
        if r.provider_id != ID
            || r.plan_id != self.plan
            || r.policy_id != POLICY
            || r.task_id.as_deref() != Some("osv-sdk-artifact")
            || r.cwd != self.root.to_string_lossy().as_ref()
            || r.origin != ToolOrigin::System
            || r.shell
            || !r.requires_network_sandbox
            || r.skip_version_probe
            || r.version_requirement.as_deref() != Some(VERSION_REQUIREMENT)
            || r.timeout_ms != TIMEOUT
            || r.stdout_limit != LIMIT
            || r.stderr_limit != LIMIT
            || r.executable != self.wrapper.to_string_lossy().as_ref()
            || r.expected_digest.as_deref() != Some(self.wrapper_digest.as_str())
            || r.args.len() != self.args.len() + 4
            || r.args[0] != "-f"
            || r.args[2] != "--"
            || r.args[3] != self.tool.to_string_lossy().as_ref()
            || r.args[4..] != self.args
            || r.accepted_exit_codes != [0, 1].into_iter().collect()
            || r.environment != self.environment
            || r.environment_allowlist != self.environment.keys().cloned().collect()
            || !r.sensitive_argument_indexes.is_empty()
            || !r.sensitive_environment_names.is_empty()
        {
            return false;
        }
        let mut version = r.args[..4].to_vec();
        version.push("--version".into());
        if r.version_args != version {
            return false;
        }
        let Some(sandbox) = r.sandbox.as_ref() else {
            return false;
        };
        let Ok(profile) = fs::canonicalize(&r.args[1]) else {
            return false;
        };
        let escaped = self
            .root
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let expected=format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
        profile.starts_with(&self.run)
            && sandbox.network
            && sandbox.filesystem_scope.as_deref() == self.root.to_str()
            && sandbox.id
                == format!(
                    "sandbox:macos:{}",
                    digest(expected.as_bytes()).trim_start_matches("sha256:")
                )
            && fs::read(profile).ok().as_deref() == Some(expected.as_bytes())
            && fs::read(&self.tool).ok().map(|b| digest(&b)).as_deref() == Some(pin())
            && fs::read(&self.wrapper).ok().map(|b| digest(&b)).as_deref()
                == Some(self.wrapper_digest.as_str())
            && fs::read(&self.database).ok().map(|b| digest(&b)).as_deref()
                == Some(self.database_digest.as_str())
            && fs::read(self.root.join("package-lock.json"))
                .ok()
                .map(|b| digest(&b))
                .as_deref()
                == Some(self.source_digest.as_str())
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        let allowed = self.permits(r);
        self.decisions.lock().unwrap().push(
            json!({"allowed":allowed,"requestId":r.request_id,"providerId":r.provider_id,
            "planId":r.plan_id,"policyId":r.policy_id,"args":r.args,"versionArgs":r.version_args,"versionRequirement":r.version_requirement}),
        );
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&serde_json::to_vec(&self.definition()).unwrap()),
            reason: Some("exact constructed OSV offline SDK/artifact fixture only".into()),
        }
    }
}
struct SharedPolicy(Arc<ScopedPolicy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(r)
    }
}

fn retained(root: &Path, artifact: &legion_effects::ArtifactRecord) -> Value {
    let bytes = fs::read(root.join(&artifact.path)).unwrap();
    assert!(artifact.immutable);
    assert_eq!(digest(&bytes), artifact.digest);
    assert_eq!(bytes.len(), artifact.bytes);
    json!({"path": artifact.path, "digest": artifact.digest, "bytes": artifact.bytes, "immutable": artifact.immutable, "raw": String::from_utf8(bytes).unwrap()})
}
/// Exact field projection of actual EffectExecutor receipt; no inferred process proof.
fn receipt_json(receipt: &legion_effects::ExecutionReceipt, artifacts: &Path) -> Value {
    json!({"schemaVersion": receipt.schema_version, "receiptId": receipt.receipt_id,
        "requestId": receipt.request_id, "providerId": receipt.provider_id, "planId": receipt.plan_id,
        "policyId": receipt.policy_id, "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}",e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}",e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified,"skippedByPolicy":e.version.skipped_by_policy}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd":receipt.cwd,"environmentNames":receipt.environment_names,
        "sandbox":{"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree":{"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing":{"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode":receipt.exit_code,"signal":receipt.signal,
        "stdout":receipt.stdout.as_ref().map(|a| retained(artifacts,a)),"stderr":receipt.stderr.as_ref().map(|a| retained(artifacts,a)),
        "parser":{"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error},"gaps":receipt.gaps})
}

fn case(id: &str, version: &str, planted: bool, malformed: bool, directory: &Path) -> Value {
    let fixture = directory.join(id);
    // Refuse reuse rather than silently consume earlier output.
    fs::create_dir(&fixture).unwrap();
    let root = fixture.join("source");
    let run = fixture.join("run");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&run).unwrap();
    fs::create_dir(run.join("home")).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let run = fs::canonicalize(run).unwrap();
    let cache = fixture.join("database");
    fs::create_dir_all(cache.join("osv-scanner/npm")).unwrap();
    let cache = fs::canonicalize(cache).unwrap();
    let database = cache.join("osv-scanner/npm/all.zip");
    let archive = fixture_zip();
    fs::write(&database, &archive).unwrap();
    let database_digest = digest(&archive);
    let (fixture_path, source_bytes): (&str, &[u8]) = match id {
        "lodash-planted" => (
            "engine/crates/legion-audit/tests/fixtures/osv/lodash-planted/package-lock.json",
            include_bytes!("fixtures/osv/lodash-planted/package-lock.json"),
        ),
        "lodash-fixed" => (
            "engine/crates/legion-audit/tests/fixtures/osv/lodash-fixed/package-lock.json",
            include_bytes!("fixtures/osv/lodash-fixed/package-lock.json"),
        ),
        "malformed-lockfile" => (
            "engine/crates/legion-audit/tests/fixtures/osv/malformed-lockfile/package-lock.json",
            include_bytes!("fixtures/osv/malformed-lockfile/package-lock.json"),
        ),
        _ => panic!("unreviewed OSV control"),
    };
    let source = source_bytes.to_vec();
    assert_eq!(
        archive
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        include_str!("fixtures/osv/all.zip.hex").trim()
    );
    fs::write(root.join("package-lock.json"), &source).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(id)
        .unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.entries[0].path, "package-lock.json");
    assert_eq!(
        inventory.entries[0].digest.as_deref(),
        Some(digest(&source).as_str())
    );
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec().0])
        .unwrap()
        .freeze(Some(b"osv-sdk-artifact-fixture-key"))
        .unwrap();
    let provider = frozen.provider(ID).unwrap();
    assert_eq!(provider.configuration["denominatorCount"], 1);
    // Bound to current shipped private producer command, not defective public
    // osv_command helper. Whole producer source is included in source closure.
    let producer_source: String = include_str!("../src/native_providers/security/producer.rs")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(
        producer_source
            .replace(",]", "]")
            .contains(&serde_json::to_string(ARGV).unwrap()),
        "reviewed --all-packages producer prerequisite required"
    );
    let tool = fs::canonicalize(
        std::env::var_os("LEGION_OSV_BIN").expect("official pinned OSV binary required"),
    )
    .unwrap();
    assert!(!tool.starts_with(&fixture));
    assert_eq!(digest(&fs::read(&tool).unwrap()), pin());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let wrapper_digest = digest(&fs::read(&wrapper).unwrap());
    let args: Vec<String> = ARGV.iter().map(|arg| (*arg).into()).collect();
    // Deliberately constructed SDK environment, no network DB update & no
    // claim that private ArtifactProducer admission/retention was exercised.
    let mut environment = BTreeMap::from([
        (
            "HOME".into(),
            run.join("home").to_string_lossy().into_owned(),
        ),
        (
            "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY".into(),
            cache.to_string_lossy().into_owned(),
        ),
    ]);
    if let Ok(path) = std::env::var("PATH") {
        environment.insert("PATH".into(), path);
    }
    let policy = Arc::new(ScopedPolicy {
        root: root.clone(),
        run: run.clone(),
        plan: frozen.digest().into(),
        inventory: inventory.digest.clone(),
        source_digest: digest(&source),
        database: database.clone(),
        database_digest: database_digest.clone(),
        tool: tool.clone(),
        wrapper,
        wrapper_digest: wrapper_digest.clone(),
        args: args.clone(),
        environment: environment.clone(),
        decisions: Mutex::new(vec![]),
    });
    let auth = legion_effects::authenticate_sandbox(
        tool.to_str().unwrap(),
        &args,
        root.to_str().unwrap(),
        legion_effects::SandboxMode::DenyNetworkDenyProjectWrite,
        &run.join("sandbox"),
    )
    .unwrap();
    let mut version_args = auth.wrapped_args[..4].to_vec();
    version_args.push("--version".into());
    let request = ExternalToolRequest {
        request_id: format!("osv-{id}"),
        provider_id: ID.into(),
        plan_id: frozen.digest().into(),
        policy_id: POLICY.into(),
        task_id: Some("osv-sdk-artifact".into()),
        executable: auth.wrapped_executable,
        args: auth.wrapped_args,
        version_args,
        cwd: root.to_string_lossy().into_owned(),
        origin: ToolOrigin::System,
        expected_digest: Some(wrapper_digest),
        version_requirement: Some(VERSION_REQUIREMENT.into()),
        environment_allowlist: environment.keys().cloned().collect(),
        environment,
        accepted_exit_codes: [0, 1].into_iter().collect(),
        requires_network_sandbox: true,
        sandbox: Some(legion_effects::SandboxReceipt {
            id: auth.id,
            network: auth.network,
            filesystem_scope: auth.filesystem_scope,
        }),
        timeout_ms: TIMEOUT,
        stdout_limit: LIMIT,
        stderr_limit: LIMIT,
        ..ExternalToolRequest::default()
    };
    let artifacts = run.join("artifacts");
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(&artifacts),
        SharedPolicy(policy.clone()),
    );
    let receipt = tokio::runtime::Runtime::new().unwrap().block_on(
        AuditExternalProjectTool::new(effects)
            .execute(request, tokio_util::sync::CancellationToken::new()),
    );
    let full_receipt = receipt_json(&receipt, &artifacts);
    // Preserve actual diagnostic evidence even if admission/process controls fail.
    fs::write(
        fixture.join("execution-receipt.json"),
        serde_json::to_vec_pretty(&full_receipt).unwrap(),
    )
    .unwrap();
    println!(
        "OSV_SDK_ACTUAL_RECEIPT {}",
        serde_json::to_string(&full_receipt).unwrap()
    );
    if malformed {
        // Require genuine parser/process failure, never denial-only success.
        assert_eq!(
            receipt.state,
            legion_effects::ExecutionState::Failed,
            "{full_receipt}"
        );
        assert!(
            !receipt.complete
                && receipt.process_tree.started
                && receipt.process_tree.terminated
                && receipt.process_tree.reaped,
            "{full_receipt}"
        );
        assert!(
            receipt.exit_code.is_some_and(|code| code != 0 && code != 1),
            "{full_receipt}"
        );
        assert!(
            !full_receipt["stderr"]["raw"].as_str().unwrap().is_empty(),
            "{full_receipt}"
        );
        assert!(
            full_receipt["stdout"]["raw"].as_str().unwrap().is_empty(),
            "{full_receipt}"
        );
        let mut registry = NativeProviderRegistry::new(&root);
        registry.security =
            legion_audit::native_providers::security::adapter::SecurityProviderExecutor::new(
                BTreeMap::new(),
            );
        let execution = execute(&frozen, &inventory, &registry).unwrap();
        let result = &execution.results[0].result;
        assert!(
            !result.complete && result.findings.is_empty() && !result.coverage_gaps.is_empty(),
            "{result:?}"
        );
        assert_eq!(fs::read(root.join("package-lock.json")).unwrap(), source);
        assert_eq!(digest(&fs::read(&database).unwrap()), database_digest);
        assert_eq!(digest(&fs::read(&tool).unwrap()), pin());
        let decisions = policy.decisions.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["allowed"], true);
        return json!({"caseId":id,"stage":"finding","controlKind":"real-malformed-lockfile-process-error","controlMatched":true,
            "expectedIncomplete":true,"actualIncomplete":!result.complete,"qualificationEligible":false,"productionQualification":false,
            "selfProducerQualification":false,"publicHelperQualification":false,
            "source":{"path":"package-lock.json","fixturePath":fixture_path,"bytes":String::from_utf8(source).unwrap(),"digest":policy.source_digest},
            "database":{"archivePath":database,"archiveDigest":database_digest,"archiveBytes":archive.len(),"archiveHex":archive.iter().map(|b|format!("{b:02x}")).collect::<String>()},
            "planDigest":frozen.digest(),"frozenPlan":frozen.plan(),"planSignature":frozen.signature(),"inventory":inventory,
            "policy":policy.definition(),"policyDecisions":*decisions,"actualExecutionReceipt":full_receipt,"actualProviderResult":result});
    }
    assert_eq!(
        receipt.state,
        legion_effects::ExecutionState::Completed,
        "{full_receipt}"
    );
    assert!(
        receipt.complete
            && receipt.process_tree.started
            && receipt.process_tree.terminated
            && receipt.process_tree.reaped
            && receipt.gaps.is_empty(),
        "{full_receipt}"
    );
    assert_eq!(
        receipt.exit_code,
        Some(if planted { 1 } else { 0 }),
        "{full_receipt}"
    );
    // v2.2.2 matcher logs an error & continues after failed cache loading.
    // Process success alone therefore cannot prove offline database evidence.
    assert!(
        full_receipt["stderr"]["raw"]
            .as_str()
            .unwrap()
            .contains(&format!("Loaded npm local db from {}", database.display())),
        "{full_receipt}"
    );
    let actual_version = receipt
        .executable
        .as_ref()
        .unwrap()
        .version
        .output
        .as_deref()
        .unwrap();
    assert!(receipt.executable.as_ref().unwrap().version.qualified);
    let output: Value =
        serde_json::from_str(full_receipt["stdout"]["raw"].as_str().unwrap()).unwrap();
    let results = output["results"]
        .as_array()
        .expect("real OSV package results required");
    assert_eq!(results.len(), 1, "{output}");
    let reported = Path::new(results[0]["source"]["path"].as_str().unwrap());
    let relative = if reported.is_absolute() {
        reported.strip_prefix(&root).unwrap()
    } else {
        reported.strip_prefix(".").unwrap_or(reported)
    };
    assert_eq!(relative, Path::new("package-lock.json"), "{output}");
    let packages = results[0]["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 1, "{output}");
    let package = &packages[0]["package"];
    assert_eq!(package["name"], "lodash");
    assert_eq!(package["version"], version);
    assert_eq!(package["ecosystem"], "npm");
    let vulnerabilities = packages[0]
        .get("vulnerabilities")
        .map(|v| {
            v.as_array()
                .expect("OSV vulnerabilities must be an array")
                .clone()
        })
        .unwrap_or_default();
    assert_eq!(vulnerabilities.len(), usize::from(planted), "{output}");
    if planted {
        assert_eq!(vulnerabilities[0]["id"], "GHSA-35jh-r3h4-6jhm");
    }
    let findings: Vec<Value> = vulnerabilities
        .iter()
        .map(|raw| {
            let mut raw = raw.clone();
            raw["package"] = package.clone();
            dependency_osv::normalize_vulnerability(&raw, Some("osv.scanner"), Some(actual_version))
        })
        .collect();
    let mut observed_receipt = full_receipt.clone();
    observed_receipt["tool"] =
        json!({"name":"osv-scanner","version":actual_version,"executableDigest":pin()});
    let binding = json!({"repositoryRevision":inventory.generation,"digest":inventory.digest});
    // Same transformation as shipped producer, based solely on actual package
    // JSON. Reachable here means graph presence, never proved call reachability.
    let input = json!({"plan":{"binding":binding,"denominator":{"pathCount":1}},"projection":{"files":[{"path":"package-lock.json"}]},
        "artifacts":{"dependencyReceipts":[{"manifest":"package-lock.json","binding":binding,"executionReceipt":observed_receipt,
            "database":{"digest":database_digest,"version":format!("fixture-one-official-advisory:{ADVISORY_DIGEST}"),"status":"offline"},
            "paths":[{"package":format!("lodash@{version}"),"reachability":"reachable","basis":"dependency-graph"}],"findings":findings}]}});
    let mut registry = NativeProviderRegistry::new(&root);
    registry.security.artifacts.insert(ID.into(), input.clone());
    let execution = execute(&frozen, &inventory, &registry).unwrap();
    assert_eq!(execution.results.len(), 1);
    let result = &execution.results[0].result;
    assert!(
        result.complete
            && result.applicable
            && result.coverage_gaps.is_empty()
            && result.degradation.is_empty(),
        "{result:?}"
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (1, 1));
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    assert_eq!(result.details["analysis"]["complete"], true);
    assert_eq!(result.details["analysis"]["coverageGaps"], json!([]));
    assert_eq!(
        result.details["analysis"]["denominator"],
        json!({"kind":"dependency-manifests","expected":1,"examined":1})
    );
    assert_eq!(
        result.details["analysis"]["findings"]
            .as_array()
            .unwrap()
            .len(),
        usize::from(planted)
    );
    assert_eq!(result.findings.len(), usize::from(planted));
    let actual: Vec<String> = result
        .findings
        .iter()
        .map(|finding| {
            let evidence = &result.details["findingEvidence"][finding.id.as_str()];
            assert_eq!(evidence["provider"], ID);
            assert_eq!(evidence["path"], "package-lock.json");
            assert_eq!(evidence["line"], 1);
            format!(
                "{}|{}|{}",
                evidence["ruleId"].as_str().unwrap(),
                evidence["path"].as_str().unwrap(),
                evidence["line"].as_u64().unwrap()
            )
        })
        .collect();
    let expected: Vec<String> = if planted {
        vec!["GHSA-35jh-r3h4-6jhm|package-lock.json|1".into()]
    } else {
        vec![]
    };
    assert_eq!(fs::read(root.join("package-lock.json")).unwrap(), source);
    assert_eq!(digest(&fs::read(&database).unwrap()), database_digest);
    assert_eq!(digest(&fs::read(&tool).unwrap()), pin());
    let mut missing_registry = NativeProviderRegistry::new(&root);
    missing_registry.security =
        legion_audit::native_providers::security::adapter::SecurityProviderExecutor::new(
            BTreeMap::new(),
        );
    let missing_execution = execute(&frozen, &inventory, &missing_registry).unwrap();
    let missing = &missing_execution.results[0].result;
    assert!(!missing.complete && missing.findings.is_empty());
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["allowed"], true);
    json!({"caseId":id,"stage":"finding","expected":expected,"actual":actual,"controlMatched":actual==expected,
        "source":{"path":"package-lock.json","fixturePath":fixture_path,"bytes":String::from_utf8(source).unwrap(),"digest":policy.source_digest},
        "database":{"archivePath":database,"archiveDigest":database_digest,"archiveBytes":archive.len(),"archiveHex":archive.iter().map(|b|format!("{b:02x}")).collect::<String>(),
            "scope":"one unchanged official advisory only; not complete ecosystem coverage"},
        "planDigest":frozen.digest(),"frozenPlan":frozen.plan(),"planSignature":frozen.signature(),"inventory":inventory,"providerConfiguration":provider.configuration,
        "policy":policy.definition(),"policyDecisions":*decisions,"actualExecutionReceipt":full_receipt,"actualRawOutput":output,
        "actualArtifactInput":input,"actualProviderResult":result,"missingContextProviderResult":missing,"productionQualification":false,
        "selfProducerQualification":false,"publicHelperQualification":false,"executionPath":"native-sdk-shipped-production-argv-to-frozen-registry-artifact"})
}

#[test]
#[ignore = "requires official pinned OSV 2.2.2 native binary & macOS deny-network sandbox"]
fn real_sdk_artifact_accuracy_osv() {
    let runner =
        fs::canonicalize(std::env::var_os("RUNNER_TEMP").expect("managed CI RUNNER_TEMP required"))
            .unwrap();
    let requested = PathBuf::from(
        std::env::var_os("LEGION_OSV_RECEIPTS")
            .expect("explicit retained receipt directory required"),
    );
    let parent = fs::canonicalize(requested.parent().expect("receipt parent required"))
        .expect("CI must create retained parent first");
    assert!(parent.starts_with(&runner));
    let directory = parent.join(
        requested
            .file_name()
            .expect("receipt directory name required"),
    );
    assert!(!directory.is_symlink());
    fs::create_dir_all(&directory).unwrap();
    let directory = fs::canonicalize(directory).unwrap();
    assert!(directory.starts_with(&runner) && directory != runner);
    let cases = vec![
        case("lodash-planted", "4.17.20", true, false, &directory),
        case("lodash-fixed", "4.17.21", false, false, &directory),
    ];
    let error = case("malformed-lockfile", "4.17.21", false, true, &directory);
    let matched =
        cases.iter().all(|case| case["controlMatched"] == true) && error["controlMatched"] == true;
    let (mut tp, mut fp, mut fn_) = (0usize, 0usize, 0usize);
    for case in &cases {
        let expected: BTreeSet<&str> = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        let actual = case["actual"].as_array().unwrap();
        let unique: BTreeSet<&str> = actual.iter().map(|s| s.as_str().unwrap()).collect();
        tp += expected.intersection(&unique).count();
        fp += unique.difference(&expected).count() + actual.len() - unique.len();
        fn_ += expected.difference(&unique).count();
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let sources = source_binding(&repo);
    let (_, mut provider) = spec();
    provider.as_object_mut().unwrap().remove("benchmark");
    let mut record = json!({"schema":"legion-osv-sdk-artifact-accuracy/1","provider":ID,"stage":"finding","outputKind":"findings",
        "scope":"constructed native SDK + one official advisory offline cache + frozen registry artifact controls; manifest default locus only",
        "productionQualification":false,"selfProducerQualification":false,"publicHelperQualification":false,"modelCalls":0,
        "qualificationEligible":matched,"status":if matched {"pass"} else {"fail"},
        "binding":{"repositoryRoot":fs::canonicalize(&repo).unwrap(),"retainedRoot":directory,"providerSpec":provider,"specDigest":digest(&serde_json::to_vec(&provider).unwrap()),"harnessPath":SOURCE,"sources":sources,
            "sourcesDigest":digest(&serde_json::to_vec(&sources).unwrap()),"advisory":{"url":ADVISORY_URL,"path":ADVISORY_PATH,"digest":ADVISORY_DIGEST,"bytes":String::from_utf8(ADVISORY.to_vec()).unwrap()},
            "tool":{"version":"2.2.2","digest":pin(),"source":"https://github.com/google/osv-scanner/releases/tag/v2.2.2"},
            "argvSource":"engine/crates/legion-audit/src/native_providers/security/producer.rs::dependency_osv","argv":ARGV},
        "metrics":{"truePositives":tp,"falsePositives":fp,"falseNegatives":fn_,"positiveCases":1,"cleanCases":1,"errorCases":1},"cases":cases,"errorControl":error});
    record["qualificationDigest"] = json!(digest(&serde_json::to_vec(&record).unwrap()));
    fs::write(
        directory.join("dependency_osv_sdk_artifact.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    println!(
        "OSV_SDK_ARTIFACT_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
    assert!(
        matched && tp == 1 && fp == 0 && fn_ == 0,
        "exact advisory controls must match"
    );
}
