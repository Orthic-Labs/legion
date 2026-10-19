//! Explicit, constructed semantic capsules. Location proxies never adjudicate claims.
use crate::audit_bench::{self, Options, TokenBudget};
use legion_audit::native_providers::reasoning::{ingest, PendingLensWork, ReasoningInvocation};
use legion_audit::snapshot::{FrozenSnapshot, SnapshotSide};
use legion_contracts::canonical_digest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::Duration,
};

const PROVIDERS: &[&str] = &[
    "doc-drift",
    "architecture",
    "correctness",
    "ai-slop",
    "naming",
    "dead-file",
    "schema",
    "minimize",
    "performance",
    "a11y",
    "data-safety",
    "resilience",
    "platform-parity",
    "release-readiness",
    "security",
];
const MAX_JSON: usize = 2 * 1024 * 1024;
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn canonical(value: &impl Serialize) -> Result<String, String> {
    canonical_digest(value).map_err(|e| e.to_string())
}
fn read_json(path: &Path) -> Result<Value, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_JSON as u64 {
        return Err(format!(
            "not a bounded regular JSON file: {}",
            path.display()
        ));
    }
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", path.display()))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    constructed: bool,
    capsules: Vec<Capsule>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capsule {
    id: String,
    lens: String,
    provider_id: String,
    contract: Contract,
    cases: Vec<Case>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Contract {
    Text(String),
    Structured(StructuredContract),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StructuredContract {
    invariant: String,
    supporting_files: Vec<String>,
    reachable_callers: Vec<String>,
    test_seam: Option<String>,
    execution: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Case {
    id: String,
    kind: Kind,
    #[serde(deserialize_with = "unique_files")]
    files: BTreeMap<String, String>,
    expected: Vec<Expected>,
    required_evidence: Vec<Span>,
    forbidden_claims: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Planted,
    Clean,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Span {
    path: String,
    line_range: [u32; 2],
    role: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    path: String,
    line_range: [u32; 2],
    claim: String,
    severity: String,
}
fn capsule_identity(c: &Capsule) -> bool {
    let expected = match c.lens.as_str() {
        "doc-drift" => "core-doc-drift-retries",
        "architecture" => "core-architecture-domain-ui",
        "correctness" => "core-correctness-shipping-boundary",
        "ai-slop" => "core-ai-slop-comment",
        "naming" => "core-naming-boolean-prefix",
        "dead-file" => "core-dead-file-unreferenced-module",
        "schema" => "core-schema-integer-cents",
        "minimize" => "conditional-minimize-rounding-strategy",
        "performance" => "conditional-performance-batched-order-query",
        "a11y" => "conditional-a11y-checkout-action",
        "data-safety" => "conditional-data-safety-orders-migration",
        "resilience" => "conditional-resilience-child-process",
        "platform-parity" => "conditional-platform-parity-workspace",
        "release-readiness" => "conditional-release-sign-before-upload",
        "security" => "core-security-invoice-tenant-isolation",
        _ => return false,
    };
    c.id == expected && c.provider_id == format!("reasoning.{}", c.lens)
}
fn unique_files<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Files;
    impl<'de> serde::de::Visitor<'de> for Files {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("unique source file paths")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut files = BTreeMap::new();
            while let Some((p, s)) = map.next_entry::<String, String>()? {
                if files.insert(p, s).is_some() {
                    return Err(serde::de::Error::custom("duplicate source file path"));
                }
            }
            Ok(files)
        }
    }
    deserializer.deserialize_map(Files)
}
fn safe_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn safe_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 240
        && !s.contains(['\\', ':', '\0'])
        && !Path::new(s).is_absolute()
        && s.split('/').enumerate().all(|(index, p)| {
            !p.is_empty()
                // Only this source-owned hidden directory is admitted. Git
                // controls, dot segments & other hidden components stay refused.
                && (!p.starts_with('.')
                    || (index == 0 && p == ".github" && s.contains('/')))
                && ![
                    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                    "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
                    "LPT8", "LPT9",
                ]
                .contains(
                    &p.split('.')
                        .next()
                        .unwrap_or("")
                        .to_ascii_uppercase()
                        .as_str(),
                )
                && !p.ends_with([' ', '.'])
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        && Path::new(s)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
}
fn literal_span(case: &Case, path: &str, range: [u32; 2]) -> Result<String, String> {
    if !safe_path(path) || range[0] == 0 || range[1] < range[0] {
        return Err("invalid evidence span".into());
    }
    let source = case
        .files
        .get(path)
        .ok_or("evidence path missing from files")?;
    let lines: Vec<_> = source.lines().collect();
    if range[1] as usize > lines.len() {
        return Err(format!("{}: evidence span exceeds literal source", case.id));
    }
    Ok(lines[range[0] as usize - 1..range[1] as usize].join("\n"))
}
fn validate(corpus: &Corpus) -> Result<(), String> {
    if corpus.schema != "legion-audit-capsules/1"
        || !corpus.constructed
        || corpus.capsules.is_empty()
        || corpus.capsules.len() > PROVIDERS.len()
    {
        return Err("invalid constructed capsule corpus".into());
    }
    let mut ids = BTreeSet::new();
    for c in &corpus.capsules {
        if !capsule_identity(c)
            || !safe_id(&c.id)
            || !ids.insert(c.id.clone())
            || !PROVIDERS.contains(&c.lens.as_str())
            || c.provider_id != format!("reasoning.{}", c.lens)
            || c.cases.len() != 2
        {
            return Err("duplicate/invalid capsule/provider identity".into());
        }
        match &c.contract {
            Contract::Text(s) if s.trim().is_empty() => return Err("empty contract".into()),
            Contract::Structured(v)
                if v.invariant.trim().is_empty()
                    || v.supporting_files.is_empty()
                    || v.reachable_callers.is_empty() =>
            {
                return Err("invalid structured contract".into())
            }
            _ => {}
        }
        if c.cases.iter().filter(|k| k.kind == Kind::Clean).count() != 1 {
            return Err("capsule requires one planted & one clean case".into());
        }
        for k in &c.cases {
            if !safe_id(&k.id)
                || !ids.insert(k.id.clone())
                || k.files.is_empty()
                || k.files.len() > 64
                || k.required_evidence.is_empty()
                || k.forbidden_claims.is_empty()
                || k.forbidden_claims.iter().any(|s| s.trim().is_empty())
                || (k.kind == Kind::Clean) != k.expected.is_empty()
            {
                return Err("invalid case population/expectations".into());
            }
            let mut paths = BTreeSet::new();
            let mut total = 0usize;
            for (p, s) in &k.files {
                total += s.len();
                if !safe_path(p)
                    || !paths.insert(p.to_ascii_lowercase())
                    || s.len() > 256 * 1024
                    || s.contains('\0')
                {
                    return Err("unsafe/colliding file path or source size".into());
                }
            }
            if total > MAX_JSON
                || paths
                    .iter()
                    .any(|p| paths.iter().any(|q| q.starts_with(&format!("{p}/"))))
            {
                return Err("source size/path prefix collision".into());
            }
            let mut evidence = BTreeSet::new();
            for span in &k.required_evidence {
                if literal_span(k, &span.path, span.line_range)?
                    .trim()
                    .is_empty()
                {
                    return Err("empty required evidence span".into());
                }
                if !["contract", "caller", "behavior"].contains(&span.role.as_str())
                    || !evidence.insert((span.path.clone(), span.line_range, span.role.clone()))
                {
                    return Err("invalid/duplicate required evidence".into());
                }
            }
            for role in ["contract", "caller", "behavior"] {
                if !k.required_evidence.iter().any(|s| s.role == role) {
                    return Err(format!("missing {role} evidence"));
                }
            }
            for e in &k.expected {
                literal_span(k, &e.path, e.line_range)?;
                if e.claim.trim().is_empty()
                    || !["critical", "high", "medium", "low", "info"].contains(&e.severity.as_str())
                {
                    return Err("invalid expected claim/severity".into());
                }
            }
            if let Contract::Structured(v) = &c.contract {
                for p in &v.supporting_files {
                    if !safe_path(p) || !k.files.contains_key(p) {
                        return Err("contract supporting file missing".into());
                    }
                }
            }
        }
    }
    Ok(())
}
fn parse(bytes: &[u8]) -> Result<Corpus, String> {
    if bytes.len() > MAX_JSON {
        return Err("capsule corpus exceeds byte bound".into());
    }
    let corpus: Corpus = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    validate(&corpus)?;
    Ok(corpus)
}
fn materialize(case: &Case, root: &Path) -> Result<(), String> {
    // create_dir (not create_dir_all) refuses reuse, links & preexisting case roots.
    fs::create_dir(root).map_err(|e| e.to_string())?;
    for (p, s) in &case.files {
        if !safe_path(p) {
            return Err("unsafe materialization path".into());
        }
        let path = root.join(p);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        f.write_all(s.as_bytes()).map_err(|e| e.to_string())?;
    }
    verify_materialized(case, root)
}
fn verify_materialized(case: &Case, root: &Path) -> Result<(), String> {
    let mut observed = BTreeMap::new();
    for e in walkdir::WalkDir::new(root).follow_links(false) {
        let e = e.map_err(|e| e.to_string())?;
        if e.file_type().is_symlink() {
            return Err("materialized source contains symlink".into());
        }
        if e.file_type().is_file() {
            let path = e
                .path()
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            observed.insert(
                path,
                digest(&fs::read(e.path()).map_err(|e| e.to_string())?),
            );
        } else if !e.file_type().is_dir() {
            return Err("materialized source contains special file".into());
        }
    }
    let expected: BTreeMap<_, _> = case
        .files
        .iter()
        .map(|(p, s)| (p.clone(), digest(s.as_bytes())))
        .collect();
    if observed != expected {
        return Err("materialized source differs from exact files map".into());
    }
    Ok(())
}
fn command(
    binary: &Path,
    args: &[String],
    cwd: &Path,
    logs: &Path,
    label: &str,
) -> Result<Value, String> {
    let out = fs::File::create(logs.join(format!("{label}.stdout"))).map_err(|e| e.to_string())?;
    let err = fs::File::create(logs.join(format!("{label}.stderr"))).map_err(|e| e.to_string())?;
    let started = std::time::Instant::now();
    let result = audit_bench::run_bounded_with_stderr(
        binary,
        args,
        cwd,
        Stdio::from(out),
        Stdio::from(err),
        Duration::from_secs(600),
    );
    Ok(match result {
        Ok(status) => {
            json!({"status":"exited","exitCode":status.code(),"success":status.success(),"wallTimeMs":started.elapsed().as_millis(),"args":args})
        }
        Err(error) => {
            json!({"status":"failed","error":error,"wallTimeMs":started.elapsed().as_millis(),"args":args})
        }
    })
}
// The synthetic repository exists only in this new scratch case. No branch ref,
// checkout, clone, worktree, hook, project script or filter is used.
fn fixture_git(root: &Path, logs: &Path, label: &str, tail: &[&str]) -> Result<String, String> {
    let mut args: Vec<String> = [
        "-c",
        "core.hooksPath=",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.safecrlf=false",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=Legion constructed capsule",
        "-c",
        "user.email=capsule@invalid.example",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(tail.iter().map(|s| s.to_string()));
    let stdout = logs.join(format!("git-{label}.stdout"));
    let stderr = logs.join(format!("git-{label}.stderr"));
    let mut cmd = rightkit_child_process::OwnedCommand::new("git");
    cmd.env_allowlist(["PATH", "SystemRoot", "WINDIR", "TMP", "TEMP"]);
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    cmd.command_mut()
        .args(&args)
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_ATTR_NOSYSTEM", "1")
        .stdin(Stdio::null())
        .stdout(fs::File::create(&stdout).map_err(|e| e.to_string())?)
        .stderr(fs::File::create(stderr).map_err(|e| e.to_string())?);
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let result = child.wait_timeout(Duration::from_secs(30));
    let status = match result {
        Ok(Some(s)) => s,
        other => {
            let _ = child.terminate_tree_bounded(Duration::from_secs(2));
            return Err(format!("fixture git {label} failed/timed out: {other:?}"));
        }
    };
    if !status.success() {
        return Err(format!("fixture git {label} exited {:?}", status.code()));
    }
    let meta = fs::metadata(&stdout).map_err(|e| e.to_string())?;
    if meta.len() > 64 * 1024 {
        return Err("fixture Git output exceeded bound".into());
    }
    fs::read_to_string(stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|e| e.to_string())
}
fn fixture_repository(case: &Case, root: &Path, logs: &Path) -> Result<Value, String> {
    verify_materialized(case, root)?;
    let template = logs.join("empty-git-template");
    fs::create_dir(&template).map_err(|e| e.to_string())?;
    fixture_git(
        root,
        logs,
        "init",
        &[
            "init",
            "--quiet",
            "--template",
            template.to_str().ok_or("non-UTF8 scratch path")?,
            ".",
        ],
    )?;
    // Explicit exact pathspecs avoid .gitignore/global exclude effects; no .gitattributes
    // is admitted by safe_path, so no source-controlled conversion/filter runs.
    let mut paths = vec!["add", "--force", "--"];
    paths.extend(case.files.keys().map(String::as_str));
    fixture_git(root, logs, "index", &paths)?;
    let tree = fixture_git(root, logs, "tree", &["write-tree"])?;
    let oid = |s: &str| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !oid(&tree) {
        return Err("invalid fixture tree object".into());
    }
    let commit = fixture_git(
        root,
        logs,
        "commit",
        &[
            "commit-tree",
            &tree,
            "--no-gpg-sign",
            "-m",
            "Constructed semantic capsule source; no historical claim",
        ],
    )?;
    if !oid(&commit) {
        return Err("invalid fixture commit object".into());
    }
    fixture_git(
        root,
        logs,
        "head",
        &["update-ref", "--no-deref", "HEAD", &commit],
    )?;
    if !fixture_git(root, logs, "refs", &["for-each-ref", "--format=%(refname)"])?.is_empty() {
        return Err("synthetic fixture unexpectedly has branch/tag refs".into());
    }
    // Git adds only .git. Verify original source bytes separately after admission.
    for (p, s) in &case.files {
        if fs::read(root.join(p)).map_err(|e| e.to_string())? != s.as_bytes() {
            return Err("fixture source changed during Git preparation".into());
        }
    }
    Ok(
        json!({"scope":"constructed-scratch-fixture","tree":tree,"rootCommit":commit,"branchRefs":[],"historicalClaim":false}),
    )
}

fn required_delivery(case: &Case, requests: &[ReasoningInvocation]) -> Result<Value, String> {
    let mut rows = Vec::new();
    for span in &case.required_evidence {
        let literal = literal_span(case, &span.path, span.line_range)?;
        for n in span.line_range[0]..=span.line_range[1] {
            let expected = case.files[&span.path]
                .lines()
                .nth(n as usize - 1)
                .ok_or("missing literal line")?;
            let delivered = requests.iter().any(|r| {
                r.packet["excerpts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|e| {
                        if e["path"] != span.path
                            || e["sourceSide"] != "selected"
                            || e["mode"].as_str().is_none_or(|s| {
                                !["raw", "skeleton", "regions"]
                                    .iter()
                                    .any(|known| s.eq_ignore_ascii_case(known))
                            })
                            || e["truncated"] != false
                            || e["redacted"] != false
                        {
                            return false;
                        }
                        let Some(start) = e["startLine"].as_u64() else {
                            return false;
                        };
                        let Some(end) = e["endLine"].as_u64() else {
                            return false;
                        };
                        let Some(content) = e["content"].as_str() else {
                            return false;
                        };
                        // Known modes receive identical literal, positional checks.
                        // A collapsed run destroys this direct line mapping; neither
                        // anchors nor file membership restore absent source bytes.
                        start > 0
                            && end >= start
                            && content.lines().count() as u64 == end - start + 1
                            && n as u64 >= start
                            && n as u64 <= end
                            && content.lines().nth((n as u64 - start) as usize) == Some(expected)
                    })
            });
            if !delivered {
                return Err(format!(
                    "required literal evidence not delivered: {}:{n}",
                    span.path
                ));
            }
        }
        rows.push(json!({"span":span,"literal":literal,"literalDigest":digest(literal.as_bytes()),"status":"authenticated-delivery-only"}));
    }
    Ok(json!(rows))
}
fn same_invocation(
    r: &ReasoningInvocation,
    c: &Capsule,
    plan: &legion_audit::FrozenPlan,
    snapshot: &FrozenSnapshot,
) -> Result<(), String> {
    r.validate()?;
    if r.provider_id != c.provider_id
        || r.plan_digest != plan.digest()
        || Some(r.plan_signature.as_str()) != plan.signature()
        || r.repository_id != plan.plan().repository_id
        || r.inventory_digest != plan.plan().inventory_digest
        || r.inventory_generation != plan.plan().inventory_generation
        || r.packet
            .pointer("/reviewContext/snapshotKey")
            .and_then(Value::as_str)
            != Some(snapshot.manifest.key.as_str())
    {
        return Err("cross-provider/plan/snapshot invocation substitution".into());
    }
    let provider = plan
        .provider(&c.provider_id)
        .ok_or("selected provider missing from sealed plan")?;
    if provider.not_applicable()
        || provider
            .configuration
            .get("denominatorDigest")
            .and_then(Value::as_str)
            != Some(r.denominator_digest.as_str())
        || provider
            .configuration
            .get("denominatorCount")
            .and_then(Value::as_u64)
            != Some(r.denominator_count)
    {
        return Err("inapplicable/unbound capsule provider denominator".into());
    }
    Ok(())
}
fn authenticated_case(
    case: &Case,
    capsule: &Capsule,
    source: &Path,
    run: &Path,
) -> Result<Value, String> {
    let (plan, _, _) = ingest::frozen_reasoning_basis(run).map_err(|e| e.to_string())?;
    let outer = read_json(&run.join("plan.json"))?;
    let manifest = outer
        .pointer("/reviewContext/snapshotManifest")
        .and_then(Value::as_str)
        .ok_or("snapshot manifest missing")?;
    let snapshot = FrozenSnapshot::open(Path::new(manifest)).map_err(|e| e.to_string())?;
    if snapshot.manifest.scope.source_root != source {
        return Err("snapshot source belongs to another capsule case".into());
    }
    let expected: BTreeMap<_, _> = case
        .files
        .iter()
        .map(|(p, s)| (p.clone(), digest(s.as_bytes())))
        .collect();
    let actual: BTreeMap<_, _> = snapshot
        .manifest
        .files
        .iter()
        .map(|(p, f)| (p.clone(), f.digest.clone()))
        .collect();
    if expected != actual {
        return Err("sealed case snapshot differs from exact capsule files".into());
    }
    let mut packets = Vec::new();
    let mut proofs = Vec::new();
    let mut paths: Vec<_> = fs::read_dir(run.join(ingest::LENS_PACKET_DIR))
        .map_err(|e| e.to_string())?
        .map(|e| e.map(|e| e.path()).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    paths.sort();
    for path in paths {
        if path.extension().and_then(|s| s.to_str()) != Some("json")
            || path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(".index.json"))
        {
            continue;
        }
        let work: PendingLensWork =
            serde_json::from_value(read_json(&path)?).map_err(|e| e.to_string())?;
        if work.provider_id != capsule.provider_id || work.request.provider_id != work.provider_id {
            return Err("unexpected provider packet in exact capsule run".into());
        }
        same_invocation(&work.request, capsule, &plan, &snapshot)?;
        let proof = ingest::authenticated_runtime_evidence(run, &work.request)
            .map_err(|e| e.to_string())?;
        if proof["delivery"].is_null() || proof["verification"].is_null() {
            return Err("missing authenticated delivery/fresh verifier evidence".into());
        }
        proofs.push(json!({"requestId":work.request.request_id,"packetDigest":canonical(&work.request.packet)?,"invocationDigest":canonical(&work.request)?,"proof":proof}));
        packets.push(work.request);
    }
    if packets.is_empty() {
        return Err("selected provider produced no applicable packet".into());
    }
    let required = required_delivery(case, &packets)?;
    let recomputed = ingest::recompute_run(run).map_err(|e| e.to_string())?;
    if recomputed.pending.iter().any(|p| p == &capsule.provider_id)
        || !recomputed
            .ingested
            .iter()
            .any(|p| p == &capsule.provider_id)
    {
        return Err("capsule provider lacks fully authenticated ingest".into());
    }
    let result = recomputed
        .execution
        .results
        .iter()
        .find(|r| r.provider == capsule.provider_id)
        .ok_or("selected provider execution missing")?;
    if result.skipped
        || !result.result.applicable
        || !result.result.complete
        || !result.result.coverage_gaps.is_empty()
    {
        return Err("capsule selected provider incomplete/inapplicable".into());
    }
    if recomputed
        .report
        .findings
        .iter()
        .any(|f| f.provider.as_deref() != Some(capsule.provider_id.as_str()))
    {
        return Err("cross-provider final finding substitution".into());
    }
    let final_findings =
        serde_json::to_value(&recomputed.report.findings).map_err(|e| e.to_string())?;
    let mut originals = Vec::new();
    let mut ledgers = Vec::new();
    for proof in &proofs {
        for row in proof
            .pointer("/proof/verification/findings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            originals.push(json!({"requestId":proof["requestId"],"packetDigest":proof["packetDigest"],"finding":row["authorFinding"]}));
            ledgers.push(json!({"requestId":proof["requestId"],"packetDigest":proof["packetDigest"],"disposition":row}));
        }
    }
    let negative: Vec<_> = proofs
        .iter()
        .filter_map(|p| p.pointer("/proof/verification/negativeReview"))
        .cloned()
        .collect();
    let original_projection = json!(originals);
    let score = location_score(
        case,
        final_findings
            .as_array()
            .ok_or("final findings malformed")?,
    );
    Ok(
        json!({"providerId":capsule.provider_id,"caseDigest":canonical(case)?,"planDigest":plan.digest(),"planSignature":plan.signature(),"snapshotKey":snapshot.manifest.key,"proofs":proofs,"requiredEvidence":required,"originalAuthorFindings":original_projection,"verifierFindings":ledgers,"negativeReviews":negative,"authenticatedProviderResult":result.result,"finalFindings":final_findings,"score":score,"semanticClaimCorrectness":"unadjudicated","sourceContractDelivery":"requiredEvidence-source-files-only","narrativeMetadataDelivered":false,"narrativeMetadataIntentionallyExcluded":true,"contractCoverageBasis":"capsule-declared source spans; semantic invariant sufficiency unadjudicated"}),
    )
}
// Finding identity/provider is established before this purely mechanical scorer.
// A matching location or an upheld verdict is never a claim-equivalence result.
fn location_score(case: &Case, findings: &[Value]) -> Value {
    let mut matched = BTreeSet::new();
    let expected: Vec<_> = case.expected.iter().map(|e| {
        let hits: Vec<_> = findings.iter().enumerate().filter(|(_,f)|f["locations"].as_array().into_iter().flatten().filter_map(Value::as_str).map(audit_bench::parse_location).any(|l|l.path == e.path && l.start.zip(l.end).is_some_and(|(s,t)|s<=e.line_range[1] && t>=e.line_range[0]))).map(|(i,f)| {matched.insert(i);json!({"findingId":f["id"],"observedClaim":{"title":f["title"],"message":f["message"]},"observedSeverity":f["severity"],"severityMatch":f["severity"]==e.severity,"semanticClaimCorrectness":"unadjudicated"})}).collect();
        json!({"expected":e,"locationMatched":!hits.is_empty(),"observed":hits,"semanticClaimCorrectness":"unadjudicated"})
    }).collect();
    let hits = expected
        .iter()
        .filter(|e| e["locationMatched"] == true)
        .count();
    json!({"expectedCount":case.expected.len(),"locationHits":hits,"locationMisses":case.expected.len()-hits,"extras":findings.iter().enumerate().filter(|(i,_)|!matched.contains(i)).map(|(_,f)|f).collect::<Vec<_>>(),"expectedAndObserved":expected,"zeroFinalFindings":findings.is_empty(),"cleanCase":case.kind==Kind::Clean,"semanticClaimCorrectness":"unadjudicated","forbiddenClaimAssessment":"unadjudicated","forbiddenClaims":case.forbidden_claims})
}
fn usage(run: &Path, runtime: &Value) -> Result<Value, String> {
    let mut files: Vec<_> = fs::read_dir(run.join("runtime-calls"))
        .map_err(|e| e.to_string())?
        .map(|e| e.map(|e| e.path()).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    files.sort();
    if files.len() > 4096 {
        return Err("runtime call count exceeds bound".into());
    }
    let mut totals = [0u64; 4];
    let mut ids = BTreeSet::new();
    let mut stages = BTreeSet::new();
    let mut calls = Vec::new();
    for path in files {
        let envelope = read_json(&path)?;
        let call = ingest::verify_runtime_call(run, &envelope).map_err(|e| e.to_string())?;
        if call["strictNoRetry"] != true
            || !ids.insert(
                call["callId"]
                    .as_str()
                    .ok_or("call identity missing")?
                    .to_owned(),
            )
        {
            return Err("non-strict/duplicate runtime call".into());
        }
        let stage = (
            call["seatId"].as_str().ok_or("seat missing")?.to_owned(),
            call.pointer("/execution/stage")
                .and_then(Value::as_str)
                .ok_or("execution stage missing")?
                .to_owned(),
        );
        if !stages.insert(stage) {
            return Err("strict capsule attempted multiple calls for one seat/stage".into());
        }
        for (i, key) in [
            "inputTokens",
            "outputTokens",
            "cachedInputTokens",
            "retryTokens",
        ]
        .iter()
        .enumerate()
        {
            totals[i] = totals[i]
                .checked_add(
                    call["observation"]["usage"][*key]
                        .as_u64()
                        .ok_or("authenticated actual usage unknown")?,
                )
                .ok_or("usage overflow")?;
        }
        calls.push(call);
    }
    if runtime["calls"].as_u64() != Some(calls.len() as u64)
        || runtime.get("followup").is_some_and(|v| !v.is_null())
    {
        return Err("runtime call total/followup differs from exact capsule run".into());
    }
    let metrics = audit_bench::runtime_usage(run, runtime);
    if metrics["status"] != "reported"
        || metrics["inputTokens"].as_u64() != Some(totals[0])
        || metrics["outputTokens"].as_u64() != Some(totals[1])
        || metrics["cachedInputTokens"].as_u64() != Some(totals[2])
        || metrics["retryTokens"].as_u64() != Some(totals[3])
    {
        return Err("runtime usage projection differs from authenticated calls".into());
    }
    Ok(
        json!({"metrics":metrics,"authenticatedCalls":calls,"chargedTokens":totals[0].checked_add(totals[1]).and_then(|n|n.checked_add(totals[3])).ok_or("usage overflow")?}),
    )
}
fn pin(path: &Path) -> Result<Value, String> {
    let actual = path.canonicalize().map_err(|e| e.to_string())?;
    let m = fs::metadata(&actual).map_err(|e| e.to_string())?;
    if !m.is_file() {
        return Err("runtime executable is not a file".into());
    }
    // Stream identity hashing so installed executables need no artificial size cap.
    use std::io::Read;
    let mut file = fs::File::open(&actual).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(json!({"path":actual,"digest":format!("sha256:{}",hex::encode(hasher.finalize()))}))
}
fn retained_diagnostics(run: &Path) -> Value {
    let mut rows = Vec::new();
    for dir in [
        run.to_path_buf(),
        run.join("runtime-author-results"),
        run.join("lens-results"),
    ] {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if dir == run
                && !["report.json", "review-runtime.json"]
                    .contains(&p.file_name().and_then(|s| s.to_str()).unwrap_or(""))
            {
                continue;
            }
            rows.push(match read_json(&p) { Ok(value)=>json!({"path":p,"value":value,"admission":"diagnostic-only; scoring requires authenticatedCase"}),Err(error)=>json!({"path":p,"error":error}) });
        }
    }
    json!(rows)
}
fn attempt(
    opts: &Options,
    capsule: &Capsule,
    case: &Case,
    parent: &Path,
    allocation: u64,
    pins: &Value,
) -> (Value, Option<u64>) {
    let mut row = json!({"status":"failed","providerId":capsule.provider_id,"capsuleId":capsule.id,"caseId":case.id,"kind":case.kind,"caseDigest":canonical(case).ok(),"contract":capsule.contract,"expected":case.expected,"forbiddenClaims":case.forbidden_claims,"semanticClaimCorrectness":"unadjudicated","modelQualityCertification":false,"CAP-3":"unproven until authenticated requiredEvidence delivery"});
    let mut model_started = false;
    let mut charged = Some(0);
    let run = parent.join("case-run");
    let result = (|| -> Result<(), String> {
        fs::create_dir(parent).map_err(|e| e.to_string())?;
        let source = parent.join("source");
        materialize(case, &source)?;
        row["fixtureRepository"] = fixture_repository(case, &source, parent)?;
        let claude = opts.claude.as_deref().ok_or("--claude required")?;
        if pin(&opts.legion)? != pins["legion"] || pin(claude)? != pins["claude"] {
            return Err("runtime executable changed before case".into());
        }
        let args = vec![
            "audit".into(),
            source.to_string_lossy().into_owned(),
            "--type".into(),
            "repo".into(),
            "--only".into(),
            capsule.provider_id.clone(),
            "--coverage".into(),
            "exhaustive".into(),
            "--run-token-budget".into(),
            allocation.to_string(),
            "--out".into(),
            run.to_string_lossy().into_owned(),
        ];
        row["precursorCommand"] = command(&opts.legion, &args, &source, parent, "audit")?;
        // A nonzero Audit result can mean pending reasoning. A valid report,
        // sealed source & exact target packet are checked after runtime admission.
        let report = read_json(&run.join("report.json"))?;
        fs::write(
            parent.join("precursor-report.json"),
            serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        row["rawPrecursorReport"] = report;
        if row["precursorCommand"]["status"] != "exited" {
            return Err("Audit precursor did not terminate normally".into());
        }
        // Verify case/source/selection seal BEFORE paying for any generation.
        preflight(case, capsule, &source, &run)?;
        let runtime_args = vec![
            "audit".into(),
            "run-reasoning".into(),
            "--run".into(),
            run.to_string_lossy().into_owned(),
            "--claude".into(),
            claude.to_string_lossy().into_owned(),
            "--model".into(),
            opts.model.clone().ok_or("--model required")?,
            "--strict-no-retry".into(),
            "--max-calls-per-packet".into(),
            "1".into(),
        ];
        model_started = true;
        charged = None;
        row["runtimeCommand"] = command(&opts.legion, &runtime_args, &source, parent, "reasoning")?;
        let runtime = read_json(&run.join("review-runtime.json"))?;
        row["rawRuntime"] = runtime.clone();
        match usage(&run, &runtime) {
            Ok(value) => {
                charged = value["chargedTokens"].as_u64();
                row["usage"] = value;
            }
            Err(e) => {
                row["usage"] = json!({"status":"unknown","reason":e});
            }
        }
        if pin(&opts.legion)? != pins["legion"] || pin(claude)? != pins["claude"] {
            return Err("runtime executable changed during case".into());
        }
        row["authenticatedCase"] = authenticated_case(case, capsule, &source, &run)?;
        row["CAP-3"] = json!("authenticated-required-source-delivery");
        if row["runtimeCommand"]["success"] != true
            || runtime["status"] != "done"
            || runtime["complete"] != true
            || charged.is_none()
        {
            return Err("runtime incomplete or actual usage unknown".into());
        }
        row["status"] = json!("completed");
        Ok(())
    })();
    if let Err(error) = result {
        row["error"] = json!(error);
    }
    row["modelRuntimeAttempted"] = json!(model_started);
    row["retainedDiagnostics"] = retained_diagnostics(&run);
    row["run"] = json!(run);
    // Retain every partial/unstarted outcome without giving diagnostic JSON credit.
    if parent.is_dir() {
        if let Err(error) = serde_json::to_vec_pretty(&row)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                fs::write(parent.join("outcome.json"), bytes).map_err(|e| e.to_string())
            })
        {
            row["status"] = json!("failed");
            row["retentionError"] = json!(error);
        }
    }
    (row, charged)
}
fn preflight(case: &Case, capsule: &Capsule, source: &Path, run: &Path) -> Result<(), String> {
    let (plan, _, _) = ingest::frozen_reasoning_basis(run).map_err(|e| e.to_string())?;
    let outer = read_json(&run.join("plan.json"))?;
    let snapshot = FrozenSnapshot::open(Path::new(
        outer
            .pointer("/reviewContext/snapshotManifest")
            .and_then(Value::as_str)
            .ok_or("snapshot missing")?,
    ))
    .map_err(|e| e.to_string())?;
    if snapshot.manifest.scope.source_root != source
        || snapshot.manifest.files.len() != case.files.len()
    {
        return Err("wrong capsule source root/population".into());
    }
    for (p, s) in &case.files {
        if snapshot
            .read(p, SnapshotSide::Selected, 256 * 1024)
            .map_err(|e| e.to_string())?
            != s.as_bytes()
        {
            return Err("capsule snapshot source mismatch".into());
        }
    }
    let mut requests = Vec::new();
    for e in fs::read_dir(run.join(ingest::LENS_PACKET_DIR)).map_err(|e| e.to_string())? {
        let p = e.map_err(|e| e.to_string())?.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json")
            || p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(".index.json"))
        {
            continue;
        }
        let work: PendingLensWork =
            serde_json::from_value(read_json(&p)?).map_err(|e| e.to_string())?;
        if work.provider_id != capsule.provider_id {
            return Err("provider dependency/selection differs from exact capsule".into());
        }
        same_invocation(&work.request, capsule, &plan, &snapshot)?;
        requests.push(work.request);
    }
    if requests.is_empty() {
        return Err("capsule unavailable/inapplicable or dependencies not satisfied".into());
    }
    required_delivery(case, &requests)?; // structural only here; authentication required after runtime.
    Ok(())
}
pub(super) fn run(root: &Path, opts: &Options) -> Result<bool, String> {
    if !opts.fixtures.is_empty() || !opts.cases.is_empty() {
        return Err("--capsule cannot combine bundle --fixture/--case selection".into());
    }
    if !opts.with_lenses
        || opts.claude.is_none()
        || opts.model.as_deref().is_none_or(|m| m.trim().is_empty())
    {
        return Err(
            "capsules require --with-lenses, --claude & --model; no default model calls".into(),
        );
    }
    let total = opts
        .capsule_token_budget
        .filter(|n| *n > 0)
        .ok_or("explicit positive --capsule-token-budget required")?;
    let per_case = opts
        .capsule_case_token_budget
        .filter(|n| *n > 0)
        .ok_or("explicit positive --capsule-case-token-budget required")?;
    if per_case > total {
        return Err("capsule case budget exceeds separate total allowance".into());
    }
    let selected: BTreeSet<_> = opts.capsules.iter().cloned().collect();
    if selected.len() != opts.capsules.len() {
        return Err("duplicate capsule selection".into());
    }
    let mut capsules = Vec::new();
    let mut corpus_pins = Vec::new();
    let mut ids = BTreeSet::new();
    let mut providers = BTreeSet::new();
    for (name, optional) in [
        ("core.json", false),
        ("conditional.json", false),
        ("security.json", true),
    ] {
        let path = root.join("evals/audit-bench/capsules").join(name);
        if optional && !path.exists() {
            continue;
        }
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;
        let corpus = parse(&bytes)?;
        let found: BTreeSet<_> = corpus.capsules.iter().map(|c| c.lens.as_str()).collect();
        let wanted: BTreeSet<_> = match name {
            "core.json" => PROVIDERS[..7].iter().copied().collect(),
            "conditional.json" => PROVIDERS[7..14].iter().copied().collect(),
            _ => ["security"].into_iter().collect(),
        };
        if found != wanted || found.len() != corpus.capsules.len() {
            return Err(format!(
                "{name}: corpus provider population differs from owned set"
            ));
        }
        for c in &corpus.capsules {
            if !ids.insert(c.id.clone()) || !providers.insert(c.provider_id.clone()) {
                return Err("duplicate cross-corpus capsule/provider".into());
            }
            for case in &c.cases {
                if !ids.insert(case.id.clone()) {
                    return Err("duplicate cross-corpus case".into());
                }
            }
        }
        corpus_pins.push(json!({"path":path,"bytesDigest":digest(&bytes),"parsedDigest":canonical(&corpus)?,"providers":found}));
        capsules.extend(corpus.capsules);
    }
    if selected
        .iter()
        .any(|id| !capsules.iter().any(|c| &c.id == id))
    {
        return Err("unknown capsule selection".into());
    }
    capsules.retain(|c| selected.contains(&c.id));
    let base = opts
        .work_dir
        .as_ref()
        .ok_or("capsules require explicit external --work-dir for retained evidence")?;
    fs::create_dir_all(base).map_err(|e| e.to_string())?;
    let base = base.canonicalize().map_err(|e| e.to_string())?;
    if base.starts_with(root.canonicalize().map_err(|e| e.to_string())?) {
        return Err("capsule evidence directory must be outside audited repository".into());
    }
    let work = base.join(format!(
        "capsules-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    ));
    fs::create_dir(&work).map_err(|e| e.to_string())?;
    let pins = json!({"legion":pin(&opts.legion)?,"claude":pin(opts.claude.as_deref().ok_or("Claude missing")?)?,"approvedModel":opts.model});
    let mut population = Vec::new();
    for arm in if opts.aa { vec!["A", "B"] } else { vec!["A"] } {
        for repeat in 1..=opts.repeat {
            for capsule in &capsules {
                for case in &capsule.cases {
                    population.push(json!({"attempt":format!("{arm}{repeat}-{}-{}",capsule.id,case.id),"capsuleId":capsule.id,"providerId":capsule.provider_id,"caseId":case.id,"caseDigest":canonical(case)?,"kind":case.kind,"expected":case.expected,"forbiddenClaims":case.forbidden_claims,"initialStatus":"unstarted"}));
                }
            }
        }
    }
    let population_path = work.join("capsule-plan.json");
    fs::write(&population_path,serde_json::to_vec_pretty(&json!({"constructed":true,"corpus":corpus_pins,"runtimeIdentity":pins,"population":population,"totalTokens":total,"perCaseTokens":per_case,"semanticClaimCorrectness":"unadjudicated","modelQualityCertification":false})).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let mut budget = TokenBudget::new(total, per_case);
    let mut outcomes = Vec::new();
    for arm in if opts.aa { vec!["A", "B"] } else { vec!["A"] } {
        for repeat in 1..=opts.repeat {
            for capsule in &capsules {
                for case in &capsule.cases {
                    let label = format!("{arm}{repeat}-{}-{}", capsule.id, case.id);
                    let parent = work.join(&label);
                    let mut row = match budget.reserve_case() {
                        Some(allocation) => {
                            let (mut row, actual) =
                                attempt(opts, capsule, case, &parent, allocation, &pins);
                            budget.settle_case(allocation, actual);
                            row["reservationTokens"] = json!(allocation);
                            row
                        }
                        None => {
                            json!({"status":"unstarted","reason":"qualification-budget-exhausted-or-unknown","providerId":capsule.provider_id,"capsuleId":capsule.id,"caseId":case.id,"kind":case.kind,"expected":case.expected,"forbiddenClaims":case.forbidden_claims,"caseDigest":canonical(case)?,"semanticClaimCorrectness":"unadjudicated","modelQualityCertification":false})
                        }
                    };
                    row["attempt"] = json!(label);
                    outcomes.push(row);
                    let partial = json!({"kind":"legion-semantic-capsule-observations/1","constructed":true,"corpus":corpus_pins,"selectedCapsules":selected,"runtimeIdentity":pins,"plannedPopulation":population_path,"plannedAttempts":capsules.iter().map(|c|c.cases.len()).sum::<usize>()*opts.repeat as usize*if opts.aa{2}else{1},"caseOutcomes":outcomes,"budget":budget.to_json(),"semanticClaimCorrectness":"unadjudicated","modelQualityCertification":false,"wholeAuditCleanClaim":false,"registryPromotion":false,"missingLifecycleControls":["legacy.security.adjudication","legacy.security.variant-analysis"],"securityCapsulePresent":providers.contains("reasoning.security")});
                    fs::write(
                        work.join("observations.json"),
                        serde_json::to_vec_pretty(&partial).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
    }
    let all_completed = outcomes.iter().all(|r| r["status"] == "completed");
    let summary = json!({"kind":"legion-semantic-capsule-bridge-summary/1","completeExecution":all_completed,"plannedAttempts":outcomes.len(),"completed":outcomes.iter().filter(|r|r["status"]=="completed").count(),"failed":outcomes.iter().filter(|r|r["status"]=="failed").count(),"unstarted":outcomes.iter().filter(|r|r["status"]=="unstarted").count(),"semanticClaimCorrectness":"unadjudicated","modelQualityCertification":false,"wholeAuditCleanClaim":false,"evidence":work.join("observations.json"),"budget":budget.to_json()});
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?
    );
    Ok(all_completed)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn corpus() -> Corpus {
        parse(include_bytes!(
            "../../../../evals/audit-bench/capsules/core.json"
        ))
        .unwrap()
    }
    fn temp() -> PathBuf {
        static SERIAL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base = std::env::var_os("RUNNER_TEMP")
            .or_else(|| std::env::var_os("LEGION_TEST_SCRATCH"))
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    PathBuf::from(r"D:\scratch")
                } else {
                    PathBuf::from("/Volumes/D/scratch")
                }
            });
        fs::create_dir_all(&base).unwrap();
        let root = base.join(format!(
            "legion-capsule-unit-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        root
    }
    fn request(packet: Value) -> ReasoningInvocation {
        serde_json::from_value(json!({"schemaVersion":1,"kind":"legion-reasoning-invocation","requestId":"request","providerId":"reasoning.doc-drift","contract":"lens","planDigest":"plan","planSignature":"signature","repositoryId":"repository","inventoryGeneration":"generation","inventoryDigest":"inventory","denominatorDigest":"denominator","denominatorCount":1,"denominatorPaths":["docs/retries.md"],"packet":packet})).unwrap()
    }
    #[test]
    fn strict_unknown_fields_ids_providers_spans_paths_and_duplicate_files() {
        let valid = corpus();
        for variant in 0..6 {
            let mut value = serde_json::to_value(&valid).unwrap();
            match variant {
                0 => value["capsules"][0]["surprise"] = json!(true),
                1 => value["capsules"][1]["id"] = value["capsules"][0]["id"].clone(),
                2 => value["capsules"][0]["providerId"] = json!("reasoning.security"),
                3 => {
                    value["capsules"][0]["cases"][0]["requiredEvidence"][0]["lineRange"] =
                        json!([1, 999])
                }
                4 => {
                    value["capsules"][0]["cases"][0]["files"]["../outside"] = json!("source");
                }
                _ => {
                    value["capsules"][0]["cases"][1]["id"] =
                        value["capsules"][0]["cases"][0]["id"].clone()
                }
            }
            assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let duplicate = r#"{"x":"first","x":"second"}"#;
        #[derive(Deserialize)]
        struct FilesOnly(#[serde(deserialize_with = "unique_files")] BTreeMap<String, String>);
        assert!(serde_json::from_str::<FilesOnly>(duplicate).is_err());
        for p in [
            "../x",
            "/x",
            "x/../y",
            ".git/config",
            "a/.gitattributes",
            "a\\b",
            "a:b",
            "CON.txt",
            "x//y",
        ] {
            assert!(!safe_path(p), "{p}");
        }
    }
    #[test]
    fn mandatory_corpora_parse_with_workflow_source_and_without_git_controls() {
        let core = corpus();
        let conditional = parse(include_bytes!(
            "../../../../evals/audit-bench/capsules/conditional.json"
        ))
        .unwrap();
        assert_eq!(core.capsules.len(), PROVIDERS[..7].len());
        assert_eq!(conditional.capsules.len(), PROVIDERS[7..14].len());
        assert!(conditional
            .capsules
            .iter()
            .flat_map(|c| &c.cases)
            .any(|case| { case.files.contains_key(".github/workflows/platforms.yml") }));
        assert!(safe_path(".github/workflows/platforms.yml"));
        for p in [
            ".github",
            "src/.github/file",
            ".github/../file",
            ".github/.git/config",
            ".GIT/config",
            ".gitmodules",
            ".gitattributes",
            ".gitignore",
            "src/.hidden/file",
        ] {
            assert!(!safe_path(p), "{p}");
        }
    }
    #[test]
    fn materialization_is_exact_and_scoring_answers_remain_outside_source() {
        let case = corpus().capsules.remove(0).cases.remove(0);
        let parent = temp();
        let source = parent.join("source");
        materialize(&case, &source).unwrap();
        verify_materialized(&case, &source).unwrap();
        assert!(materialize(&case, &source).is_err());
        assert!(!source.join("expected.json").exists());
        fs::write(source.join("injected.txt"), "not capsule source").unwrap();
        assert!(verify_materialized(&case, &source).is_err());
        fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn location_and_severity_matches_do_not_adjudicate_claims() {
        let case = corpus().capsules.remove(0).cases.remove(0);
        let findings = vec![
            json!({"id":"one","locations":["docs/retries.md:4"],"severity":"medium","title":"Opposite semantic claim","message":"Runtime permits three retries."}),
            json!({"id":"extra","locations":["src/client.ts:1"],"severity":"high","title":"Other","message":"Other"}),
        ];
        let score = location_score(&case, &findings);
        assert_eq!(score["locationHits"], 1);
        assert_eq!(score["extras"].as_array().unwrap().len(), 1);
        assert_eq!(score["semanticClaimCorrectness"], "unadjudicated");
        assert_eq!(
            score["expectedAndObserved"][0]["observed"][0]["severityMatch"],
            true
        );
        assert_eq!(
            location_score(&case, &[])["locationMisses"],
            case.expected.len()
        );
    }
    #[test]
    fn delivered_literal_span_rejects_missing_redacted_and_changed_source() {
        let case = corpus().capsules.remove(0).cases.remove(0);
        let excerpts:Vec<_>=case.files.iter().map(|(p,s)|json!({"path":p,"sourceSide":"selected","mode":"raw","truncated":false,"redacted":false,"startLine":1,"endLine":s.lines().count(),"content":s})).collect();
        let r = request(json!({"excerpts":excerpts}));
        assert!(required_delivery(&case, &[r.clone()]).is_ok());
        for mutation in 0..4 {
            let mut tampered = r.clone();
            match mutation {
                0 => tampered.packet["excerpts"] = json!([]),
                1 => tampered.packet["excerpts"][0]["redacted"] = json!(true),
                2 => tampered.packet["excerpts"][0]["content"] = json!("changed"),
                _ => tampered.packet["excerpts"][0]["sourceSide"] = json!("base"),
            }
            assert!(required_delivery(&case, &[tampered]).is_err());
        }
    }
    #[test]
    fn known_excerpt_modes_require_literal_bytes_at_original_line_offsets() {
        let case = corpus().capsules.remove(0).cases.remove(0);
        for mode in ["raw", "skeleton", "regions"] {
            let excerpts: Vec<_> = case
                .files
                .iter()
                .map(|(p, s)| {
                    json!({
                        "path":p,"sourceSide":"selected","mode":mode,"truncated":false,
                        "redacted":false,"startLine":1,"endLine":s.lines().count(),"content":s
                    })
                })
                .collect();
            let exact = request(json!({"excerpts":excerpts}));
            assert!(required_delivery(&case, &[exact.clone()]).is_ok(), "{mode}");
            for mutation in 0..6 {
                let mut changed = exact.clone();
                let excerpt = &mut changed.packet["excerpts"][0];
                match mutation {
                    0 => excerpt["content"] = json!("    { ... }\n"),
                    1 => {
                        // Same line count preserves offsets but omitted body is absent.
                        let source = excerpt["content"].as_str().unwrap();
                        let mut lines: Vec<_> = source.lines().map(str::to_owned).collect();
                        lines[0] = "    { ... }".into();
                        excerpt["content"] = json!(lines.join("\n"));
                    }
                    2 => excerpt["startLine"] = json!(2),
                    3 => excerpt["truncated"] = json!(true),
                    4 => excerpt["mode"] = json!("unknown"),
                    _ => {
                        // Correct bytes at wrong original offsets give no credit.
                        let source = excerpt["content"].as_str().unwrap();
                        excerpt["content"] = json!(format!("shifted\n{source}"));
                        excerpt["endLine"] = json!(excerpt["endLine"].as_u64().unwrap() + 1);
                    }
                }
                assert!(
                    required_delivery(&case, &[changed]).is_err(),
                    "{mode}/{mutation}"
                );
            }
        }
    }
    #[test]
    fn receipt_shaped_json_cannot_supply_authenticated_runtime_evidence() {
        let parent = temp();
        let r = request(json!({"excerpts":[]}));
        assert!(ingest::authenticated_runtime_evidence(&parent, &r).is_err());
        fs::create_dir(parent.join("runtime-calls")).unwrap();
        fs::write(
            parent.join("runtime-calls/fake.json"),
            br#"{"complete":true,"observation":{"usage":{"inputTokens":0,"outputTokens":0}}}"#,
        )
        .unwrap();
        assert!(usage(&parent, &json!({"calls":1})).is_err());
        fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn unknown_usage_halts_and_unstarted_cases_cannot_reclaim_allowance() {
        let mut b = TokenBudget::new(100, 60);
        let reservation = b.reserve_case().unwrap();
        assert_eq!(reservation, 60);
        b.settle_case(reservation, None);
        assert!(b.reserve_case().is_none());
        assert_eq!(b.to_json()["unknownUsageCases"], 1);
        assert_eq!(b.to_json()["remainingTokens"], 40);
        let mut b = TokenBudget::new(100, 60);
        let r = b.reserve_case().unwrap();
        b.settle_case(r, Some(80));
        assert!(b.reserve_case().is_none());
        assert_eq!(b.to_json()["overrunTokens"], 20);
    }
}
