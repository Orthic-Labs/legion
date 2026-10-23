//! `security.surface-model`: deterministic, revision-bound security surface
//! model. Covers entrypoint/asset/boundary derivation from fixtures, evidence
//! binding, fail-closed gaps, SEC section 6.7 applicability, and graph binding.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use legion_audit::graph_context::{scoped_bytes_digest, ContextEdge, GraphContext, SourceSpan};
use legion_audit::native_providers::security::surface_model::{
    build_security_model, SecurityModel, SurfaceModelInput, MODEL_KIND, PROVIDER_ID,
};
use legion_audit::source_cache::bytes_digest;
use legion_audit::{InventoryEntry, InventoryEnvelope};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const PLAN: &str = "sha256:plan";

fn fixture_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/security-surface-model")
        .join(name)
}

fn load_dir(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).expect("read fixture dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .expect("relative")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, fs::read(&path).expect("read fixture"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn envelope(files: &BTreeMap<String, Vec<u8>>) -> InventoryEnvelope {
    let entries = files
        .iter()
        .map(|(path, bytes)| InventoryEntry {
            path: path.clone(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: [".js", ".rs", ".py", ".ts", ".go"]
                .iter()
                .any(|e| path.ends_with(e)),
            digest: Some(format!("sha256:{}", bytes_digest(bytes))),
        })
        .collect();
    InventoryEnvelope::new("repo", "gen-1", entries).expect("inventory envelope")
}

fn build(
    inv: &InventoryEnvelope,
    files: &BTreeMap<String, Vec<u8>>,
    graph: Option<&GraphContext>,
    plan: Option<&str>,
) -> SecurityModel {
    build_security_model(&SurfaceModelInput {
        inventory: inv,
        files,
        graph,
        repository_revision: REVISION,
        plan_digest: plan,
        cortex_generation_id: Some("cortex-1"),
    })
}

fn model_of(files: &BTreeMap<String, Vec<u8>>) -> SecurityModel {
    build(&envelope(files), files, None, Some(PLAN))
}

fn fixture_model(name: &str) -> SecurityModel {
    model_of(&load_dir(&fixture_root(name)))
}

fn names<'a>(m: &'a SecurityModel, kind: &str, sub: &str) -> BTreeSet<&'a str> {
    m.entities_of(kind, sub)
        .iter()
        .map(|e| e.name.as_str())
        .collect()
}

fn domain<'a>(
    m: &'a SecurityModel,
    id: &str,
) -> &'a legion_audit::native_providers::security::surface_model::DomainApplicability {
    m.applicability
        .iter()
        .find(|d| d.domain_id == id)
        .expect("domain row")
}

fn gap<'a>(
    m: &'a SecurityModel,
    kind: &str,
) -> Option<&'a legion_audit::native_providers::security::surface_model::ModelGap> {
    m.gaps.iter().find(|g| g.kind == kind)
}

#[test]
fn web_app_entrypoints_assets_and_evidence() {
    let files = load_dir(&fixture_root("web-app"));
    let m = model_of(&files);

    assert_eq!(m.kind, MODEL_KIND);
    assert_eq!(m.provider, PROVIDER_ID);

    let routes = names(&m, "entrypoint", "http-route");
    assert!(routes.contains("GET /api/users"), "{routes:?}");
    assert!(routes.contains("POST /api/login"));
    assert!(routes.contains("DELETE /admin/users/:id"));
    // `app.get('port')` is an express setting, not a route.
    assert!(!routes.iter().any(|r| r.contains("port")));
    assert_eq!(
        names(&m, "entrypoint", "webhook"),
        BTreeSet::from(["POST /webhooks/stripe"])
    );
    assert_eq!(
        names(&m, "entrypoint", "queue-consumer"),
        BTreeSet::from(["emails"])
    );
    assert!(names(&m, "entrypoint", "scheduled-job").contains("cron 0 3 * * *"));
    assert!(names(&m, "entrypoint", "ci-trigger").contains("pull_request_target"));

    // Guard token proximity is recorded but never claimed as enforcement.
    let users = m
        .entities
        .iter()
        .find(|e| e.name == "GET /api/users")
        .expect("users route");
    assert_eq!(
        users.attributes["authObservation"],
        "guard-token-near-declaration"
    );
    let login = m
        .entities
        .iter()
        .find(|e| e.name == "POST /api/login")
        .unwrap();
    assert_eq!(login.attributes["authObservation"], "none-observed");
    let guards = m.entities_of("control", "auth-guard-token");
    assert!(!guards.is_empty());
    assert!(guards
        .iter()
        .all(|g| g.attributes["controlState"] == "unknown"));
    // The guard window must not leak across route declarations.
    assert!(m
        .relations
        .iter()
        .filter(|r| r.kind == "protects" && r.to == login.id)
        .next()
        .is_none());

    // Assets / crown jewels.
    assert!(names(&m, "crown-jewel", "secret").contains("STRIPE_SECRET_KEY"));
    assert!(!names(&m, "crown-jewel", "secret").contains("PORT"));
    assert!(m
        .entities_of("crown-jewel", "secret")
        .iter()
        .all(|e| e.attributes["valueRecorded"] == "false"));
    assert!(names(&m, "crown-jewel", "pii-store").contains("db/schema.sql"));
    let pii = &m.entities_of("crown-jewel", "pii-store")[0];
    assert_eq!(pii.attributes["fieldNames"], "date_of_birth,ssn");
    assert!(m
        .entities_of("crown-jewel", "money")
        .iter()
        .any(|e| e.name == "payment-provider:stripe"));
    assert!(names(&m, "crown-jewel", "admin-capability").contains("/admin/users/:id"));
    assert!(!m.entities_of("identity", "auth-library").is_empty());

    // Every cited evidence ref resolves and is bound to the inventory + bytes.
    let inv = envelope(&files);
    let ev: BTreeMap<_, _> = m.evidence.iter().map(|e| (e.id.as_str(), e)).collect();
    for e in &m.entities {
        if e.assertion == "observed" {
            assert!(
                !e.evidence_refs.is_empty(),
                "observed entity without evidence: {}",
                e.name
            );
        }
        for r in &e.evidence_refs {
            let r = ev.get(r.as_str()).expect("evidence resolves");
            assert_eq!(r.inventory_digest, inv.digest);
            assert!(r.start_line >= 1 && r.end_line >= r.start_line);
            assert_eq!(r.source_digest, bytes_digest(&files[&r.path]));
        }
    }
    let route_ev = &ev[users.evidence_refs[0].as_str()];
    assert_eq!(route_ev.path, "server/app.js");
    assert_eq!(route_ev.start_line, route_ev.end_line);
    assert!(std::str::from_utf8(&files["server/app.js"])
        .unwrap()
        .lines()
        .nth(route_ev.start_line as usize - 1)
        .unwrap()
        .contains("/api/users"));

    // Admin crown jewel is exposed by the admin route, with no claim of access.
    assert!(m.relations.iter().any(|r| r.kind == "exposes"));
}

#[test]
fn web_app_domains_are_applicable_only_with_evidence() {
    let m = fixture_model("web-app");
    for id in [
        "http-service",
        "webhooks",
        "queue-processing",
        "scheduled-automation",
        "ci-cd",
    ] {
        let d = domain(&m, id);
        assert_eq!(d.status, "applicable", "{id}");
        assert!(d.denominator.count > 0 && !d.evidence_refs.is_empty());
        assert_eq!(d.denominator.count as usize, d.evidence_refs.len());
    }
    for id in [
        "native-desktop",
        "cli",
        "mcp-agent",
        "mobile",
        "smart-contract",
        "cloud-iac",
    ] {
        let d = domain(&m, id);
        assert_eq!(d.status, "not-evidenced", "{id}");
        assert!(d.evidence_refs.is_empty() && d.selected_because.is_empty());
        assert_eq!(d.denominator.count, 0);
    }
}

#[test]
fn tauri_app_models_ipc_commands_permissions_and_boundary() {
    let m = fixture_model("tauri-app");
    assert_eq!(
        names(&m, "entrypoint", "ipc-command"),
        BTreeSet::from(["read_note", "save_note"])
    );
    assert_eq!(
        names(&m, "permission-scope", "tauri-permission"),
        BTreeSet::from(["core:default", "fs:allow-read-file"])
    );
    assert_eq!(m.entities_of("deployment-context", "tauri-app").len(), 1);

    // Actors/boundaries are assumed, evidence-citing, and relate to the commands.
    let boundary = &m.entities_of("trust-boundary", "ipc-command")[0];
    assert_eq!(boundary.name, "renderer-to-privileged-core");
    assert_eq!(boundary.assertion, "assumed");
    assert!(!boundary.evidence_refs.is_empty());
    let crossings = m
        .relations
        .iter()
        .filter(|r| r.kind == "crosses" && r.to == boundary.id)
        .count();
    assert_eq!(crossings, 2);

    assert_eq!(domain(&m, "native-desktop").status, "applicable");
    assert_eq!(domain(&m, "http-service").status, "not-evidenced");
    assert!(gap(&m, "no-entrypoints-evidenced").is_none());
}

#[test]
fn cli_app_models_cli_mcp_tools_and_config() {
    let m = fixture_model("cli-app");
    assert!(!m.entities_of("entrypoint", "cli").is_empty());
    assert_eq!(
        names(&m, "entrypoint", "mcp-tool"),
        BTreeSet::from(["search_docs", "delete_doc"])
    );
    let cfg = m.entities_of("tool-capability", "mcp-server-config");
    assert_eq!(cfg.len(), 1);
    assert_eq!(cfg[0].name, "docs");
    assert_eq!(cfg[0].attributes["command"], "npx");
    // Arguments are never copied into the model.
    assert!(!serde_json::to_string(&m.to_value())
        .unwrap()
        .contains("docs-mcp"));
    assert!(m
        .relations
        .iter()
        .any(|r| r.kind == "loads" && r.to == cfg[0].id));

    // Env secret recorded by name only; HOME is not a secret.
    assert!(names(&m, "crown-jewel", "secret").contains("API_TOKEN"));
    assert!(!names(&m, "crown-jewel", "secret").contains("HOME"));
    assert_eq!(domain(&m, "cli").status, "applicable");
    assert_eq!(domain(&m, "mcp-agent").status, "applicable");
}

#[test]
fn model_is_deterministic_and_revision_bound() {
    let files = load_dir(&fixture_root("web-app"));
    let inv = envelope(&files);
    let a = build(&inv, &files, None, Some(PLAN));
    let b = build(&inv, &files, None, Some(PLAN));
    assert_eq!(a, b);
    assert_eq!(a.to_value(), b.to_value());
    assert_eq!(a.binding.inventory_digest, inv.digest);
    assert_eq!(a.binding.repository_revision, REVISION);
    assert_eq!(a.binding.scoped_bytes_digest, scoped_bytes_digest(&files));
    assert_eq!(a.binding.plan_digest.as_deref(), Some(PLAN));
    assert_eq!(a.binding.cortex_generation_id.as_deref(), Some("cortex-1"));
    assert!(a.binding.plan_bound);

    // A different revision or changed byte changes the digest.
    let other = build_security_model(&SurfaceModelInput {
        inventory: &inv,
        files: &files,
        graph: None,
        repository_revision: "ffffffffffffffffffffffffffffffffffffffff",
        plan_digest: Some(PLAN),
        cortex_generation_id: Some("cortex-1"),
    });
    assert_ne!(a.digest, other.digest);

    // No plan digest: explicit, non-blocking gap, binding says unbound.
    let unbound = build(&inv, &files, None, None);
    assert!(!unbound.binding.plan_bound);
    assert!(gap(&unbound, "plan-digest-unbound").is_some());
    assert!(gap(&a, "plan-digest-unbound").is_none());
}

#[test]
fn absent_graph_is_an_explicit_gap_not_a_clean_claim() {
    let m = fixture_model("web-app");
    let g = gap(&m, "graph-context-absent").expect("graph gap");
    assert!(!g.blocking);
    assert!(m.binding.graph.is_none());
    assert!(m.relations.iter().all(|r| r.origin == "inventory-bytes"));
}

#[test]
fn empty_repository_is_not_applicable_anywhere() {
    let files = BTreeMap::new();
    let m = model_of(&files);
    assert!(m.entities.is_empty());
    assert!(m.applicability.iter().all(|d| d.status == "not-evidenced"));
    assert!(gap(&m, "no-entrypoints-evidenced").is_some());
}

#[test]
fn unsupported_framework_fails_closed() {
    let mut files = BTreeMap::new();
    files.insert(
        "src/users.controller.ts".to_string(),
        b"import { Controller, Get } from '@nestjs/common';\n@Controller('users')\nexport class UsersController {}\n"
            .to_vec(),
    );
    let m = model_of(&files);
    let g = gap(&m, "unsupported-framework:nestjs").expect("unsupported gap");
    assert!(g.blocking);
    assert_eq!(g.paths, vec!["src/users.controller.ts".to_string()]);
    assert!(!m.coverage.complete);
    assert!(m.has_blocking_gap());
    // No entrypoints are invented and http-service is not marked applicable.
    assert!(m.entities_of("entrypoint", "http-route").is_empty());
    assert_eq!(domain(&m, "http-service").status, "not-evidenced");
    assert!(gap(&m, "no-entrypoints-evidenced").unwrap().blocking);
}

#[test]
fn missing_or_drifted_bytes_become_blocking_gaps() {
    let mut files = BTreeMap::new();
    files.insert(
        "a.js".to_string(),
        b"const app = require('express')();\napp.get('/a', h);\n".to_vec(),
    );
    files.insert(
        "b.js".to_string(),
        b"const app = require('express')();\napp.get('/b', h);\n".to_vec(),
    );
    files.insert(
        "c.js".to_string(),
        b"const app = require('express')();\napp.get('/c', h);\n".to_vec(),
    );
    let inv = envelope(&files);

    let mut frozen = files.clone();
    frozen.remove("a.js");
    frozen.insert("b.js".to_string(), b"app.get('/drifted', h);\n".to_vec());
    let m = build(&inv, &frozen, None, Some(PLAN));

    assert_eq!(
        gap(&m, "source-bytes-unavailable").unwrap().paths,
        vec!["a.js"]
    );
    assert_eq!(
        gap(&m, "source-digest-unverified").unwrap().paths,
        vec!["b.js"]
    );
    assert!(m.has_blocking_gap() && !m.coverage.complete);
    assert_eq!(
        names(&m, "entrypoint", "http-route"),
        BTreeSet::from(["GET /c"])
    );
    assert_eq!(m.coverage.files_skipped, 2);
}

#[test]
fn secret_files_are_recorded_by_name_without_content() {
    let mut files = BTreeMap::new();
    files.insert(
        ".env".to_string(),
        b"STRIPE_KEY=placeholder-value\n".to_vec(),
    );
    files.insert(".env.example".to_string(), b"STRIPE_KEY=\n".to_vec());
    files.insert("keys/server.pem".to_string(), b"placeholder\n".to_vec());
    let m = model_of(&files);
    assert_eq!(
        names(&m, "crown-jewel", "secret-file"),
        BTreeSet::from([".env", "keys/server.pem"])
    );
    assert!(!serde_json::to_string(&m.to_value())
        .unwrap()
        .contains("placeholder-value"));
}

#[test]
fn registry_vocabulary_is_reused_and_nothing_is_verified() {
    let registry: serde_json::Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../src/registry/rules/security/enums.json"),
        )
        .expect("enums.json"),
    )
    .unwrap();
    let set = |k: &str| -> BTreeSet<String> {
        registry["enums"][k]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };
    let entity_kinds = set("entityKind");
    let relation_kinds = set("relationKind");
    let strengths = set("evidenceStrength");

    for fixture in ["web-app", "tauri-app", "cli-app"] {
        let m = fixture_model(fixture);
        let ids: BTreeSet<_> = m.entities.iter().map(|e| e.id.as_str()).collect();
        for e in &m.entities {
            assert!(entity_kinds.contains(&e.kind), "{fixture}: {}", e.kind);
            assert!(strengths.contains(&e.evidence_strength));
            assert_ne!(e.evidence_strength, "verified");
            assert_eq!(e.provider, PROVIDER_ID);
        }
        for r in &m.relations {
            assert!(relation_kinds.contains(&r.kind), "{fixture}: {}", r.kind);
            assert_ne!(r.evidence_strength, "verified");
            assert!(ids.contains(r.from.as_str()) && ids.contains(r.to.as_str()));
        }
    }
}

fn graph_files() -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    files.insert(
        "routes/pay.js".to_string(),
        b"const app = require('express')();\nconst billing = require('../lib/billing');\napp.post('/pay', (req, res) => billing.charge(req));\n"
            .to_vec(),
    );
    files.insert(
        "lib/billing.js".to_string(),
        b"const key = process.env.BILLING_API_KEY;\nmodule.exports = { charge() {} };\n".to_vec(),
    );
    files
}

fn bound_graph(files: &BTreeMap<String, Vec<u8>>) -> GraphContext {
    GraphContext {
        contract_version: "legion-graph/1".into(),
        blueprint_version: Some("bp-1".into()),
        scoped_bytes_digest: scoped_bytes_digest(files),
        covered_files_digest: None,
        resolver_config_digest: "resolver".into(),
        coverage_floor: "provenance-bound-blueprint-plus-lexical-floor".into(),
        freshness: "bound-to-frozen-covered-bytes".into(),
        trusted_files: files.keys().cloned().collect(),
        edges: vec![ContextEdge {
            from: "routes/pay.js".into(),
            to: "lib/billing.js".into(),
            kind: "imports".into(),
            confidence: "certain".into(),
            source: "blueprint".into(),
            evidence: SourceSpan {
                path: "routes/pay.js".into(),
                start_line: 2,
                end_line: 2,
                source_digest: bytes_digest(&files["routes/pay.js"]),
            },
        }],
        unknowns: Vec::new(),
        truncated: false,
    }
}

#[test]
fn bound_graph_adds_cross_file_reachability_with_evidence() {
    let files = graph_files();
    let inv = envelope(&files);
    let graph = bound_graph(&files);
    let m = build(&inv, &files, Some(&graph), Some(PLAN));

    assert!(gap(&m, "graph-context-absent").is_none());
    assert!(m.binding.graph.as_ref().unwrap().used);
    let route = m.entities.iter().find(|e| e.name == "POST /pay").unwrap();
    let secret = m
        .entities
        .iter()
        .find(|e| e.name == "BILLING_API_KEY")
        .unwrap();
    let rel = m
        .relations
        .iter()
        .find(|r| r.kind == "reaches" && r.from == route.id && r.to == secret.id)
        .expect("reaches relation");
    assert_eq!(rel.origin, "graph-context");
    assert_eq!(rel.assertion, "inferred");
    assert_eq!(rel.evidence_strength, "strong-inference");
    let paths: BTreeSet<_> = rel
        .evidence_refs
        .iter()
        .map(|id| {
            m.evidence
                .iter()
                .find(|e| &e.id == id)
                .unwrap()
                .path
                .as_str()
        })
        .collect();
    assert!(paths.contains("routes/pay.js") && paths.contains("lib/billing.js"));
}

#[test]
fn unbound_or_stale_graph_is_ignored_with_a_gap() {
    let files = graph_files();
    let inv = envelope(&files);

    let mut wrong = bound_graph(&files);
    wrong.scoped_bytes_digest = "deadbeef".into();
    let m = build(&inv, &files, Some(&wrong), Some(PLAN));
    assert!(gap(&m, "graph-context-unbound").is_some());
    assert!(!m.binding.graph.as_ref().unwrap().used);
    assert!(m.relations.iter().all(|r| r.origin != "graph-context"));

    let mut stale = bound_graph(&files);
    stale.freshness = "artifact-rejected-unbound-or-stale".into();
    let m = build(&inv, &files, Some(&stale), Some(PLAN));
    assert!(gap(&m, "graph-context-unbound").is_some());
    assert!(m.relations.iter().all(|r| r.origin != "graph-context"));
}

#[test]
fn truncated_graph_is_a_blocking_gap_and_weak_edges_stay_possible() {
    let files = graph_files();
    let inv = envelope(&files);
    let mut graph = bound_graph(&files);
    graph.truncated = true;
    graph.edges[0].confidence = "possible".into();
    graph.edges[0].source = "lexical".into();
    let m = build(&inv, &files, Some(&graph), Some(PLAN));
    assert!(gap(&m, "graph-truncated").unwrap().blocking);
    assert!(!m.coverage.complete);
    let rel = m
        .relations
        .iter()
        .find(|r| r.origin == "graph-context")
        .expect("weak reachability kept");
    assert_eq!(rel.evidence_strength, "possible");
}
