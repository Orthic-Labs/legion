//! A11 acceptance coverage for `framework.nginx`. Authored, never run by the
//! packet worker; root executes. Requires root to add `pub mod nginx;` to
//! `native_providers/architecture/mod.rs`.

use legion_audit::native_providers::architecture::nginx::{
    analyze_nginx, evaluate_nginx, parse_nginx, plan_effective_check, reconcile_runtime,
    redact_effective_dump, split_effective_dump, AssertionState, ConfigOrigin, LocationKind,
    NginxContext, NginxFacts, NginxFileInput, NginxPolicy, NginxRuntimeObservation,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nginx-assurance")
}

fn collect(dir: &Path, prefix: &str, out: &mut Vec<NginxFileInput>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("fixture dir")
        .map(|e| e.expect("entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        if path.is_dir() {
            collect(&path, &rel, out);
        } else {
            out.push(NginxFileInput { path: rel, text: fs::read_to_string(&path).expect("text") });
        }
    }
}

fn load(case: &str) -> Vec<NginxFileInput> {
    let mut out = Vec::new();
    collect(&root().join(case), "", &mut out);
    out
}

fn ctx(version: Option<&str>) -> NginxContext {
    NginxContext {
        version: version.map(str::to_owned),
        origin: ConfigOrigin::Rendered,
        ..NginxContext::default()
    }
}

fn gap_kinds(facts: &NginxFacts) -> Vec<&str> {
    facts.gaps.iter().map(|g| g.kind.as_str()).collect()
}

fn rules(facts: &NginxFacts, policy: &NginxPolicy) -> Vec<String> {
    evaluate_nginx(facts, policy).candidates.into_iter().map(|c| c.rule).collect()
}

#[test]
fn include_cycle_is_bounded_and_partial() {
    let facts = parse_nginx(&load("include-cycle"), &ctx(None));
    assert!(gap_kinds(&facts).contains(&"include-cycle"));
    assert!(!facts.complete());
    assert_eq!(facts.servers.len(), 1, "unrelated server still parsed");
}

#[test]
fn include_path_escape_is_never_followed() {
    let mut files = load("include-escape");
    files.push(NginxFileInput { path: "../../outside/secrets.conf".into(), text: "server{}".into() });
    let facts = parse_nginx(&files, &ctx(None));
    assert!(gap_kinds(&facts).contains(&"input-path-escape"));
    assert!(gap_kinds(&facts).contains(&"include-path-escape"));
    assert!(facts.includes.iter().all(|e| e.resolved.is_empty()));
}

#[test]
fn split_blocks_across_globbed_includes_resolve_in_order() {
    let facts = parse_nginx(&load("split-servers"), &ctx(None));
    assert!(facts.complete(), "{:?}", facts.gaps);
    assert_eq!(facts.servers.len(), 3);
    assert_eq!(facts.includes[0].resolved, vec!["sites/a.conf", "sites/b.conf"]);
    // http-level header inherited into servers that define none.
    assert!(facts.servers[0].locations[0].effective.headers.iter().any(|h| h.name == "x-frame-options"));
}

#[test]
fn quoted_delimiters_and_comments_do_not_change_structure() {
    let facts = parse_nginx(&load("quoted"), &ctx(None));
    assert!(facts.complete(), "{:?}", facts.gaps);
    let loc = &facts.servers[0].locations[0];
    let odd = loc.effective.headers.iter().find(|h| h.name == "x-odd").expect("header");
    assert_eq!(odd.value, "va;lue { } # not a comment");
}

#[test]
fn unterminated_quote_is_parse_error_not_clean() {
    let files = vec![NginxFileInput { path: "nginx.conf".into(), text: "events{}\nhttp { add_header X \"oops; }".into() }];
    let facts = parse_nginx(&files, &ctx(None));
    assert!(gap_kinds(&facts).contains(&"parse-error"));
    assert!(facts.servers.is_empty());
}

#[test]
fn variable_include_and_proxy_targets_stay_partial() {
    let facts = parse_nginx(&load("variable-target"), &ctx(None));
    assert_eq!(gap_kinds(&facts).iter().filter(|k| **k == "include-variable-target").count(), 2);
    let eval = evaluate_nginx(&facts, &NginxPolicy::default());
    assert!(eval.candidates.iter().any(|c| c.rule == "proxy-pass-client-target"));
    assert!(eval.gaps.iter().any(|g| g.kind == "proxy-pass-variable-target"));
}

#[test]
fn unknown_or_unbound_module_is_partial_and_header_state_uncertain() {
    let facts = parse_nginx(&load("unknown-module"), &ctx(None));
    let kinds = gap_kinds(&facts);
    assert!(kinds.contains(&"module-set-unbound"));
    assert!(kinds.contains(&"header-state-unproven"));
    let bound = NginxContext { modules: Some(vec!["lua".into()]), ..ctx(None) };
    let facts = parse_nginx(&load("unknown-module"), &bound);
    assert!(gap_kinds(&facts).contains(&"unknown-module"), "headers-more not in bound set");
    let policy = NginxPolicy { required_headers: vec!["X-Frame-Options".into()], ..Default::default() };
    assert!(!rules(&facts, &policy).contains(&"header-inheritance-loss".to_owned()), "uncertain state must not become a finding or a pass");
}

#[test]
fn default_add_header_inheritance_loss_is_a_candidate() {
    let facts = parse_nginx(&load("header-broken"), &ctx(Some("1.27.0")));
    let policy = NginxPolicy { required_headers: vec!["Strict-Transport-Security".into()], ..Default::default() };
    let eval = evaluate_nginx(&facts, &policy);
    let hits: Vec<_> = eval.candidates.iter().filter(|c| c.rule == "header-inheritance-loss").collect();
    assert_eq!(hits.len(), 1, "only /assets/ replaces the server set");
    assert!(hits[0].id.contains("/loc"));
    assert_eq!(hits[0].severity, "warning");
    // No declared policy: no candidate invented.
    assert!(rules(&facts, &NginxPolicy::default()).is_empty());
}

#[test]
fn add_header_inherit_merge_is_version_aware() {
    let policy = NginxPolicy { required_headers: vec!["Strict-Transport-Security".into()], ..Default::default() };
    let modern = parse_nginx(&load("header-merge"), &ctx(Some("1.29.3")));
    assert!(modern.complete(), "{:?}", modern.gaps);
    assert!(rules(&modern, &policy).is_empty(), "merge keeps HSTS");

    let old = parse_nginx(&load("header-merge"), &ctx(Some("1.28.0")));
    assert!(rules(&old, &policy).contains(&"add-header-inherit-version".to_owned()));
    assert!(gap_kinds(&old).contains(&"header-state-unproven"));
    assert!(!rules(&old, &policy).contains(&"header-inheritance-loss".to_owned()));

    let unbound = parse_nginx(&load("header-merge"), &ctx(None));
    assert!(gap_kinds(&unbound).contains(&"header-state-unproven"));
    assert!(rules(&unbound, &policy).is_empty());
}

#[test]
fn private_cache_positive_and_negative() {
    let policy = NginxPolicy {
        private_path_prefixes: vec!["/account/".into()],
        public_path_prefixes: vec!["/public/".into()],
        ..Default::default()
    };
    let bad = parse_nginx(&load("private-cache-bad"), &ctx(None));
    let bad_rules = rules(&bad, &policy);
    assert!(bad_rules.contains(&"cache-private-shared".to_owned()));
    assert!(!bad_rules.contains(&"auth-routing-gap".to_owned()), "auth_request present");

    let good = parse_nginx(&load("private-cache-good"), &ctx(None));
    let good_rules = rules(&good, &policy);
    assert!(!good_rules.contains(&"cache-private-shared".to_owned()), "{good_rules:?}");
    assert!(!good_rules.contains(&"auth-request-target-missing".to_owned()));
}

#[test]
fn cache_without_declared_policy_is_a_gap_not_a_verdict() {
    let facts = parse_nginx(&load("private-cache-good"), &ctx(None));
    let eval = evaluate_nginx(&facts, &NginxPolicy::default());
    assert!(eval.gaps.iter().any(|g| g.kind == "cache-policy-undeclared"));
}

#[test]
fn undeclared_private_prefix_without_auth_is_flagged_only_with_policy() {
    let facts = parse_nginx(&load("alias-bad"), &ctx(None));
    let policy = NginxPolicy { private_path_prefixes: vec!["/ok/".into()], ..Default::default() };
    assert!(rules(&facts, &policy).contains(&"auth-routing-gap".to_owned()));
    assert!(!rules(&facts, &NginxPolicy::default()).contains(&"auth-routing-gap".to_owned()));
}

#[test]
fn static_only_locations_are_never_dead_or_gapped() {
    let facts = parse_nginx(&load("static-only"), &ctx(None));
    assert!(facts.complete(), "{:?}", facts.gaps);
    let kinds: Vec<LocationKind> = facts.servers[0].locations.iter().map(|l| l.kind).collect();
    assert_eq!(
        kinds,
        vec![LocationKind::Return, LocationKind::Static, LocationKind::Unspecified, LocationKind::Return]
    );
    let policy = NginxPolicy {
        required_headers: vec![],
        max_body_bytes: None,
        ..Default::default()
    };
    let eval = evaluate_nginx(&facts, &policy);
    assert!(eval.candidates.is_empty() && eval.gaps.is_empty());
    let analysis = analyze_nginx(&load("static-only"), &ctx(None), &policy, &[]);
    assert_eq!(analysis.status, "pass");
    assert!(analysis.findings.iter().all(|f| !f["rule"].as_str().unwrap().contains("dead")));
}

#[test]
fn alias_and_proxy_path_handling() {
    let facts = parse_nginx(&load("alias-bad"), &ctx(None));
    let r = rules(&facts, &NginxPolicy::default());
    assert!(r.contains(&"alias-path-traversal".to_owned()));
    assert!(r.contains(&"proxy-pass-slash-mismatch".to_owned()));
    assert_eq!(r.iter().filter(|x| *x == "alias-path-traversal").count(), 1, "/ok/ is correct");
}

#[test]
fn forwarded_trust_and_secret_protection_in_facts() {
    let facts = parse_nginx(&load("forwarded"), &ctx(None));
    let r = rules(&facts, &NginxPolicy::default());
    assert_eq!(r.iter().filter(|x| *x == "forwarded-host-trust").count(), 3, "real_ip 0/0, Host, XFF");
    let json = serde_json::to_string(&facts).unwrap();
    assert!(!json.contains("topsecret"), "Authorization value must be digested");
    assert!(json.contains("[redacted:sha256:"));
}

#[test]
fn request_id_replacement_inheritance() {
    let facts = parse_nginx(&load("request-id"), &ctx(None));
    let policy = NginxPolicy { request_id_header: Some("X-Request-ID".into()), ..Default::default() };
    let hits: Vec<_> = evaluate_nginx(&facts, &policy)
        .candidates
        .into_iter()
        .filter(|c| c.rule == "request-id-propagation")
        .collect();
    assert_eq!(hits.len(), 1);
    assert!(hits[0].id.ends_with(":1") || hits[0].message.contains("x-request-id"));
}

#[test]
fn tls_default_depends_on_bound_version() {
    let files = vec![NginxFileInput {
        path: "nginx.conf".into(),
        text: "events{} http { server { listen 443 ssl; location / { return 204; } } }".into(),
    }];
    let policy = NginxPolicy::default();
    assert!(rules(&parse_nginx(&files, &ctx(Some("1.22.1"))), &policy).contains(&"tls-weak-protocol".to_owned()));
    assert!(rules(&parse_nginx(&files, &ctx(Some("1.26.0"))), &policy).is_empty());
    let unbound = evaluate_nginx(&parse_nginx(&files, &ctx(None)), &policy);
    assert!(unbound.candidates.is_empty());
    assert!(unbound.gaps.iter().any(|g| g.kind == "version-unbound-tls-default"));
}

#[test]
fn effective_dump_split_and_redaction() {
    let dump = fs::read_to_string(root().join("dump/effective-T.txt")).unwrap();
    let files = split_effective_dump(&dump);
    assert_eq!(files.len(), 2);
    let redacted = redact_effective_dump(&dump);
    for secret in ["topsecret", "hunter2", "/etc/ssl/private/k.pem"] {
        assert!(!redacted.contains(secret), "{secret} leaked");
    }
    assert!(redacted.contains("add_header X-Ok yes"));
    let facts = parse_nginx(&files, &NginxContext { origin: ConfigOrigin::Rendered, ..NginxContext::default() });
    assert!(!serde_json::to_string(&facts).unwrap().contains("hunter2"));
}

#[test]
fn source_only_never_claims_delivery_and_unadmitted_nginx_is_a_gap() {
    let source = NginxContext { origin: ConfigOrigin::Source, ..NginxContext::default() };
    let policy = NginxPolicy::default();
    let analysis = analyze_nginx(&load("static-only"), &source, &policy, &[]);
    assert_eq!(analysis.status, "unproven");
    assert!(!analysis.complete);
    assert_eq!(analysis.extras["delivery"], "source-only");
    assert_eq!(plan_effective_check(&source).unbound_gap.kind, "nginx-executable-not-admitted");
    assert!(plan_effective_check(&source).requires_pinned_executable_digest);
}

#[test]
fn runtime_assertions_require_verified_evidence() {
    let facts = parse_nginx(&load("private-cache-good"), &ctx(None));
    let policy = NginxPolicy {
        required_headers: vec!["Strict-Transport-Security".into()],
        private_path_prefixes: vec!["/account/".into()],
        ..Default::default()
    };
    let mut headers = BTreeMap::new();
    headers.insert("strict-transport-security".to_owned(), "max-age=1".to_owned());
    let verified = NginxRuntimeObservation {
        evidence_id: "ev1".into(),
        verified: true,
        path: "/account/me".into(),
        status: 200,
        response_headers: headers.clone(),
        cache_status: Some("HIT".into()),
        tls_protocol: Some("TLSv1.1".into()),
        authenticated: Some(false),
    };
    let unverified = NginxRuntimeObservation { evidence_id: "ev2".into(), verified: false, ..verified.clone() };
    let out = reconcile_runtime(&facts, &policy, &[verified, unverified]);
    let state = |kind: &str, id: &str| out.iter().find(|a| a.kind == kind && a.evidence_id == id).map(|a| a.state);
    assert_eq!(state("runtime-header", "ev1"), Some(AssertionState::Confirmed));
    assert_eq!(state("runtime-private-cache", "ev1"), Some(AssertionState::Contradicted));
    assert_eq!(state("runtime-tls", "ev1"), Some(AssertionState::Contradicted));
    assert_eq!(state("runtime-evidence-unverified", "ev2"), Some(AssertionState::Unproven));
    assert!(out.iter().filter(|a| a.evidence_id == "ev2").all(|a| a.state == AssertionState::Unproven));
    let analysis = analyze_nginx(&load("private-cache-good"), &ctx(None), &policy, &[]);
    assert_eq!(analysis.extras["delivery"], "source-only");
}
