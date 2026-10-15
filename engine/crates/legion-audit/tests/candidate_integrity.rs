use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use legion_audit::native_providers::{
    p11d_quality::data_suite,
    reasoning::security_adjudication::{
        build_adjudication_plan, cluster_candidates, evaluate_adjudication, scanner_candidates,
        ScannerCandidate, SecurityAdjudicationError, TriageContext,
    },
};
use legion_contracts::{ProviderId, ProviderResult, ProviderStatus};
use serde_json::{json, Value};

fn fixture() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "legion-candidate-integrity-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("src")).unwrap();
    root
}

fn generated(candidates: Value) -> ProviderResult {
    ProviderResult {
        schema_version: 1,
        provider: ProviderId::new("data.internal-suite").unwrap(),
        applicable: true,
        required: true,
        status: ProviderStatus::Ok,
        complete: true,
        coverage: None,
        findings: vec![],
        coverage_gaps: vec![],
        degradation: vec![],
        details: BTreeMap::from([("candidates".into(), candidates)]),
    }
}

#[test]
fn adapter_preserves_top_level_nested_ranges_and_unresolved_locations() {
    let root = fixture();
    fs::write(
        root.join("src/data.ts"),
        "first\nredis.set('session', value);\nthird\n",
    )
    .unwrap();
    let result = generated(json!([
        {"id":"top","ruleId":"data.redis-unbounded-value","file":"./src\\data.ts","line":2,"endLine":3,"claim":"retain location"},
        {"id":"nested","ruleId":"data.redis-unbounded-value","evidence":[{"file":"src/data.ts","line":2,"endLine":3}],"source":{"tool":"redis-scanner","ruleId":"ttl"}},
        {"id":"unknown","ruleId":"data.transaction-missing","claim":"unknown location"},
        {"id":"unsafe","ruleId":"data.transaction-missing","file":"../outside.ts","line":1},
        {"id":"conflict","ruleId":"data.transaction-missing","file":"src/data.ts","line":2,"evidence":[{"file":"src/other.ts","line":2}]},
        {"id":"range","file":"src/data.ts","line":3,"endLine":2},
        {"id":"zero","file":"src/data.ts","line":0}
    ]));
    let rows = scanner_candidates(&root, "data.internal-suite", &result);
    assert_eq!(rows.len(), 7);
    for id in ["top", "nested"] {
        let row = rows.iter().find(|row| row.finding_id == id).unwrap();
        assert_eq!(row.path.as_deref(), Some("src/data.ts"));
        assert_eq!((row.line, row.end_line), (Some(2), Some(3)));
        assert_eq!(row.location_status, "known");
        assert_eq!(row.domain, "data");
        assert!(row
            .evidence_excerpt
            .as_deref()
            .unwrap()
            .contains("redis.set"));
        assert!(row.evidence_digest.starts_with("sha256:"));
    }
    assert_eq!(
        rows.iter()
            .find(|row| row.finding_id == "nested")
            .unwrap()
            .source_mapping["source"]["ruleId"],
        "ttl"
    );
    assert_eq!(
        rows.iter()
            .find(|row| row.finding_id == "unknown")
            .unwrap()
            .location_status,
        "unknown"
    );
    for id in ["unsafe", "range", "zero"] {
        let row = rows.iter().find(|row| row.finding_id == id).unwrap();
        assert_eq!(row.location_status, "invalid");
        assert!(row.path.is_none());
    }
    assert_eq!(
        rows.iter()
            .find(|row| row.finding_id == "conflict")
            .unwrap()
            .location_status,
        "conflicting"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn safe_source_mapping_redacts_secrets_but_digest_binds_original_evidence() {
    let root = fixture();
    let rows = scanner_candidates(
        &root,
        "scanner.native",
        &generated(json!([
            {"id":"first","ruleId":"security.credential","api_key":"opaque-secret-value-123456789"},
            {"id":"second","ruleId":"security.credential","api_key":"different-secret-value-987654321"}
        ])),
    );
    assert_eq!(rows[0].source_mapping["api_key"], "[REDACTED]");
    assert_eq!(rows[1].source_mapping["api_key"], "[REDACTED]");
    assert_ne!(rows[0].evidence_digest, rows[1].evidence_digest);
    fs::remove_dir_all(root).unwrap();
}

fn candidate(id: &str) -> ScannerCandidate {
    ScannerCandidate {
        finding_id: id.into(),
        provider: "security.sast".into(),
        rule: "security.command".into(),
        severity: "medium".into(),
        path: Some("src/handler.ts".into()),
        line: Some(4),
        end_line: Some(4),
        evidence_excerpt: Some("Shell.exec(input)".into()),
        domain: "security".into(),
        ..Default::default()
    }
}

#[test]
fn equivalence_requires_same_provider_context_and_case_preserved_evidence() {
    let base = candidate("base");
    let duplicate = candidate("duplicate");
    let mut other_file = candidate("file");
    other_file.path = Some("src/other.ts".into());
    let mut other_line = candidate("line");
    other_line.line = Some(5);
    let mut other_provider = candidate("provider");
    other_provider.provider = "security.other".into();
    let mut other_receiver = candidate("receiver");
    other_receiver.evidence_excerpt = Some("shell.exec(input)".into());
    let mut no_path = candidate("no-path");
    no_path.path = None;
    let mut no_path_again = no_path.clone();
    no_path_again.finding_id = "no-path-again".into();
    let mut generic = candidate("generic");
    generic.evidence_excerpt = None;
    generic.message = "Possible unsafe call".into();
    let mut generic_again = generic.clone();
    generic_again.finding_id = "generic-again".into();
    let clusters = cluster_candidates(&[
        base,
        duplicate,
        other_file,
        other_line,
        other_provider,
        other_receiver,
        no_path,
        no_path_again,
        generic,
        generic_again,
    ])
    .unwrap();
    assert_eq!(clusters.len(), 9);
    assert_eq!(
        clusters
            .iter()
            .filter(|cluster| cluster.member_ids.len() == 2)
            .count(),
        1
    );
    let merged = clusters
        .iter()
        .find(|cluster| cluster.member_ids.len() == 2)
        .unwrap();
    assert_eq!(merged.member_ids, ["base", "duplicate"]);
}

#[test]
fn duplicate_ids_never_disappear_during_adapter_or_plan_construction() {
    let root = fixture();
    let result = generated(
        json!([{"id":"duplicate","file":"a.ts","line":1},{"id":"duplicate","file":"b.ts","line":1}]),
    );
    let rows = scanner_candidates(&root, "scanner.native", &result);
    assert_eq!(rows.len(), 2);
    assert!(build_adjudication_plan(&rows, &TriageContext::default(), "sha256:parent").is_err());
    assert!(
        legion_audit::native_providers::reasoning::security_adjudication::adjudication_work_items(
            &rows,
            "sha256:parent"
        )
        .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_partial_batch_ids_are_errors_instead_of_missing_work_or_panics() {
    let rows = vec![candidate("known"), candidate("duplicate-observation")];
    let plan = build_adjudication_plan(&rows, &TriageContext::default(), "sha256:parent").unwrap();
    let batch = &plan.batches[0];
    let unknown = json!({"stage":"batch","batchId":batch.batch_id,"candidateId":"absent"});
    assert!(matches!(
        evaluate_adjudication(&plan, &rows, &[unknown]),
        Err(SecurityAdjudicationError::UnknownCandidate { .. })
    ));
    let missing = json!({"stage":"batch","batchId":batch.batch_id});
    assert!(matches!(
        evaluate_adjudication(&plan, &rows, &[missing]),
        Err(SecurityAdjudicationError::MissingCandidateId(_))
    ));
    let nonrepresentative = rows
        .iter()
        .find(|row| row.finding_id != plan.clusters[0].representative_id)
        .unwrap();
    let wrong = json!({"stage":"batch","batchId":batch.batch_id,"candidateId":nonrepresentative.finding_id});
    assert!(matches!(
        evaluate_adjudication(&plan, &rows, &[wrong]),
        Err(SecurityAdjudicationError::MalformedVerdict { .. })
    ));
}

fn data_rules(source: &str) -> Vec<Value> {
    let root = fixture();
    fs::write(root.join("subject.ts"), source).unwrap();
    let result = data_suite::run_data_suite(&root, &["subject.ts".into()]);
    fs::remove_dir_all(root).unwrap();
    result["candidates"].as_array().unwrap().clone()
}

#[test]
fn redis_retention_uses_bound_library_receiver_key_and_positive_ttl() {
    let prelude = "import { createClient } from 'redis';\nconst redis = createClient();\n";
    for code in [
        "redis.set('session:' + id, value);",
        "redis.set('session:' + id, value, { EX: 0 });",
        "redis.hset('session:' + id, 'EX', 60);",
    ] {
        let rows = data_rules(&format!("{prelude}{code}"));
        assert!(
            rows.iter()
                .any(|row| row["ruleId"] == "data.redis-unbounded-value"
                    && row["applicability"]["retentionPolicy"] == "ephemeral-ttl-required"),
            "{code}"
        );
    }
    for code in [
        "redis.set('session:' + id, value, { EX: 60 });",
        "redis.set('session:' + id, value, 'PX', 60000);",
        "redis.set('session:' + id, value);\nawait redis.expire('session:' + id, 60);",
        "const cache = new Map(); cache.set('session:' + id, value);",
        "config.set('session', value);",
        "// redis.set('session:' + id, value);",
        "const example = `redis.set('session:' + id, value)`;",
    ] {
        let rows = data_rules(&format!("{prelude}{code}"));
        assert!(
            !rows
                .iter()
                .any(|row| row["ruleId"] == "data.redis-unbounded-value"),
            "{code}"
        );
    }
    let durable = data_rules(&format!("{prelude}redis.set('account:' + id, value);"));
    assert!(durable
        .iter()
        .any(|row| row["applicability"]["retentionPolicy"] == "unknown-durable-intent"));
}

#[test]
fn injected_redis_parameters_bind_import_alias_and_function_scope() {
    let source = r#"import type { RedisClientType as SessionClient } from 'redis';
function save(redis: SessionClient, id: string, value: string) {
  redis.set(`session:${id}`, value);
  function local(redis: Map<string, string>) { redis.set('session:local', value); }
}
function ordinary(redis: Map<string, string>, value: string) { redis.set('session:map', value); }
function safe(redis: SessionClient, value: string) { redis.set('session:safe', value, { EX: 60 }); }
"#;
    let candidates = data_rules(source);
    let writes = candidates
        .iter()
        .filter(|row| row["ruleId"] == "data.redis-unbounded-value")
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 1, "{candidates:?}");
    assert_eq!(writes[0]["line"], 3);
    assert_eq!(writes[0]["applicability"]["receiver"], "redis");
    for source in [
        "import type { RedisClientType } from 'unrelated'; function save(redis: RedisClientType) { redis.set('session:x', value); }",
        "// import type { RedisClientType } from 'redis';\nfunction save(redis: RedisClientType) { redis.set('session:x', value); }",
        "import type { RedisClientType } from 'redis'; function save(redis: RedisClientTypeFake) { redis.set('session:x', value); }",
    ] {
        assert!(!data_rules(source).iter().any(|row| row["ruleId"] == "data.redis-unbounded-value"), "{source}");
    }
}

#[test]
fn injected_redis_proof_does_not_cross_block_or_arrow_parameter_shadows() {
    let source = r#"import type { RedisClientType } from 'redis';
function save(redis: RedisClientType, items: Array<Map<string, string>>) {
  redis.set('session:before', 'real');
  { const redis = new Map<string, string>(); redis.set('session:const', 'local'); }
  { let redis = new Map<string, string>(); redis.set('session:let', 'local'); }
  items.forEach(redis => redis.set('session:arrow', 'local'));
  items.forEach((redis) => { redis.set('session:arrow-block', 'local'); });
  items.forEach((redis: Map<string, string>) => redis.set('session:typed-arrow', 'local'));
  function local() { redis.set('session:hoisted', 'local'); var redis = new Map<string, string>(); }
  redis.set('session:after', 'real');
  { var redis = new Map<string, string>(); redis.set('session:var', 'local'); }
  redis.set('session:reassigned', 'local');
}
"#;
    let rows = data_rules(source);
    let writes = rows
        .iter()
        .filter(|row| row["ruleId"] == "data.redis-unbounded-value")
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 2, "{rows:?}");
    assert_eq!(writes[0]["line"], 3);
    assert_eq!(writes[1]["line"], 10);
}

#[test]
fn loop_header_lexical_bindings_preserve_real_redis_writes_before_and_after_loop() {
    let source = |header: &str| {
        format!(
        "import type {{ RedisClientType }} from 'redis';\nfunction save(redis: RedisClientType, maps: Array<Map<string, string>>) {{\n  redis.set('session:before', 'real');\n  for ({header}) {{\n    redis.set('session:loop', 'local');\n  }}\n  redis.set('session:after', 'real');\n}}\n"
    )
    };
    for header in [
        "const redis of maps",
        "let redis of maps",
        "const redis in maps",
        "let redis in maps",
        "let redis = new Map<string, string>(); redis.set('session:condition', 'local'); redis.set('session:update', 'local')",
    ] {
        let rows = data_rules(&source(header));
        let lines = rows.iter().filter(|row| row["ruleId"] == "data.redis-unbounded-value").map(|row| row["line"].as_u64().unwrap()).collect::<Vec<_>>();
        assert_eq!(lines, [3, 7], "{header}: {rows:?}");
    }
    let rows = data_rules(&source("var redis of maps"));
    let lines = rows
        .iter()
        .filter(|row| row["ruleId"] == "data.redis-unbounded-value")
        .map(|row| row["line"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(lines, [3], "var retains function lifetime: {rows:?}");
}

#[test]
fn imported_redis_parameter_accepts_balanced_types_before_executable_body() {
    for return_type in [
        "Promise<void>",
        "Promise<{ value: string }>",
        "{ value: string }",
        "() => { value: string }",
    ] {
        let source = format!("import type {{ RedisClientType }} from 'redis';\nfunction save(redis: RedisClientType): {return_type} {{\n  redis.set('session:actual', 'real');\n}}\n");
        let rows = data_rules(&source);
        let writes = rows
            .iter()
            .filter(|row| row["ruleId"] == "data.redis-unbounded-value")
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1, "{return_type}: {rows:?}");
        assert_eq!(writes[0]["line"], 3);
    }
    let source = "import type { RedisClientType } from 'redis';\nfunction factory(): (redis: RedisClientType) => void { const redis = new Map(); redis.set('session:map', 'local'); return () => {}; }";
    assert!(!data_rules(source)
        .iter()
        .any(|row| row["ruleId"] == "data.redis-unbounded-value"));
}

#[test]
fn database_atomicity_requires_database_receiver_and_retains_unknown() {
    let prelude =
        "import { PrismaClient } from '@prisma/client';\nconst prisma = new PrismaClient();\n";
    let positive = data_rules(&format!("{prelude}function transfer() {{ prisma.account.update({{}}); prisma.ledger.create({{}}); }}"));
    assert!(positive
        .iter()
        .any(|row| row["ruleId"] == "data.transaction-missing"
            && row["applicability"]["atomicity"] == "required"));
    let unknown = data_rules(&format!("{prelude}function independent() {{ prisma.account.update({{}}); prisma.ledger.create({{}}); }}"));
    assert!(unknown
        .iter()
        .any(|row| row["ruleId"] == "data.transaction-missing"
            && row["applicability"]["status"] == "unknown"));
    for code in ["function transfer() { store.update({}); store.save({}); }", "function transfer() { prisma.$transaction(() => { tx.account.update({}); tx.ledger.create({}); }); }", "function first() { prisma.account.update({}); }\nfunction second() { prisma.ledger.create({}); }"] {
        let rows = data_rules(&format!("{prelude}{code}"));
        assert!(!rows.iter().any(|row| row["ruleId"] == "data.transaction-missing"), "{code}");
    }
}

#[test]
fn separate_same_line_redis_writes_keep_unique_instance_ids() {
    let rows = data_rules("import { createClient } from 'redis';\nconst redis = createClient();\nredis.set('session:a', a); redis.set('session:b', b);\n");
    let writes = rows
        .iter()
        .filter(|row| row["ruleId"] == "data.redis-unbounded-value")
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 2);
    assert_ne!(writes[0]["id"], writes[1]["id"]);
    assert_eq!(writes[0]["sourceInstance"], 0);
    assert_eq!(writes[1]["sourceInstance"], 1);
}

fn observed_batch_fixture() -> (
    Vec<ScannerCandidate>,
    legion_audit::native_providers::reasoning::security_adjudication::AdjudicationPlan,
    Value,
    Value,
    Value,
) {
    use legion_contracts::canonical_digest;
    let rows = vec![candidate("observed")];
    let plan = build_adjudication_plan(&rows, &TriageContext::default(), "sha256:observed-parent")
        .unwrap();
    let batch = &plan.batches[0];
    let stage = json!({"schemaVersion":1,"kind":"legion-audit-adjudication-seat","stage":"batch","round":1,
        "batchId":batch.batch_id,"itemId":batch.item_id,"contextId":batch.context_id,
        "parentPacketDigest":plan.parent_packet_digest,"packet":batch.packet});
    let verdict = json!({"candidateId":"observed","stage":"batch","workItemId":batch.item_id,
        "workPacketDigest":canonical_digest(&batch.packet).unwrap(),"contextId":batch.context_id,
        "verdict":"FALSE_POSITIVE","rationale":"fixture assessment bound to actual host response"});
    let host = json!({"sent":true,"contextId":"native-session-actual-1","processId":4123,"processCreated":true,
        "responseDigest":"sha256:physical-response-one","error":null});
    (rows, plan, stage, verdict, host)
}

#[test]
fn authenticated_stage_receipt_binds_real_process_packet_source_and_verdict() {
    use legion_audit::native_providers::reasoning::security_adjudication::{
        stage_observation, validate_stage_observations,
    };
    let (rows, plan, stage, verdict, host) = observed_batch_fixture();
    let observation = stage_observation(&stage, &[verdict.clone()], &host, &rows).unwrap();
    assert_ne!(observation["observedContextId"], verdict["contextId"]);
    assert!(
        validate_stage_observations(&plan, &rows, &[verdict.clone()], &[observation.clone()])
            .unwrap()
            .is_empty()
    );
    let missing = validate_stage_observations(&plan, &rows, &[verdict.clone()], &[]).unwrap();
    assert!(missing[0].contains("adjudication-host-unverified"));
    let mut wrong_packet = observation.clone();
    wrong_packet["workPacketDigest"] = json!("sha256:foreign-packet");
    assert!(
        validate_stage_observations(&plan, &rows, &[verdict.clone()], &[wrong_packet]).is_err()
    );
    let mut altered = verdict.clone();
    altered["rationale"] = json!("model output rewritten after observed physical response");
    let gaps = validate_stage_observations(&plan, &rows, &[altered], &[observation]).unwrap();
    assert!(gaps
        .iter()
        .any(|gap| gap.contains("adjudication-host-unverified")));
}

#[test]
fn source_delivery_never_counts_unread_ranges_or_skeleton_placeholders() {
    use legion_audit::native_providers::reasoning::security_adjudication::{
        stage_observation, validate_stage_observations,
    };
    let (mut rows, _, _, _, mut host) = observed_batch_fixture();
    rows[0].end_line = Some(8);
    let plan = build_adjudication_plan(&rows, &TriageContext::default(), "sha256:observed-parent")
        .unwrap();
    let batch = &plan.batches[0];
    let stage = json!({"schemaVersion":1,"kind":"legion-audit-adjudication-seat","stage":"batch","round":1,
        "batchId":batch.batch_id,"itemId":batch.item_id,"contextId":batch.context_id,"parentPacketDigest":plan.parent_packet_digest,"packet":batch.packet});
    let verdict = json!({"candidateId":"observed","stage":"batch","workItemId":batch.item_id,
        "workPacketDigest":legion_contracts::canonical_digest(&batch.packet).unwrap(),"contextId":batch.context_id});
    host["deliveredExcerpts"] = json!([{"path":"src/handler.ts","mode":"skeleton","startLine":1,"endLine":100,"content":"{ ... }","anchors":["src/handler.ts:1-100"]}]);
    let observation = stage_observation(&stage, &[verdict.clone()], &host, &rows).unwrap();
    let gaps =
        validate_stage_observations(&plan, &rows, &[verdict.clone()], &[observation]).unwrap();
    assert!(gaps
        .iter()
        .any(|gap| gap.contains("required range not delivered")));
    host["deliveredExcerpts"][0]["mode"] = json!("raw");
    host["deliveredExcerpts"][0]["content"] =
        json!("one physical source line cannot prove one hundred lines");
    let observation = stage_observation(&stage, &[verdict.clone()], &host, &rows).unwrap();
    assert!(
        !validate_stage_observations(&plan, &rows, &[verdict.clone()], &[observation])
            .unwrap()
            .is_empty()
    );
    host["deliveredExcerpts"][0]["content"] = json!((1..=100)
        .map(|line| format!("source line {line}\n"))
        .collect::<String>());
    host["deliveredExcerpts"][0]["sourceSide"] = json!("baseline");
    let observation = stage_observation(&stage, &[verdict.clone()], &host, &rows).unwrap();
    assert!(
        !validate_stage_observations(&plan, &rows, &[verdict.clone()], &[observation])
            .unwrap()
            .is_empty()
    );
    host["deliveredExcerpts"][0]["sourceSide"] = json!("selected");
    let observation = stage_observation(&stage, &[verdict.clone()], &host, &rows).unwrap();
    assert!(
        validate_stage_observations(&plan, &rows, &[verdict], &[observation])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn authenticated_retries_keep_history_without_authorizing_changed_response() {
    use legion_audit::native_providers::reasoning::security_adjudication::{
        stage_observation, validate_stage_observations,
    };
    let (rows, plan, stage, verdict, mut host) = observed_batch_fixture();
    let mut previous = verdict.clone();
    previous["rationale"] = json!("earlier physical attempt returned different assessment text");
    let old = stage_observation(&stage, &[previous], &host, &rows).unwrap();
    host["contextId"] = json!("native-session-actual-2");
    host["processId"] = json!(4124);
    host["responseDigest"] = json!("sha256:physical-response-two");
    let current = stage_observation(&stage, &[verdict.clone()], &host, &rows).unwrap();
    assert!(
        validate_stage_observations(&plan, &rows, &[verdict.clone()], &[old, current.clone()])
            .unwrap()
            .is_empty()
    );
    assert!(
        validate_stage_observations(&plan, &rows, &[verdict], &[current.clone(), current]).is_err()
    );
}

#[test]
fn data_reliability_and_release_proofs_omit_security_attacker_requirements() {
    use legion_audit::native_providers::reasoning::security_adjudication::{
        adjudicate_scanner_candidates_isolated, adjudication_work_items, confirmed_findings,
        ContextPolicy,
    };
    for domain in ["data", "reliability", "release"] {
        let mut source = candidate("domain-candidate");
        source.domain = domain.into();
        let rows = vec![source];
        let work = adjudication_work_items(&rows, "sha256:domain-parent").unwrap();
        let input = json!({"candidateId":"domain-candidate","contextId":work[0].context_id,
            "verdict":"TRUE_POSITIVE","severity":"medium","evidenceStrength":"observed",
            "domainProof":{"domain":domain,"invariant":"paired state transitions must commit together","trigger":"second operation fails after first state mutation"},
            "reachability":"operation invokes src/handler.ts during normal state transition",
            "impact":"partial state persists after operation reports failure",
            "proof":"trace in src/handler.ts demonstrates partial durable state after second operation fails",
            "devilsAdvocate":"independent state changes were ruled out by caller invariant",
            "evidence":[{"file":"src/handler.ts","line":4}]});
        let output = adjudicate_scanner_candidates_isolated(
            &rows,
            &[input.clone()],
            "sha256:domain-parent",
            ContextPolicy::Attested,
        )
        .unwrap();
        assert_eq!(output[0].domain, domain);
        assert!(!output[0].variant_analysis_required);
        assert!(confirmed_findings(&rows, &output).is_empty());
        let serialized = serde_json::to_value(&output[0]).unwrap();
        assert!(serialized.get("attackerControl").is_none());
        assert!(serialized.get("threatModel").is_none());
        let mut wrong_domain = input.clone();
        wrong_domain["domainProof"]["domain"] = json!("unknown");
        assert!(adjudicate_scanner_candidates_isolated(
            &rows,
            &[wrong_domain],
            "sha256:domain-parent",
            ContextPolicy::Attested
        )
        .is_err());
        let mut proofless = input;
        proofless.as_object_mut().unwrap().remove("proof");
        assert!(adjudicate_scanner_candidates_isolated(
            &rows,
            &[proofless],
            "sha256:domain-parent",
            ContextPolicy::Attested
        )
        .is_err());
    }
}
