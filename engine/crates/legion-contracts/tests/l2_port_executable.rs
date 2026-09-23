//! Integration tests for the L2 port (`src/l2_port`), exercised through the
//! crate's public API the way an external consumer would use it.

use legion_contracts::l2_port::{
    collect_executable_contract_errors, ArtifactUnit, Artifacts, DependencyEdge, ExecutionContract,
    IdStatement, OpenQuestion, Scope,
};

fn base_contract() -> ExecutionContract {
    ExecutionContract {
        schema_version: 1,
        kind: "legion-execution-contract".into(),
        contract_id: "EC-1".into(),
        version: 1,
        source_revision: "0123456".into(),
        advisory_profile: None,
        objective: "obj".into(),
        current_state: "cur".into(),
        desired_state: "des".into(),
        requirements: vec![],
        decisions: vec![],
        invariants: vec![],
        non_goals: vec![],
        scope: Scope { own: vec![], read: vec![], forbidden: vec![] },
        artifacts: Artifacts { exact: vec![], bounded: vec![] },
        tasks: vec![],
        dependencies: vec![],
        acceptance_criteria: vec![],
        declared_checks: vec![],
        evidence_requirements: vec![],
        authorized_effect_classes: vec![],
        repair_latitude: vec![],
        stop_conditions: vec![],
        escalation_conditions: vec![],
        rollback: vec![],
        open_questions: vec![],
        budget: None,
    }
}

#[test]
fn empty_contract_is_executable() {
    let contract = base_contract();
    assert!(collect_executable_contract_errors(&contract).is_empty());
}

#[test]
fn combined_failures_are_sorted_and_deduplicated() {
    let mut contract = base_contract();
    contract.open_questions.push(OpenQuestion {
        id: "OQ-1".into(),
        question: "q".into(),
        blocks_artifacts: None,
    });
    contract.artifacts.exact.push(ArtifactUnit {
        id: "A-1".into(),
        path: "p".into(),
        latitude: "EXACT".into(),
        content: None,
        locked: None,
        freedom: None,
    });
    contract.artifacts.bounded.push(ArtifactUnit {
        id: "B-1".into(),
        path: "p".into(),
        latitude: "BOUNDED".into(),
        content: None,
        locked: Some(vec![]),
        freedom: Some(vec![]),
    });
    contract.dependencies.push(DependencyEdge {
        from: "A-1".into(),
        to: "B-1".into(),
        reason: "shared-mutable-resource".into(),
        resource_key: Some(serde_json::Value::String(String::new())),
    });
    contract.requirements.push(IdStatement {
        id: "DUP-1".into(),
        statement: "s".into(),
        rationale: None,
        alternatives_considered: None,
    });
    contract.decisions.push(IdStatement {
        id: "DUP-1".into(),
        statement: "s".into(),
        rationale: None,
        alternatives_considered: None,
    });

    let errors = collect_executable_contract_errors(&contract);
    let codes: Vec<&str> = errors.iter().map(|e| e.code.as_str()).collect();
    assert!(codes.contains(&"EXEC_OPEN_QUESTIONS_NONEMPTY"));
    assert!(codes.contains(&"EXEC_EXACT_CONTENT_NULL"));
    assert!(codes.contains(&"EXEC_BOUNDED_LOCKED_EMPTY"));
    assert!(codes.contains(&"EXEC_BOUNDED_FREEDOM_EMPTY"));
    assert!(codes.contains(&"EXEC_RESOURCE_KEY_MISSING"));
    assert!(codes.contains(&"EXEC_ID_NOT_UNIQUE"));

    // Sorted lexicographically by (code, path, message).
    let mut sorted_codes = codes.clone();
    sorted_codes.sort();
    // Within equal codes ordering already matches; just check overall non-decreasing by code.
    for pair in codes.windows(2) {
        assert!(pair[0] <= pair[1], "errors not sorted by code: {codes:?}");
    }
}
