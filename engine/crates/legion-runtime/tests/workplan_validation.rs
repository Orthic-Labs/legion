use legion_contracts::{AgentId, TaskId};
use legion_runtime::workplan::{
    parse_work_plan_json, validate_work_plan, CompletionEvidence, EvidenceAssurance,
    EvidenceOutcome, WorkPlan, WorkPlanReasonCode as Code, WorkUnit, WorkUnitAccess, WorkUnitStatus,
    WriteScopeKind, MAX_WORK_PLAN_BYTES, MAX_WORK_UNITS,
};

fn fixture() -> WorkPlan {
    parse_work_plan_json(include_bytes!("workplan-ready.json")).expect("typed fixture")
}

fn assert_error(plan: &WorkPlan, expected: Code) {
    let error = validate_work_plan(plan).expect_err("plan must be rejected");
    assert_eq!(error.code, expected, "{error}");
    assert!(!error.field.is_empty());
}

fn complete(unit: &mut WorkUnit) {
    unit.status = WorkUnitStatus::Complete;
    unit.evidence = unit
        .evidence_requirements
        .iter()
        .map(|requirement| {
            let predicate = unit.completion.iter().find(|p| p.id == requirement.predicate_id).unwrap();
            CompletionEvidence {
                name: requirement.name.clone(),
                predicate_id: predicate.id.clone(),
                unit_id: unit.id.clone(),
                unit_revision: unit.revision.clone(),
                artifact: predicate.artifact.clone(),
                author: unit.owner.clone(),
                reviewer: Some(AgentId::new("independent-reviewer").unwrap()),
                outcome: EvidenceOutcome::Passed,
            }
        })
        .collect();
}

#[test]
fn ready_fixture_uses_existing_topology_and_never_claims_verified_proof() {
    let plan = fixture();
    let assessment = validate_work_plan(&plan).unwrap();
    assert_eq!(assessment.ready_units.iter().map(TaskId::as_str).collect::<Vec<_>>(), ["documentation", "implementation"]);
    assert_eq!(assessment.topological_order.iter().map(TaskId::as_str).collect::<Vec<_>>(), ["documentation", "implementation", "integration"]);
    assert!(assessment.asserted_complete_units.is_empty());
    assert_eq!(assessment.evidence_assurance, EvidenceAssurance::ImportedAssertionsOnly);
    let mut reversed = plan;
    reversed.units.reverse();
    assert_eq!(assessment, validate_work_plan(&reversed).unwrap());
}

#[test]
fn readonly_units_can_observe_artifacts_without_claiming_write_ownership() {
    let mut plan = fixture();
    let readonly = &mut plan.units[1];
    readonly.access = WorkUnitAccess::ReadOnly;
    readonly.write_scopes.clear();
    // This artifact is owned by the concurrently ready implementation unit.
    readonly.completion[0].artifact.path = "src/feature.rs".into();
    let assessment = validate_work_plan(&plan).expect("read-only inspection may observe another unit's artifact");
    assert_eq!(assessment.ready_units.iter().map(TaskId::as_str).collect::<Vec<_>>(), ["documentation", "implementation"]);

    complete(&mut plan.units[1]);
    validate_work_plan(&plan).expect("read-only completion evidence binds the observed artifact");
    plan.units[1].evidence[0].artifact.sha256 = "d".repeat(64);
    assert_error(&plan, Code::StaleEvidence);
}

#[test]
fn access_mode_requires_matching_write_scope_declaration() {
    let mut plan = fixture();
    plan.units[0].access = WorkUnitAccess::ReadOnly;
    assert_error(&plan, Code::InvalidField);

    let mut plan = fixture();
    plan.units[0].write_scopes.clear();
    assert_error(&plan, Code::EmptyField);
}

#[test]
fn access_mode_is_required_in_json() {
    let mut json = serde_json::to_value(fixture()).unwrap();
    json["units"][0].as_object_mut().unwrap().remove("access");
    assert_eq!(parse_work_plan_json(&serde_json::to_vec(&json).unwrap()).unwrap_err().code, Code::InvalidJson);
}

#[test]
fn asserted_completion_unlocks_only_actual_dependents() {
    let mut plan = fixture();
    complete(&mut plan.units[0]);
    let assessment = validate_work_plan(&plan).unwrap();
    assert_eq!(assessment.ready_units.iter().map(TaskId::as_str).collect::<Vec<_>>(), ["documentation"]);
    complete(&mut plan.units[1]);
    let assessment = validate_work_plan(&plan).unwrap();
    assert_eq!(assessment.ready_units.iter().map(TaskId::as_str).collect::<Vec<_>>(), ["integration"]);
    complete(&mut plan.units[2]);
    let assessment = validate_work_plan(&plan).unwrap();
    assert!(assessment.ready_units.is_empty());
    assert_eq!(assessment.asserted_complete_units.len(), 3);
}

#[test]
fn rejects_duplicate_missing_self_and_cyclic_dependencies() {
    let mut plan = fixture();
    plan.units.push(plan.units[0].clone());
    assert_error(&plan, Code::DuplicateUnit);
    let mut plan = fixture();
    plan.units[0].depends_on.push(TaskId::new("missing").unwrap());
    assert_error(&plan, Code::MissingDependency);
    let mut plan = fixture();
    let dependency = plan.units[0].id.clone();
    plan.units[0].depends_on.push(dependency);
    assert_error(&plan, Code::SelfDependency);
    let mut plan = fixture();
    let dependency = plan.units[2].id.clone();
    plan.units[0].depends_on.push(dependency);
    assert_error(&plan, Code::DependencyCycle);
    let mut plan = fixture();
    let dependency = plan.units[0].id.clone();
    plan.units[2].depends_on.push(dependency);
    assert_error(&plan, Code::DuplicateItem);
}

#[test]
fn concurrent_same_owner_cannot_bypass_exclusive_write_scope() {
    let mut plan = fixture();
    plan.units[1].owner = plan.units[0].owner.clone();
    plan.units[1].write_scopes = plan.units[0].write_scopes.clone();
    plan.units[1].completion[0].artifact.path = "src/feature.rs".into();
    assert_error(&plan, Code::ScopeConflict);
    let dependency = plan.units[0].id.clone();
    plan.units[1].depends_on.push(dependency);
    validate_work_plan(&plan).expect("a real dependency serializes shared writes");
}

#[test]
fn catches_directory_case_and_file_ancestor_conflicts() {
    for (left, right, kind) in [
        ("src", "src/feature.md", WriteScopeKind::Directory),
        ("SRC/FEATURE.RS", "src/feature.rs", WriteScopeKind::File),
        ("src", "src/feature.rs", WriteScopeKind::File),
    ] {
        let mut plan = fixture();
        plan.units[0].write_scopes[0].path = left.into();
        plan.units[0].write_scopes[0].kind = kind;
        plan.units[0].completion[0].artifact.path = left.into();
        plan.units[1].write_scopes[0].path = right.into();
        plan.units[1].completion[0].artifact.path = right.into();
        assert_error(&plan, Code::ScopeConflict);
    }
}

#[test]
fn distinct_path_components_do_not_conflict() {
    let mut plan = fixture();
    plan.units[0].write_scopes[0].path = "src/a".into();
    plan.units[0].write_scopes[0].kind = WriteScopeKind::Directory;
    plan.units[0].completion[0].artifact.path = "src/a/file".into();
    plan.units[1].write_scopes[0].path = "src/ab/file".into();
    plan.units[1].completion[0].artifact.path = "src/ab/file".into();
    validate_work_plan(&plan).unwrap();
}

#[test]
fn rejects_absolute_traversal_globs_platform_aliases_and_non_normalized_paths() {
    for bad in ["/tmp/file", "../file", "src/../file", "./src/file", "C:/file", "C:\\file", "\\\\server\\file", "src//file", "src/", ".", "src/**", "src/NUL.txt", "src/com1", "src/file.", "src/file ", "src/%2e%2e/file", "src/é"] {
        let mut plan = fixture();
        plan.units[0].write_scopes[0].path = bad.into();
        assert!(validate_work_plan(&plan).is_err(), "unsafe path {bad}");
    }
}

#[test]
fn artifacts_cannot_escape_declared_ownership() {
    let mut plan = fixture();
    plan.units[0].completion[0].artifact.path = "other/feature.rs".into();
    assert_error(&plan, Code::UnsafePath);
}

#[test]
fn stale_identity_revision_owner_or_artifact_never_completes() {
    for changed in ["unit", "revision", "path", "artifact_revision", "digest", "author"] {
        let mut plan = fixture();
        complete(&mut plan.units[0]);
        let evidence = &mut plan.units[0].evidence[0];
        match changed {
            "unit" => evidence.unit_id = TaskId::new("another-unit").unwrap(),
            "revision" => evidence.unit_revision = "old-work".into(),
            "path" => evidence.artifact.path = "src/another.rs".into(),
            "artifact_revision" => evidence.artifact.revision = "old-artifact".into(),
            "digest" => evidence.artifact.sha256 = "d".repeat(64),
            "author" => evidence.author = AgentId::new("different-author").unwrap(),
            _ => unreachable!(),
        }
        assert_error(&plan, Code::StaleEvidence);
        // Pending evidence is checked as well, not silently ignored.
        plan.units[0].status = WorkUnitStatus::Pending;
        assert_error(&plan, Code::StaleEvidence);
    }
}

#[test]
fn every_predicate_and_named_evidence_item_is_required() {
    let mut plan = fixture();
    plan.units[0].status = WorkUnitStatus::Complete;
    assert_error(&plan, Code::MissingEvidence);
    let mut plan = fixture();
    let mut extra = plan.units[0].completion[0].clone();
    extra.id = "second-predicate".into();
    plan.units[0].completion.push(extra);
    assert_error(&plan, Code::MissingEvidence);
    let mut plan = fixture();
    complete(&mut plan.units[0]);
    plan.units[0].evidence[0].predicate_id = "wrong".into();
    assert_error(&plan, Code::UnexpectedEvidence);
    let mut plan = fixture();
    complete(&mut plan.units[0]);
    plan.units[0].evidence[0].name = "unrequested".into();
    assert_error(&plan, Code::UnexpectedEvidence);
    let mut plan = fixture();
    complete(&mut plan.units[0]);
    let duplicate = plan.units[0].evidence[0].clone();
    plan.units[0].evidence.push(duplicate);
    assert_error(&plan, Code::DuplicateItem);
}

#[test]
fn failed_evidence_and_incomplete_dependencies_block_completion() {
    let mut plan = fixture();
    complete(&mut plan.units[0]);
    plan.units[0].evidence[0].outcome = EvidenceOutcome::Failed;
    assert_error(&plan, Code::FailedEvidence);
    let mut plan = fixture();
    complete(&mut plan.units[2]);
    assert_error(&plan, Code::DependencyIncomplete);
}

#[test]
fn independent_review_requires_a_distinct_named_identity() {
    let mut plan = fixture();
    complete(&mut plan.units[1]);
    plan.units[1].evidence[0].reviewer = None;
    assert_error(&plan, Code::IndependentReviewRequired);
    plan.units[1].evidence[0].reviewer = Some(plan.units[1].owner.clone());
    assert_error(&plan, Code::IndependentReviewRequired);
}

#[test]
fn typed_and_json_inputs_have_bounded_dimensions_and_strict_fields() {
    let too_large = vec![b' '; MAX_WORK_PLAN_BYTES + 1];
    assert_eq!(parse_work_plan_json(&too_large).unwrap_err().code, Code::InputLimit);
    let mut plan = fixture();
    plan.units = vec![plan.units[0].clone(); MAX_WORK_UNITS + 1];
    assert_error(&plan, Code::InputLimit);
    let mut plan = fixture();
    plan.units[0].revision = "x".repeat(1025);
    assert_error(&plan, Code::InputLimit);
    let mut json = serde_json::to_value(fixture()).unwrap();
    json["units"][0]["evidence_is_verified"] = true.into();
    assert_eq!(parse_work_plan_json(&serde_json::to_vec(&json).unwrap()).unwrap_err().code, Code::InvalidJson);
    let mut plan = fixture();
    plan.schema_version = 2;
    assert_error(&plan, Code::UnsupportedVersion);
}
