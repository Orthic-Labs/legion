use super::*;
use WorkPlanReasonCode as Code;

type ValidationResult = Result<(), WorkPlanValidationError>;

fn text(value: &str, field: &str, unit: Option<&WorkUnit>) -> ValidationResult {
    if value.len() > MAX_FIELD_BYTES {
        return Err(failure(
            Code::InputLimit,
            field,
            unit,
            "field exceeds byte limit",
        ));
    }
    if value.trim().is_empty() {
        return Err(failure(
            Code::EmptyField,
            field,
            unit,
            "field must be non-empty",
        ));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(failure(
            Code::InvalidField,
            field,
            unit,
            "field must be trimmed and contain no control characters",
        ));
    }
    Ok(())
}

fn items(length: usize, field: &str, unit: &WorkUnit, required: bool) -> ValidationResult {
    if length > MAX_UNIT_ITEMS {
        return Err(failure(
            Code::InputLimit,
            field,
            Some(unit),
            "too many items",
        ));
    }
    if required && length == 0 {
        return Err(failure(
            Code::EmptyField,
            field,
            Some(unit),
            "at least one item is required",
        ));
    }
    Ok(())
}

/// A portable lexical scope, deliberately excluding glob syntax, root scopes,
/// ambiguous separators, Windows aliases and device names. Filesystem symlinks
/// and mounted volumes must still be resolved by the effect-owning host.
fn path(value: &str, field: &str, unit: &WorkUnit) -> ValidationResult {
    text(value, field, Some(unit))?;
    let unsafe_component = value.split('/').any(|part| {
        let base = part.split('.').next().unwrap_or("").to_ascii_lowercase();
        part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with('.')
            || part.ends_with(' ')
            || matches!(base.as_str(), "con" | "prn" | "aux" | "nul")
            || (base.len() == 4
                && (base.starts_with("com") || base.starts_with("lpt"))
                && matches!(base.as_bytes()[3], b'1'..=b'9'))
    });
    if !value.is_ascii()
        || unsafe_component
        || value.bytes().any(|byte| {
            matches!(
                byte,
                b'\\' | b':' | b'*' | b'?' | b'[' | b']' | b'<' | b'>' | b'|' | b'"' | b'%'
            )
        })
    {
        return Err(failure(
            Code::UnsafePath,
            field,
            Some(unit),
            "expected a normalized portable repository-relative path without globs or escapes",
        ));
    }
    Ok(())
}

fn artifact(value: &ArtifactRevision, field: &str, unit: &WorkUnit) -> ValidationResult {
    path(&value.path, field, unit)?;
    text(&value.revision, field, Some(unit))?;
    if value.sha256.len() != 64
        || !value
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(failure(
            Code::InvalidField,
            field,
            Some(unit),
            "artifact requires a lowercase hexadecimal SHA-256",
        ));
    }
    Ok(())
}

fn contains(scope: &WriteScope, target: &str) -> bool {
    let root = scope.path.to_ascii_lowercase();
    let target = target.to_ascii_lowercase();
    root == target
        || (scope.kind == WriteScopeKind::Directory && target.starts_with(&format!("{root}/")))
}

fn overlaps(left: &WriteScope, right: &WriteScope) -> bool {
    // A file that is an ancestor of another declared path is also a conflict:
    // the same portable filesystem cannot hold both declarations as files.
    let left = left.path.to_ascii_lowercase();
    let right = right.path.to_ascii_lowercase();
    left == right
        || left.starts_with(&format!("{right}/"))
        || right.starts_with(&format!("{left}/"))
}

fn validate_unit(unit: &WorkUnit) -> ValidationResult {
    text(unit.id.as_str(), "id", Some(unit))?;
    text(unit.owner.as_str(), "owner", Some(unit))?;
    text(&unit.revision, "revision", Some(unit))?;
    items(unit.write_scopes.len(), "write_scopes", unit, false)?;
    match unit.access {
        WorkUnitAccess::ReadOnly if !unit.write_scopes.is_empty() => {
            return Err(failure(
                Code::InvalidField,
                "write_scopes",
                Some(unit),
                "read-only units must not declare write scopes",
            ));
        }
        WorkUnitAccess::Write if unit.write_scopes.is_empty() => {
            return Err(failure(
                Code::EmptyField,
                "write_scopes",
                Some(unit),
                "write units require at least one write scope",
            ));
        }
        _ => {}
    }
    items(unit.depends_on.len(), "depends_on", unit, false)?;
    items(unit.completion.len(), "completion", unit, true)?;
    items(
        unit.evidence_requirements.len(),
        "evidence_requirements",
        unit,
        true,
    )?;
    items(unit.evidence.len(), "evidence", unit, false)?;
    let mut scope_paths = BTreeSet::new();
    for scope in &unit.write_scopes {
        path(&scope.path, "write_scopes.path", unit)?;
        if !scope_paths.insert(scope.path.to_ascii_lowercase()) {
            return Err(failure(
                Code::DuplicateItem,
                "write_scopes.path",
                Some(unit),
                "duplicate scope path",
            ));
        }
    }
    let mut dependencies = BTreeSet::new();
    for dependency in &unit.depends_on {
        text(dependency.as_str(), "depends_on", Some(unit))?;
        if dependency == &unit.id {
            return Err(failure(
                Code::SelfDependency,
                "depends_on",
                Some(unit),
                "unit cannot depend on itself",
            ));
        }
        if !dependencies.insert(dependency) {
            return Err(failure(
                Code::DuplicateItem,
                "depends_on",
                Some(unit),
                "duplicate dependency",
            ));
        }
    }
    let mut predicates = BTreeMap::new();
    for predicate in &unit.completion {
        text(&predicate.id, "completion.id", Some(unit))?;
        text(&predicate.description, "completion.description", Some(unit))?;
        artifact(&predicate.artifact, "completion.artifact", unit)?;
        if unit.access == WorkUnitAccess::Write
            && !unit
                .write_scopes
                .iter()
                .any(|scope| contains(scope, &predicate.artifact.path))
        {
            return Err(failure(
                Code::UnsafePath,
                "completion.artifact.path",
                Some(unit),
                "completion artifact must belong to a declared write scope",
            ));
        }
        if predicates
            .insert(predicate.id.as_str(), predicate)
            .is_some()
        {
            return Err(failure(
                Code::DuplicateItem,
                "completion.id",
                Some(unit),
                "duplicate completion predicate",
            ));
        }
    }
    let mut requirements = BTreeMap::new();
    let mut covered = BTreeSet::new();
    for requirement in &unit.evidence_requirements {
        text(&requirement.name, "evidence_requirements.name", Some(unit))?;
        text(
            &requirement.predicate_id,
            "evidence_requirements.predicate_id",
            Some(unit),
        )?;
        if !predicates.contains_key(requirement.predicate_id.as_str()) {
            return Err(failure(
                Code::MissingPredicate,
                "evidence_requirements.predicate_id",
                Some(unit),
                "evidence requirement references an unknown predicate",
            ));
        }
        covered.insert(requirement.predicate_id.as_str());
        if requirements
            .insert(requirement.name.as_str(), requirement)
            .is_some()
        {
            return Err(failure(
                Code::DuplicateItem,
                "evidence_requirements.name",
                Some(unit),
                "duplicate evidence requirement name",
            ));
        }
    }
    if covered.len() != predicates.len() {
        return Err(failure(
            Code::MissingEvidence,
            "evidence_requirements",
            Some(unit),
            "every completion predicate requires named evidence",
        ));
    }
    let mut supplied = BTreeSet::new();
    for evidence in &unit.evidence {
        text(&evidence.name, "evidence.name", Some(unit))?;
        text(&evidence.predicate_id, "evidence.predicate_id", Some(unit))?;
        text(evidence.unit_id.as_str(), "evidence.unit_id", Some(unit))?;
        text(
            &evidence.unit_revision,
            "evidence.unit_revision",
            Some(unit),
        )?;
        text(evidence.author.as_str(), "evidence.author", Some(unit))?;
        if let Some(reviewer) = &evidence.reviewer {
            text(reviewer.as_str(), "evidence.reviewer", Some(unit))?;
        }
        artifact(&evidence.artifact, "evidence.artifact", unit)?;
        if !supplied.insert(evidence.name.as_str()) {
            return Err(failure(
                Code::DuplicateItem,
                "evidence.name",
                Some(unit),
                "duplicate supplied evidence name",
            ));
        }
        let requirement = requirements.get(evidence.name.as_str()).ok_or_else(|| {
            failure(
                Code::UnexpectedEvidence,
                "evidence.name",
                Some(unit),
                "evidence has no matching named requirement",
            )
        })?;
        if evidence.predicate_id != requirement.predicate_id {
            return Err(failure(
                Code::UnexpectedEvidence,
                "evidence.predicate_id",
                Some(unit),
                "evidence names the wrong predicate",
            ));
        }
        let predicate = predicates[evidence.predicate_id.as_str()];
        if evidence.unit_id != unit.id
            || evidence.unit_revision != unit.revision
            || evidence.artifact != predicate.artifact
            || evidence.author != unit.owner
        {
            return Err(failure(Code::StaleEvidence, "evidence", Some(unit), "evidence must match the current unit, owner, unit revision, artifact path, artifact revision and digest"));
        }
        if requirement.independent_review
            && evidence
                .reviewer
                .as_ref()
                .is_none_or(|reviewer| reviewer.trim().eq_ignore_ascii_case(evidence.author.trim()))
        {
            return Err(failure(
                Code::IndependentReviewRequired,
                "evidence.reviewer",
                Some(unit),
                "required reviewer must differ from the unit owner and evidence author",
            ));
        }
        if unit.status == WorkUnitStatus::Complete && evidence.outcome != EvidenceOutcome::Passed {
            return Err(failure(
                Code::FailedEvidence,
                "evidence.outcome",
                Some(unit),
                "complete unit has failed evidence",
            ));
        }
    }
    if unit.status == WorkUnitStatus::Complete && supplied.len() != requirements.len() {
        return Err(failure(
            Code::MissingEvidence,
            "evidence",
            Some(unit),
            "complete unit requires every named evidence item",
        ));
    }
    Ok(())
}

/// Validate declarations and imported assertions; return ready units without
/// dispatching, authorizing effects or treating the assertions as runtime proof.
pub fn validate_work_plan(plan: &WorkPlan) -> Result<WorkPlanAssessment, WorkPlanValidationError> {
    if plan.schema_version != 1 {
        return Err(failure(
            Code::UnsupportedVersion,
            "schema_version",
            None,
            "only work-plan schema version 1 is supported",
        ));
    }
    text(plan.plan_id.as_str(), "plan_id", None)?;
    if plan.units.is_empty() {
        return Err(failure(
            Code::EmptyField,
            "units",
            None,
            "at least one unit is required",
        ));
    }
    if plan.units.len() > MAX_WORK_UNITS {
        return Err(failure(
            Code::InputLimit,
            "units",
            None,
            "too many work units",
        ));
    }
    let mut by_id = BTreeMap::new();
    for unit in &plan.units {
        validate_unit(unit)?;
        if by_id.insert(unit.id.clone(), unit).is_some() {
            return Err(failure(
                Code::DuplicateUnit,
                "units.id",
                Some(unit),
                "duplicate work unit id",
            ));
        }
    }
    for unit in &plan.units {
        if unit.depends_on.iter().any(|id| !by_id.contains_key(id)) {
            return Err(failure(
                Code::MissingDependency,
                "depends_on",
                Some(unit),
                "dependency names an unknown unit",
            ));
        }
    }
    let order = ordered(plan)?;
    let ancestors = ancestors(plan, &order);
    for (index, left) in plan.units.iter().enumerate() {
        for right in plan.units.iter().skip(index + 1) {
            if ancestors[&left.id].contains(&right.id) || ancestors[&right.id].contains(&left.id) {
                continue;
            }
            if left
                .write_scopes
                .iter()
                .any(|a| right.write_scopes.iter().any(|b| overlaps(a, b)))
            {
                return Err(failure(Code::ScopeConflict, "write_scopes", Some(left), "unordered units have overlapping exclusive scopes; add a real dependency or split ownership"));
            }
        }
    }
    let mut ready = Vec::new();
    let mut complete = Vec::new();
    for id in &order {
        let unit = by_id[id];
        let dependencies_complete = unit
            .depends_on
            .iter()
            .all(|dependency| by_id[dependency].status == WorkUnitStatus::Complete);
        match unit.status {
            WorkUnitStatus::Complete if !dependencies_complete => {
                return Err(failure(
                    Code::DependencyIncomplete,
                    "status",
                    Some(unit),
                    "complete unit depends on incomplete work",
                ));
            }
            WorkUnitStatus::Complete => complete.push(id.clone()),
            WorkUnitStatus::Pending if dependencies_complete => ready.push(id.clone()),
            WorkUnitStatus::Pending => {}
        }
    }
    Ok(WorkPlanAssessment {
        schema_version: 1,
        plan_id: plan.plan_id.clone(),
        topological_order: order,
        ready_units: ready,
        asserted_complete_units: complete,
        evidence_assurance: EvidenceAssurance::ImportedAssertionsOnly,
    })
}
