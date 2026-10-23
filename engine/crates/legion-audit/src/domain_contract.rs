//! Versioned domain vocabulary & cross-repository contracts (A12).
//!
//! Repository contract files are **evidence, never execution authority**: they
//! are frozen (bytes + `sha256:` digest) against the snapshot set, parsed
//! strictly, and compared only through explicit term-id mappings. Nothing is
//! joined by name: different names may map to one term id, and identical names
//! mapped to different term ids are reported as collisions, never equated.
//!
//! Missing, conflicting or unresolvable input becomes an [`UnresolvedBoundary`]
//! (surfaced by callers as `unproven`/missing-context), never a guessed
//! requirement and never clean. Terms with unresolved authority or conflicting
//! definitions are excluded from comparison.
//!
//! Disposition statuses reuse the requirement-traceability vocabulary. A term
//! with no findings is `implemented-unverified`; `implemented-and-verified`
//! requires authenticated evidence this module cannot supply. SPEC and
//! STANDARDS outcomes stay separate: this module only judges SPEC fidelity.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::assurance::SnapshotRef;

pub const DOMAIN_CONTRACT_SCHEMA_VERSION: u32 = 1;

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn safe_rel_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\0')
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.split('/').any(|part| part.is_empty() || part == "..")
}

// ---------------------------------------------------------------- schema

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueKind {
    Money,
    Instant,
    Date,
    Quantity,
    Identifier,
    State,
    Text,
    Flag,
}

/// Unit/scale/currency/timezone meaning of a value as stated or as represented.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValueSemantics {
    pub kind: Option<ValueKind>,
    /// e.g. `minor` (cents) or `major`.
    #[serde(default)]
    pub unit: Option<String>,
    /// Decimal scale, e.g. 2 for cents-per-major.
    #[serde(default)]
    pub scale: Option<i32>,
    #[serde(default)]
    pub currency: Option<String>,
    /// IANA zone or `UTC`; `local` is a distinct, non-UTC value.
    #[serde(default)]
    pub timezone: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateTransition {
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBoundary {
    pub tenant_scoped: bool,
    /// Term id (`namespace/id`) of the tenant identifier scoping this term.
    #[serde(default)]
    pub tenant_term: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumerDecl {
    pub repository_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DomainTerm {
    pub namespace: String,
    pub id: String,
    pub version: String,
    /// Owning team/repository. Required; absence is unresolved, not defaulted.
    #[serde(default)]
    pub owner: String,
    /// Authority that ratified the meaning. Required.
    #[serde(default)]
    pub authority: String,
    #[serde(default)]
    pub meaning: String,
    #[serde(default)]
    pub semantics: Option<ValueSemantics>,
    #[serde(default)]
    pub states: Vec<String>,
    #[serde(default)]
    pub transitions: Vec<StateTransition>,
    #[serde(default)]
    pub nullable: Option<bool>,
    #[serde(default)]
    pub identity: Option<IdentityBoundary>,
    /// Consumers the authority knows about.
    #[serde(default)]
    pub consumers: Vec<ConsumerDecl>,
    /// True only when the authority states the consumer list is complete.
    #[serde(default)]
    pub external_consumers_enumerated: bool,
}

impl DomainTerm {
    pub fn key(&self) -> String {
        format!("{}/{}", self.namespace, self.id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MappingRole {
    Producer,
    Consumer,
    /// Persisted representation (also treated as a producer of values).
    Store,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Surface {
    Backend,
    Api,
    Database,
    Admin,
    Storefront,
    Mobile,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidencePointer {
    pub path: String,
    #[serde(default)]
    pub start_line: Option<u32>,
    #[serde(default)]
    pub end_line: Option<u32>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TermMapping {
    pub term_id: String,
    /// Term version this mapping was written against.
    pub term_version: String,
    pub repository_id: String,
    pub role: MappingRole,
    pub surface: Surface,
    /// Field/column/property name as it appears in this repository.
    pub symbol: String,
    #[serde(default)]
    pub semantics: Option<ValueSemantics>,
    #[serde(default)]
    pub nullable: Option<bool>,
    #[serde(default)]
    pub states: Vec<String>,
    #[serde(default)]
    pub transitions: Vec<StateTransition>,
    #[serde(default)]
    pub tenant_term: Option<String>,
    #[serde(default)]
    pub evidence: Vec<EvidencePointer>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractFileDoc {
    pub schema_version: u32,
    #[serde(default)]
    pub terms: Vec<DomainTerm>,
    #[serde(default)]
    pub mappings: Vec<TermMapping>,
}

// ---------------------------------------------------------------- inputs

/// One contract file read from a frozen repository snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractFileInput {
    pub repository_id: String,
    /// Repository-relative path; `.json`, `.yaml` or `.yml`.
    pub path: String,
    pub bytes: Vec<u8>,
    /// Digest frozen with the snapshot, when known; a mismatch is unresolved.
    pub expected_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractFileRef {
    pub repository_id: String,
    pub path: String,
    pub digest: String,
    /// False when the file was read but could not be trusted (parse error,
    /// digest mismatch, unbound repository...). Its digest still binds.
    pub accepted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnresolvedKind {
    MissingContracts,
    InvalidContract,
    DigestMismatch,
    UnboundRepository,
    MissingAuthority,
    ConflictingVersions,
    ConflictingMapping,
    VersionSkew,
    UnknownTerm,
    MappingOutsideRepository,
    MissingEvidence,
    UnknownConsumer,
    UnknownExternalConsumers,
}

impl UnresolvedKind {
    /// Kinds that make a term's meaning ambiguous rather than merely unproven.
    pub fn is_conflict(self) -> bool {
        matches!(
            self,
            Self::ConflictingVersions | Self::ConflictingMapping | Self::VersionSkew
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnresolvedBoundary {
    pub kind: UnresolvedKind,
    pub term_id: Option<String>,
    pub repository_id: Option<String>,
    pub detail: String,
}

fn unresolved(
    kind: UnresolvedKind,
    term_id: Option<&str>,
    repository_id: Option<&str>,
    detail: impl Into<String>,
) -> UnresolvedBoundary {
    UnresolvedBoundary {
        kind,
        term_id: term_id.map(str::to_owned),
        repository_id: repository_id.map(str::to_owned),
        detail: detail.into(),
    }
}

// ------------------------------------------------------------------- set

/// Frozen, digest-bound set of domain terms and their per-repository mappings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainContractSet {
    pub schema_version: u32,
    pub required: bool,
    /// Always false: contracts are evidence, not execution authority.
    pub execution_authority: bool,
    pub snapshots: Vec<SnapshotRef>,
    pub files: Vec<ContractFileRef>,
    /// Resolved terms keyed by `namespace/id`.
    pub terms: BTreeMap<String, DomainTerm>,
    pub mappings: Vec<TermMapping>,
    pub unresolved: Vec<UnresolvedBoundary>,
    pub set_digest: String,
}

/// Cache binding of a lens/finding context to the exact contracts it used.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainContextBinding {
    pub schema_version: u32,
    pub set_digest: String,
    pub files: Vec<ContractFileRef>,
    pub snapshots: Vec<SnapshotRef>,
    pub term_digests: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum BindingStatus {
    Valid,
    Invalidated { reasons: Vec<String> },
}

impl DomainContextBinding {
    /// Compare this binding with the contracts now in force. Any digest,
    /// snapshot, file or term change invalidates it even when implementation
    /// bytes are unchanged.
    pub fn verify_against(&self, current: &DomainContractSet) -> BindingStatus {
        let now = current.binding();
        let mut reasons = Vec::new();
        if self.schema_version != now.schema_version {
            reasons.push("schema version changed".to_owned());
        }
        if self.snapshots != now.snapshots {
            reasons.push("snapshot set changed".to_owned());
        }
        if self.files != now.files {
            reasons.push("contract file set or digest changed".to_owned());
        }
        for (term, digest) in &self.term_digests {
            match now.term_digests.get(term) {
                None => reasons.push(format!("term {term} no longer resolved")),
                Some(found) if found != digest => {
                    reasons.push(format!("term {term} definition or mappings changed"))
                }
                Some(_) => {}
            }
        }
        for term in now.term_digests.keys() {
            if !self.term_digests.contains_key(term) {
                reasons.push(format!("term {term} newly defined"));
            }
        }
        if reasons.is_empty() && self.set_digest != now.set_digest {
            reasons.push("set digest changed (unresolved boundaries differ)".to_owned());
        }
        if reasons.is_empty() {
            BindingStatus::Valid
        } else {
            BindingStatus::Invalidated { reasons }
        }
    }
}

type MappingKey = (String, String, MappingRole, Surface, String);

fn mapping_key(m: &TermMapping) -> MappingKey {
    (
        m.term_id.clone(),
        m.repository_id.clone(),
        m.role,
        m.surface,
        m.symbol.clone(),
    )
}

fn parse_doc(path: &str, bytes: &[u8]) -> Result<ContractFileDoc, String> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".json") {
        serde_json::from_slice(bytes).map_err(|e| e.to_string())
    } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        serde_yaml::from_slice(bytes).map_err(|e| e.to_string())
    } else {
        Err("unsupported contract file extension".to_owned())
    }
}

fn term_problem(term: &DomainTerm) -> Option<(UnresolvedKind, String)> {
    if !valid_token(&term.namespace) || !valid_token(&term.id) || term.version.trim().is_empty() {
        return Some((
            UnresolvedKind::InvalidContract,
            "term requires token namespace, id and non-empty version".into(),
        ));
    }
    if term.owner.trim().is_empty() || term.authority.trim().is_empty() {
        return Some((
            UnresolvedKind::MissingAuthority,
            "term requires explicit owner and authority".into(),
        ));
    }
    if let Some(identity) = &term.identity {
        if identity.tenant_scoped && identity.tenant_term.as_deref().unwrap_or("").is_empty() {
            return Some((
                UnresolvedKind::InvalidContract,
                "tenantScoped term requires tenantTerm".into(),
            ));
        }
    }
    None
}

impl DomainContractSet {
    /// Build the set. Never fails: every defect becomes an unresolved
    /// boundary. `required` makes an absent/empty contract set unresolved
    /// (missing context); when not required, absence yields an empty set and
    /// invents no requirement.
    pub fn build(
        inputs: &[ContractFileInput],
        snapshots: &[SnapshotRef],
        required: bool,
    ) -> Self {
        let mut snapshots = snapshots.to_vec();
        snapshots.sort();
        snapshots.dedup();
        let bound: BTreeSet<&str> = snapshots.iter().map(|s| s.repository_id.as_str()).collect();

        let mut ordered: Vec<&ContractFileInput> = inputs.iter().collect();
        ordered.sort_by(|a, b| (&a.repository_id, &a.path).cmp(&(&b.repository_id, &b.path)));

        let mut issues: BTreeSet<UnresolvedBoundary> = BTreeSet::new();
        let mut files: Vec<ContractFileRef> = Vec::new();
        let mut defs: BTreeMap<String, Vec<DomainTerm>> = BTreeMap::new();
        let mut excluded: BTreeSet<String> = BTreeSet::new();
        let mut raw_mappings: Vec<TermMapping> = Vec::new();

        for input in ordered {
            let digest = sha256_digest(&input.bytes);
            let repo = input.repository_id.as_str();
            let mut accepted = true;
            if !bound.contains(repo) {
                accepted = false;
                issues.insert(unresolved(
                    UnresolvedKind::UnboundRepository,
                    None,
                    Some(repo),
                    format!("{}: repository not in frozen snapshot set", input.path),
                ));
            }
            if !safe_rel_path(&input.path) {
                accepted = false;
                issues.insert(unresolved(
                    UnresolvedKind::InvalidContract,
                    None,
                    Some(repo),
                    format!("unsafe contract path {:?}", input.path),
                ));
            }
            if let Some(expected) = &input.expected_digest {
                if !is_sha256_digest(expected) || expected != &digest {
                    accepted = false;
                    issues.insert(unresolved(
                        UnresolvedKind::DigestMismatch,
                        None,
                        Some(repo),
                        format!("{}: bytes do not match frozen digest", input.path),
                    ));
                }
            }
            let doc = if accepted {
                match parse_doc(&input.path, &input.bytes) {
                    Ok(doc) if doc.schema_version == DOMAIN_CONTRACT_SCHEMA_VERSION => Some(doc),
                    Ok(doc) => {
                        issues.insert(unresolved(
                            UnresolvedKind::InvalidContract,
                            None,
                            Some(repo),
                            format!("{}: unsupported schemaVersion {}", input.path, doc.schema_version),
                        ));
                        None
                    }
                    Err(error) => {
                        issues.insert(unresolved(
                            UnresolvedKind::InvalidContract,
                            None,
                            Some(repo),
                            format!("{}: {error}", input.path),
                        ));
                        None
                    }
                }
            } else {
                None
            };
            files.push(ContractFileRef {
                repository_id: input.repository_id.clone(),
                path: input.path.clone(),
                digest,
                accepted: doc.is_some(),
            });
            let Some(doc) = doc else { continue };
            for term in doc.terms {
                let key = term.key();
                if let Some((kind, detail)) = term_problem(&term) {
                    let id = if valid_token(&term.namespace) && valid_token(&term.id) {
                        excluded.insert(key.clone());
                        Some(key.clone())
                    } else {
                        None
                    };
                    issues.insert(unresolved(kind, id.as_deref(), Some(repo), detail));
                    continue;
                }
                defs.entry(key).or_default().push(term);
            }
            for mapping in doc.mappings {
                if mapping.repository_id != input.repository_id {
                    issues.insert(unresolved(
                        UnresolvedKind::MappingOutsideRepository,
                        Some(&mapping.term_id),
                        Some(repo),
                        format!(
                            "{}: mapping for repository {:?} declared by {:?}",
                            input.path, mapping.repository_id, input.repository_id
                        ),
                    ));
                    continue;
                }
                raw_mappings.push(mapping);
            }
        }

        // Resolve term definitions: identical duplicates collapse, differing
        // ones conflict and are excluded (never merged or "latest wins").
        let mut terms: BTreeMap<String, DomainTerm> = BTreeMap::new();
        for (key, list) in defs {
            if excluded.contains(&key) {
                continue;
            }
            let mut distinct: Vec<DomainTerm> = Vec::new();
            for term in list {
                if !distinct.contains(&term) {
                    distinct.push(term);
                }
            }
            if distinct.len() == 1 {
                terms.insert(key, distinct.remove(0));
            } else {
                let versions: Vec<String> = distinct.iter().map(|t| t.version.clone()).collect();
                issues.insert(unresolved(
                    UnresolvedKind::ConflictingVersions,
                    Some(&key),
                    None,
                    format!("conflicting definitions (versions {})", versions.join(", ")),
                ));
                excluded.insert(key);
            }
        }
        // A term that also has an invalid sibling definition is not trusted.
        for key in &excluded {
            terms.remove(key);
        }

        // Mappings: dedupe identical, conflict on differing duplicates.
        let mut by_key: BTreeMap<MappingKey, Vec<TermMapping>> = BTreeMap::new();
        for mapping in raw_mappings {
            by_key.entry(mapping_key(&mapping)).or_default().push(mapping);
        }
        let mut mappings: Vec<TermMapping> = Vec::new();
        for (key, list) in by_key {
            let mut distinct: Vec<TermMapping> = Vec::new();
            for mapping in list {
                if !distinct.contains(&mapping) {
                    distinct.push(mapping);
                }
            }
            if distinct.len() > 1 {
                issues.insert(unresolved(
                    UnresolvedKind::ConflictingMapping,
                    Some(&key.0),
                    Some(&key.1),
                    format!("conflicting mappings for symbol {:?}", key.4),
                ));
                continue;
            }
            let mapping = distinct.remove(0);
            match terms.get(&mapping.term_id) {
                None => {
                    if !excluded.contains(&mapping.term_id) {
                        issues.insert(unresolved(
                            UnresolvedKind::UnknownTerm,
                            Some(&mapping.term_id),
                            Some(&mapping.repository_id),
                            format!("mapping {:?} references an undefined term", mapping.symbol),
                        ));
                    }
                    continue;
                }
                Some(term) if term.version != mapping.term_version => {
                    issues.insert(unresolved(
                        UnresolvedKind::VersionSkew,
                        Some(&mapping.term_id),
                        Some(&mapping.repository_id),
                        format!(
                            "mapping {:?} targets version {} but contract is {}",
                            mapping.symbol, mapping.term_version, term.version
                        ),
                    ));
                    continue;
                }
                Some(_) => {}
            }
            if mapping.evidence.is_empty() {
                issues.insert(unresolved(
                    UnresolvedKind::MissingEvidence,
                    Some(&mapping.term_id),
                    Some(&mapping.repository_id),
                    format!("mapping {:?} carries no evidence pointer", mapping.symbol),
                ));
            }
            mappings.push(mapping);
        }
        mappings.sort_by_key(mapping_key);

        // Consumer coverage.
        for (key, term) in &terms {
            for consumer in &term.consumers {
                if !bound.contains(consumer.repository_id.as_str()) {
                    issues.insert(unresolved(
                        UnresolvedKind::UnknownConsumer,
                        Some(key),
                        Some(&consumer.repository_id),
                        "declared consumer repository is not in the frozen snapshot set",
                    ));
                } else if !mappings.iter().any(|m| {
                    &m.term_id == key
                        && m.repository_id == consumer.repository_id
                        && m.role == MappingRole::Consumer
                }) {
                    issues.insert(unresolved(
                        UnresolvedKind::UnknownConsumer,
                        Some(key),
                        Some(&consumer.repository_id),
                        "declared consumer has no consumer mapping",
                    ));
                }
            }
            let exposed = mappings.iter().any(|m| {
                &m.term_id == key
                    && matches!(m.role, MappingRole::Producer | MappingRole::Store)
                    && matches!(m.surface, Surface::Api | Surface::Database)
            });
            if exposed && !term.external_consumers_enumerated {
                issues.insert(unresolved(
                    UnresolvedKind::UnknownExternalConsumers,
                    Some(key),
                    None,
                    "exposed value; authority does not enumerate all external consumers",
                ));
            }
        }

        if required && terms.is_empty() && issues.is_empty() {
            issues.insert(unresolved(
                UnresolvedKind::MissingContracts,
                None,
                None,
                "domain contracts required but none supplied",
            ));
        } else if required && terms.is_empty() {
            issues.insert(unresolved(
                UnresolvedKind::MissingContracts,
                None,
                None,
                "domain contracts required but no term resolved",
            ));
        }

        let mut set = Self {
            schema_version: DOMAIN_CONTRACT_SCHEMA_VERSION,
            required,
            execution_authority: false,
            snapshots,
            files,
            terms,
            mappings,
            unresolved: issues.into_iter().collect(),
            set_digest: String::new(),
        };
        set.set_digest = set.compute_digest();
        set
    }

    fn compute_digest(&self) -> String {
        let terms: BTreeMap<String, String> = self
            .terms
            .keys()
            .map(|k| (k.clone(), self.term_digest(k).unwrap_or_default()))
            .collect();
        let body = json!({
            "schemaVersion": self.schema_version,
            "required": self.required,
            "snapshots": self.snapshots,
            "files": self.files,
            "terms": terms,
            "unresolved": self.unresolved,
        });
        sha256_digest(&serde_json::to_vec(&body).unwrap_or_default())
    }

    /// Digest of one term definition plus every mapping bound to it.
    pub fn term_digest(&self, term_id: &str) -> Option<String> {
        let term = self.terms.get(term_id)?;
        let maps: Vec<&TermMapping> = self.mappings.iter().filter(|m| m.term_id == term_id).collect();
        Some(sha256_digest(
            &serde_json::to_vec(&json!({"term": term, "mappings": maps})).unwrap_or_default(),
        ))
    }

    /// Digest scoped to the named terms (for per-finding/lens cache keys).
    /// Unknown terms are bound as `missing`, so later definition invalidates.
    /// Unresolved boundaries touching the terms are bound too.
    pub fn scoped_digest(&self, term_ids: &[String]) -> String {
        let mut ids: Vec<&String> = term_ids.iter().collect();
        ids.sort();
        ids.dedup();
        let parts: Vec<Value> = ids
            .iter()
            .map(|id| {
                let issues: Vec<&UnresolvedBoundary> = self
                    .unresolved
                    .iter()
                    .filter(|u| u.term_id.as_deref() == Some(id.as_str()))
                    .collect();
                json!({
                    "term": id,
                    "digest": self.term_digest(id).unwrap_or_else(|| "missing".into()),
                    "unresolved": issues,
                })
            })
            .collect();
        sha256_digest(&serde_json::to_vec(&parts).unwrap_or_default())
    }

    pub fn binding(&self) -> DomainContextBinding {
        DomainContextBinding {
            schema_version: self.schema_version,
            set_digest: self.set_digest.clone(),
            files: self.files.clone(),
            snapshots: self.snapshots.clone(),
            term_digests: self
                .terms
                .keys()
                .filter_map(|k| self.term_digest(k).map(|d| (k.clone(), d)))
                .collect(),
        }
    }

    /// True when any contract term resolved. Absence is never "clean".
    pub fn has_terms(&self) -> bool {
        !self.terms.is_empty()
    }

    pub fn is_fully_resolved(&self) -> bool {
        self.unresolved.is_empty() && (self.has_terms() || !self.required)
    }

    /// Compare every mapping with its authoritative term.
    pub fn evaluate(&self) -> DomainEvaluation {
        let mut candidates: BTreeMap<String, DomainCandidate> = BTreeMap::new();
        let mut unstated: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for (key, term) in &self.terms {
            let maps: Vec<&TermMapping> = self.mappings.iter().filter(|m| &m.term_id == key).collect();
            for m in &maps {
                check_mapping(self, term, m, &mut candidates, &mut unstated);
            }
            check_cross(self, term, &maps, &mut candidates);
        }

        let candidates: Vec<DomainCandidate> = candidates.into_values().collect();

        let mut collisions: BTreeMap<(String, Surface, String), BTreeSet<String>> = BTreeMap::new();
        for m in &self.mappings {
            collisions
                .entry((m.repository_id.clone(), m.surface, m.symbol.clone()))
                .or_default()
                .insert(m.term_id.clone());
        }
        let name_collisions: Vec<NameCollision> = collisions
            .into_iter()
            .filter(|(_, ids)| ids.len() > 1)
            .map(|((repository_id, surface, symbol), ids)| NameCollision {
                repository_id,
                surface,
                symbol,
                term_ids: ids.into_iter().collect(),
            })
            .collect();

        let mut ids: BTreeSet<String> = self.terms.keys().cloned().collect();
        ids.extend(self.unresolved.iter().filter_map(|u| u.term_id.clone()));
        let dispositions = ids
            .into_iter()
            .map(|id| self.disposition(&id, &candidates, &unstated))
            .collect();

        DomainEvaluation {
            set_digest: self.set_digest.clone(),
            execution_authority: false,
            candidates,
            dispositions,
            unresolved: self.unresolved.clone(),
            name_collisions,
        }
    }

    fn disposition(
        &self,
        id: &str,
        candidates: &[DomainCandidate],
        unstated: &BTreeMap<String, BTreeSet<String>>,
    ) -> TermDisposition {
        let term = self.terms.get(id);
        let found: Vec<&DomainCandidate> = candidates.iter().filter(|c| c.term_id == id).collect();
        let issues: Vec<&UnresolvedBoundary> = self
            .unresolved
            .iter()
            .filter(|u| u.term_id.as_deref() == Some(id))
            .collect();
        let gaps: Vec<String> = unstated
            .get(id)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();
        let mapped = self.mappings.iter().any(|m| m.term_id == id);

        let (status, spec_status, reason) = if !found.is_empty() {
            (
                "contradicted",
                "findings",
                format!("{} mapping(s) contradict the authoritative term", found.len()),
            )
        } else if issues.iter().any(|u| u.kind.is_conflict()) {
            (
                "ambiguous",
                "unproven",
                "conflicting contract versions or mappings; no meaning was guessed".to_owned(),
            )
        } else if !issues.is_empty() || !gaps.is_empty() || !mapped || term.is_none() {
            let mut why: Vec<String> = issues.iter().map(|u| format!("{:?}", u.kind)).collect();
            why.extend(gaps.iter().map(|g| format!("unstated {g}")));
            if !mapped {
                why.push("no repository mapping".into());
            }
            if term.is_none() {
                why.push("term unresolved".into());
            }
            ("unproven", "unproven", why.join("; "))
        } else {
            (
                "implemented-unverified",
                "pass",
                "all mappings agree with the authoritative term; verification evidence is separate".to_owned(),
            )
        };
        let mut evidence: Vec<EvidencePointer> = self
            .mappings
            .iter()
            .filter(|m| m.term_id == id)
            .flat_map(|m| m.evidence.iter().cloned())
            .collect();
        evidence.sort();
        evidence.dedup();
        TermDisposition {
            term_id: id.to_owned(),
            version: term.map(|t| t.version.clone()),
            owner: term.map(|t| t.owner.clone()).unwrap_or_default(),
            authority: term.map(|t| t.authority.clone()).unwrap_or_default(),
            status: status.to_owned(),
            spec: AxisOutcome {
                axis: "spec".into(),
                status: spec_status.into(),
                reason,
            },
            standards: AxisOutcome {
                axis: "standards".into(),
                status: "not-applicable".into(),
                reason: "domain contracts state behavior, not coding standards; the STANDARDS verdict stays with its own lens".into(),
            },
            evidence,
            scoped_digest: self.scoped_digest(&[id.to_owned()]),
        }
    }
}

// ------------------------------------------------------------ evaluation

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateCategory {
    Correctness,
    Schema,
    DataSafety,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainCandidate {
    /// Deterministic `domain:` + 16 hex characters.
    pub id: String,
    pub term_id: String,
    pub term_version: String,
    pub repository_id: String,
    pub surface: Surface,
    pub symbol: String,
    pub category: CandidateCategory,
    /// e.g. `money-unit-mismatch`, `timezone-mismatch`, `tenant-id-mismatch`,
    /// `order-state-incompatible`, `nullability-mismatch`.
    pub rule: String,
    /// SPEC axis disposition (`wrong`); STANDARDS is never inferred here.
    pub axis: String,
    pub disposition: String,
    pub severity: String,
    pub message: String,
    pub evidence: Vec<EvidencePointer>,
    pub contract_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AxisOutcome {
    /// `spec` or `standards`.
    pub axis: String,
    /// `pass|findings|unproven|not-applicable`.
    pub status: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TermDisposition {
    pub term_id: String,
    pub version: Option<String>,
    /// Empty when the term is unresolved.
    pub owner: String,
    pub authority: String,
    /// Requirement-traceability status (never `implemented-and-verified`).
    pub status: String,
    pub spec: AxisOutcome,
    pub standards: AxisOutcome,
    pub evidence: Vec<EvidencePointer>,
    pub scoped_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NameCollision {
    pub repository_id: String,
    pub surface: Surface,
    pub symbol: String,
    pub term_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainEvaluation {
    pub set_digest: String,
    pub execution_authority: bool,
    pub candidates: Vec<DomainCandidate>,
    pub dispositions: Vec<TermDisposition>,
    pub unresolved: Vec<UnresolvedBoundary>,
    /// Same symbol bound to different terms: reported, never equated.
    pub name_collisions: Vec<NameCollision>,
}

impl DomainEvaluation {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

// ---------------------------------------------------------------- checks

fn norm_tz(value: &str) -> String {
    let upper = value.trim().to_ascii_uppercase();
    match upper.as_str() {
        "Z" | "UTC" | "ETC/UTC" | "GMT" | "UT" => "UTC".to_owned(),
        _ => upper,
    }
}

fn norm(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

/// Returns (mismatches as (rule, category, detail), unstated field names).
fn compare_semantics(
    canon: &ValueSemantics,
    actual: Option<&ValueSemantics>,
) -> (Vec<(&'static str, CandidateCategory, String)>, Vec<String>) {
    let mut bad = Vec::new();
    let mut gaps = Vec::new();
    let Some(actual) = actual else {
        gaps.push("semantics".to_owned());
        return (bad, gaps);
    };
    let money = canon.kind == Some(ValueKind::Money);
    if let (Some(c), Some(a)) = (canon.kind, actual.kind) {
        if c != a {
            bad.push((
                "value-kind-mismatch",
                CandidateCategory::Schema,
                format!("contract kind {c:?}, mapping kind {a:?}"),
            ));
        }
    } else if canon.kind.is_some() {
        gaps.push("kind".into());
    }
    match (&canon.unit, &actual.unit) {
        (Some(c), Some(a)) if norm(c) != norm(a) => bad.push((
            if money { "money-unit-mismatch" } else { "unit-mismatch" },
            CandidateCategory::Correctness,
            format!("contract unit {c:?}, mapping unit {a:?}"),
        )),
        (Some(_), None) => gaps.push("unit".into()),
        _ => {}
    }
    match (canon.scale, actual.scale) {
        (Some(c), Some(a)) if c != a => bad.push((
            if money { "money-unit-mismatch" } else { "scale-mismatch" },
            CandidateCategory::Correctness,
            format!("contract scale {c}, mapping scale {a}"),
        )),
        (Some(_), None) => gaps.push("scale".into()),
        _ => {}
    }
    match (&canon.currency, &actual.currency) {
        (Some(c), Some(a)) if norm(c) != norm(a) => bad.push((
            "currency-mismatch",
            CandidateCategory::Correctness,
            format!("contract currency {c:?}, mapping currency {a:?}"),
        )),
        (Some(_), None) => gaps.push("currency".into()),
        _ => {}
    }
    match (&canon.timezone, &actual.timezone) {
        (Some(c), Some(a)) if norm_tz(c) != norm_tz(a) => bad.push((
            "timezone-mismatch",
            CandidateCategory::Correctness,
            format!("contract timezone {c:?}, mapping timezone {a:?}"),
        )),
        (Some(_), None) => gaps.push("timezone".into()),
        _ => {}
    }
    (bad, gaps)
}

fn severity_for(rule: &str) -> &'static str {
    match rule {
        "tenant-id-mismatch" | "money-unit-mismatch" | "currency-mismatch" => "error",
        _ => "warning",
    }
}

#[allow(clippy::too_many_arguments)]
fn push_candidate(
    set: &DomainContractSet,
    term: &DomainTerm,
    mapping: &TermMapping,
    rule: &str,
    category: CandidateCategory,
    detail: String,
    out: &mut BTreeMap<String, DomainCandidate>,
) {
    let key = term.key();
    let seed = format!(
        "{key}|{}|{}|{:?}|{:?}|{}|{rule}|{detail}",
        term.version, mapping.repository_id, mapping.role, mapping.surface, mapping.symbol
    );
    let id = format!("domain:{}", &hex::encode(Sha256::digest(seed.as_bytes()))[..16]);
    out.entry(id.clone()).or_insert_with(|| DomainCandidate {
        id,
        term_id: key.clone(),
        term_version: term.version.clone(),
        repository_id: mapping.repository_id.clone(),
        surface: mapping.surface,
        symbol: mapping.symbol.clone(),
        category,
        rule: rule.to_owned(),
        axis: "spec".into(),
        disposition: "wrong".into(),
        severity: severity_for(rule).into(),
        message: format!("{key}@{}: {rule}: {detail}", term.version),
        evidence: mapping.evidence.clone(),
        contract_digest: set.term_digest(&key).unwrap_or_default(),
    });
}

fn check_mapping(
    set: &DomainContractSet,
    term: &DomainTerm,
    m: &TermMapping,
    out: &mut BTreeMap<String, DomainCandidate>,
    unstated: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let key = term.key();
    let mut note = |field: String| {
        unstated.entry(key.clone()).or_default().insert(format!("{}:{field}", m.repository_id));
    };

    if let Some(canon) = &term.semantics {
        let (bad, gaps) = compare_semantics(canon, m.semantics.as_ref());
        for (rule, category, detail) in bad {
            push_candidate(set, term, m, rule, category, detail, out);
        }
        for gap in gaps {
            note(gap);
        }
    }

    if term.nullable == Some(false) {
        match m.nullable {
            Some(true) => push_candidate(
                set,
                term,
                m,
                "nullability-mismatch",
                CandidateCategory::Schema,
                "contract is non-null, mapping is nullable".into(),
                out,
            ),
            None => note("nullability".into()),
            Some(false) => {}
        }
    }

    if !term.states.is_empty() {
        if m.states.is_empty() {
            note("states".into());
        }
        let outside: Vec<&String> = m.states.iter().filter(|s| !term.states.contains(s)).collect();
        if !outside.is_empty() {
            push_candidate(
                set,
                term,
                m,
                "order-state-incompatible",
                CandidateCategory::Correctness,
                format!("states outside contract: {outside:?}"),
                out,
            );
        }
        if !term.transitions.is_empty() {
            let bad: Vec<String> = m
                .transitions
                .iter()
                .filter(|t| !term.transitions.contains(t))
                .map(|t| format!("{}->{}", t.from, t.to))
                .collect();
            if !bad.is_empty() {
                push_candidate(
                    set,
                    term,
                    m,
                    "order-state-incompatible",
                    CandidateCategory::Correctness,
                    format!("transitions outside contract: {bad:?}"),
                    out,
                );
            }
        }
    }

    if let Some(identity) = &term.identity {
        if identity.tenant_scoped {
            match (&identity.tenant_term, &m.tenant_term) {
                (Some(c), Some(a)) if c != a => push_candidate(
                    set,
                    term,
                    m,
                    "tenant-id-mismatch",
                    CandidateCategory::DataSafety,
                    format!("contract scopes by {c}, mapping scopes by {a}"),
                    out,
                ),
                (_, None) => note("tenant-scope".into()),
                _ => {}
            }
        }
    }
}

fn check_cross(
    set: &DomainContractSet,
    term: &DomainTerm,
    maps: &[&TermMapping],
    out: &mut BTreeMap<String, DomainCandidate>,
) {
    let producers: Vec<&&TermMapping> = maps
        .iter()
        .filter(|m| matches!(m.role, MappingRole::Producer | MappingRole::Store))
        .collect();
    let consumers: Vec<&&TermMapping> = maps.iter().filter(|m| m.role == MappingRole::Consumer).collect();
    for c in &consumers {
        for p in &producers {
            if !p.states.is_empty() && !c.states.is_empty() {
                let missing: Vec<&String> = p.states.iter().filter(|s| !c.states.contains(s)).collect();
                if !missing.is_empty() {
                    push_candidate(
                        set,
                        term,
                        c,
                        "order-state-incompatible",
                        CandidateCategory::Correctness,
                        format!(
                            "producer {}:{} emits states the consumer does not accept: {missing:?}",
                            p.repository_id, p.symbol
                        ),
                        out,
                    );
                }
            }
            if p.nullable == Some(true) && c.nullable == Some(false) {
                push_candidate(
                    set,
                    term,
                    c,
                    "nullability-mismatch",
                    CandidateCategory::Schema,
                    format!(
                        "producer {}:{} may be null but consumer requires non-null",
                        p.repository_id, p.symbol
                    ),
                    out,
                );
            }
        }
    }
}
