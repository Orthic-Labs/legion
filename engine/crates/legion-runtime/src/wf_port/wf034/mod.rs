//! Port of `src/lib/routing/{index,loader,resolver,validator}.mjs` (chunk
//! wf034).
//!
//! Grouping-integrity port (M-019). Domains are optional grouping metadata
//! only — they never decide routing. The routing registry is a generated
//! projection (`scripts/generate-skill-catalog.mjs`) grouping `kind:
//! capability` entries by their optional `domain` label. There is no fixed
//! exactly-five-domain invariant, no engineering/advisory distinction, and no
//! role-as-domain-leaf semantics. Entrypoints and roles do not appear in the
//! grouping projection.
//!
//! The integrator wires this module in via `pub mod wf_port;` in
//! `legion-runtime/src/lib.rs` and `pub mod wf034;` in `wf_port/mod.rs`.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Data shapes
// ---------------------------------------------------------------------------

/// One grouping entry from `src/registry/routing/domains.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDomain {
    pub id: String,
    pub kind: Option<String>,
    #[serde(default)]
    pub children: Vec<RoutingChild>,
    /// Any additional fields present on the JSON object are preserved
    /// unparsed so a round-trip through this struct cannot silently drop
    /// registry metadata the JS loader would have retained.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingChild {
    pub id: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Mirrors the loader's `{ root, domains, skillIndex }` return shape.
#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct RoutingGroups {
    pub root: PathBuf,
    pub domains: Vec<RoutingDomain>,
    pub skill_index: Value,
}

/// A resolved grouping child — the catalog capability record for a domain
/// member (`{ id, manifest }` in the JS loader).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCapability {
    pub id: String,
    pub manifest: String,
}

/// A single validation finding, matching `finding(code, detail, nodeId)` in
/// the JS validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub detail: String,
    #[serde(rename = "nodeId", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

impl Finding {
    fn new(code: &str, detail: &str, node_id: Option<&str>) -> Self {
        Finding {
            code: code.to_string(),
            detail: detail.to_string(),
            node_id: node_id.map(str::to_string),
        }
    }
}

/// Result of `validateRoutingGroups`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub ok: bool,
    pub findings: Vec<Finding>,
}

/// Result of `resolveDomain`, matching the JS `{ status, domainId, ... }`
/// discriminated shape via an enum instead of an ad hoc `status` string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum DomainResolution {
    Resolved {
        #[serde(rename = "domainId")]
        domain_id: String,
        capabilities: Vec<ResolvedCapability>,
    },
    NotFound {
        #[serde(rename = "domainId")]
        domain_id: String,
    },
    Invalid {
        #[serde(rename = "domainId")]
        domain_id: String,
        findings: Vec<Finding>,
    },
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RoutingLoadError {
    #[error("failed to read {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path:?} as JSON: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

// ---------------------------------------------------------------------------
// loader.mjs
// ---------------------------------------------------------------------------

fn read_json(path: &Path) -> Result<Value, RoutingLoadError> {
    let text = fs::read_to_string(path).map_err(|source| RoutingLoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| RoutingLoadError::Json {
        path: path.to_path_buf(),
        source,
    })
}

/// Port of `loadRoutingGroups(root)`.
pub fn load_routing_groups(root: &Path) -> Result<RoutingGroups, RoutingLoadError> {
    let registry = read_json(&root.join("src/registry/routing/domains.json"))?;
    let skill_index = read_json(&root.join("src/registry/skills/index.json"))?;

    let domains = match registry.get("domains") {
        Some(value) => serde_json::from_value(value.clone()).map_err(|source| {
            RoutingLoadError::Json {
                path: root.join("src/registry/routing/domains.json"),
                source,
            }
        })?,
        None => Vec::new(),
    };

    Ok(RoutingGroups {
        root: root.to_path_buf(),
        domains,
        skill_index,
    })
}

/// Port of `resolveGroupChild(skillIndex, childId)`. A child is a catalog
/// capability id resolved through the canonical catalog: only `kind:
/// "capability"` bundles resolve; entrypoints and roles return `None`.
pub fn resolve_group_child(skill_index: &Value, child_id: &str) -> Option<ResolvedCapability> {
    let bundles = skill_index.get("bundles")?.as_array()?;
    let bundle = bundles
        .iter()
        .find(|bundle| bundle.get("id").and_then(Value::as_str) == Some(child_id))?;
    if bundle.get("kind").and_then(Value::as_str) != Some("capability") {
        return None;
    }
    let id = bundle.get("id")?.as_str()?.to_string();
    let manifest = bundle.get("manifest")?.as_str()?.to_string();
    Some(ResolvedCapability { id, manifest })
}

// ---------------------------------------------------------------------------
// validator.mjs
// ---------------------------------------------------------------------------

/// Port of `validateRoutingGroups(graph)`. Keeps only the generic grouping
/// invariants live consumers need: valid domain array, unique domain ids,
/// children resolve to catalog capabilities, no duplicate child membership,
/// and no entrypoints/roles in the grouping projection. Does not route.
pub fn validate_routing_groups(graph: &RoutingGroups) -> ValidationReport {
    let mut findings = Vec::new();

    let ids: Vec<&str> = graph.domains.iter().map(|d| d.id.as_str()).collect();
    let unique_ids: HashSet<&str> = ids.iter().copied().collect();
    if unique_ids.len() != ids.len() {
        findings.push(Finding::new(
            "duplicate-root",
            "grouping roots must be unique",
            None,
        ));
    }

    for domain in &graph.domains {
        if domain.id.is_empty() {
            findings.push(Finding::new(
                "domain-id",
                "grouping id must be a string",
                None,
            ));
            continue;
        }
        if domain.kind.as_deref() != Some("group") {
            findings.push(Finding::new(
                "domain-kind",
                "grouping entries must be groups",
                Some(&domain.id),
            ));
        }
        // `children` deserializes to `Vec<RoutingChild>` (defaulting to
        // empty), so the JS "children must be an array when present" check
        // is structurally guaranteed here and has no Rust equivalent to
        // raise a `group-children` finding against.
        let child_ids: Vec<&str> = domain.children.iter().map(|c| c.id.as_str()).collect();
        if child_ids.iter().any(|id| id.is_empty()) {
            findings.push(Finding::new(
                "child-id",
                "group child id must be a string",
                Some(&domain.id),
            ));
        }
        let unique_child_ids: HashSet<&str> = child_ids.iter().copied().collect();
        if unique_child_ids.len() != child_ids.len() {
            findings.push(Finding::new(
                "duplicate-child",
                "group child membership must be unique",
                Some(&domain.id),
            ));
        }
        for child in &domain.children {
            if resolve_group_child(&graph.skill_index, &child.id).is_none() {
                findings.push(Finding::new(
                    "dangling-target",
                    &format!("group child '{}' is not a catalog capability", child.id),
                    Some(&domain.id),
                ));
            }
        }
    }

    ValidationReport {
        ok: findings.is_empty(),
        findings,
    }
}

// ---------------------------------------------------------------------------
// resolver.mjs
// ---------------------------------------------------------------------------

/// Port of `resolveDomain(root, domainId)`. Grouping lookup only — domains
/// never route (M-019).
pub fn resolve_domain(root: &Path, domain_id: &str) -> Result<DomainResolution, RoutingLoadError> {
    let graph = load_routing_groups(root)?;
    let validation = validate_routing_groups(&graph);
    if !validation.ok {
        return Ok(DomainResolution::Invalid {
            domain_id: domain_id.to_string(),
            findings: validation.findings,
        });
    }
    let domain = match graph.domains.iter().find(|d| d.id == domain_id) {
        Some(domain) => domain,
        None => {
            return Ok(DomainResolution::NotFound {
                domain_id: domain_id.to_string(),
            })
        }
    };
    let capabilities = domain
        .children
        .iter()
        .filter_map(|child| resolve_group_child(&graph.skill_index, &child.id))
        .collect();
    Ok(DomainResolution::Resolved {
        domain_id: domain_id.to_string(),
        capabilities,
    })
}
