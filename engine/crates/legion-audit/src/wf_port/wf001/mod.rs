//! Port of `src/lib/analysis/components.mjs` and
//! `src/lib/analysis/reachability.mjs`.
//!
//! `components.mjs` assigns each monorepo package a stable, content-derived
//! id (`component:<sha256-prefix>`) from its manifest name and root path,
//! and normalizes dependency/dependent edges into sorted lists.
//!
//! `reachability.mjs` joins a vulnerability record with observed call-graph
//! evidence using four categorical states. Missing graph evidence is never
//! inferred as safe: an empty evidence set resolves to `unknown`, and a
//! fully-examined graph that never reaches the sink resolves to
//! `not-reached-in-observed-graph` (carrying an explicit limitation that this
//! is not proof of safety), never to a "safe"/"not-vulnerable" state.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Error mirroring the JS `throw new Error(\`component manifest required: ${root}\`)`.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ComponentError {
    #[error("component manifest required: {root}")]
    ManifestRequired { root: String },
}

/// Manifest input for a package. JS reads only `manifest?.name` for hashing
/// but preserves the whole manifest value on the output component, so this
/// keeps the rest of the manifest as an opaque JSON value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One input package, matching the JS destructured
/// `{root, manifest, dependencies=[], dependents=[]}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub root: String,
    /// `None` mirrors JS `manifest` being absent/null/undefined, or an
    /// object with no `name` — both fail the `manifest?.name` check.
    pub manifest: Option<Manifest>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub dependents: Vec<String>,
}

/// A resolved component, matching the JS output shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Component {
    pub id: String,
    pub root: String,
    pub manifest: Manifest,
    pub dependencies: Vec<String>,
    pub dependents: Vec<String>,
}

impl PartialEq for Manifest {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.extra == other.extra
    }
}
impl Eq for Manifest {}

/// Faithful port of `buildComponents`.
///
/// For each package: requires `manifest.name` (else
/// [`ComponentError::ManifestRequired`] naming the failing `root`, exactly
/// as the JS `throw` does); derives
/// `component:<first-20-hex-chars-of-sha256("<name>\0<root>")>` as the id
/// (JS `.slice(0,20)` on the hex digest string is 20 hex chars = 10 bytes);
/// sorts `dependencies` and `dependents` independently (JS `[...deps].sort()`
/// is a default lexicographic string sort); and sorts the resulting
/// components by `id` (JS `.sort((a,b)=>a.id.localeCompare(b.id))`).
pub fn build_components(packages: Vec<Package>) -> Result<Vec<Component>, ComponentError> {
    let mut components = Vec::with_capacity(packages.len());
    for pkg in packages {
        let manifest = pkg.manifest.ok_or_else(|| ComponentError::ManifestRequired {
            root: pkg.root.clone(),
        })?;
        if manifest.name.is_empty() {
            return Err(ComponentError::ManifestRequired { root: pkg.root.clone() });
        }

        let mut hasher = Sha256::new();
        hasher.update(manifest.name.as_bytes());
        hasher.update(b"\0");
        hasher.update(pkg.root.as_bytes());
        let digest = hasher.finalize();
        let hex_digest = hex::encode(digest);
        let id = format!("component:{}", &hex_digest[..20]);

        let mut dependencies = pkg.dependencies;
        dependencies.sort();
        let mut dependents = pkg.dependents;
        dependents.sort();

        components.push(Component {
            id,
            root: pkg.root,
            manifest,
            dependencies,
            dependents,
        });
    }
    components.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(components)
}

/// The four categorical reachability states, matching `REACHABILITY_STATES`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReachabilityState {
    Reachable,
    PossiblyReachable,
    NotReachedInObservedGraph,
    Unknown,
}

impl ReachabilityState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReachabilityState::Reachable => "reachable",
            ReachabilityState::PossiblyReachable => "possibly-reachable",
            ReachabilityState::NotReachedInObservedGraph => "not-reached-in-observed-graph",
            ReachabilityState::Unknown => "unknown",
        }
    }
}

/// All four states, in the exact order `REACHABILITY_STATES` freezes them.
pub const REACHABILITY_STATES: [ReachabilityState; 4] = [
    ReachabilityState::Reachable,
    ReachabilityState::PossiblyReachable,
    ReachabilityState::NotReachedInObservedGraph,
    ReachabilityState::Unknown,
];

/// Whether a single call-evidence entry reached the sink: JS compares
/// `evidence.reached === true` / `=== 'possibly'`, so any other value
/// (including `false`, `undefined`, or other strings) counts as neither.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ReachedFlag {
    Bool(bool),
    Possibly(String),
}

impl ReachedFlag {
    fn is_true(&self) -> bool {
        matches!(self, ReachedFlag::Bool(true))
    }
    fn is_possibly(&self) -> bool {
        matches!(self, ReachedFlag::Possibly(s) if s == "possibly")
    }
}

/// One observed call-graph edge, matching the JS destructured
/// `{id,from,to,provider,confidence}` used to build the `trace`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallEvidence {
    pub id: Option<String>,
    pub from: Option<serde_json::Value>,
    pub to: Option<serde_json::Value>,
    pub provider: Option<serde_json::Value>,
    pub confidence: Option<serde_json::Value>,
    pub reached: ReachedFlag,
}

/// The `{id,from,to,provider,confidence}` slice kept for `trace`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceEntry {
    pub id: Option<String>,
    pub from: Option<serde_json::Value>,
    pub to: Option<serde_json::Value>,
    pub provider: Option<serde_json::Value>,
    pub confidence: Option<serde_json::Value>,
}

/// Joined reachability result. `vulnerability` carries the spread input
/// object (JS `{...vulnerability, ...}` merges these fields onto it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JoinedReachability {
    #[serde(flatten)]
    pub vulnerability: serde_json::Map<String, serde_json::Value>,
    pub reachability: ReachabilityState,
    pub graph_scope: Option<serde_json::Value>,
    pub evidence_refs: Vec<String>,
    pub trace: Vec<TraceEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

/// Faithful port of `joinReachability`.
///
/// - No call evidence (`None` or empty) → `unknown`, `graphScope` passed
///   through (defaulting to `null`/`None`), empty `evidenceRefs`/`trace`,
///   and the `missing-qualified-call-evidence` limitation. This is the
///   "never inferred as safe" case for missing graph coverage.
/// - Any evidence with `reached === true` → `reachable`.
/// - Else any evidence with `reached === 'possibly'` → `possibly-reachable`.
/// - Else (every observed call site was examined, none reached the sink) →
///   `not-reached-in-observed-graph`, with the
///   `observed graph is not proof of safety` limitation.
///
/// `evidenceRefs` is every evidence entry's `id` where present (JS
/// `.map(e=>e.id ?? null).filter(Boolean)`), in input order.
pub fn join_reachability(
    vulnerability: serde_json::Map<String, serde_json::Value>,
    call_evidence: Option<Vec<CallEvidence>>,
    graph_scope: Option<serde_json::Value>,
) -> JoinedReachability {
    let evidence = match &call_evidence {
        Some(v) if !v.is_empty() => v,
        _ => {
            return JoinedReachability {
                vulnerability,
                reachability: ReachabilityState::Unknown,
                graph_scope,
                evidence_refs: Vec::new(),
                trace: Vec::new(),
                limitations: vec!["missing-qualified-call-evidence".to_string()],
            };
        }
    };

    let evidence_refs: Vec<String> = evidence.iter().filter_map(|e| e.id.clone()).collect();
    let trace: Vec<TraceEntry> = evidence
        .iter()
        .map(|e| TraceEntry {
            id: e.id.clone(),
            from: e.from.clone(),
            to: e.to.clone(),
            provider: e.provider.clone(),
            confidence: e.confidence.clone(),
        })
        .collect();

    let reached = evidence.iter().any(|e| e.reached.is_true());
    if reached {
        return JoinedReachability {
            vulnerability,
            reachability: ReachabilityState::Reachable,
            graph_scope,
            evidence_refs,
            trace,
            limitations: Vec::new(),
        };
    }

    let possibly = evidence.iter().any(|e| e.reached.is_possibly());
    if possibly {
        return JoinedReachability {
            vulnerability,
            reachability: ReachabilityState::PossiblyReachable,
            graph_scope,
            evidence_refs,
            trace,
            limitations: Vec::new(),
        };
    }

    JoinedReachability {
        vulnerability,
        reachability: ReachabilityState::NotReachedInObservedGraph,
        graph_scope,
        evidence_refs,
        trace,
        limitations: vec!["observed graph is not proof of safety".to_string()],
    }
}

/// A reachability gap record, matching `reachabilityGap`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReachabilityGap {
    pub kind: String,
    pub package_name: String,
    pub graph_scope: Option<serde_json::Value>,
    pub reason: String,
}

/// Faithful port of `reachabilityGap`: `kind` is always the literal
/// `"reachability-unproven"`; `graphScope` defaults to `null`/`None`;
/// `reason` defaults to `"no call evidence in observed graph"`.
pub fn reachability_gap(
    package_name: String,
    graph_scope: Option<serde_json::Value>,
    reason: Option<String>,
) -> ReachabilityGap {
    ReachabilityGap {
        kind: "reachability-unproven".to_string(),
        package_name,
        graph_scope,
        reason: reason.unwrap_or_else(|| "no call evidence in observed graph".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str) -> Manifest {
        Manifest {
            name: name.to_string(),
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn missing_manifest_errors_with_root() {
        let err = build_components(vec![Package {
            root: "packages/a".to_string(),
            manifest: None,
            dependencies: vec![],
            dependents: vec![],
        }])
        .unwrap_err();
        assert_eq!(
            err,
            ComponentError::ManifestRequired {
                root: "packages/a".to_string()
            }
        );
        assert_eq!(err.to_string(), "component manifest required: packages/a");
    }

    #[test]
    fn ids_are_stable_and_sorted() {
        let out = build_components(vec![
            Package {
                root: "packages/b".to_string(),
                manifest: Some(manifest("b-pkg")),
                dependencies: vec!["z".to_string(), "a".to_string()],
                dependents: vec![],
            },
            Package {
                root: "packages/a".to_string(),
                manifest: Some(manifest("a-pkg")),
                dependencies: vec![],
                dependents: vec!["y".to_string(), "x".to_string()],
            },
        ])
        .unwrap();

        assert_eq!(out.len(), 2);
        assert!(out[0].id.starts_with("component:"));
        // Deterministic: same inputs produce the same id every call.
        let again = build_components(vec![Package {
            root: "packages/a".to_string(),
            manifest: Some(manifest("a-pkg")),
            dependencies: vec![],
            dependents: vec!["y".to_string(), "x".to_string()],
        }])
        .unwrap();
        let a_component = out.iter().find(|c| c.root == "packages/a").unwrap();
        assert_eq!(again[0].id, a_component.id);
        assert_eq!(a_component.dependents, vec!["x".to_string(), "y".to_string()]);

        // Output sorted by id, lexicographically.
        assert!(out[0].id <= out[1].id);
    }

    #[test]
    fn empty_manifest_name_errors() {
        let err = build_components(vec![Package {
            root: "packages/c".to_string(),
            manifest: Some(manifest("")),
            dependencies: vec![],
            dependents: vec![],
        }])
        .unwrap_err();
        assert_eq!(
            err,
            ComponentError::ManifestRequired {
                root: "packages/c".to_string()
            }
        );
    }

    #[test]
    fn no_call_evidence_is_unknown() {
        let out = join_reachability(serde_json::Map::new(), Some(vec![]), None);
        assert_eq!(out.reachability, ReachabilityState::Unknown);
        assert_eq!(out.limitations, vec!["missing-qualified-call-evidence".to_string()]);
        assert!(out.evidence_refs.is_empty());
        assert!(out.trace.is_empty());

        let out_none = join_reachability(serde_json::Map::new(), None, None);
        assert_eq!(out_none.reachability, ReachabilityState::Unknown);
    }

    #[test]
    fn verified_reach_is_reachable() {
        let out = join_reachability(
            serde_json::Map::new(),
            Some(vec![CallEvidence {
                id: Some("e1".to_string()),
                from: None,
                to: None,
                provider: None,
                confidence: None,
                reached: ReachedFlag::Bool(true),
            }]),
            None,
        );
        assert_eq!(out.reachability, ReachabilityState::Reachable);
        assert_eq!(out.evidence_refs, vec!["e1".to_string()]);
        assert!(out.limitations.is_empty());
    }

    #[test]
    fn possibly_reached_beats_not_reached() {
        let out = join_reachability(
            serde_json::Map::new(),
            Some(vec![
                CallEvidence {
                    id: Some("e1".to_string()),
                    from: None,
                    to: None,
                    provider: None,
                    confidence: None,
                    reached: ReachedFlag::Bool(false),
                },
                CallEvidence {
                    id: Some("e2".to_string()),
                    from: None,
                    to: None,
                    provider: None,
                    confidence: None,
                    reached: ReachedFlag::Possibly("possibly".to_string()),
                },
            ]),
            None,
        );
        assert_eq!(out.reachability, ReachabilityState::PossiblyReachable);
    }

    #[test]
    fn examined_and_never_reached_carries_limitation() {
        let out = join_reachability(
            serde_json::Map::new(),
            Some(vec![CallEvidence {
                id: Some("e1".to_string()),
                from: None,
                to: None,
                provider: None,
                confidence: None,
                reached: ReachedFlag::Bool(false),
            }]),
            Some(serde_json::json!("scope")),
        );
        assert_eq!(out.reachability, ReachabilityState::NotReachedInObservedGraph);
        assert_eq!(out.limitations, vec!["observed graph is not proof of safety".to_string()]);
        assert_eq!(out.graph_scope, Some(serde_json::json!("scope")));
    }

    #[test]
    fn reachability_gap_defaults_and_kind() {
        let gap = reachability_gap("x".to_string(), None, None);
        assert_eq!(gap.kind, "reachability-unproven");
        assert_ne!(gap.kind, "reachable");
        assert_eq!(gap.reason, "no call evidence in observed graph");
        assert_eq!(gap.graph_scope, None);

        let gap2 = reachability_gap(
            "y".to_string(),
            Some(serde_json::json!({"repo": "z"})),
            Some("custom reason".to_string()),
        );
        assert_eq!(gap2.reason, "custom reason");
        assert_eq!(gap2.graph_scope, Some(serde_json::json!({"repo": "z"})));
    }

    #[test]
    fn reachability_states_order_matches_js_freeze() {
        assert_eq!(
            REACHABILITY_STATES.map(|s| s.as_str()),
            [
                "reachable",
                "possibly-reachable",
                "not-reached-in-observed-graph",
                "unknown",
            ]
        );
    }
}
