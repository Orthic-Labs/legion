//! Frozen coverage plan for the reasoning lenses (design
//! `docs/architecture/2026-10-15-scaled-audit-design.md` section 1, with
//! Astra's D2 conditions).
//!
//! A lens never claims that every lens judged every line. At plan time this
//! module chooses, per seat bundle, the **review set** the lens will examine:
//!
//! 1. **mandatory** stratum, reviewed exhaustively and never shrunk to fit:
//!    entrypoints, security-sensitive paths, files changed since the base, and
//!    the top-N files by churn;
//! 2. **hotspot** stratum, ranked by churn + fan-in + size, reviewed
//!    exhaustively up to the bundle budget;
//! 3. **remainder** stratum, sampled in `sha256(seed || path)` order with a
//!    budget-bounded target of `min(30, |stratum|)`.
//!
//! The result is frozen into each lens provider's `configuration.coverage`, so
//! the plan digest covers it. Everything here is pure and deterministic: the
//! same facts and request give the same review set. File facts come from the
//! frozen inventory, `fs::metadata`, and read-only `git log --numstat`; no
//! search or indexing code lives here (fan-in uses only the inventory's own
//! `dependencies`, which is empty for most source files; that signal is an
//! acknowledged gap, see `gather_facts`).
//!
//! Statistical statements are deliberately narrow (Astra D2): only the seeded
//! random remainder stratum carries a confidence statement, scoped to "findings
//! this lens can detect in a sampled file". The rule of three is used only when
//! zero high-severity findings were observed; Clopper-Pearson otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use legion_contracts::canonical_digest;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::lens_plan::{self, BundleInfo, ExcerptMode, BUNDLE_ADJUDICATION, COVERAGE_BUNDLES};
use crate::{
    error::AuditError,
    inventory::{glob_match, InventoryEnvelope},
};

pub const MODE_EXHAUSTIVE: &str = "exhaustive";
pub const MODE_RISK_SAMPLED: &str = "risk-sampled";

/// Run budget: estimated input tokens across every seat.
pub const DEFAULT_RUN_TOKEN_BUDGET: u64 = 6_000_000;
/// Most seats the whole run may use (all waves).
pub const DEFAULT_MAX_TOTAL_SEATS: u64 = 48;
/// Largest estimated token count one seat may carry.
pub const DEFAULT_SEAT_TOKEN_BUDGET: u64 = 150_000;
/// Wave width (`CHILD_AGENTS_MAX` in the Audit manual).
pub const WAVE_WIDTH: u64 = 16;
/// Desired remainder sample size; budgets may yield a smaller declared sample.
pub const SAMPLE_FLOOR: usize = 30;
/// Top-N files by churn that join the mandatory stratum.
pub const CHURN_TOP_N: usize = 25;
/// Share (percent) of the budget left after the mandatory stratum that the
/// hotspot stratum may take; the rest is the sample's.
pub const HOTSPOT_SHARE_PERCENT: u64 = 70;
/// Percent of a bundle's budget the plan commits; the rest is headroom for
/// findings promotion and packet overhead.
pub const COMMIT_PERCENT: u64 = 90;
/// Fixed per-lens packet reserve (lens plan, report schema, contracts, binding,
/// per-part metadata) a seat-derived part cap leaves room for.
pub const SEAT_PACKET_RESERVE_BYTES: usize = 32 * 1024;

/// Largest serialized excerpt payload one packet part may carry so that a seat
/// (the part read once plus `lenses` lens packets of overhead, each reserving
/// `SEAT_PACKET_RESERVE_BYTES + context_bytes`) stays within `seat_tokens`.
/// A pure function of the frozen request, bundle size and review context, so
/// every lens of a bundle derives the same starting cap. Exact physical
/// envelope refinement tightens it; no minimum may override the seat budget.
pub fn seat_part_cap_bytes(seat_tokens: u64, lenses: usize, context_bytes: usize) -> usize {
    let lenses = lenses.clamp(1, 16);
    let seat_bytes = usize::try_from(seat_tokens.saturating_mul(4)).unwrap_or(usize::MAX);
    let reserve = lenses.saturating_mul(SEAT_PACKET_RESERVE_BYTES + context_bytes) + 4096;
    seat_bytes
        .saturating_sub(reserve.min(seat_bytes / 2))
        .max(1)
        .min(super::excerpts::MAX_TOTAL_EXCERPT_BYTES)
}

/// Digest of the review set a lens actually examines after findings
/// promotion: the frozen review set minus the displaced sampled paths plus the
/// promoted paths. Shared by packet construction and ingest verification so a
/// packet's promotion can be re-derived from the frozen plan alone.
pub fn effective_review_set_digest(
    review_set: &BTreeSet<String>,
    displaced: &[String],
    promoted: &[String],
) -> Result<String, AuditError> {
    let mut effective: BTreeSet<&str> = review_set.iter().map(String::as_str).collect();
    for path in displaced {
        effective.remove(path.as_str());
    }
    effective.extend(promoted.iter().map(String::as_str));
    let effective: Vec<&str> = effective.into_iter().collect();
    canonical_digest(&effective).map_err(|error| AuditError::Invalid(error.to_string()))
}

/// Rank of a scanner severity for promotion order (higher promotes first).
pub fn promotion_severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" | "error" => 4,
        "medium" | "moderate" | "warning" => 3,
        "low" => 2,
        "info" | "note" => 1,
        _ => 0,
    }
}

/// Commits read for churn.
const CHURN_COMMIT_LIMIT: &str = "2000";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageMode {
    Auto,
    Exhaustive,
    RiskSampled,
}

impl CoverageMode {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "auto" => Some(Self::Auto),
            "exhaustive" => Some(Self::Exhaustive),
            "risk-sampled" => Some(Self::RiskSampled),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Exhaustive => "exhaustive",
            Self::RiskSampled => "risk-sampled",
        }
    }
}

/// What the invoker asked for; frozen into every lens provider's
/// `configuration.reasoning.coverageRequest` so a recompile is reproducible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageRequest {
    pub mode: CoverageMode,
    pub run_token_budget: u64,
    pub max_total_seats: u64,
    pub seat_token_budget: u64,
}

impl Default for CoverageRequest {
    fn default() -> Self {
        Self {
            mode: CoverageMode::Auto,
            run_token_budget: DEFAULT_RUN_TOKEN_BUDGET,
            max_total_seats: DEFAULT_MAX_TOTAL_SEATS,
            seat_token_budget: DEFAULT_SEAT_TOKEN_BUDGET,
        }
    }
}

impl CoverageRequest {
    pub fn to_value(self) -> Value {
        json!({
            "mode": self.mode.as_str(),
            "runTokenBudget": self.run_token_budget,
            "maxTotalSeats": self.max_total_seats,
            "seatTokenBudget": self.seat_token_budget,
        })
    }

    /// Reads `reasoning.coverageRequest`; absent or malformed fields fall back
    /// to the defaults.
    pub fn from_reasoning(reasoning: &Value) -> Self {
        let mut request = Self::default();
        let Some(value) = reasoning.get("coverageRequest") else {
            return request;
        };
        if let Some(mode) = value
            .get("mode")
            .and_then(Value::as_str)
            .and_then(CoverageMode::parse)
        {
            request.mode = mode;
        }
        for (field, slot) in [
            ("runTokenBudget", &mut request.run_token_budget),
            ("maxTotalSeats", &mut request.max_total_seats),
            ("seatTokenBudget", &mut request.seat_token_budget),
        ] {
            if let Some(number) = value.get(field).and_then(Value::as_u64).filter(|n| *n > 0) {
                *slot = number;
            }
        }
        request
    }
}

/// Facts about one inventory file, gathered read-only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileFacts {
    pub size: u64,
    pub digest: Option<String>,
    /// Commits touching the file in the churn window.
    pub churn: u32,
    pub fan_in: u32,
    /// `entrypoint` | `security-sensitive` when a mandatory path/symbol rule hit.
    pub signal: Option<&'static str>,
    /// Changed since the base commit (diff-scoped runs).
    pub changed: bool,
}

/// One coverage-planned lens provider and its (selector-bound) denominator.
#[derive(Clone, Debug)]
pub struct LensInput {
    pub provider_id: String,
    pub paths: Vec<String>,
}

const ENTRYPOINT_GLOBS: &[&str] = &[
    "**/main.*",
    "**/bin/**",
    "**/bins/**/main.rs",
    "**/commands/**",
    "**/routes/**",
    "**/handlers/**",
    "**/controllers/**",
    "**/api/**",
    "**/ipc/**",
    "**/server.*",
    "**/router.*",
    "src-tauri/src/lib.rs",
    "src-tauri/src/main.rs",
];

const SECURITY_TOKENS: &[&str] = &[
    "auth",
    "authn",
    "authz",
    "authentication",
    "authorization",
    "crypto",
    "cryptography",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "password",
    "passwords",
    "token",
    "tokens",
    "keychain",
    "signing",
    "signature",
    "signatures",
    "ipc",
    "deserialize",
    "sandbox",
    "permission",
    "permissions",
    "entitlement",
    "entitlements",
    "jwt",
    "oauth",
    "session",
    "sessions",
    "cookie",
    "cookies",
    "tls",
    "cert",
    "certs",
    "exec",
    "shell",
    "network",
    "socket",
    "sockets",
    "http",
    "security",
    "guard",
];

const SECURITY_SYMBOL_HINTS: &[&str] = &[
    "exec",
    "spawn",
    "deserialize",
    "decrypt",
    "verify_signature",
];

/// Mandatory-stratum path/symbol rule.
pub fn classify_signal(path: &str, symbols: &[String]) -> Option<&'static str> {
    if ENTRYPOINT_GLOBS.iter().any(|glob| glob_match(glob, path)) {
        return Some("entrypoint");
    }
    let lower = path.to_ascii_lowercase();
    let hit = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| SECURITY_TOKENS.contains(&token));
    if hit
        || symbols.iter().any(|symbol| {
            let symbol = symbol.to_ascii_lowercase();
            SECURITY_SYMBOL_HINTS
                .iter()
                .any(|hint| symbol.contains(hint))
        })
    {
        return Some("security-sensitive");
    }
    None
}

/// Generated, vendored, lock and minified files: kept in deterministic
/// denominators, left out of lens review sets (declared, not silently dropped).
pub fn is_lens_excluded(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    const SEGMENTS: &[&str] = &[
        "vendor",
        "vendored",
        "node_modules",
        "third_party",
        "third-party",
        "generated",
        "__generated__",
        ".yarn",
    ];
    if lower
        .split('/')
        .rev()
        .skip(1)
        .any(|segment| SEGMENTS.contains(&segment))
    {
        return true;
    }
    const SUFFIXES: &[&str] = &[
        ".lock",
        "-lock.json",
        "-lock.yaml",
        ".min.js",
        ".min.mjs",
        ".min.css",
        ".generated.ts",
        ".generated.rs",
        "_generated.rs",
        ".pb.go",
        ".g.dart",
        ".bundle.js",
    ];
    SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

/// Changed paths of a diff-scoped audit (`reviewContext.changedHunks` keys).
pub fn changed_paths_from_reasoning(reasoning: &Value) -> BTreeSet<String> {
    let context = reasoning.get("reviewContext");
    if context
        .and_then(|value| value.get("mode"))
        .and_then(Value::as_str)
        != Some("diff")
    {
        return BTreeSet::new();
    }
    context
        .and_then(|value| value.get("changedHunks"))
        .and_then(Value::as_object)
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

/// Per-path commit counts from read-only `git log --numstat`. Empty when the
/// root is not a git work tree or git is unavailable (churn is then 0).
fn git_churn(root: &Path) -> BTreeMap<String, u32> {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    let Some(stdout) = crate::trusted_git::run_stdout(
        root,
        &[
            "log",
            "--numstat",
            "--format=",
            "-n",
            CHURN_COMMIT_LIMIT,
            "--no-renames",
        ],
        std::time::Duration::from_secs(60),
        256 * 1024 * 1024,
    ) else {
        return counts;
    };
    for line in String::from_utf8_lossy(&stdout).lines() {
        let mut fields = line.splitn(3, '\t');
        let (Some(added), Some(deleted), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if added == "-" || deleted == "-" {
            continue;
        }
        *counts.entry(path.to_owned()).or_insert(0) += 1;
    }
    counts
}

/// Gathers facts for every inventory file. Fan-in is the number of inventory
/// entries whose `dependencies` name the file (by path or stem); the
/// filesystem inventory only fills `dependencies` for manifests, so this is
/// usually 0 and the hotspot score leans on churn and size. A blueprint graph
/// would be the better source; none is available to this crate (reported gap).
pub fn gather_facts(
    root: &Path,
    inventory: &InventoryEnvelope,
    changed: &BTreeSet<String>,
) -> BTreeMap<String, FileFacts> {
    let churn = git_churn(root);
    let snapshot = crate::inventory::frozen_snapshot(root).ok().flatten();
    let mut dependency_counts: BTreeMap<&str, u32> = BTreeMap::new();
    for entry in &inventory.entries {
        for dependency in &entry.dependencies {
            *dependency_counts.entry(dependency.as_str()).or_insert(0) += 1;
        }
    }
    inventory
        .entries
        .iter()
        .map(|entry| {
            let size = snapshot
                .as_ref()
                .and_then(|(snapshot, side)| {
                    let use_base = *side == crate::snapshot::SnapshotSide::Base
                        || !snapshot.manifest.files.contains_key(&entry.path)
                            && snapshot
                                .uncovered_metadata(
                                    &entry.path,
                                    crate::snapshot::SnapshotSide::Selected,
                                )
                                .is_none()
                            && snapshot.manifest.scope.changed_paths.contains(&entry.path);
                    let source_side = if use_base {
                        crate::snapshot::SnapshotSide::Base
                    } else {
                        crate::snapshot::SnapshotSide::Selected
                    };
                    let files = if use_base {
                        &snapshot.manifest.base_files
                    } else {
                        &snapshot.manifest.files
                    };
                    files
                        .get(&entry.path)
                        .map(|file| file.bytes as u64)
                        .or_else(|| {
                            snapshot
                                .uncovered_metadata(&entry.path, source_side)
                                .map(|file| file.bytes)
                        })
                })
                .unwrap_or_else(|| {
                    std::fs::metadata(root.join(&entry.path))
                        .map(|metadata| metadata.len())
                        .unwrap_or(0)
                });
            let stem = Path::new(&entry.path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default();
            let fan_in = dependency_counts
                .get(entry.path.as_str())
                .copied()
                .unwrap_or(0)
                + dependency_counts.get(stem).copied().unwrap_or(0);
            (
                entry.path.clone(),
                FileFacts {
                    size,
                    digest: entry.digest.clone(),
                    churn: churn.get(&entry.path).copied().unwrap_or(0),
                    fan_in,
                    signal: classify_signal(&entry.path, &entry.symbols),
                    changed: changed.contains(&entry.path),
                },
            )
        })
        .collect()
}

/// Estimated excerpt bytes for one file in `mode` (a labelled estimate; the
/// dispatch plan later measures the real packets).
pub fn estimate_bytes(mode: ExcerptMode, size: u64) -> u64 {
    match super::excerpts::effective_excerpt_mode(mode, size) {
        ExcerptMode::Raw => size,
        ExcerptMode::Skeleton => size / 4 + 200,
        ExcerptMode::Regions => size.min(size / 4 + 6144),
    }
}

fn seeded_key(seed: &str, path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update([0u8]);
    hasher.update(path.as_bytes());
    hex::encode(hasher.finalize())
}

/// Hotspot score: churn, fan-in and size (KiB, capped). Higher is riskier.
pub fn hotspot_score(facts: &FileFacts) -> u64 {
    u64::from(facts.churn) * 4 + u64::from(facts.fan_in) * 3 + (facts.size / 1024).min(64)
}

#[derive(Clone, Copy)]
enum Stratum {
    Mandatory,
    Hotspot,
    Sample,
}

struct BundleSelection {
    /// path -> stratum chosen for it
    chosen: BTreeMap<String, Stratum>,
    estimated_bytes: u64,
}

fn sample_mode(bundle: &BundleInfo, mandatory: bool) -> ExcerptMode {
    if mandatory && bundle.raw_mandatory {
        ExcerptMode::Raw
    } else {
        bundle.sampled_mode
    }
}

/// Selects one bundle's review set from the global strata under `budget_bytes`.
fn select_for_bundle(
    bundle: &BundleInfo,
    budget_bytes: u64,
    mandatory: &[&str],
    hotspots: &[&str],
    remainder: &[&str],
    facts: &BTreeMap<String, FileFacts>,
) -> BundleSelection {
    let size_of = |path: &str| facts.get(path).map_or(0, |f| f.size);
    let mut chosen: BTreeMap<String, Stratum> = BTreeMap::new();
    let mut used = 0u64;
    // Mandatory coverage never shrinks to fit.
    for path in mandatory {
        used += estimate_bytes(sample_mode(bundle, true), size_of(path));
        chosen.insert((*path).to_owned(), Stratum::Mandatory);
    }
    let remaining = budget_bytes.saturating_sub(used);
    let hotspot_budget = remaining * HOTSPOT_SHARE_PERCENT / 100;
    let mut hot_used = 0u64;
    for path in hotspots {
        let cost = estimate_bytes(sample_mode(bundle, false), size_of(path));
        if hot_used + cost > hotspot_budget {
            break;
        }
        hot_used += cost;
        chosen.insert((*path).to_owned(), Stratum::Hotspot);
    }
    used += hot_used;
    let sample_budget = budget_bytes.saturating_sub(used);
    // Fix sample size before consulting seeded order. A cost-stopped random
    // prefix biases inclusion toward cheaper files. The largest-k cost bound
    // guarantees any seeded k-file sample fits, preserving uniform selection.
    let mut costs: Vec<u64> = remainder
        .iter()
        .map(|path| estimate_bytes(sample_mode(bundle, false), size_of(path)))
        .collect();
    costs.sort_unstable_by(|left, right| right.cmp(left));
    let mut worst_cost = 0u64;
    let sample_count = costs
        .iter()
        .take_while(|cost| {
            let next = worst_cost.saturating_add(**cost);
            if next > sample_budget {
                false
            } else {
                worst_cost = next;
                true
            }
        })
        .count();
    let mut sample_used = 0u64;
    for path in remainder.iter().take(sample_count) {
        sample_used += estimate_bytes(sample_mode(bundle, false), size_of(path));
        chosen.insert((*path).to_owned(), Stratum::Sample);
    }
    BundleSelection {
        chosen,
        estimated_bytes: used + sample_used,
    }
}

/// Plans coverage for every coverage-planned lens in `lenses` and returns the
/// `configuration.coverage` value to freeze per provider id.
pub fn plan_coverage(
    seed_basis: &Value,
    facts: &BTreeMap<String, FileFacts>,
    lenses: &[LensInput],
    request: &CoverageRequest,
) -> Result<BTreeMap<String, Value>, AuditError> {
    plan_coverage_with_witnesses(seed_basis, facts, lenses, request, &BTreeMap::new())
}

/// Conditional trigger witnesses are fixed before sampling & join mandatory
/// work in their bundle. Declared unsampled paths retain their existing policy.
pub fn plan_coverage_with_witnesses(
    seed_basis: &Value,
    facts: &BTreeMap<String, FileFacts>,
    lenses: &[LensInput],
    request: &CoverageRequest,
    witnesses: &BTreeMap<String, BTreeSet<String>>,
) -> Result<BTreeMap<String, Value>, AuditError> {
    let seed = canonical_digest(&json!({
        "kind": "legion-coverage-seed:v1",
        "basis": seed_basis,
        "request": request.to_value(),
        "mandatoryWitnesses": witnesses,
    }))
    .map_err(|error| AuditError::Invalid(error.to_string()))?;

    // Providers per bundle, in provider-id order.
    let mut bundle_lenses: BTreeMap<&'static str, Vec<&LensInput>> = BTreeMap::new();
    for lens in lenses {
        if let Some(bundle) = lens_plan::bundle_for_provider(&lens.provider_id) {
            bundle_lenses.entry(bundle.id).or_default().push(lens);
        }
    }
    let present: Vec<BundleInfo> = COVERAGE_BUNDLES
        .iter()
        .copied()
        .filter(|bundle| bundle_lenses.contains_key(bundle.id))
        .collect();

    // Shares: absent bundles' shares flow to the present ones pro rata.
    let present_share: u64 = present.iter().map(|b| u64::from(b.budget_share_bp)).sum();
    let planned_share = present_share.max(1);
    // One full physical allowance stays available for finding verification or
    // context followups. Initial review cannot consume the entire call ledger.
    let followup_reserve = request.seat_token_budget;
    let initial_budget = request.run_token_budget.saturating_sub(followup_reserve);
    // Bundle count is not a physical call floor: compatible contracts share
    // exact source bytes across bundles. Host selection uses no model call.
    // Only the rendered dispatch plan can admit or reject physical calls.
    if !present.is_empty() && (initial_budget == 0 || request.max_total_seats < 2) {
        return Err(AuditError::BoundExceeded(format!("audit budget infeasible: no author call plus fresh verification reserve fits runTokenBudget {} & maxTotalSeats {}", request.run_token_budget, request.max_total_seats)));
    }
    let spendable = 10_000 - u64::from(BUNDLE_ADJUDICATION.budget_share_bp);
    let base_tokens = |bundle: &BundleInfo| -> u64 {
        // Present bundles split the non-adjudication budget by relative share,
        // so an absent bundle's share is not wasted.
        initial_budget * spendable / 10_000 * u64::from(bundle.budget_share_bp) / planned_share
    };

    // Union eligible universe per bundle.
    let denominators: BTreeMap<&'static str, BTreeSet<&str>> = bundle_lenses
        .iter()
        .map(|(id, members)| {
            (
                *id,
                members
                    .iter()
                    .flat_map(|lens| lens.paths.iter().map(String::as_str))
                    .collect(),
            )
        })
        .collect();

    // Exhaustive-fit estimate: base excerpt mode of each lens, one seat read
    // per bundle part (max over the bundle's lenses).
    let mut fits = true;
    let mut estimated_seats = 0u64;
    let mut exhaustive_tokens: BTreeMap<&'static str, u64> = BTreeMap::new();
    for bundle in &present {
        let members = &bundle_lenses[bundle.id];
        let bytes = members
            .iter()
            .map(|lens| {
                let mode = lens_plan::lens_plan_excerpt_mode(&lens.provider_id)
                    .unwrap_or(ExcerptMode::Raw);
                lens.paths
                    .iter()
                    .map(|path| estimate_bytes(mode, facts.get(path).map_or(0, |f| f.size)))
                    .sum::<u64>()
            })
            .max()
            .unwrap_or(0);
        let tokens = bytes / 4;
        exhaustive_tokens.insert(bundle.id, tokens);
        // Parts close at the seat-derived cap (excerpt bytes plus a per-lens
        // reserve), not at the legacy fixed cap; estimate seats the same way.
        let cap = seat_part_cap_bytes(request.seat_token_budget, members.len(), 0) as u64;
        estimated_seats += bytes.div_ceil(cap.max(1)).max(1);
        if tokens * 100 > base_tokens(bundle) * COMMIT_PERCENT {
            fits = false;
        }
    }
    if estimated_seats.saturating_add(1) > request.max_total_seats {
        fits = false;
    }
    let sampled = match request.mode {
        CoverageMode::Exhaustive => false,
        CoverageMode::RiskSampled => true,
        CoverageMode::Auto => !fits,
    };

    let mut configs: BTreeMap<String, Value> = BTreeMap::new();
    if !sampled {
        for lens in lenses {
            let Some(bundle) = lens_plan::bundle_for_provider(&lens.provider_id) else {
                continue;
            };
            let mut paths = lens.paths.clone();
            paths.sort();
            paths.dedup();
            let digest =
                canonical_digest(&paths).map_err(|error| AuditError::Invalid(error.to_string()))?;
            configs.insert(
                lens.provider_id.clone(),
                json!({
                    "schemaVersion": 1,
                    "mode": MODE_EXHAUSTIVE,
                    "requestedMode": request.mode.as_str(),
                    "fitsExhaustive": fits,
                    "seed": seed,
                    "bundle": bundle.id,
                    "tier": bundle.tier,
                    "budgetShareBp": bundle.budget_share_bp,
                    "tokenBudget": base_tokens(&bundle),
                    "seatTokenBudget": request.seat_token_budget,
                    "bundleLensCount": bundle_lenses.get(bundle.id).map_or(1, Vec::len),
                    "estimatedTokens": exhaustive_tokens.get(bundle.id).copied().unwrap_or(0),
                    "denominator": paths.len(),
                    "reviewSet": paths,
                    "reviewSetDigest": digest,
                    "mandatoryWitnessPaths": witnesses.get(&lens.provider_id).cloned().unwrap_or_default(),
                    "strata": [{"name": "all", "N": lens.paths.len(), "n": lens.paths.len(), "paths": Value::Null}],
                    "excluded": {"count": 0},
                    "declaredUnsampled": 0,
                    "excerpt": {"mode": Value::Null, "mandatoryMode": Value::Null, "dedup": false},
                }),
            );
        }
        return Ok(configs);
    }

    // ---- risk-sampled -------------------------------------------------------
    let universe: BTreeSet<&str> = denominators.values().flatten().copied().collect();
    let bundle_witnesses: BTreeMap<&str, BTreeSet<&str>> = bundle_lenses
        .iter()
        .map(|(bundle, members)| {
            let paths = members
                .iter()
                .flat_map(|lens| {
                    witnesses
                        .get(&lens.provider_id)
                        .into_iter()
                        .flatten()
                        .map(String::as_str)
                })
                .collect();
            (*bundle, paths)
        })
        .collect();
    let eligible: Vec<&str> = universe
        .iter()
        .copied()
        .filter(|path| !is_lens_excluded(path))
        .collect();

    // Mandatory: signal, changed, top-N churn.
    let mut churn_ranked: Vec<&str> = eligible
        .iter()
        .copied()
        .filter(|path| facts.get(*path).is_some_and(|f| f.churn > 0))
        .collect();
    churn_ranked.sort_by(|left, right| {
        let (l, r) = (&facts[*left], &facts[*right]);
        r.churn.cmp(&l.churn).then_with(|| left.cmp(right))
    });
    let churn_top: BTreeSet<&str> = churn_ranked.into_iter().take(CHURN_TOP_N).collect();
    let mandatory: Vec<&str> = eligible
        .iter()
        .copied()
        .filter(|path| {
            facts
                .get(*path)
                .is_some_and(|f| f.signal.is_some() || f.changed)
                || churn_top.contains(path)
        })
        .collect();
    let mandatory_set: BTreeSet<&str> = mandatory.iter().copied().collect();
    let mandatory_tokens: u64 = present
        .iter()
        .map(|bundle| {
            denominators[bundle.id]
                .iter()
                .filter(|path| {
                    mandatory_set.contains(**path) || bundle_witnesses[bundle.id].contains(**path)
                })
                .map(|path| {
                    estimate_bytes(
                        sample_mode(bundle, true),
                        facts.get(*path).map_or(0, |f| f.size),
                    )
                })
                .sum::<u64>()
                .div_ceil(4)
        })
        .sum();
    let output_reserve = super::ingest::dispatch_output_tokens(request.seat_token_budget)
        .saturating_mul(present.len() as u64);
    if request.seat_token_budget <= SEAT_PACKET_RESERVE_BYTES as u64
        || present.len() as u64 + 1 > request.max_total_seats
        || mandatory_tokens.saturating_add(output_reserve) > initial_budget
    {
        return bounded_coverage(
            &seed,
            facts,
            lenses,
            request,
            witnesses,
            &mandatory_set,
            fits,
        );
    }
    let mut hotspots: Vec<&str> = eligible
        .iter()
        .copied()
        .filter(|path| !mandatory_set.contains(path))
        .collect();
    hotspots.sort_by(|left, right| {
        let default = FileFacts::default();
        let l = hotspot_score(facts.get(*left).unwrap_or(&default));
        let r = hotspot_score(facts.get(*right).unwrap_or(&default));
        r.cmp(&l).then_with(|| left.cmp(right))
    });
    // Size alone does not make a hotspot: only files with a churn or fan-in
    // signal are ranked hotspots; the rest is remainder material (sampled).
    let (hotspots, mut remainder): (Vec<&str>, Vec<&str>) =
        hotspots.into_iter().partition(|path| {
            facts
                .get(*path)
                .is_some_and(|f| f.churn > 0 || f.fan_in > 0)
        });
    remainder.sort_by_key(|path| (seeded_key(&seed, path), (*path).to_owned()));

    // Budgets: surplus of bundles that fit entirely flows to the others.
    let mut budget_tokens: BTreeMap<&'static str, u64> = present
        .iter()
        .map(|bundle| (bundle.id, base_tokens(bundle)))
        .collect();
    let mut full_cost: BTreeMap<&'static str, u64> = BTreeMap::new();
    for bundle in &present {
        let tokens: u64 = denominators[bundle.id]
            .iter()
            .filter(|path| !is_lens_excluded(path) || bundle_witnesses[bundle.id].contains(**path))
            .map(|path| {
                let mandatory =
                    mandatory_set.contains(path) || bundle_witnesses[bundle.id].contains(*path);
                estimate_bytes(
                    sample_mode(bundle, mandatory),
                    facts.get(*path).map_or(0, |f| f.size),
                )
            })
            .sum::<u64>()
            / 4;
        full_cost.insert(bundle.id, tokens);
    }
    let surplus: u64 = present
        .iter()
        .map(|bundle| {
            budget_tokens[bundle.id].saturating_sub(full_cost[bundle.id] * 100 / COMMIT_PERCENT)
        })
        .sum();
    let deficit_share: u64 = present
        .iter()
        .filter(|bundle| full_cost[bundle.id] * 100 > budget_tokens[bundle.id] * COMMIT_PERCENT)
        .map(|bundle| u64::from(bundle.budget_share_bp))
        .sum();
    if deficit_share > 0 {
        for bundle in &present {
            if full_cost[bundle.id] * 100 > budget_tokens[bundle.id] * COMMIT_PERCENT {
                *budget_tokens.get_mut(bundle.id).expect("present bundle") +=
                    surplus * u64::from(bundle.budget_share_bp) / deficit_share;
            }
        }
        for bundle in &present {
            if full_cost[bundle.id] * 100 <= budget_tokens[bundle.id] * COMMIT_PERCENT {
                budget_tokens.insert(bundle.id, full_cost[bundle.id] * 100 / COMMIT_PERCENT);
            }
        }
    }

    // Bundle shares are allocation targets, not limits. The mandatory stratum
    // never shrinks (Astra D2), so a bundle whose mandatory cost exceeds its
    // share borrows from the other bundles' unspent share (proportionally to
    // each donor's headroom above its own mandatory cost). Only a run whose
    // mandatory strata together exceed the run budget stays over: the gate then
    // refuses it.
    let mandatory_required: BTreeMap<&'static str, u64> = present
        .iter()
        .map(|bundle| {
            let bytes: u64 = denominators[bundle.id]
                .iter()
                .filter(|path| {
                    mandatory_set.contains(**path) || bundle_witnesses[bundle.id].contains(**path)
                })
                .map(|path| {
                    estimate_bytes(
                        sample_mode(bundle, true),
                        facts.get(*path).map_or(0, |f| f.size),
                    )
                })
                .sum();
            // Budget at which the committed share (COMMIT_PERCENT) covers it.
            (bundle.id, (bytes / 4 * 100).div_ceil(COMMIT_PERCENT))
        })
        .collect();
    let need_total: u64 = present
        .iter()
        .map(|bundle| mandatory_required[bundle.id].saturating_sub(budget_tokens[bundle.id]))
        .sum();
    if need_total > 0 {
        let headroom_total: u64 = present
            .iter()
            .map(|bundle| budget_tokens[bundle.id].saturating_sub(mandatory_required[bundle.id]))
            .sum();
        let take = need_total.min(headroom_total);
        let mut next = budget_tokens.clone();
        for bundle in &present {
            let budget = budget_tokens[bundle.id];
            let required = mandatory_required[bundle.id];
            if required > budget {
                let gain = (u128::from(required - budget) * u128::from(take)
                    / u128::from(need_total)) as u64;
                next.insert(bundle.id, budget + gain);
            } else if headroom_total > 0 {
                let loss = (u128::from(budget - required) * u128::from(take)
                    / u128::from(headroom_total)) as u64;
                next.insert(bundle.id, budget - loss);
            }
        }
        budget_tokens = next;
    }

    let mut selections: BTreeMap<&'static str, BundleSelection> = BTreeMap::new();
    for bundle in &present {
        let den = &denominators[bundle.id];
        let keep = |list: &Vec<&str>| -> Vec<String> {
            list.iter()
                .filter(|path| den.contains(**path))
                .map(|path| (*path).to_owned())
                .collect()
        };
        let mut m = keep(&mandatory);
        // Only the applicable bundle inherits witnesses. Other bundles keep
        // their risk sample; trigger coverage never silently makes all lenses exhaustive.
        m.extend(
            bundle_witnesses[bundle.id]
                .iter()
                .filter(|path| den.contains(**path))
                .map(|path| (*path).to_owned()),
        );
        m.sort();
        m.dedup();
        let h = keep(&hotspots)
            .into_iter()
            .filter(|path| !bundle_witnesses[bundle.id].contains(path.as_str()))
            .collect::<Vec<_>>();
        let r = keep(&remainder)
            .into_iter()
            .filter(|path| !bundle_witnesses[bundle.id].contains(path.as_str()))
            .collect::<Vec<_>>();
        let m_refs: Vec<&str> = m.iter().map(String::as_str).collect();
        let h_refs: Vec<&str> = h.iter().map(String::as_str).collect();
        let r_refs: Vec<&str> = r.iter().map(String::as_str).collect();
        let packet_tokens = (SEAT_PACKET_RESERVE_BYTES as u64 / 4)
            .min(request.seat_token_budget / 4)
            .saturating_add(super::ingest::dispatch_output_tokens(
                request.seat_token_budget,
            ));
        let budget_bytes =
            budget_tokens[bundle.id].saturating_sub(packet_tokens) * 4 * COMMIT_PERCENT / 100;
        selections.insert(
            bundle.id,
            select_for_bundle(bundle, budget_bytes, &m_refs, &h_refs, &r_refs, facts),
        );
    }

    let hotspot_rank: BTreeMap<&str, usize> = hotspots
        .iter()
        .enumerate()
        .map(|(index, path)| (*path, index))
        .collect();
    let remainder_rank: BTreeMap<&str, usize> = remainder
        .iter()
        .enumerate()
        .map(|(index, path)| (*path, index))
        .collect();
    for lens in lenses {
        let Some(bundle) = lens_plan::bundle_for_provider(&lens.provider_id) else {
            continue;
        };
        let selection = &selections[bundle.id];
        let denominator: BTreeSet<&str> = lens.paths.iter().map(String::as_str).collect();
        let mut review_set: Vec<String> = Vec::new();
        let mut strata_paths: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for (path, stratum) in &selection.chosen {
            if !denominator.contains(path.as_str()) {
                continue;
            }
            review_set.push(path.clone());
            let name = match stratum {
                Stratum::Mandatory => "mandatory",
                Stratum::Hotspot => "hotspot",
                Stratum::Sample => "remainder",
            };
            strata_paths.entry(name).or_default().push(path.clone());
        }
        review_set.sort();
        // Hotspot and remainder paths are listed best-ranked first (hotspot
        // score order, seeded order), so findings promotion can displace the
        // lowest-ranked sampled files by walking each list from its end.
        // Mandatory paths stay in path order.
        if let Some(list) = strata_paths.get_mut("hotspot") {
            list.sort_by_key(|path| {
                hotspot_rank
                    .get(path.as_str())
                    .copied()
                    .unwrap_or(usize::MAX)
            });
        }
        if let Some(list) = strata_paths.get_mut("remainder") {
            list.sort_by_key(|path| {
                remainder_rank
                    .get(path.as_str())
                    .copied()
                    .unwrap_or(usize::MAX)
            });
        }
        let excluded = lens
            .paths
            .iter()
            .filter(|path| {
                is_lens_excluded(path) && !bundle_witnesses[bundle.id].contains(path.as_str())
            })
            .count();
        let mandatory_n = strata_paths.get("mandatory").map_or(0, Vec::len);
        let hotspot_n = hotspots
            .iter()
            .filter(|path| {
                denominator.contains(**path) && !bundle_witnesses[bundle.id].contains(**path)
            })
            .count();
        let remainder_n = remainder
            .iter()
            .filter(|path| {
                denominator.contains(**path) && !bundle_witnesses[bundle.id].contains(**path)
            })
            .count();
        let strata = json!([
            {"name": "mandatory", "N": mandatory_n, "n": strata_paths.get("mandatory").map_or(0, Vec::len),
             "paths": strata_paths.get("mandatory").cloned().unwrap_or_default()},
            {"name": "hotspot", "N": hotspot_n, "n": strata_paths.get("hotspot").map_or(0, Vec::len),
             "paths": strata_paths.get("hotspot").cloned().unwrap_or_default()},
            {"name": "remainder", "N": remainder_n, "n": strata_paths.get("remainder").map_or(0, Vec::len),
             "paths": strata_paths.get("remainder").cloned().unwrap_or_default(), "sampling": "seeded-uniform"},
            {"name": "excluded", "N": excluded, "n": 0, "paths": Value::Null,
             "reason": "generated-vendored-lock-minified"},
        ]);
        let digest = canonical_digest(&review_set)
            .map_err(|error| AuditError::Invalid(error.to_string()))?;
        let declared_unsampled = lens.paths.len().saturating_sub(review_set.len());
        configs.insert(
            lens.provider_id.clone(),
            json!({
                "schemaVersion": 1,
                "mode": MODE_RISK_SAMPLED,
                "requestedMode": request.mode.as_str(),
                "fitsExhaustive": fits,
                "seed": seed,
                "bundle": bundle.id,
                "tier": bundle.tier,
                "budgetShareBp": bundle.budget_share_bp,
                "tokenBudget": budget_tokens[bundle.id],
                "seatTokenBudget": request.seat_token_budget,
                "bundleLensCount": bundle_lenses.get(bundle.id).map_or(1, Vec::len),
                "estimatedTokens": selection.estimated_bytes / 4,
                "denominator": lens.paths.len(),
                "reviewSet": review_set,
                "reviewSetDigest": digest,
                "mandatoryWitnessPaths": witnesses.get(&lens.provider_id).cloned().unwrap_or_default(),
                "strata": strata,
                "excluded": {"count": excluded},
                "declaredUnsampled": declared_unsampled,
                "sampleFloorTarget": SAMPLE_FLOOR.min(remainder_n),
                "sampleFloorMet": strata_paths.get("remainder").map_or(0, Vec::len) >= SAMPLE_FLOOR.min(remainder_n),
                "followupReserveTokens": followup_reserve,
                "excerpt": {
                    "mode": bundle.sampled_mode,
                    "mandatoryMode": if bundle.raw_mandatory { json!(ExcerptMode::Raw) } else { Value::Null },
                    "dedup": true,
                },
            }),
        );
    }
    Ok(configs)
}

/// Tight envelopes use one deterministic raw-source selection across semantic
/// contracts. This is a bounded risk review, not a uniform statistical sample.
/// The whole mandatory universe remains frozen even when only some paths fit.
fn bounded_coverage(
    seed: &str,
    facts: &BTreeMap<String, FileFacts>,
    lenses: &[LensInput],
    request: &CoverageRequest,
    witnesses: &BTreeMap<String, BTreeSet<String>>,
    mandatory: &BTreeSet<&str>,
    fits: bool,
) -> Result<BTreeMap<String, Value>, AuditError> {
    let universe: BTreeSet<&str> = lenses
        .iter()
        .filter(|lens| lens_plan::bundle_for_provider(&lens.provider_id).is_some())
        .flat_map(|lens| lens.paths.iter().map(String::as_str))
        .collect();
    let witness_union: BTreeSet<&str> = witnesses.values().flatten().map(String::as_str).collect();
    let mut ranked: Vec<&str> = universe
        .iter()
        .copied()
        .filter(|path| !is_lens_excluded(path) || witness_union.contains(path))
        .collect();
    ranked.sort_by(|left, right| {
        let default = FileFacts::default();
        let l = facts.get(*left).unwrap_or(&default);
        let r = facts.get(*right).unwrap_or(&default);
        let priority = |path: &str, fact: &FileFacts| {
            (
                fact.changed,
                witness_union.contains(path),
                mandatory.contains(path),
                fact.signal == Some("entrypoint"),
                hotspot_score(fact),
            )
        };
        priority(right, r)
            .cmp(&priority(left, l))
            .then_with(|| left.cmp(right))
    });
    // Raw source gets one quarter of input capacity; contracts, schemas,
    // framing, escaping & tokenization headroom occupy the remainder. Exact
    // rendered dispatch remains authoritative, never this byte estimate.
    let input_tokens =
        request
            .seat_token_budget
            .saturating_sub(super::ingest::dispatch_output_tokens(
                request.seat_token_budget,
            ));
    let source_budget = input_tokens.min(initial_source_budget(request));
    let mut used = 0u64;
    let mut selected = BTreeSet::new();
    for path in ranked {
        let cost = facts
            .get(path)
            .map_or(0, |fact| fact.size)
            .saturating_add(384);
        if used.saturating_add(cost) <= source_budget {
            selected.insert(path);
            used = used.saturating_add(cost);
        }
    }
    let mut configs = BTreeMap::new();
    for lens in lenses {
        let Some(bundle) = lens_plan::bundle_for_provider(&lens.provider_id) else {
            continue;
        };
        let denominator: BTreeSet<&str> = lens.paths.iter().map(String::as_str).collect();
        let mandatory_universe: BTreeSet<&str> = denominator
            .iter()
            .copied()
            .filter(|path| {
                mandatory.contains(path)
                    || witnesses
                        .get(&lens.provider_id)
                        .is_some_and(|paths| paths.contains(*path))
            })
            .collect();
        let review: Vec<&str> = denominator.intersection(&selected).copied().collect();
        let selected_mandatory: Vec<&str> = review
            .iter()
            .copied()
            .filter(|path| mandatory_universe.contains(path))
            .collect();
        let deferred: Vec<&str> = mandatory_universe.difference(&selected).copied().collect();
        let selected_other: Vec<&str> = review
            .iter()
            .copied()
            .filter(|path| !mandatory_universe.contains(path))
            .collect();
        let excluded = denominator
            .iter()
            .filter(|path| is_lens_excluded(path) && !mandatory_universe.contains(**path))
            .count();
        let digest = |value: &Value| {
            canonical_digest(value).map_err(|error| AuditError::Invalid(error.to_string()))
        };
        let mode = if lens_plan::lens_id_for_provider(&lens.provider_id) == Some("dead-file") {
            ExcerptMode::Skeleton
        } else {
            ExcerptMode::Raw
        };
        configs.insert(lens.provider_id.clone(), json!({
            "schemaVersion":1, "mode":MODE_RISK_SAMPLED,
            "requestedMode":request.mode.as_str(), "fitsExhaustive":fits,
            "boundedAudit":true, "selection":"deterministic-risk-ranked",
            "confidence":{"claim":"none","basis":"bounded-risk-selection"},
            "seed":seed, "bundle":bundle.id, "tier":bundle.tier,
            "budgetShareBp":bundle.budget_share_bp,
            "tokenBudget":request.run_token_budget.saturating_sub(request.seat_token_budget),
            "seatTokenBudget":request.seat_token_budget,
            "bundleLensCount":1,
            "estimatedTokens":used.div_ceil(4),
            "denominator":denominator.len(), "reviewSet":review,
            "reviewSetDigest":digest(&json!(review))?,
            "mandatoryUniverse":mandatory_universe,
            "mandatoryUniverseDigest":digest(&json!(mandatory_universe))?,
            "mandatoryDeferred":deferred,
            "mandatoryDeferredDigest":digest(&json!(deferred))?,
            "mandatoryWitnessPaths":witnesses.get(&lens.provider_id).cloned().unwrap_or_default(),
            "declaredUnsampled":denominator.len().saturating_sub(review.len()),
            "excluded":{"count":excluded},
            "sampleFloorTarget":0, "sampleFloorMet":false,
            "followupReserveTokens":request.seat_token_budget,
            "strata":[
                {"name":"mandatory","N":mandatory_universe.len(),"n":selected_mandatory.len(),"paths":selected_mandatory},
                {"name":"risk-ranked","N":denominator.len().saturating_sub(mandatory_universe.len()).saturating_sub(excluded),"n":selected_other.len(),"paths":selected_other},
                {"name":"excluded","N":excluded,"n":0,"paths":null}
            ],
            "excerpt":{"mode":mode,"mandatoryMode":mode,"dedup":true}
        }));
    }
    Ok(configs)
}

fn initial_source_budget(request: &CoverageRequest) -> u64 {
    // Keep selected source bounded even for asymmetric run/per-call limits.
    request
        .run_token_budget
        .saturating_sub(request.seat_token_budget)
        .min(16 * 1024)
}

// ---------------------------------------------------------------------------
// Confidence (Astra D2: narrow, assumption-stated)
// ---------------------------------------------------------------------------

/// 95% upper bound on the share of affected files given zero observations in
/// `n` randomly sampled files: `3/n` (the rule of three). `None` for `n == 0`.
pub fn rule_of_three_upper(n: u64) -> Option<f64> {
    (n > 0).then(|| (3.0 / n as f64).min(1.0))
}

fn ln_binomial_cdf(n: u64, k: u64, p: f64) -> f64 {
    // ln P(X <= k), X ~ Binomial(n, p), summed in log space.
    if p <= 0.0 {
        return 0.0;
    }
    if p >= 1.0 {
        return if k >= n { 0.0 } else { f64::NEG_INFINITY };
    }
    let ratio = (p / (1.0 - p)).ln();
    let mut ln_pmf = n as f64 * (1.0 - p).ln();
    let mut terms = vec![ln_pmf];
    for i in 0..k.min(n) {
        ln_pmf += ((n - i) as f64 / (i + 1) as f64).ln() + ratio;
        terms.push(ln_pmf);
    }
    let max = terms.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    max + terms.iter().map(|t| (t - max).exp()).sum::<f64>().ln()
}

/// Two-sided 95% Clopper-Pearson interval for `k` affected files among `n`
/// sampled. Valid only when the sample is i.i.d.-like; the remainder stratum
/// is a seeded uniform sample without replacement, which the binomial model
/// treats conservatively when the sample is a small share of the stratum.
pub fn clopper_pearson(n: u64, k: u64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let alpha_half = 0.025f64;
    // Upper: smallest p with P(X <= k | p) <= alpha/2 (cdf decreases in p).
    let upper = if k >= n {
        1.0
    } else {
        let (mut lo, mut hi) = (0.0f64, 1.0f64);
        for _ in 0..80 {
            let mid = (lo + hi) / 2.0;
            if ln_binomial_cdf(n, k, mid).exp() > alpha_half {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        hi
    };
    // Lower: largest p with P(X >= k | p) <= alpha/2, i.e. P(X <= k-1) >= 1-alpha/2.
    let lower = if k == 0 {
        0.0
    } else {
        let (mut lo, mut hi) = (0.0f64, 1.0f64);
        for _ in 0..80 {
            let mid = (lo + hi) / 2.0;
            if ln_binomial_cdf(n, k - 1, mid).exp() >= 1.0 - alpha_half {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    };
    (lower, upper)
}

/// Confidence statement for one stratum. Only the seeded random remainder gets
/// a statistical claim; mandatory and hotspot strata are exhaustive within
/// their frozen selection and carry none. `high_findings` counts high or
/// critical findings anchored in the stratum's reviewed files.
pub fn stratum_confidence(name: &str, population: u64, sampled: u64, high_findings: u64) -> Value {
    if name != "remainder" {
        return json!({
            "claim": "none",
            "basis": "exhaustive-within-frozen-selection",
        });
    }
    if sampled == 0 {
        return json!({"claim": "none", "basis": "empty-sample"});
    }
    if sampled < population.min(SAMPLE_FLOOR as u64) {
        return json!({"claim":"none", "basis":"sample-floor-not-met"});
    }
    let assumption = "seeded uniform sample without replacement; bound is on the share of files in this stratum carrying a high-or-critical finding this lens can detect in a sampled file; says nothing about unsampled files' lens-undetectable defects";
    if high_findings == 0 {
        json!({
            "claim": "upper-bound",
            "method": "rule-of-three",
            "level": 0.95,
            "population": population,
            "sampled": sampled,
            "observed": 0,
            "upperBound": rule_of_three_upper(sampled),
            "assumption": assumption,
        })
    } else {
        let (lower, upper) = clopper_pearson(sampled, high_findings);
        json!({
            "claim": "interval",
            "method": "clopper-pearson",
            "level": 0.95,
            "population": population,
            "sampled": sampled,
            "observed": high_findings,
            "lowerBound": lower,
            "upperBound": upper,
            "assumption": assumption,
        })
    }
}

// ---------------------------------------------------------------------------
// Frozen-config readers
// ---------------------------------------------------------------------------

/// A lens provider's frozen coverage configuration.
#[derive(Clone, Debug)]
pub struct FrozenCoverage {
    pub mode: String,
    pub bundle: String,
    pub seed: String,
    pub review_set: BTreeSet<String>,
    pub review_set_digest: String,
    pub denominator: usize,
    pub excluded: usize,
    pub mandatory: BTreeSet<String>,
    pub mandatory_universe: BTreeSet<String>,
    pub mandatory_deferred: BTreeSet<String>,
    pub bounded: bool,
    pub default_mode: Option<ExcerptMode>,
    pub mandatory_mode: Option<ExcerptMode>,
    pub dedup: bool,
    pub strata: Value,
}

impl FrozenCoverage {
    pub fn is_sampled(&self) -> bool {
        self.mode == MODE_RISK_SAMPLED
    }

    /// Paths of the named stratum in frozen order (best-ranked first for the
    /// hotspot and remainder strata of a current plan).
    pub fn stratum_paths(&self, name: &str) -> Vec<String> {
        self.strata
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
            })
            .and_then(|item| item.get("paths"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let strings = |field: &str| -> BTreeSet<String> {
            object
                .get(field)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        let strata = object.get("strata").cloned().unwrap_or(Value::Null);
        let mandatory = strata
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item.get("name").and_then(Value::as_str) == Some("mandatory"))
            })
            .and_then(|item| item.get("paths"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let mode_of = |field: &str| -> Option<ExcerptMode> {
            object
                .get("excerpt")
                .and_then(|excerpt| excerpt.get(field))
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
        };
        Some(Self {
            mode: object.get("mode")?.as_str()?.to_owned(),
            bundle: object.get("bundle")?.as_str()?.to_owned(),
            seed: object.get("seed")?.as_str()?.to_owned(),
            review_set: strings("reviewSet"),
            review_set_digest: object.get("reviewSetDigest")?.as_str()?.to_owned(),
            denominator: object.get("denominator")?.as_u64()? as usize,
            excluded: object
                .get("excluded")
                .and_then(|excluded| excluded.get("count"))
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
            mandatory,
            mandatory_universe: strings("mandatoryUniverse"),
            mandatory_deferred: strings("mandatoryDeferred"),
            bounded: object
                .get("boundedAudit")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            default_mode: mode_of("mode"),
            mandatory_mode: mode_of("mandatoryMode"),
            dedup: object
                .get("excerpt")
                .and_then(|excerpt| excerpt.get("dedup"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            strata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts_for(paths: &[String], size: u64) -> BTreeMap<String, FileFacts> {
        paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                (
                    path.clone(),
                    FileFacts {
                        size,
                        digest: Some(format!("sha256:{index:064x}")),
                        churn: (index % 7) as u32,
                        fan_in: 0,
                        signal: classify_signal(path, &[]),
                        changed: false,
                    },
                )
            })
            .collect()
    }

    fn fixture_paths(count: usize) -> Vec<String> {
        let mut paths: Vec<String> = (0..count)
            .map(|index| match index % 10 {
                0 => format!("src/auth/mod_{index:04}.rs"),
                1 => format!("src/commands/cmd_{index:04}.rs"),
                _ => format!("src/lib/file_{index:04}.rs"),
            })
            .collect();
        paths.sort();
        paths
    }

    fn lenses(paths: &[String]) -> Vec<LensInput> {
        [
            "reasoning.security",
            "reasoning.correctness",
            "reasoning.schema",
            "reasoning.architecture",
            "reasoning.doc-drift",
            "reasoning.performance",
            "reasoning.minimize",
            "reasoning.ai-slop",
            "reasoning.naming",
            "reasoning.dead-file",
        ]
        .iter()
        .map(|id| LensInput {
            provider_id: (*id).to_owned(),
            paths: paths.to_vec(),
        })
        .collect()
    }

    fn request(mode: CoverageMode) -> CoverageRequest {
        CoverageRequest {
            mode,
            ..CoverageRequest::default()
        }
    }

    #[test]
    fn small_skeleton_estimates_charge_raw_before_tight_budget_selection() {
        for size in [0, 4095, 4096] {
            assert_eq!(estimate_bytes(ExcerptMode::Skeleton, size), size);
        }
        assert_eq!(estimate_bytes(ExcerptMode::Skeleton, 4097), 4097 / 4 + 200);
        let paths = vec!["small.rs".to_owned()];
        let facts = facts_for(&paths, 4096);
        let refused =
            select_for_bundle(&lens_plan::BUNDLE_M1, 4095, &[], &[], &["small.rs"], &facts);
        assert!(refused.chosen.is_empty());
        let admitted =
            select_for_bundle(&lens_plan::BUNDLE_M1, 4096, &[], &[], &["small.rs"], &facts);
        assert_eq!(admitted.chosen.len(), 1);
        assert_eq!(admitted.estimated_bytes, 4096);
        let mandatory =
            select_for_bundle(&lens_plan::BUNDLE_M1, 1, &["small.rs"], &[], &[], &facts);
        assert_eq!(mandatory.chosen.len(), 1);
        assert_eq!(mandatory.estimated_bytes, 4096); // Mandatory coverage never shrinks.
    }

    #[test]
    fn same_inputs_give_the_same_review_set() {
        let paths = fixture_paths(1100);
        let facts = facts_for(&paths, 12 * 1024);
        let basis = json!({"inventoryDigest": "sha256:aa"});
        let a = plan_coverage(
            &basis,
            &facts,
            &lenses(&paths),
            &request(CoverageMode::Auto),
        )
        .unwrap();
        let b = plan_coverage(
            &basis,
            &facts,
            &lenses(&paths),
            &request(CoverageMode::Auto),
        )
        .unwrap();
        assert_eq!(a, b);
        let c = plan_coverage(
            &json!({"inventoryDigest": "sha256:bb"}),
            &facts,
            &lenses(&paths),
            &request(CoverageMode::Auto),
        )
        .unwrap();
        // Every fixture file has churn, so all non-mandatory files rank as
        // hotspots and the seeded remainder is empty here: assert what the seed
        // controls — a different basis gives a different seed and ordering.
        let seed_a = a["reasoning.security"]["seed"].as_str().unwrap().to_owned();
        let seed_c = c["reasoning.security"]["seed"].as_str().unwrap().to_owned();
        assert_ne!(seed_a, seed_c, "a different basis gives a different seed");
        let order = |seed: &str| {
            let mut sample: Vec<&str> = paths.iter().map(String::as_str).collect();
            sample.sort_by_key(|path| seeded_key(seed, path));
            sample
                .into_iter()
                .take(30)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_ne!(
            order(&seed_a),
            order(&seed_c),
            "a different seed samples a different remainder"
        );
    }

    #[test]
    fn eleven_hundred_files_plan_within_budget_and_mandatory_never_shrinks() {
        let paths = fixture_paths(1100);
        let facts = facts_for(&paths, 12 * 1024);
        let basis = json!({"inventoryDigest": "sha256:aa"});
        let plan = plan_coverage(
            &basis,
            &facts,
            &lenses(&paths),
            &request(CoverageMode::Auto),
        )
        .unwrap();
        let security = &plan["reasoning.security"];
        assert_eq!(security["mode"], MODE_RISK_SAMPLED);
        assert_eq!(security["fitsExhaustive"], false);
        let review = security["reviewSet"].as_array().unwrap().len();
        assert!(review < 1100 && review > 200, "review set {review}");
        // Every mandatory path (auth/commands signals) is in the review set.
        let mandatory: Vec<&String> = paths
            .iter()
            .filter(|p| facts[*p].signal.is_some())
            .collect();
        let set: BTreeSet<&str> = security["reviewSet"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(mandatory.iter().all(|p| set.contains(p.as_str())));
        // Estimated tokens of all bundles stay inside the run budget.
        let total: u64 = [
            "reasoning.security",
            "reasoning.architecture",
            "reasoning.performance",
            "reasoning.minimize",
            "reasoning.ai-slop",
            "reasoning.naming",
        ]
        .iter()
        .map(|id| plan[*id]["estimatedTokens"].as_u64().unwrap())
        .sum();
        assert!(
            total <= DEFAULT_RUN_TOKEN_BUDGET,
            "estimated {total} tokens"
        );
        // Lenses in one bundle share one review set.
        assert_eq!(
            plan["reasoning.security"]["reviewSetDigest"],
            plan["reasoning.correctness"]["reviewSetDigest"]
        );
        // Declared unsampled accounts for the rest of the denominator.
        assert_eq!(
            security["declaredUnsampled"].as_u64().unwrap() as usize + review,
            1100
        );
    }

    #[test]
    fn small_repository_stays_exhaustive_under_auto() {
        let paths = fixture_paths(40);
        let facts = facts_for(&paths, 2048);
        let plan = plan_coverage(
            &json!({}),
            &facts,
            &lenses(&paths),
            &request(CoverageMode::Auto),
        )
        .unwrap();
        for config in plan.values() {
            assert_eq!(config["mode"], MODE_EXHAUSTIVE);
            assert_eq!(config["reviewSet"].as_array().unwrap().len(), 40);
            assert_eq!(config["declaredUnsampled"], 0);
        }
    }

    #[test]
    fn ember_sized_budget_freezes_mandatory_deferred_without_bundle_call_floor() {
        // Paths & sizes from Ember 9961562, including its tiny executable
        // entrypoints & a large mandatory body that cannot fit this source set.
        let source = [
            ("apps/lightcraft-desktop/src/main.rs", 478),
            ("apps/lightcraft-desktop/web/src/main.tsx", 605),
            ("crates/ui-egui/src/command_error.rs", 1164),
            ("crates/ui-egui/src/auth.rs", 120_000),
        ];
        let paths = source
            .iter()
            .map(|(path, _)| (*path).to_owned())
            .collect::<Vec<_>>();
        let facts = source
            .iter()
            .map(|(path, size)| {
                (
                    (*path).to_owned(),
                    FileFacts {
                        size: *size,
                        signal: classify_signal(path, &[]),
                        ..FileFacts::default()
                    },
                )
            })
            .collect();
        for mode in [CoverageMode::RiskSampled, CoverageMode::Auto] {
            let request = CoverageRequest {
                mode,
                run_token_budget: 50_000,
                seat_token_budget: 10_000,
                max_total_seats: 5,
            };
            let plan = plan_coverage(
                &json!({"revision":"9961562"}),
                &facts,
                &lenses(&paths),
                &request,
            )
            .unwrap();
            let config = &plan["reasoning.security"];
            assert_eq!(config["mode"], MODE_RISK_SAMPLED);
            assert_eq!(config["requestedMode"], mode.as_str());
            assert!(config["reviewSet"].as_array().unwrap().len() >= 2);
            assert_eq!(
                config["mandatoryDeferred"],
                json!(["crates/ui-egui/src/auth.rs"])
            );
            assert_eq!(config["strata"][0]["N"], 3);
            assert_eq!(config["strata"][0]["n"], 2);
            assert_eq!(config["confidence"]["claim"], "none");
            assert_eq!(plan["reasoning.minimize"]["reviewSet"], config["reviewSet"]);
            assert_eq!(plan["reasoning.minimize"]["excerpt"]["mode"], "raw");
            assert_eq!(config["followupReserveTokens"], 10_000);
        }
        let exhaustive = plan_coverage(
            &json!({}),
            &facts,
            &lenses(&paths),
            &CoverageRequest {
                mode: CoverageMode::Exhaustive,
                run_token_budget: 50_000,
                seat_token_budget: 10_000,
                max_total_seats: 5,
            },
        )
        .unwrap();
        assert_eq!(exhaustive["reasoning.security"]["mode"], MODE_EXHAUSTIVE);
        assert_eq!(
            exhaustive["reasoning.security"]["reviewSet"]
                .as_array()
                .unwrap()
                .len(),
            paths.len()
        );
    }

    #[test]
    fn explicit_exhaustive_never_samples_even_when_it_does_not_fit() {
        let paths = fixture_paths(1100);
        let facts = facts_for(&paths, 12 * 1024);
        let plan = plan_coverage(
            &json!({}),
            &facts,
            &lenses(&paths),
            &request(CoverageMode::Exhaustive),
        )
        .unwrap();
        let security = &plan["reasoning.security"];
        assert_eq!(security["mode"], MODE_EXHAUSTIVE);
        assert_eq!(security["fitsExhaustive"], false);
        assert_eq!(security["reviewSet"].as_array().unwrap().len(), 1100);
    }

    #[test]
    fn changing_the_review_set_changes_the_digest_input() {
        let paths = fixture_paths(1100);
        let facts = facts_for(&paths, 12 * 1024);
        let a = plan_coverage(
            &json!({}),
            &facts,
            &lenses(&paths),
            &request(CoverageMode::RiskSampled),
        )
        .unwrap();
        let mut bigger = request(CoverageMode::RiskSampled);
        bigger.run_token_budget *= 2;
        let b = plan_coverage(&json!({}), &facts, &lenses(&paths), &bigger).unwrap();
        assert_ne!(
            a["reasoning.security"]["reviewSetDigest"],
            b["reasoning.security"]["reviewSetDigest"]
        );
        // A bigger budget only adds files (nested prefix selection).
        let small: BTreeSet<&str> = a["reasoning.security"]["reviewSet"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let large: BTreeSet<&str> = b["reasoning.security"]["reviewSet"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(small.is_subset(&large));
    }

    #[test]
    fn remainder_sample_count_is_independent_of_seed_order_and_file_cost() {
        let facts = [
            ("large.rs", 9000),
            ("one.rs", 1000),
            ("two.rs", 1000),
            ("three.rs", 1000),
        ]
        .into_iter()
        .map(|(path, size)| {
            (
                path.to_owned(),
                FileFacts {
                    size,
                    ..Default::default()
                },
            )
        })
        .collect();
        let first = select_for_bundle(
            &lens_plan::BUNDLE_S3,
            10_000,
            &[],
            &[],
            &["large.rs", "one.rs", "two.rs", "three.rs"],
            &facts,
        );
        let other = select_for_bundle(
            &lens_plan::BUNDLE_S3,
            10_000,
            &[],
            &[],
            &["one.rs", "two.rs", "three.rs", "large.rs"],
            &facts,
        );
        assert_eq!(first.chosen.len(), 2);
        assert_eq!(other.chosen.len(), 2);
        assert!(first.estimated_bytes <= 10_000 && other.estimated_bytes <= 10_000);
    }

    #[test]
    fn confidence_is_scoped_to_the_random_stratum() {
        assert_eq!(rule_of_three_upper(0), None);
        assert!((rule_of_three_upper(30).unwrap() - 0.1).abs() < 1e-9);
        assert_eq!(stratum_confidence("remainder", 800, 7, 0)["claim"], "none");
        let zero = stratum_confidence("remainder", 800, 30, 0);
        assert_eq!(zero["method"], "rule-of-three");
        assert!((zero["upperBound"].as_f64().unwrap() - 0.1).abs() < 1e-9);
        let some = stratum_confidence("remainder", 800, 30, 2);
        assert_eq!(some["method"], "clopper-pearson");
        let (lo, hi) = (
            some["lowerBound"].as_f64().unwrap(),
            some["upperBound"].as_f64().unwrap(),
        );
        assert!(
            lo > 0.0 && lo < 2.0 / 30.0 && hi > 2.0 / 30.0 && hi < 0.3,
            "{lo} {hi}"
        );
        assert_eq!(stratum_confidence("mandatory", 10, 10, 0)["claim"], "none");
        // Known value: 0 of 30 gives a CP upper of about 0.116 (two-sided).
        let (_, upper) = clopper_pearson(30, 0);
        assert!((upper - 0.1157).abs() < 0.002, "{upper}");
    }

    #[test]
    fn excluded_and_signal_rules() {
        assert!(is_lens_excluded("vendor/x/lib.rs"));
        assert!(is_lens_excluded("web/app.min.js"));
        assert!(is_lens_excluded("Cargo.lock"));
        assert!(!is_lens_excluded("src/vendor_client.rs"));
        assert_eq!(
            classify_signal("bins/legion/src/main.rs", &[]),
            Some("entrypoint")
        );
        assert_eq!(
            classify_signal("src/auth/session.rs", &[]),
            Some("security-sensitive")
        );
        assert_eq!(classify_signal("src/design/layout.rs", &[]), None);
    }
}
