//! Per-lens work-packet planning for the native reasoning providers.
//!
//! This module is the native counterpart to the JS/skill lens contract in
//! `skills/audit/references/{lens-routing,manual,ponytail-lens,lens-cues}.md`.
//! It does not call a model and does not decide *whether* a conditional
//! lens's trigger fired (that remains an upstream plan-freeze decision,
//! already reflected by the provider's presence in the `FrozenPlan`) — it
//! supplies the fixed, lens-specific planning metadata (question, scoped
//! excerpt mode, report schema, model tier, verify-pass/skeptic
//! requirement, ponytail tag set, and cue list) that `build_invocation`
//! folds into the packet sent to the reasoning host, so every lens receives
//! the same packet shape the skill contract defines.
//!
//! Ownership note: this module covers every `REASONING_PROVIDER_IDS` entry
//! except `legacy.security.adjudication`, which is planned and executed by
//! `security_adjudication.rs`.

use serde_json::{json, Value};

/// How a lens's file excerpts must be scoped when built into its packet.
///
/// Raw excerpts carry exact tokens (needed by lenses that judge exact
/// logic/contracts/bodies). Skeleton excerpts are tree-sitter-skeletonized
/// (shape only) for lenses that reason about structure/survey, per
/// `lens-routing.md`'s "Excerpt compression" section.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExcerptMode {
    Raw,
    Skeleton,
}

use serde::Serialize;

/// Model tier routing, per `lens-routing.md`'s "Model routing" section:
/// lenses that need raw logic/exact contracts/failure-mode evidence get the
/// judgment tier; scoped-evidence lenses get the mechanical tier. Lens
/// category never upgrades the tier beyond what the lens itself requires.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelTier {
    Judgment,
    Mechanical,
}

/// A conditional lens's activation trigger, recorded as data so the packet
/// carries the same "trigger evidence, not judgment" discipline the skill
/// requires (`manual.md`: "Record the trigger evidence ... when it does NOT
/// run, its absence ... must be provably not-applicable").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applicability {
    /// Runs on every applicable diff/target; no separate trigger check.
    Always,
    /// Runs only when the named deterministic trigger fires. The trigger
    /// description is carried in the packet; `plan.rs` decides firing at
    /// plan-freeze by calling `reasoning::triggers::evaluate_trigger` over
    /// the frozen inventory before a conditional-lens provider is included,
    /// consistent with the "conditional lenses spawn only when their
    /// trigger fires" rule.
    Conditional(&'static str),
}

impl Applicability {
    fn to_json(self) -> Value {
        match self {
            Applicability::Always => json!({ "kind": "always" }),
            Applicability::Conditional(trigger) => json!({
                "kind": "conditional",
                "trigger": trigger,
            }),
        }
    }
}

/// The fixed planning packet for one lens, mirroring the JS/skill contract's
/// per-lens input: lens question, applicability, excerpt scoping, report
/// schema, model tier, correctness verify-pass requirement, and cues.
#[derive(Clone, Debug)]
pub struct LensPlan {
    /// Lens id, matching the `reasoning.<lens>` / `legacy.security.<lens>`
    /// suffix (e.g. `"minimize"`, `"variant-analysis"`).
    pub lens: &'static str,
    pub question: &'static str,
    pub applicability: Applicability,
    pub excerpt_mode: ExcerptMode,
    /// Short machine-readable report schema id; the full schema lives in
    /// `SKILL.md` per `lens-routing.md`'s input contract — this field names
    /// which one the host must render findings against.
    pub report_schema: &'static str,
    pub model_tier: ModelTier,
    /// True for `correctness` (and any lens layering on it): every finding
    /// must survive a deterministic reproduction or an adversarial skeptic
    /// pass before it renders, per "Correctness verify-pass".
    pub requires_verify_pass: bool,
    /// Non-empty only for `minimize`: the five ponytail tags from
    /// `ponytail-lens.md`.
    pub ponytail_tags: &'static [&'static str],
    /// High-signal heuristics from `lens-cues.md` that apply to this lens.
    pub cues: &'static [&'static str],
}

impl LensPlan {
    pub fn to_packet_value(&self) -> Value {
        json!({
            "lens": self.lens,
            "question": self.question,
            "applicability": self.applicability.to_json(),
            "excerptMode": self.excerpt_mode,
            "reportSchema": self.report_schema,
            "modelTier": self.model_tier,
            "requiresVerifyPass": self.requires_verify_pass,
            "ponytailTags": self.ponytail_tags,
            "cues": self.cues,
        })
    }
}

const MINIMIZE_TAGS: &[&str] = &["delete", "stdlib", "native", "yagni", "shrink"];

const AI_SLOP_CUES: &[&str] = &[
    "swallowed exceptions (catch only to log + continue)",
    "functions with >3 boolean args",
    "single-implementation interfaces that only forward",
    "comments that restate the code",
    "identical comment blocks repeated across files (LLM copy-paste tell)",
    "commented-out code blocks",
    "comment-to-code ratio >0.6 over a body",
    "generic-name clusters (handleData/processItem)",
    "hallucinated API (method call with no matching symbol-table entry)",
    "training-distribution rewrites of stdlib (O(n^2) sort, manual unique, hand-rolled reverse)",
    "style drift >2 sigma from the repo baseline",
    "try/catch around every call against a codebase that does not work that way",
    "meta-commentary left in source (\"let me...\", \"this will...\")",
];

const MINIMIZE_CUES: &[&str] = &[
    "tool sprawl: two deps doing the same job, or conflicting versions of a core lib",
    "debt_markers.meta: ponytail: shortcuts with no upgrade trigger and TODO/FIXME density",
];

const ARCHITECTURE_CUES: &[&str] = &[
    "stack suitability: is the tech overkill/misfit for the domain?",
    "negative_space.missing list: absent tests / CI / lockfile / LICENSE are real findings",
];

const DOC_DRIFT_CUES: &[&str] = &[
    "compare doc/JSDoc/docstring params against the actual signature",
    "flag empty docstrings that only restate the name",
    "check README setup commands/env vars still exist",
    "plan-implementation drift: symbols named in docs/plans with zero code hits",
    "commit-claim drift: a fix commit claiming X covers only some of the implicated paths",
    "business-constant consistency: propagated values diverge across code/tests/docs/config",
];

const CORRECTNESS_CUES: &[&str] = &[
    "business-constant consistency: propagated values diverge across code/tests/docs/config",
    "desktop/Tauri: Mutex::lock().unwrap() in async, locks held across .await/transactions, sync #[tauri::command] doing I/O, missing spawn_blocking, sequential await invoke() chains, event->full-refetch storms",
];

const PERFORMANCE_CUES: &[&str] = &[
    "desktop/Tauri IPC-waterfall and lock-discipline cues (desktop-tauri-checklist.md 1-2)",
    "embedded-DB (SQLite/SQLCipher) posture per sqlite-local-first.md when present in deps",
    "React re-render hazards: unmemoized Context value, inline object/array/arrow props, component defined inside render, key={index}, unvirtualized lists",
    "full-stack: N+1 / missing indexes / full-table loads / no pooling, network waterfalls, caching strategy, bundle/assets, blocking I/O, Core Web Vitals",
];

const SECURITY_CUES: &[&str] = &[
    "desktop: env-var escape hatches without #[cfg(debug_assertions)], prod CSP with dev origins, contract_mirror uncalled-handler surface, tauri_capabilities broad-grant flags + exposed-command count",
    "positive assurance: answer a fixed question set with grep evidence (TLS/cert bypass, secret-to-log, mutating routes without auth/validation)",
    "invariant falsification: test the app's own stated security invariants against the command/IPC/network surface",
    "app-level taxonomy: authn, authz/IDOR, injection classes, XSS/CSP, CSRF/CORS, SSRF, crypto, uploads, API hardening",
    "debt_markers.meta: ponytail: shortcuts with no upgrade trigger",
];

const DATA_SAFETY_CUES: &[&str] = &[
    "embedded-DB (SQLite/SQLCipher) posture per sqlite-local-first.md when present in deps",
    "observability: silent catch blocks with no log AND no telemetry",
    "PII/secrets leaking into log or telemetry payloads (full request bodies, tokens, emails)",
];

const RESILIENCE_CUES: &[&str] = &[
    "desktop/Tauri concurrency + IPC-waterfall cues (desktop-tauri-checklist.md 1-2)",
    "observability: silent catch blocks with no log AND no telemetry, no crash reporter on production entry points",
];

const NEGATIVE_SPACE_CUES: &[&str] = &[
    "tests asserting source-code substrings or snapshot-only are FALSE coverage",
    "meta.test_skew: heavy code-vs-test skew on a critical subtree",
    "meta.unsafe_sites clusters with no error-path test",
];

fn lens_plan_for(lens: &str) -> Option<LensPlan> {
    Some(match lens {
        "doc-drift" => LensPlan {
            lens: "doc-drift",
            question: "Where has documentation (README/CLAUDE.md/JSDoc/docstrings/plans) drifted from the actual code, and does any shipped claim disprove the code?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.doc-drift.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: DOC_DRIFT_CUES,
        },
        "architecture" => LensPlan {
            lens: "architecture",
            question: "Is the implementation's decomposition the right shape for its responsibilities, and does every runtime candidate resolve to not-needed/confirmed/undetermined with evidence?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Skeleton,
            report_schema: "audit.lens.architecture.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: ARCHITECTURE_CUES,
        },
        "correctness" => LensPlan {
            lens: "correctness",
            question: "Does the changed/oversized/entrypoint code contain real logic bugs: unhandled errors/rejections, swallowed failures, edge cases, off-by-one, races/missing await, resource leaks, incorrect conditionals?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.correctness.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: true,
            ponytail_tags: &[],
            cues: CORRECTNESS_CUES,
        },
        "ai-slop" => LensPlan {
            lens: "ai-slop",
            question: "Where does this code carry LLM-fingerprint smells (duplication, dead exports, generic names, hallucinated APIs, style drift, meta-commentary), and would a competent human plausibly have written it this way on purpose?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Skeleton,
            report_schema: "audit.lens.ai-slop.v1",
            model_tier: ModelTier::Mechanical,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: AI_SLOP_CUES,
        },
        "naming" => LensPlan {
            lens: "naming",
            question: "Does any identifier, file, or symbol name mislead about what it does, collide in meaning, or fail the repo's naming conventions?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Skeleton,
            report_schema: "audit.lens.naming.v1",
            model_tier: ModelTier::Mechanical,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: &[],
        },
        "dead-file" => LensPlan {
            lens: "dead-file",
            question: "Which files/exports are orphaned (no route/UI/CLI/API/schema/test/documented behavior reaches them), citing a knip locus or marking inferred?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Skeleton,
            report_schema: "audit.lens.dead-file.v1",
            model_tier: ModelTier::Mechanical,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: &[],
        },
        "schema" => LensPlan {
            lens: "schema",
            question: "Do type/serialization contracts (tsc/mypy errors, serialization sites) match their actual data shapes, and where has schema/contract drift crept in?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.schema.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: &[],
        },
        "security" => LensPlan {
            lens: "security",
            question: "Beyond the scanners, does the application logic contain authn/authz/IDOR, injection, XSS/CSP, CSRF/CORS, SSRF, crypto, upload, or API-hardening defects, and do the app's own stated security invariants hold against its command/IPC/network surface?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.security.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: SECURITY_CUES,
        },
        "minimize" => LensPlan {
            lens: "minimize",
            question: "Where is this codebase over-engineered: dead/not-wired code, hand-rolled stdlib/native equivalents, one-impl abstractions (yagni), or logic expressible in materially fewer lines (shrink, including mechanical include-splits)?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.minimize.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: false,
            ponytail_tags: MINIMIZE_TAGS,
            cues: MINIMIZE_CUES,
        },
        "performance" => LensPlan {
            lens: "performance",
            question: "Does the static code carry a performance-hazard smell (re-render, N+1, missing index, blocking I/O, waterfall, bundle bloat), and does any runtime.json evidence confirm a measured regression?",
            applicability: Applicability::Always,
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.performance.v1",
            model_tier: ModelTier::Mechanical,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: PERFORMANCE_CUES,
        },
        "a11y" => LensPlan {
            lens: "a11y",
            question: "Does the UI surface fail semantic accessibility: missing labels/alt, ARIA misuse, focus order/keyboard traps, non-semantic interactive elements, or contrast-as-policy violations?",
            applicability: Applicability::Conditional("UI target present (JSX/HTML/templates in scope)"),
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.a11y.v1",
            model_tier: ModelTier::Mechanical,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: &[],
        },
        "data-safety" => LensPlan {
            lens: "data-safety",
            question: "Do migrations/SQL/ORM ops risk irreversible data loss or unsafe locking, and does client storage or telemetry leak PII or persist secrets unencrypted at rest?",
            applicability: Applicability::Conditional("migration, SQL, payment/state-machine seam, client-side storage, or telemetry in scope"),
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.data-safety.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: DATA_SAFETY_CUES,
        },
        "resilience" => LensPlan {
            lens: "resilience",
            question: "Can this app/daemon target recover from sidecar/child death or hang, corrupt-file or offline states, and is a field failure diagnosable post-hoc from persisted structured logs?",
            applicability: Applicability::Conditional("sidecar/child-process/server/queue code present"),
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.resilience.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: RESILIENCE_CUES,
        },
        "platform-parity" => LensPlan {
            lens: "platform-parity",
            question: "Does every per-OS branch cover every shipped OS with real behavior (not a stub/Empty/unimplemented!/silent Ok(())) behind a cross-platform claim, with matching per-OS CI coverage?",
            applicability: Applicability::Conditional("cfg(target_os or usePlatform present"),
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.platform-parity.v1",
            model_tier: ModelTier::Mechanical,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: &[],
        },
        "release-readiness" => LensPlan {
            lens: "release-readiness",
            question: "Is the release surface (signing, updater, bundle config, third-party attribution, pinned binaries) complete and symmetric across shipped platforms?",
            applicability: Applicability::Conditional("publish/signing/updater scripts or tauri.conf.json bundle config present"),
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.release-readiness.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: &[],
        },
        "variant-analysis" => LensPlan {
            lens: "variant-analysis",
            question: "Given a confirmed security finding's root cause, are there sibling call sites or patterns in this codebase that share the same vulnerable shape?",
            applicability: Applicability::Conditional("a surviving security-adjudication verdict exists for this run"),
            excerpt_mode: ExcerptMode::Raw,
            report_schema: "audit.lens.variant-analysis.v1",
            model_tier: ModelTier::Judgment,
            requires_verify_pass: false,
            ponytail_tags: &[],
            cues: NEGATIVE_SPACE_CUES,
        },
        _ => return None,
    })
}

/// Resolves the lens id this provider plans for, or `None` for providers not
/// owned by this planner (currently only `legacy.security.adjudication`).
pub fn lens_id_for_provider(provider_id: &str) -> Option<&'static str> {
    let lens = provider_id
        .strip_prefix("reasoning.")
        .or_else(|| provider_id.strip_prefix("legacy.security."))?;
    lens_plan_for(lens).map(|plan| plan.lens)
}

/// Whether `provider_id` plans a conditional lens (one that runs only when
/// its deterministic trigger fires, per `Applicability::Conditional`).
/// `plan.rs` calls this at plan-freeze to decide whether the provider needs
/// a trigger check before inclusion; providers this planner does not cover,
/// and `Always`-applicable lens providers, both return `false`.
pub fn is_conditional_lens_provider(provider_id: &str) -> bool {
    let Some(lens) = provider_id
        .strip_prefix("reasoning.")
        .or_else(|| provider_id.strip_prefix("legacy.security."))
    else {
        return false;
    };
    matches!(
        lens_plan_for(lens).map(|plan| plan.applicability),
        Some(Applicability::Conditional(_))
    )
}

/// Builds the lens plan value to fold into a reasoning packet for
/// `provider_id`, or `None` when this provider is not one this planner
/// covers (the adjudication provider is planned by `security_adjudication.rs`).
pub fn lens_plan_packet_value(provider_id: &str) -> Option<Value> {
    let lens = provider_id
        .strip_prefix("reasoning.")
        .or_else(|| provider_id.strip_prefix("legacy.security."))?;
    lens_plan_for(lens).map(|plan| plan.to_packet_value())
}

/// Resolves the excerpt mode (`Raw`/`Skeleton`) a provider's lens requires,
/// for callers (`build_invocation`) that need to build the actual scoped
/// excerpts rather than only the packet's planning metadata.
pub fn lens_plan_excerpt_mode(provider_id: &str) -> Option<ExcerptMode> {
    let lens = provider_id
        .strip_prefix("reasoning.")
        .or_else(|| provider_id.strip_prefix("legacy.security."))?;
    lens_plan_for(lens).map(|plan| plan.excerpt_mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_providers::reasoning::REASONING_PROVIDER_IDS;

    #[test]
    fn every_non_adjudication_provider_has_a_lens_plan() {
        for id in REASONING_PROVIDER_IDS {
            if id == "legacy.security.adjudication" {
                assert!(
                    lens_plan_packet_value(id).is_none(),
                    "adjudication provider must not be planned here"
                );
                continue;
            }
            assert!(
                lens_plan_packet_value(id).is_some(),
                "missing lens plan for provider {id}"
            );
        }
    }

    #[test]
    fn minimize_carries_all_five_ponytail_tags() {
        let plan = lens_plan_for("minimize").expect("minimize plan");
        assert_eq!(plan.ponytail_tags, MINIMIZE_TAGS);
        assert_eq!(plan.excerpt_mode, ExcerptMode::Raw);
    }

    #[test]
    fn correctness_requires_verify_pass() {
        let plan = lens_plan_for("correctness").expect("correctness plan");
        assert!(plan.requires_verify_pass);
    }

    #[test]
    fn structure_lenses_use_skeleton_excerpts() {
        for lens in ["architecture", "ai-slop", "naming", "dead-file"] {
            let plan = lens_plan_for(lens).expect("plan");
            assert_eq!(plan.excerpt_mode, ExcerptMode::Skeleton, "{lens}");
        }
    }

    #[test]
    fn raw_lenses_use_raw_excerpts() {
        for lens in ["schema", "correctness", "performance", "minimize", "security"] {
            let plan = lens_plan_for(lens).expect("plan");
            assert_eq!(plan.excerpt_mode, ExcerptMode::Raw, "{lens}");
        }
    }

    #[test]
    fn conditional_lenses_carry_trigger_text() {
        for lens in ["a11y", "data-safety", "resilience", "platform-parity", "release-readiness"] {
            let plan = lens_plan_for(lens).expect("plan");
            match plan.applicability {
                Applicability::Conditional(trigger) => assert!(!trigger.is_empty(), "{lens}"),
                Applicability::Always => panic!("{lens} should be conditional"),
            }
        }
    }

    #[test]
    fn packet_value_is_object_with_expected_keys() {
        let value = lens_plan_packet_value("reasoning.minimize").expect("packet value");
        let obj = value.as_object().expect("object");
        for key in [
            "lens",
            "question",
            "applicability",
            "excerptMode",
            "reportSchema",
            "modelTier",
            "requiresVerifyPass",
            "ponytailTags",
            "cues",
        ] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
    }
}
