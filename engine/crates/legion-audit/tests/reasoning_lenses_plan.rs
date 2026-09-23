//! Integration coverage for per-lens work-packet planning
//! (`native_providers::reasoning::lens_plan`), exercised from outside the
//! crate against the production entry point: `lens_plan_packet_value`, the
//! same function `build_invocation` calls to fold a lens's planning packet
//! into every reasoning-provider invocation.

use legion_audit::native_providers::reasoning::lens_plan::lens_plan_packet_value;
use legion_audit::native_providers::reasoning::REASONING_PROVIDER_IDS;

#[test]
fn every_provider_except_adjudication_gets_a_lens_plan() {
    for id in REASONING_PROVIDER_IDS {
        let value = lens_plan_packet_value(id);
        if id == "legacy.security.adjudication" {
            assert!(
                value.is_none(),
                "adjudication provider must not receive a lens_plan packet (owned by security_adjudication.rs)"
            );
        } else {
            assert!(value.is_some(), "expected a lens plan for provider {id}");
        }
    }
}

#[test]
fn conditional_lenses_carry_their_trigger_in_the_packet() {
    let conditional = [
        ("reasoning.a11y", "UI target"),
        ("reasoning.data-safety", "migration"),
        ("reasoning.resilience", "sidecar"),
        ("reasoning.platform-parity", "cfg(target_os"),
        ("reasoning.release-readiness", "publish/signing"),
    ];
    for (id, needle) in conditional {
        let value = lens_plan_packet_value(id).expect("lens plan present");
        let applicability = &value["applicability"];
        assert_eq!(applicability["kind"], "conditional", "{id}");
        let trigger = applicability["trigger"]
            .as_str()
            .unwrap_or_else(|| panic!("{id} missing trigger text"));
        assert!(
            trigger.contains(needle),
            "{id} trigger {trigger:?} did not mention {needle:?}"
        );
    }
}

#[test]
fn always_on_lenses_are_not_conditional() {
    for id in [
        "reasoning.doc-drift",
        "reasoning.architecture",
        "reasoning.correctness",
        "reasoning.ai-slop",
        "reasoning.naming",
        "reasoning.dead-file",
        "reasoning.schema",
        "reasoning.security",
        "reasoning.minimize",
        "reasoning.performance",
    ] {
        let value = lens_plan_packet_value(id).expect("lens plan present");
        assert_eq!(value["applicability"]["kind"], "always", "{id}");
    }
}

#[test]
fn structure_lenses_get_skeleton_excerpts_and_raw_lenses_get_raw() {
    for id in [
        "reasoning.architecture",
        "reasoning.ai-slop",
        "reasoning.naming",
        "reasoning.dead-file",
    ] {
        let value = lens_plan_packet_value(id).expect("lens plan present");
        assert_eq!(value["excerptMode"], "skeleton", "{id}");
    }
    for id in [
        "reasoning.schema",
        "reasoning.correctness",
        "reasoning.performance",
        "reasoning.minimize",
        "reasoning.security",
    ] {
        let value = lens_plan_packet_value(id).expect("lens plan present");
        assert_eq!(value["excerptMode"], "raw", "{id}");
    }
}

#[test]
fn minimize_carries_all_five_ponytail_tags_and_raw_excerpts() {
    let value = lens_plan_packet_value("reasoning.minimize").expect("lens plan present");
    let tags: Vec<&str> = value["ponytailTags"]
        .as_array()
        .expect("ponytailTags array")
        .iter()
        .map(|tag| tag.as_str().expect("tag is a string"))
        .collect();
    assert_eq!(tags, vec!["delete", "stdlib", "native", "yagni", "shrink"]);
    assert_eq!(value["excerptMode"], "raw");
}

#[test]
fn correctness_requires_verify_pass_and_others_do_not() {
    let correctness = lens_plan_packet_value("reasoning.correctness").expect("lens plan present");
    assert_eq!(correctness["requiresVerifyPass"], true);

    let naming = lens_plan_packet_value("reasoning.naming").expect("lens plan present");
    assert_eq!(naming["requiresVerifyPass"], false);
}

#[test]
fn variant_analysis_is_planned_here_not_by_adjudication() {
    let value = lens_plan_packet_value("legacy.security.variant-analysis")
        .expect("variant-analysis lens plan present");
    assert_eq!(value["lens"], "variant-analysis");
    assert_eq!(value["applicability"]["kind"], "conditional");
}

#[test]
fn model_tier_never_exceeds_what_the_lens_requires() {
    // Mechanical-tier lenses per lens-routing.md: ai-slop, naming, dead-file,
    // performance, a11y, platform-parity.
    for id in [
        "reasoning.ai-slop",
        "reasoning.naming",
        "reasoning.dead-file",
        "reasoning.performance",
        "reasoning.a11y",
        "reasoning.platform-parity",
    ] {
        let value = lens_plan_packet_value(id).expect("lens plan present");
        assert_eq!(value["modelTier"], "mechanical", "{id}");
    }
    // Judgment-tier lenses: architecture, security, schema, correctness,
    // minimize, doc-drift, data-safety, resilience, release-readiness.
    for id in [
        "reasoning.architecture",
        "reasoning.security",
        "reasoning.schema",
        "reasoning.correctness",
        "reasoning.minimize",
        "reasoning.doc-drift",
        "reasoning.data-safety",
        "reasoning.resilience",
        "reasoning.release-readiness",
    ] {
        let value = lens_plan_packet_value(id).expect("lens plan present");
        assert_eq!(value["modelTier"], "judgment", "{id}");
    }
}
