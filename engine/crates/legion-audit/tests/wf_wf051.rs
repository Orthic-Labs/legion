//! wf051 verification record.
//!
//! Source files (JS legacy spec, not deleted):
//!   - src/providers/runtime/web/third-party/index.mjs (`verifyThirdPartyExercise`)
//!   - src/providers/runtime/worker/index.mjs (`SERVICE_RUNTIME_SCENARIOS`)
//!
//! Both are already ported natively:
//!   - `verifyThirdPartyExercise` -> `legion_audit::native_providers::p10_runtime::external::verify_third_party_exercise`
//!     (engine/crates/legion-audit/src/native_providers/p10_runtime/external.rs), with an explicit
//!     "Port of `web/third-party/index.mjs`" doc comment and a documented, intentional divergence:
//!     `signed_not_applicable` always fails closed (`valid` forced to `false`) because real signature
//!     verification is not available in this evidence path, whereas the JS attempts `node:crypto`
//!     `verify()`. This is a safety-conservative divergence (never trusts an unproven signature), not a
//!     behavioral bug, and is called out in this file's own comments.
//!   - `SERVICE_RUNTIME_SCENARIOS` -> ported in at least two places:
//!       - `legion_audit::native_providers::p10_runtime::desktop::SERVICE_RUNTIME_SCENARIOS`
//!       - `legion_audit::native_providers::p10_runtime::browser_service::SERVICE_RUNTIME_SCENARIOS`
//!     both carry the same 17 scenario ids in the same order as the JS array, and
//!     `tests/p10_desktop.rs` already asserts `SERVICE_RUNTIME_SCENARIOS.len() == 17` plus spot-checks
//!     for `"api-contract"` and `"observability"`.
//!
//! No new Rust logic was ported for wf051: both files are ALREADY-NATIVE-VERIFIED. This test exists to
//! record that verification and to pin the scenario list's length/order so a future edit to either
//! wired native copy is caught here too.
//!
//! The unwired `wf_port::wf047` copy of this list was retired with its module.

#[test]
fn wf051_service_runtime_scenarios_agree_across_native_copies() {
    let desktop = legion_audit::native_providers::p10_runtime::desktop::SERVICE_RUNTIME_SCENARIOS;
    let browser =
        legion_audit::native_providers::p10_runtime::browser_service::SERVICE_RUNTIME_SCENARIOS;

    let expected: &[&str] = &[
        "api-contract",
        "identity-authorization",
        "data-effect",
        "timeout-retry",
        "idempotency",
        "rate-cost-limit",
        "queue-ordering",
        "queue-duplicate",
        "poison-message",
        "backpressure",
        "worker-restart",
        "graceful-shutdown",
        "health-readiness",
        "migration",
        "capacity",
        "fault-recovery",
        "observability",
    ];

    assert_eq!(desktop, expected);
    assert_eq!(browser.as_slice(), expected);
}
