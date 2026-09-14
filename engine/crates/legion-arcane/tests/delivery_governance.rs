use legion_arcane::{
    DeliveryGovernanceDispatcher, admit_capacity, dispatch_delivery_governance,
};
use serde_json::json;

#[test]
fn dispatch_capacity_admits_to_narrowest_constraint() {
    let result = admit_capacity(&json!({
        "readyTasks": ["a", "b"],
        "constraints": [{ "name": "lane", "capacity": 1 }],
    }));
    assert_eq!(result["outcome"], "CAPACITY_ADMITTED");
    assert_eq!(result["admitted"], json!(["a"]));
}

#[test]
fn delivery_governance_marks_untrusted_cutover_as_diagnostic() {
    let dispatcher = DeliveryGovernanceDispatcher::new();
    let cutover = dispatcher.dispatch(&json!({
        "operation": "migration-cutover",
        "input": {
            "plan": {
                "mode": "HARD_CUT",
                "hard_cut": {
                    "absence_checks": {
                        "imports": [],
                        "routes": [],
                        "runtime_registrations": [],
                        "configuration_keys": [],
                        "dependencies": [],
                        "tests": [],
                        "documentation": [],
                        "emitted_protocol_variants": []
                    }
                }
            },
            "observations": {
                "absence": {
                    "imports": [],
                    "routes": [],
                    "runtime_registrations": [],
                    "configuration_keys": [],
                    "dependencies": [],
                    "tests": [],
                    "documentation": [],
                    "emitted_protocol_variants": []
                }
            }
        }
    }));
    assert_eq!(cutover["code"], "ARC_DIAGNOSTIC_ONLY");
    assert_eq!(cutover["consumable"], false);
}

#[test]
fn unknown_delivery_operation_is_denied() {
    let result = dispatch_delivery_governance(&json!({
        "operation": "unknown",
        "input": {},
    }));
    assert_eq!(result["code"], "ARC_OPERATION_UNKNOWN");
}
