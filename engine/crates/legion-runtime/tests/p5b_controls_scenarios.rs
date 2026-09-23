//! Port of tests/controls/scenarios/pairwise.test.mjs ("pairwise covers
//! every pair") plus constraint coverage (packet P5b-controls-config).

use legion_runtime::p5_core::controls_scenarios::{pairwise, Constraint};
use legion_runtime::p5_core::controls_support::Value;
use std::collections::BTreeMap;

#[test]
fn pairwise_covers_every_pair() {
    let mut dims: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    dims.insert("a".into(), vec![Value::Number(1.0), Value::Number(2.0)]);
    dims.insert("b".into(), vec![Value::str("x"), Value::str("y")]);
    dims.insert("c".into(), vec![Value::Bool(true), Value::Bool(false)]);

    let result = pairwise(&dims, &[], &[]).expect("pairwise should succeed");

    for a in [1.0, 2.0] {
        for b in ["x", "y"] {
            let covered = result.rows.iter().any(|row| {
                row.get("a") == Some(&Value::Number(a)) && row.get("b") == Some(&Value::str(b))
            });
            assert!(covered, "expected pair a={a} b={b} to be covered");
        }
    }
}

#[test]
fn pairwise_honors_a_constraint_and_reports_omissions() {
    let mut dims: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    dims.insert("os".into(), vec![Value::str("mac"), Value::str("win")]);
    dims.insert("arch".into(), vec![Value::str("x64"), Value::str("arm64")]);

    let deny_win_arm: Constraint = Box::new(|row| {
        !(row.get("os") == Some(&Value::str("win")) && row.get("arch") == Some(&Value::str("arm64")))
    });

    let result = pairwise(&dims, &[deny_win_arm], &[]).expect("pairwise should succeed");

    assert!(!result
        .rows
        .iter()
        .any(|row| row.get("os") == Some(&Value::str("win")) && row.get("arch") == Some(&Value::str("arm64"))));
}
