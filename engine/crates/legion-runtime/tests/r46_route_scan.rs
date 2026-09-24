//! Integration tests for packet r46
//! (`src/lib/dispatch-validator/validate-dispatch.py::managed_rust_route_errors`).
//!
//! **Wiring note**: this test file (and the module it exercises,
//! `legion_runtime::wf_port::r46`) will not compile until
//! `engine/crates/legion-runtime/src/wf_port/mod.rs` adds `pub mod r46;`
//! alongside its existing `pub mod w2_044;` / `pub mod w2_045;` lines —
//! packet r46's brief forbids editing that file directly, so this is left
//! for the integration step that wires new `wf_port` chunks together. See
//! the packet r46 report for the exact one-line diff needed.

use legion_runtime::wf_port::r46::managed_rust_route_errors;

#[test]
fn direct_cargo_invocation_outside_rightkit_is_rejected() {
    let text = "\
## 5. Execution Procedure

```bash
cargo test --workspace
```
";
    let errors = managed_rust_route_errors(text, None, None);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("fenced block 1"));
    assert!(errors[0].contains("direct cargo invocation must use rightkit cargo"));
}

#[test]
fn rightkit_wrapped_cargo_is_accepted() {
    let text = "\
```bash
rightkit build cargo test --workspace
```
";
    let errors = managed_rust_route_errors(text, None, None);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn repeated_tool_within_one_source_is_reported_once() {
    // Two `cargo` mentions inside the SAME fenced block dedupe to one
    // error keyed on (source, tool); a `cargo` mention in a later, distinct
    // fenced block is a different source and reports separately.
    let text = "\
```bash
cargo build && cargo test
```

```bash
cargo check
```
";
    let errors = managed_rust_route_errors(text, None, None);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors.iter().any(|e| e.contains("fenced block 1")));
    assert!(errors.iter().any(|e| e.contains("fenced block 2")));
}
