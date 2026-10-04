# Swift Testing Xcode workflows and evidence

Use Xcode’s test navigator to run a function, suite, tag, or one failing parameterized argument.
Group by tag to inspect cross-suite behavior. Stable tags are preferable to fragile test-name
patterns for local loops and CI plans.

Configure test plans with intentional include/exclude semantics (`any` versus `all` tags) and
separate fast core, integration, slower/optional, and release-gate coverage. Example tags include
`core`, `integration`, `regression`, and temporary `flaky`; use project vocabulary when one exists.

For report triage, check whether failures cluster by tag, bug, or destination, inspect one
representative failure, distinguish dependency/outage/configuration from test-local defects, and
remove temporary known-issue annotations after fixing root cause. Keep expectations narrow and
argument/type descriptions readable.

Record actual target, scheme, test plan, simulator/device model, OS, SDK, build/test exit status,
and result bundle when available. A compile-only result is not an executed test pass. Screenshots
support visual evidence but do not prove persistence, accessibility contracts, data writes, or
correct runtime state. Simulators cannot prove hardware, permissions, keychain, push, background,
performance, or distribution behavior; name those missing checks. Preserve existing XCTest/UI
runtime evidence, accessibility identifiers, interruption/re-entry paths, and data isolation.
