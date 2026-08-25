# Native Rust Migration M1–M8 Direct Dispatch Request

## Objective

Implement the accepted native-Rust product migration in exact waves derived from the immutable M0 contract freeze and file-ownership map. Each lane owns every file in its allowlist for its complete end-to-end change. No integration owner, later cleanup lane, or peer lane may edit a lane-owned path.

## Accepted authority

- `migration/native-rust/PRODUCT-ARCHITECTURE-V2.md`
- `migration/native-rust/MIGRATION-PLAN-V2.md`
- `migration/native-rust/dispatches/M0-REQUEST.md`
- `migration/native-rust/m0/contract-freeze.json` at its content-addressed source revision
- `migration/native-rust/m0/m0-acceptance.json` at its recorded PASS
- `migration/native-rust/m0/file-ownership-map.json` at its frozen ownership projection

## Required execution contract

- Start only after a fresh adversarial Oracle review passes the direct packet's allowlist completeness, lane disjointness, dependency validity, maximum safe parallelization, and end-to-end lane closure.
- Use the direct packet's exact repository-relative allowlists. A file cannot be added, removed, moved to another lane, or edited by an integrator without a new M0 ownership freeze and a newly validated/reviewed packet.
- Run all currently eligible lanes in the earliest declared wave. There are no worker-to-worker dependencies; cross-lane ordering is represented only by completed dispatch waves.
- Preserve Membrane; no lane may modify its source.
- Retain classified Node/Python development tools. Delete only the M7 preclassified deletion candidates after M6 qualification succeeds.
- M1–M8 executors may use only RightKit-routed Rust tool commands when a Rust build/test/documentation command is authorized by their lane. M0 did not authorize Cargo.
- One integration owner verifies, stages, commits, pushes, and deploys only after lane completion and fresh Oracle PASS. The integration owner does not edit lane-owned implementation paths.

## Frozen source and acceptance facts

- M0 baseline commit: `396f427009ade1a4243188c7da75ff335efe9e82`.
- M0 acceptance: `PASS`; zero unknown runtime paths, owner collisions, unresolved decisions, and Blueprint global gate.
- M0 freeze source: `migration/native-rust/m0/contract-freeze.json`; downstream packet `sourceRevision` must equal the SHA-256 of these exact bytes.
- Frozen ownership proves a closed, disjoint M1–M8 union. Its selectors resolve 903 legacy runtime/deletion paths, 161 native product engine paths, 38 reconciled non-product engine paths, and 18 new planned paths.

## Packet and receipt

- Direct packet: `migration/native-rust/dispatches/M1-M8-DISPATCH.json`
- Adjacent receipt: `migration/native-rust/dispatches/M1-M8-DISPATCH.receipt.json`
- Validator: `python3 skills/dispatch/scripts/validate-dispatch.py migration/native-rust/dispatches/M1-M8-DISPATCH.json --packet-type authority --write-receipt migration/native-rust/dispatches/M1-M8-DISPATCH.receipt.json`

## Required result

The result is a validated direct packet and adjacent receipt, ready for—not substituted for—a fresh adversarial Oracle PASS before M1 execution.
