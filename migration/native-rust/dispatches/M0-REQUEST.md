# Native Rust Migration M0 Dispatch Request

## User requirements

- Turn accepted Legion Product Architecture v2 and Migration Plan v2 into a bounded implementation plan.
- Keep implementation minimal; do not overengineer.
- Each planned changed file belongs to one lane for its complete end-to-end change. No later lane or integrator edits that file.
- Group every currently independent lane into earliest dependency wave so each wave runs at maximum safe parallelism.
- Give every lane an exact repository-relative file allowlist.
- Before execution, obtain fresh adversarial Oracle review for allowlist completeness, lane disjointness, dependency necessity, earliest-wave placement, maximum safe parallelism, and end-to-end lane closure.

## Boundaries

- Execute M0 only: rebaseline current source, freeze target contracts, and compile exact M1–M8 implementation dispatch packet from verified M0 outputs.
- Do not implement Rust product runtime in this packet.
- Do not modify Membrane.
- Do not run Cargo; M0 is source inspection and contract generation.
- Do not guess downstream file ownership. M1–M8 packet must derive exact file allowlists from refreshed inventories and frozen ownership map.
- Blueprint is optional context. Its absence cannot stop M0 or future Audit work; record typed coverage degradation where relevant.
- Preserve development-only Node/Python tests and build tools. Classify only shipped Legion runtime product paths for migration or deletion.
- No lane commits or pushes. One integration owner verifies, stages, commits, and pushes without editing lane-owned files.

## Accepted authority

- `migration/native-rust/PRODUCT-ARCHITECTURE-V2.md`
- `migration/native-rust/MIGRATION-PLAN-V2.md`
- `docs/LEGION-CANONICAL-SSOT.md`
- `migration/native-rust/README.md`

## Required result

M0 ends with current-baseline inventories, frozen contracts, exact ownership map, M0 acceptance result, and validator-clean M1–M8 direct dispatch packet plus receipt ready for its own fresh adversarial Oracle review.
