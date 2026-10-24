# Root integration assignment

Implement this folder's architecture in existing Legion Audit. Root owns integration, shared paths, execution & final verification. Bounded workers own only their packet allowlists.

## Preflight & sequencing

1. Read current repository/workspace AGENTS, canonical ownership rules, this architecture & packet index. Confirm primary checkout, HEAD & dirty paths. Baseline inspected: `3b72295cccbfcb6633a67dc8cd06d419a646b299`; preserve untracked `vendor/`. If source advanced, inspect affected interfaces before applying this map.
2. Reconcile installed capability inventory against pinned dependencies. A01 must establish real Guard/RustRight/RightKit integration: local source or declaration-only metadata cannot prove installed behavior. Missing owner functionality becomes an exact upstream prerequisite, never permission bypass.
3. Before any local build/check/test, inspect managed RightKit build inventory once, including previous 30 minutes, under current AGENTS. Queued/running/recent work or unavailable inventory routes verification to CI. Existing local-build grant does not override this rule. Do not poll for capacity.
4. Freeze minimal shared types below, provider IDs & signature sketches; send only relevant snippets to workers. Ready independent work may proceed concurrently using `fork_turns: "none"`. No worker runs checks. Root may edit unowned integration paths during coding; no overlapping worker writes.
5. Integrate all source & fixture edits, then run one coordinated verification batch per repository/host. New repairs justify focused rechecks; do not repeat successful broad checks without cause.
6. Use independent Oracle for source assurance of implementation/evidence claims. Oracle reads actual diff/results & raw user constraints, never implements or reruns tests. Resolve outcome/safety defects before marking implemented.

Dependencies describe interfaces, not permission to wait indefinitely for runtime qualification. Missing execution owner can coexist with parser/planner implementation, but execution qualification remains unmet.

## Shared interface freeze

Use existing Rust types; names below are proposed new audit-local types, not assertions about current APIs.

| Producer | Interface to agree before dependent dispatch |
|---|---|
| A01 | Admission constructor behind existing `PolicyAuthorizer`; `PlatformProcess` owner adapter; explicit unsupported/denied outcomes. No grant minted by Audit config. |
| A02 | `AssurancePlan`, `ObligationId`, `ObligationResult`, `QualificationScope`, `RuntimeConstraint`, `AssuranceSummary`; versioned `auditAssuranceV1` serialization. |
| A03 | `ArtifactEnvelope` parser + verifier receiving frozen expectations & trusted host verifier; returns validated evidence reference or typed rejection. |
| A08 | `DependencyInventory` + graph/source/metadata digests; unsupported formats & freshness explicit. |
| A12 | `DomainContractSet` + authoritative term mappings, version/digests & unresolved boundaries. |
| A14 | Canonical byte-range/source-digest anchor helper + existing ReportV2 projection; model text never supplies trusted location. |
| A15 | Pure finding-context reconciliation over existing reports/store; verified resolution evidence separate from user dismissal. |
| A16 | Runtime/target obligation builders consuming A02/A03 types; performance comparison keyed by workload/device/environment. |
| A17 | Existing review packet/budget ledger receives frozen contracts, anchors & obligations; no second scheduler. |

Prevent circular crate dependencies: `legion-audit` already depends on `legion-report`. Report renderers consume existing report JSON/extensions or shared contract types; never import audit-local types into `legion-report`. Promote only genuinely shared serialization types into `legion-contracts`, with root-owned exports.

Obligation identity includes product/repository set, target/variant, concern, evidence kind & policy/rule revisions. Result state separates execution from findings. “Satisfied with findings” is not “clean.” Aggregate output contains completion, finding policy outcome & release eligibility independently.

Product-declared requirements may add scope; they cannot remove host/profile minimum requirements. Applicability must be checked against frozen inventory. Missing target files, unsupported format or an omitted required provider cannot manufacture inapplicability. Explicit waiver requires authority, exact scope, reason & expiry; it changes policy disposition, never executed coverage.

## Shared files — root ownership

All paths relative to Legion checkout. Worker-owned files remain untouched until that worker returns.

| Paths | Required integration |
|---|---|
| `engine/crates/legion-audit/src/lib.rs`; relevant `native_providers/{mod,code/mod,architecture/mod,security/mod}.rs`; `legion-{contracts,effects,report}/src/lib.rs` | Export/register new modules, preserve crate direction, attach constructors. |
| `engine/crates/legion-audit/src/{plan,execution,report,verify}.rs` | Freeze obligation/contract/import expectations in plan bounds before signing. Validate result coverage against frozen denominator & target; retain gaps in every renderer. Claims cannot override missing evidence. |
| `engine/crates/legion-audit/src/{snapshot,scope,source_cache,graph_context}.rs` | Bind repository-set snapshots & contextual evidence. Preserve authenticated completed history, unknown graph edges & existing source-scope behavior. |
| `engine/crates/legion-audit/src/p12_pipeline/{mod,store}.rs` | Reuse existing `FindingStore` / lifecycle / stable IDs. Add evidence-backed assurance disposition without silently rewriting old resolved/dismissed records as verified-fixed. No second finding ledger. |
| `src/registry/providers.json`; `engine/crates/legion-audit/src/wf_port/wf010/{registry,provider_registry}.rs` | Extend canonical registry & projections, selectors, dependencies, configuration, qualification scope & honest clean-claim text. |
| `engine/crates/legion-audit/src/native_providers/code/{tools,evidence}.rs`; `native_providers/legacy_checks/{mod,registry,resolver,parsers}.rs` | Wire new tools/parsers through existing SDK/result normalization; keep project execution vs file-only scans distinct. Existing code.jvm remains separate. |
| `engine/crates/legion-audit/src/native_providers/security/producer.rs` | Route authenticated evidence through A03; preserve self-attested label for ordinary local SARIF. Reuse existing OSV/Squawk/security providers. |
| `engine/crates/legion-audit/src/native_providers/reasoning/{coverage_plan,ingest,lens_plan,lens_schemas,packet_context,triggers,excerpts}.rs`; `review_runtime/{mod,cost,partial,tools}.rs`; `continuation.rs` | Bind platform/domain/target evidence; retain candidate & zero-finding verification; exact shared budget accounting; preserve unknowns during continuation. |
| `engine/crates/legion-report/src/{lib,markdown,html,sarif,ponytail}.rs` | Render assurance, inherited uncertainty, waiver/debt & trend distinctions from existing reports. A14 owns `review.rs` until return. |
| `engine/bins/legion/src/{cli,apple_mcp}.rs`; `commands/{audit,audit_runtime,report}.rs` | Attach admission, profile/import/domain options & reporting; reuse Apple host operations without audit→CLI dependency. Extract shared Apple seam only if actual reuse requires it. |
| `engine/bins/legion-dev/src/main.rs`; `engine/**/Cargo.toml`; `engine/Cargo.lock` | Register A18 command; add only required dependencies/exports/test targets. Lock through admitted Rust toolchain. No speculative owner upgrades. |
| `scripts/ci/audit-*-sdk-inputs.json`; qualification sources under `qualification/provider-accuracy/**`; generated catalogs/schemas/manifests | Add exact scanner/SDK/config pins & observed qualifications. Extend managed CI source through existing owner; do not hand-edit generated workflow projections. |

Where a listed module does not exist at implementation HEAD, use its current canonical parent; record mapping change. No whole-directory ownership is granted to workers by this table.

## Provider & CLI changes

Minimum new distinct capabilities: `code.kotlin.detekt-source`, `code.kotlin.detekt-typed`, `code.android.lint`, explicit Xcode target evidence, native JS/TS lint, structure facts, PostgreSQL/Nginx facts & runtime target obligations. Root chooses remaining IDs once against registry naming; do not create a provider for every reasoning lens.

Existing report selector is **`--report`**, not `--style`:

```text
legion report <report.json> --report review --format markdown
legion report <report.json> --report review --format github-review --out <review.json>
legion report <report.json> --report ponytail --format markdown
```

Target additions (not existing commands):
- Preserve legacy `audit --profile standard`; add `pre-pr`, `repository`, `release`.
- Add `--runtime-policy no-node-python`, `--product-contract <json>` & repeatable `--artifact-manifest <json>`. Native-only constraint is frozen into new profiles; imports disclose upstream runtime.
- Extend `report --report assurance|trend|debt --format json|markdown` as projections over saved reports/store.
- Add thin `audit gate --run <dir>`: validate frozen run + requirements, report structured `eligible|blocked-findings|incomplete` with reasons. CLI adapter maps these to established exit-code conventions; no second policy engine or new scan.
- Register `legion-dev check-audit-assurance` for native A18 record validation; reuse existing benchmark runner for actual model observations.
- Reuse `audit findings` lifecycle routes & existing source scopes / since-last-completed behavior. No duplicate review engine, hook installer, auto-posting or update bot.

CLI table is authoritative over earlier illustrative commands in parent design documents. Validate clap/help/error handling & old report v1/v2 round trips.

## Documentation & generated artifacts

Update `skills/audit/SKILL.md` & relevant existing audit references: dispatch/profile behavior, stack coverage, runtime constraint, qualification limits & emitted results. Preserve current workflow authority. A13 owns pattern-card docs/evals until return. Add focused skill evals for user requests covering Kotlin without JVM contract, iOS vs SwiftPM, native-only web checks, incomplete release & pre-PR review.

Use native `legion-dev` generators after source settles: `generate-catalogs`, `generate-schemas`, `generate-manifest`, `refresh-local-skill-manifests audit`; include affected dependency bundles only if their source changed. Check generated drift & skill references/evals; structure-only eval success is not semantic qualification. Refresh other projections only when corresponding source changed.

Final implementation response identifies integrated packets, native test results, qualification scope, owner prerequisites, measured gaps & exact next runnable work. Deliver native Audit extension with reproducible evidence & truthful per-target coverage.

