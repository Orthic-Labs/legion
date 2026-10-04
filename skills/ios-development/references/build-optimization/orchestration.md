# End-to-end orchestration

Use this route for full build optimization. Work in two operational phases: baseline/analysis, then scoped implementation/verification. A request to optimize authorizes ordinary in-scope edits; retain a recommendation-only phase when user asks for analysis or plan.

## Phase 1: evidence and plan

1. Resolve project/workspace, scheme, configuration, destination, current pain, Xcode/toolchain, and cache condition. Prefer project unless workspace contains required subprojects.
2. Run [benchmarking](benchmarking.md), verify non-empty timing categories and cached-clean runs when cache enabled.
3. Check variance and compare category totals to wall-clock. If compile categories are critical-path, run compilation diagnostics; otherwise label source findings parallel workload.
4. Run project, compilation, and SPM lanes that evidence supports. Preserve raw artifacts and source locations.
5. Rank by developer wall-clock savings: serial scripts, invalidation/planning, target graph/options, critical-path asset/link/signing work, then source hotspots and low-evidence cleanup.
6. Produce a plan with recommendation records and explicit expected impact; do not present aggregate task seconds as wait-time savings.

## Recommendation impact language

Use one statement per item: “Expected to reduce your clean/incremental build by approximately X seconds”; “Reduces parallel compile work but may not reduce build wait time”; “Impact on wait time is uncertain—remeasure”; or “No wait-time improvement expected; benefit is deterministic resolution, branch-switch caching, or CI cost.” For cache, retain measured context (5–14% across tested projects, 87–1,991 Swift files) without treating it as a promise.

## Phase 2: implementation and verification

Apply only scoped, user-authorized items through [fixing](fixing.md), one logical change at a time. Verify settings/links, compile, relevant tests, and then rerun same benchmark contract. Append post-change medians, absolute/percentage deltas, confidence, deviations, blocked findings, and remaining follow-up. Do not claim improvement while median remains inside baseline noise.

## Recommendation record

Each finding carries:

- `title`
- `wait_time_impact`
- `actionability`: `repo-local`, `package-manager`, `xcode-behavior`, or `upstream`
- `category`
- `observed_evidence`
- `estimated_impact`
- `confidence`
- `approval_required` (governance metadata; user authority remains live)
- `benchmark_verification_status`: `Not yet verified`, `Queued for verification`, `Verified improvement`, `No measurable improvement`, or `Inconclusive due to benchmark noise`
- optional scope, affected files/targets/packages, implementation notes, risk

Render same order with native Rust `build-analysis` operations: `recommendations.render` or `report.summarize` consumes supplied JSON, while `project.audit`, `timing.parse`, and `compiler.parse` provide evidence sections. Keep generated report evidence-bound.

## Final report

Lead with wall-clock: “Your clean build now takes X.Xs (was Y.Ys) — Z.Zs faster/slower.” Include clean, cached-clean, zero-change/touched incremental medians, min/max/range, command/environment, changed files, status per fix, confidence, and non-actionable findings. If task totals improve while wait does not, state that parallel work hid wait-time benefit. Do not include donor PR/social-sharing steps unless explicitly requested.
