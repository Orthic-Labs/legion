# Legion Architecture

## Roster vocabulary

Sage, Alchemist, & Oracle are Legion's **champions**. Together they form Legion's **roster**. A harness may instantiate a champion as an agent, but `agent` names the runtime mechanism rather than the champion's product identity.

Arcane is Legion's deterministic control plane, not a champion. Covenant is Legion's challenge chamber, not a champion; its isolated seats review frozen evidence without joining the roster.

## Canonical audit flow

1. **Freeze audit target**
   - Bind exact commit, dirty state, release artifact, configuration, & requested claim depth: inventory, source, runtime, product, or release.

2. **Identify product portfolio**
   - Detect web, desktop, mobile, API, worker, CLI, library, infrastructure, or hybrid targets.
   - Treat a repository as a portfolio: a Tauri product may include desktop, embedded web UI, API, installer, updater, & shared libraries.

3. **Map components & boundaries**
   - Map frontend, backend, database, sidecars, IPC, installers, external services, ownership, data flows, & trust boundaries.

4. **Identify stack per component**
   - Detect languages such as PHP, TypeScript, Rust, Swift, or Kotlin.
   - Detect frameworks such as Laravel, Next.js, Tauri, Electron, Flutter, or React Native.
   - Record toolchains, runtimes, databases, build systems, package managers, versions, component ownership, & evidence paths.

5. **Compile applicable audit controls**
   - Combine universal, app-type, component, language/framework, feature, risk, release-contract, & claim-level controls.
   - Add conditional controls for AI, payments, realtime, offline, multi-tenant, UGC, hardware, or regulated data only when applicable.
   - For shipped native targets, include process discipline, build efficiency, & native-platform leverage controls.

6. **Select required deterministic providers**
   - Select only providers needed by compiled controls.
   - Examples: build, tests, lint, Biome/ESLint, `tsc`, Clippy, PHPStan, dependency scans, secrets, AST/SAST, dead code, duplication, architecture policy, & compatibility checks.
   - File size triggers decomposition review; size alone never proves decomposition is required.
   - Process providers compare expected versus observed process trees, privileges, lifetimes, startup entries, helpers, sidecars, & orphaned children.
   - Build providers measure clean/incremental time, cache use, reproducibility, artifact size/content, unused assets, duplicate bundles, symbols/source maps, & release-profile correctness against declared budgets or a frozen baseline.
   - Native-leverage providers identify custom implementations of OS-owned capabilities, then require native APIs or an explicit portability/security rationale; static detection alone produces a review candidate, not a failure.

7. **Run applicable reasoning lenses**
   - Correctness, architecture, security, performance, accessibility, data safety, reliability, platform parity, release readiness, UX, & content.
   - Security candidates require independent adjudication; confirmed findings require repository-wide variant analysis.
   - Review whether each spawned process is necessary, each build cost has a justified owner, & handwritten platform behavior is safer or more portable than Windows/macOS native APIs.

8. **Run dynamic evidence**
   - Web browser/runtime, API, database, worker, failure, & network scenarios.
   - Desktop expected/observed process trees, IPC, installer, updater, local storage, lifecycle, native API behavior, build/package outputs, & Windows/macOS/Linux matrices.
   - Mobile simulator/device, lifecycle, permissions, deep-link, WebView, offline/sync, battery, thermal, store, & device matrices.

9. **Run visual audit**
   - Capture applicable UI surfaces, states, viewports, themes, locales, & platforms.
   - Check geometry, overflow, responsive behavior, accessibility, visual regression, interaction states, & design quality.

10. **Reconcile without false clean results**
    - Every applicable control ends as `PASS`, `FAIL`, `UNPROVEN`, `NOT_APPLICABLE`, or `ACCEPTED_RISK`.
    - Missing provider, tool, browser, device, native host, signing, store, deployment, or release evidence stays `UNPROVEN` at affected claim level.
    - A passing target cannot hide an unproven target in a hybrid portfolio.

11. **Produce sealed evidence**
    - Emit sealed plan, topology, stack graph, selected-control denominator, facts, findings, SARIF, screenshots, receipts, coverage gaps, rerun commands, & out-of-band verification result.

## Selection formula

```text
applicable controls = universal
                    + product target
                    + component
                    + language/framework/runtime
                    + detected feature/risk
                    + release contract
                    + requested claim level

provider plan = qualified providers referenced by applicable controls
```

Detection narrows execution, never obligation. An applicable control without usable evidence remains visible & `UNPROVEN`.

## Dispatch relationship

Validated `legion-source-completion-20260808` dispatch completes Books 1–8 machinery: core contracts, topology, controls, providers, runtime, visual, security, reporting, CLI/MCP, qualification, parity, tests, & delivery.

This architecture supplies final operating shape: it makes topology → stack graph → applicable controls → provider plan mandatory, ingests desktop/mobile/web checklist sources, selects only relevant audit work, & reconciles every applicable control without false clean results.

Follow-on implementation must add explicit source-backed controls & fixtures for unnecessary process spawning, build efficiency, & native-platform leverage; dispatch supplies underlying provider/runtime machinery but does not complete these controls by itself.

Both parts are required. Dispatch completion alone does not create this final connected flow.

Detailed workspace decision: `$WORKSPACE/docs/plans/legion/ARCHITECTURE.md` (historical provenance only — superseded by `docs/LEGION-CANONICAL-SSOT.md`).
