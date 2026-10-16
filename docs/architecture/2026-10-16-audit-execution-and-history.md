# Audit execution & historical coverage

**Current status (2026-10-16; source `c16e0166f7fc157dbb694451d1eff610655baf00`):** CI [38920849719](https://github.com/Orthic-Labs/legion/actions/runs/38920849719)
passed Mac (5,190/0/7) and Windows (5,153/0/7); native simulation passed both, and installed MCP root false/true passed on Mac. Full deterministic real-Ember producer gate on
`9961562ed4c652b0bc6a9b3bc3a63142d885f583` recorded positive source coverage, plan 12,963,861 bytes, facts 13,529,161 bytes, and 0 model calls; its audit status remains incomplete.
Artifact 12055344535 was canonically installed on Mac; installed CLI SHA-256 matches payload `65119557a7cb1ffde70f23a050fad7c6b35c8a79d5deff2d69f5fcbf2d396eb3`.
Receipt: `/Volumes/D/scratch/legion-verified-c16e0166/installation-receipt.json`. Independent Oracle Standards & Spec passed for CI/install. Maintained Ember `a297ccc145df28943978db97e5e2e547a7858f92`
setup and doctor completed; installed live full scan at `/Volumes/D/scratch/ember-audit-c16e0166-20261016` completed in 170.607s with compact plan/facts of 13,183,760/13,744,269 bytes.
Its report contained 817 raw candidates, zero duplicate-ID groups, and zero duplicate-ID gaps; these are raw candidates, not confirmed bugs. The same frozen run resumed after the wrapper fix, kept temporary exclusions through reasoning and top-level verification, then restored original bytes and the stray.
One Sonnet 5.5 native call failed/refused without usable semantic output. Provider usage was 10,938 input tokens (2 uncached + 10,936 cache-creation), 289 output (214 thinking), 11,227 total; Oracle independently confirmed API-equivalent cost $0.046638, invoice charge unknown. This exceeded the 10,000 per-call cap by 1,227 while staying under 50,000 total.
Failure subtype was dropped and is unrecoverable, so no cause is assigned. Terminal status is incomplete: persistent budget-overrun stop denies further reservations. Verification valid=true with one verified runtime call, receipt, and reservation proves accounting only, not semantic completion.
No further paid resume, budget reset/raise, or benchmark was run. CI [38935609755](https://github.com/Orthic-Labs/legion/actions/runs/38935609755) for `5dc6f015` failed both OS gates: full 12-line correctness RAW source did not survive packing, and three expectation classes still used older cue/accounting/admission rules. The source repair preserves that full-source assertion, compacts only normative prose and pinned metadata, and updates stale expectations; independent source-only Oracle Standards & Spec passed. Explicit linked continuation is being implemented to retain the immutable failed parent and cumulative accounting under original ceilings. This recovery, replacement CI, installation, and admitted Ember reasoning remain pending.

Historical `90ab5972` stage: CI passed both platforms; only Mac artifact was installed. Subsequent c16 source-only Oracle Standards & Spec reviews passed for serialization repair, full-scan CI gate, and narrow a11y signed-value/ID-dedup fix.
Its local scan on the same Ember revision completed in 150.837s, then reasoning stopped before native dispatch because pretty plan/facts exceeded the 16 MiB reader guard; no runtime host, calls, or ledger were created,
and exact spend remained unknown. It reported three duplicate-ID groups from a11y parsing negative `tabindex` in selector strings as positive; the fix preserves heuristic candidate boundaries and gives no DOM-parser guarantee.
Earlier `64e515f1` CI plan-only gate on `9961562ed4c652b0bc6a9b3bc3a63142d885f583` passed cold/warm (14 excerpts, 3 paths, 4 authors + 1 reserve); its separate local scan was terminated/incomplete at 468.953s.
No speedup ratio or 10/10 claim follows from those partial runs. Caps remain 50,000 total tokens, 10,000 per call, 2,500 output tokens, five physical calls, concurrency one.
Earlier failures are historical: `01e20409` had graph fragmentation and Mac promotion growth; `c996cce9` fixed measured-fit and canonical-promotion issues; `f395` corrected the obsolete exact-two-lens test.

Requested by Adrian, 16 October 2026. Comparison baseline: `bogusyogi/claude` commit
`7bd906af4226e236be0b49813003ea761171fe28`, immediately before removal commit
`1377d7262facd2ede80cc35e9e8ec7bcac0e0bc9`. Historical inventory was read from Legion
`17c29c612128895487c3d05063d1ba05a571d512`; source repairs below reflect `23930e5f` plus registry
projection sync `8eec8f79`. They are source-state descriptions, not build, CI, live-run, or installation
completion evidence.

## Findings

Audit retained all 15 original general AI lenses. Scanner names mostly survived, but names do not
prove behavioral parity. The major migration loss is broad native language-family execution.
The major cost defect is that planned work tiers were not enforced by the native model runtime.

Audit is a capability supplying review method. Alchemist executes its bounded work; Oracle supplies
independent assurance. Neither the word “audit” nor Oracle authority requires frontier models for
bulk source review. Adrian explicitly requires Haiku/Luna for cheap work & Sonnet/Sol for specialist
execution. Astra/Fable/Opus orchestration may separately validate findings.

## Current deterministic inventory

The base registry contains **96 canonical providers**: 45 with role `deterministic`, 34 with role
`candidate-generator`, 16 with role `adjudicator`, & one `variant-analysis`. The first two categories
are **79 non-AI provider contracts**. This is not 79 installed scanner binaries: some are built-in
analyses, wrappers, imports, or overlapping contracts. Candidate generators use deterministic rules
to nominate issues; independent AI review decides whether those candidates are real findings.

Sources: [base registry](../../src/registry/providers.json),
[legacy command projection](../../engine/crates/legion-audit/src/native_providers/legacy_checks/registry.rs),
[named scanner commands](../../engine/crates/legion-audit/src/native_providers/security/scanner_tools.rs),
[security producers](../../engine/crates/legion-audit/src/native_providers/security/producer.rs).

| Area | Implemented scanners/check families |
|---|---|
| Repository & structure | Git state, decomposition size triggers, debt markers, negative-space checks, tool-exclusion coverage, React Hooks configuration, Apple platform configuration |
| Project commands | Project build, test, types & lint adapters; TypeScript, Python & Rust tool selection; SwiftLint |
| Dead code & duplication | Knip, cargo-machete, jscpd |
| Dependencies | npm/pnpm/package audit, pip-audit, cargo-audit, cargo-deny, cargo-geiger, package/cargo outdated, license-checker; vendored dependencies, dependency pins & binary-download pins |
| Secrets & SAST | Gitleaks, native credential patterns, OpenGrep/Semgrep, ast-grep; current-tree & history coverage must be distinguished |
| Supply chain & imports | OSV Scanner, Trivy configuration scan, Syft SBOM output, imported SARIF, license/SBOM/provenance checks |
| CI, infrastructure & languages | Actionlint, Hadolint, ShellCheck, Zizmor, Squawk, TFLint, Kubeconform with pinned local schemas, Kube-Linter, Brakeman, GolangCI-Lint |
| Native security packs | Credentials, insecure defaults, misuse resistance, agentic CI, agent-skill/MCP boundaries, suppression changes |
| Tauri | Capability permissions & frontend/backend command mirror |
| Static architecture & quality | Architecture, compatibility, documentation contracts, backend/data/frontend framework facts, requirements traceability, test-quality facts |
| Language source adapters | C-family, .NET, Go, JavaScript, JVM, long-tail, mobile, PHP/Ruby, Python & Rust; adapter presence does not imply build/test support |
| Runtime & rendered evidence | App runtime capture, accessibility, visual comparison; host capture/sandbox inputs required |
| Framework/data/infrastructure suites | Native candidate generation for framework, data & infrastructure patterns |
| Governance | Policy input & optional host-declared capability-ownership scan |

The legacy projection has **33 checks**: `apple_platform`, `decomposition`, `repo`, `build`, `test`,
`dead_code`, `debt_markers`, `duplication`, `lint`, `negative_space`, `cargo_unused_deps`, `swift_lint`,
`tool_coverage`, `types`, `react_hooks`, `runtime`, `binary_pins`, `dep_pinning`, `docker`, `ci_lint`,
`js_licenses`, `deps_cve`, `py_deps_cve`, `cargo_audit`, `cargo_deny`, `cargo_unsafe`, `sast`, `secrets`,
`vendored_deps`, `outdated`, `cargo_outdated`, `tauri_capabilities`, & `contract_mirror`.

Optional executables, project applicability, pinned local rule/schema inputs, online authorization &
host network containment determine which checks can run. A registered scanner is not evidence it ran
on Ember. Sqllint, SQLFluff, RuboCop, Checkov, Bandit & Oxlint are explicitly deferred integrations,
not current executable scanner coverage.

## Current AI lanes

All 15 general lenses below existed at the historical baseline. The two security pipeline lanes are
listed separately to avoid counting detection, adjudication & variant search as one operation.

| Lane | Judgment requested |
|---|---|
| `doc-drift` | Documentation versus implementation |
| `architecture` | Boundaries, dependencies, design risks |
| `correctness` | Behavioral defects & explicit specification fidelity |
| `ai-slop` | Repository standards, needless patterns & weak implementation choices |
| `naming` | Misleading names & semantic consistency |
| `dead-file` | Bounded dead-file survey; candidates need verification |
| `schema` | Schema & contract drift |
| `security` | Reachable vulnerabilities with concrete threat models |
| `minimize` | Unnecessary complexity while preserving real seams |
| `performance` | Supported performance problems |
| `a11y` | Applicable accessibility concerns |
| `data-safety` | Applicable data-loss/corruption risks |
| `resilience` | Applicable recovery & failure handling |
| `platform-parity` | Applicable platform divergence |
| `release-readiness` | Applicable release/distribution risks |
| `legacy.security.adjudication` | Challenge deterministic security candidates; retain per-candidate verdicts |
| `legacy.security.variant-analysis` | Search bounded related source after confirmed security findings |

Source: [reasoning provider allowlist](../../engine/crates/legion-audit/src/native_providers/reasoning/mod.rs).
Conditional lenses run only when frozen applicability selects them. Their existence does not mean
every audit invokes every lane.

## What did not survive unchanged

Historical source locations below are paths at the baseline commit, not live files.

| Historical behavior | Current state |
|---|---|
| 31 core legacy checks plus runtime check | All have aliases/native projections; project-test is an added current check. Current total is 33 including runtime & test. |
| 15 general AI lenses | All retained; explicit `run-reasoning` executes them. Library `pending-host` is the planning boundary, not proof execution is absent. |
| Framework, data, infrastructure, accessibility & visual suites | Native replacements exist through `legacy.*` aliases; absent old `.mjs` paths do not mean these five suites are missing. |
| `native.family-suite` | No direct live provider/alias. Current `code.*` plus legacy adapters replace only part of its command coverage. |
| `generic.source-accounting` | No direct live provider/alias. `code.long-tail` supplies unknown-language accounting, but with different extension claims. |
| Broad native language build/test/syntax execution | Partial migration, detailed below. |
| Historical framework-specific direct checks | React/Tauri/Tailwind/Laravel/ASP.NET checks from native-family runner lack complete one-to-one coverage in current framework suite; some related checks exist elsewhere. Spring overlaps. |
| Benchmark-only detectors & old bench runners | Intentionally retired; `bench_recall.rs` is recorded successor. Their removal is not removal of production scanner coverage. |

Historical `tools/skills/audit/providers/native-family-runner.mjs` ran:

The current native adapter restores the syntax-only subset for PHP, Ruby, bash, zsh, & PowerShell by
staging frozen source into isolated syntax invocations. These checks are conditional on host tools and
remain bounded; they do not execute project configuration. Historical project build, test, dependency,
and package-validation commands are represented as typed deferred commands with `executed: false` and
policy reasons. That records the missing work explicitly; it is not restored build/test parity.

| Family | Historical commands | Current parity gap |
|---|---|---|
| JS/TS | Package-manager `typecheck/types/check`, lint, test/test:unit, build | `code.javascript` directly plans tsc/eslint; legacy project adapters provide some build/test coverage, but native-family behavior is not fully equivalent. |
| Python | compileall & optional pytest | `code.python` provides bounded py_compile/Ruff; pytest is policy-gapped. |
| Rust | metadata, check all targets, Clippy, tests | `code.rust` plans metadata/check/Clippy; its tests are policy-gapped. Legacy project-test is a separate route. |
| Go | go test & go vet | Typed `go test ./...` plan restored; execution is deferred. Existing module/vet/gofmt plans are separate. |
| Swift/Obj-C | SwiftPM build/test, otherwise swiftc typecheck | Typed SwiftPM build/test plans or `swiftc -typecheck` plan restored; execution is deferred. |
| JVM | Gradle/Maven build/test/verify | Typed offline Gradle build/test and Maven verify/test plans restored; execution is deferred. |
| .NET | restore/build/test | Typed `dotnet build/test --no-restore` plans restored; restore remains not planned under `policy-no-dependency-install`, and execution is deferred. |
| C/C++ | CMake build or make dry run | Typed CMake configure/build and `make -n` plans restored; execution remains deferred because project code may run. |
| PHP | php syntax checks & composer validate | Isolated PHP syntax check is restored when available; Composer validation stays deferred. |
| Ruby | ruby syntax checks & bundle/rake tests | Isolated Ruby/Ripper syntax check is restored when available; bundle/rake tests stay deferred. |
| Dart/Flutter | analyze & test | Typed Dart analyze/test plans restored; execution is deferred. |
| Shell/PowerShell | Syntax checks | Isolated bash, zsh, and PowerShell syntax checks are restored when available; ShellCheck remains separate. |
| Elixir/Erlang | mix compile/test or rebar3 eunit | Typed Mix compile/test and Rebar3 EUnit plans restored; execution is deferred. |

Remaining build, test, dependency, and package execution items are migration gaps, not permission to run
uncontained project commands. Their current frozen-plan rows explicitly say deferred and `executed: false`;
they do not establish historical execution parity. Syntax-only restorations are bounded source checks,
not project build/test acceptance evidence.

Historical `generic-source-suite.mjs` accepted 51 extensions as covered. Current source analysis now reads
and analyzes the 29 formerly whitelisted extensions below from actual frozen source bytes. This restores
bounded generic source analysis, not language/compiler coverage; `code.long-tail` retains typed gaps when
no language provider or compiler evidence exists:
`astro`, `bash`, `bat`, `cjs`, `cts`, `css`, `cxx`, `dart`, `erl`, `ex`, `exs`, `gql`, `graphql`, `hrl`,
`html`, `kts`, `mjs`, `mts`, `nsh`, `nsi`, `ps1`, `psm1`, `rb`, `sh`, `sql`, `svelte`, `vbs`, `vue`, `zsh`.
Source-analysis findings require the same actual-path evidence as other providers. A historical extension
being read does not imply that a dedicated parser, syntax check, build, or test ran. Some dedicated
scanners can examine these files without closing general language coverage.

Gitleaks history mode survives in `legacy.security.secrets`. Current-tree native credential detection
does not replace history scanning when Gitleaks is absent. Before this repair, `secrets.current-history`
could accept native fallback or `gitleaks dir` output as complete, because its denominator accepted zero
history refs. This repair retains useful current-tree findings but emits `secret-history-not-examined`
until explicit history evidence is supplied. Counted refs alone cannot close the gap.

## Source restorations & execution boundary

Source changes through `23930e5f` implement bounded source analysis for all 29 historical generic-source
extensions; isolated syntax checks for PHP, Ruby, bash, zsh, & PowerShell; and typed deferred records for
historical project commands that were not executed. The command restores syntax/static policy visibility,
not complete historical build, test, type, or dependency execution parity.

Reasoning now routes non-security scanner candidates to their matching existing semantic lens; only
security candidates use threat adjudication. Unsupported candidate domains remain explicit pending or
unavailable gaps. Deterministic host-side evidence gathering costs no model calls; optional cheap gathering
is admitted only when needed. Bundled lenses share exact RAW source bytes while retaining independent
lens contracts and result IDs. Planning reserves one fresh verification call; findings outside its bounded
envelope remain unverified. Mandatory paths beyond selected coverage are recorded as actual deferred paths
with digests and explicit gaps, making the run incomplete; the planner selects affordable work rather than
refusing solely because mandatory work exceeds the budget. Explicit exhaustive mode remains strict.

The host may supply an optional graph JSON artifact through `LEGION_AUDIT_GRAPH_ARTIFACT`. It is bound to
frozen source and resolver context; without it, graph context uses lexical fallback and preserves its limits.
The registry capability projections were synchronized at `8eec8f79`.

These source facts do not establish a completed live repository audit. No CI, current installed-build, or
current installation completion claim is made here; append those results only after evidence for the exact
source revision is available.

The supported transport remains native Claude. Haiku/Sonnet are its executable choices; Luna/Sol
are corresponding Codex tiers in canonical policy, not a claim that an OpenAI audit transport exists.

Historical validation for revision `6ede1515fab643a3ca2ccd69dcedd8cdfa802a67` received independent Oracle
Standards PASS & Spec PASS; its CI and installation receipts below apply only to that revision and do not
validate the later source restorations `23930e5f` and `8eec8f79`.
[CI 38859651460](https://github.com/Orthic-Labs/legion/actions/runs/38859651460) passed macOS (5,135 tests)
& Windows (5,101 tests), zero failures, seven ignored per platform; native simulation passed both.
Its exact macOS artifact was installed through canonical headless installer; setup repair, status & doctor
passed. Installed binary SHA-256 matches CI payload:
`ece435b0c238e5f98d1a4519b5275810a96ff6ed84b1e29c5e9a149ae6cf5da8`.

Historical Ember attempt at `9961562ed4c652b0bc6a9b3bc3a63142d885f583` used a 50,000 total-token cap,
10,000 per call, 2,500 output tokens, five physical calls & concurrency one. Preflight refused after
34.978 seconds under that revision's then-current call-floor plan: six active bundles required six author
calls, five cheap gathering calls & one verification/context reserve (12 total). Mandatory coverage was
preserved. No plan froze or reasoning transport ran: exact Audit model calls/input/cache/output/cost were
`0 / 0 / 0 / 0 / $0`. This refusal is historical evidence for the older planner, not current behavior;
`23930e5f` removes the per-lens gathering floor and records deferred mandatory coverage while selecting
affordable work.
This meter excludes chat, implementation/review agents, CI & subscription billing. Minimum call count
is a lower bound, not proof that 12 calls would fit token budget. Ember quality/security remains unproven;
[issue #33](https://github.com/Orthic-Labs/legion/issues/33) tracks remaining audit outcome.

Local run evidence: `/Volumes/D/scratch/ember-audit-rerun-6ede1515/attempt-summary.json`;
installation evidence: `/Volumes/D/scratch/legion-verified-6ede1515/installation-receipt.json`.
Earlier rejected 802-job/25.47M-token attempt remains failure evidence, not an audit verdict.

## Historical source state at `92e8b294` (2026-10-16)

Source through `92e8b294` keeps the full frozen denominator and records exact deferred paths while
selecting affordable sampled work (`23930e5f`). Bundled lenses share exact RAW bytes; deterministic
gather uses zero model calls, and planned tiers are enforced. Authenticated usage reconciliation is
in `ea5fa434`; candidate-routing metadata compaction is in `2c97f9a8`, denominator compaction in
`7733d44d`, and graph/binding compaction in `92e8b294`. These compact metadata paths preserve the
coverage identities above. The 50,000-token cap on the Ember run is scoped to that run; configured
defaults remain unchanged, and tokens are not a universal quality ceiling.

Source-only Oracle review passed for this state. CI, installation, and live-run evidence remain
pending; no delivery or Ember semantic-coverage claim follows from source review. Donor pins and
historical inventory remain anchored to their recorded revisions, and held-out semantic cases remain
unexecuted.

## Historical source state at `9ebd42ce` (2026-10-16)

`packet-envelope-v1` projects deterministic physical requests while retaining original signed logical
invocations. RAW source, candidates, questions, and normative contracts stay inline; only full-run
accounting and illustrative examples use digest references. Physical delivery receipts remain distinct
from logical reconstruction. Sampling drafts affordable, source-bearing work breadth-first per provider
before continuations. Model estimates count canonical prompt, system, and schema once; transport escaping
remains in separate wire metrics.

Headroom, full 10,000-token authorization reservation, caps, defaults, and verifier are unchanged. The
regression requires complete 12-line RAW files for correctness and ai-slop within 50,000 run tokens,
10,000 per call, 2,500 output tokens, five calls, and concurrency one; tests are not yet verified at this
commit. Oracle Standards & Spec passed on source only. CI [38893510643](https://github.com/Orthic-Labs/legion/actions/runs/38893510643)
was launched at this source revision; prior two-platform CI failed only on real graph coverage, while simulation passed. Installation
and live execution remain pending.
