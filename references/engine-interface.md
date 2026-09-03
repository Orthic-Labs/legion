# Audit engine interface (CLI · scanner registry · report shape)

Extracted from SKILL.md (2026-07-18) unchanged. This is the deterministic engine's machine
interface: the CLI ergonomics flags, the scanner registry table, and the `report.json` contract.

## CLI ergonomics (CodeRabbit-inspired flags)

Use audit doctor and these flags for local-review convenience without changing `/audit` into single-PR review:

- `audit-facts <root> --doctor` prints scanner readiness without running scanners.
- `--dir <path>` records a directory scope in `facts.scope` and filters changed files to that directory.
- `--type all|local|committed|uncommitted`, `--base <branch>`, and `--base-commit <sha>` record diff context in `facts.scope`. `all` = whole-repo (default, no diff scope); `local` = ALL local changes (committed-but-unpushed ∪ staged ∪ unstaged ∪ untracked — what `/commit` uses); `uncommitted` = working tree only; `committed` = last commit.
- `audit-report --facts <facts.json> --report <report.json> --filter-dir <path>` renders only findings under a directory.
- `audit-report --facts <facts.json> --report <report.json> --agent` emits compact JSON for agent/CI consumption.
- For portable agent consumption, also emit findings as a **compressed OKF bundle** (one concept per finding, required `type` frontmatter, link graph; prose compressed structure-safely) via `okf emit <root>/.audit/<ts>/okf <concepts.json> --compress`. `report.json` stays the machine source of truth and the rendered `.md` stays the uncompressed human report. Pattern: `references/okf-output.md`. For the lens INPUTS, prep agent reads with `crypt prep <tmp> <files...>` (code→skel, prose→compress) — SURVEY reads only, never the FULL-read verification path. Full compaction stack: `references/okf-output.md`.

Scope metadata is advisory context. Scanner coverage remains honest: a scoped report must not claim unscanned checks were clean.

## Scanner registry (check → command → runs when)

Commands (the literal re-run lines the report prints):

| check | command | runs when |
|---|---|---|
| decomposition | measure tracked code LOC/bytes and reconstruct mechanical part-splits; Blueprint enriches candidates with symbol/span and relationship metrics | git repo. Default 400 LOC is a configurable **review trigger**, not a finding or clean-gate failure; configure `.agent/config.json → hygiene.decompositionReviewLoc` |
| secrets | `gitleaks git .` (git repo, tracked history) / `gitleaks dir .` (non-git) → json | gitleaks present (else NOT-SCANNED) |
| deps_cve | `pnpm audit --json` / `npm audit --json` | package.json |
| py_deps_cve | `pip-audit -r requirements.txt -f json` / `pip-audit -f json` (active env) | Python project + pip-audit present (else NOT-SCANNED — a Python tree without it has ZERO dep-CVE coverage; the npm/cargo-audit sibling) |
| cargo_audit | `cargo audit --json` (cwd = Cargo.lock dir, incl. `src-tauri/`) | Cargo.lock + cargo-audit present (else NOT-SCANNED — a Rust tree without it has ZERO CVE coverage) |
| cargo_deny | `cargo deny --format json check` (cwd = Cargo.toml dir) | Cargo.toml + cargo-deny present. Supply-chain POLICY beyond advisories: license compliance + banned/duplicate crates (cargo-audit is advisory-only) |
| cargo_unused_deps | `cargo machete --with-metadata` (cwd = Cargo.toml dir) | Cargo.toml + cargo-machete present. Unused declared crates — the knip sibling for Rust; stable toolchain (no nightly) |
| cargo_unsafe | `cargo geiger --output-format Json` (cwd = Cargo.toml dir) | Cargo.toml + cargo-geiger present (heavy full-compile — runs only when explicitly installed). Counts `unsafe` usage; relevant where raw FFI lives |
| vendored_deps | enumerate tracked `vendor/**/{package.json,Cargo.toml}` trees + lockfile presence | git repo. Root audits do NOT cover these trees — each is reported as covered-or-unscanned, never implied-covered |
| dep_pinning | scan package.json/Cargo.toml for git deps without a commit/tag pin | git repo. Unpinned `git+`/`github:` deps bypass registry + audit tooling |
| tool_coverage | read `.eslintignore` / flat-config `ignores` / tsconfig include+exclude vs top-level code dirs | always. A lint that skips half the repo reports clean — the exclusions are the finding (heuristic on flat configs; lens verifies) |
| contract_mirror | diff `generate_handler![]` names vs frontend `invoke("...")` literals | src-tauri present. Uncalled handlers = dead attack surface; unregistered invokes = dead UI path (verify wrapper indirection before flagging) |
| tauri_capabilities | parse `src-tauri/capabilities/*.json` permissions + count `#[tauri::command]` handlers | src-tauri present. Flags broad/dangerous grants (`allow-all`/`default` on fs·shell·http·process, shell execute/spawn, wide `**` scopes) + exposed-command count. Review trigger for the security lens, not a verdict |
| react_hooks | package.json: `react` present ⇒ `eslint-plugin-react-hooks` configured? | React project. A React app without the hooks plugin ships conditional-hook + stale-dependency bugs unlinted (config-coverage, not a scanner) |
| build | `pnpm run build` / `cargo build` | build script / Cargo.toml |
| types | `npx tsc --noEmit` / `basedpyright --outputjson` (fallback `mypy .`) | tsconfig / py types + checker present. ruff does NOT type-check — basedpyright is the Python half of the types gate |
| lint | `biome lint --reporter=json --max-diagnostics=1000` / `eslint . -f json` / `ruff check --output-format json` / `cargo clippy --all-targets --message-format=json -- -D warnings` | lint config / py / rust + tool present. Counts **warnings AND errors** — clippy runs `-D warnings` so every rustc lint (dead_code, unused) + clippy lint fails the bar; `--all-targets` covers tests/examples/benches |
| dead_code · duplication · ci_lint · docker · sast | knip · jscpd · actionlint · hadolint · semgrep | P2, optional |
| swift_lint | `swiftlint lint --quiet --reporter json` | tracked `.swift` sources + swiftlint present (macOS; else NOT-SCANNED — Apple-platform code without it has zero lint coverage). The eslint/clippy sibling for the shared iOS packages + app repos |
| js_licenses | `npx license-checker --json --production` | package.json + license-checker present. Copyleft exposure (GPL/AGPL/SSPL/…) in the JS dep tree of a proprietary product; the npm half of `cargo deny check licenses` |
| negative_space | fs presence (tests / CI / LICENSE / lockfile / README / .gitignore) + meta: `test_skew` (code-vs-test counts per subtree), `large_tracked_files` (>5MB binaries degrade grep scanners), `ci_advisory_gates` (`continue-on-error`/`\|\| true` — a gate that doesn't gate), `unsafe_sites` (Rust) | always |
| outdated | `pnpm outdated --json` / `npm outdated --json` (majors behind) | package.json |
| cargo_outdated | `cargo outdated --format json --root-deps-only` (cwd = Cargo.lock dir, incl. `src-tauri/`; majors behind) | Cargo.lock + cargo-outdated present (else NOT-SCANNED — a Rust/Tauri tree reports zero stale crates) |
| binary_pins | scan tracked build/packaging scripts (`.ps1`/`.sh`/`.mjs`/`.py`/Dockerfile/Makefile) for hardcoded artifact-download URLs; 64-hex literal within ±6 lines = integrity pin; resolve GitHub `releases/latest` per repo (`AUDIT_OFFLINE=1` skips network) | git repo. The bundled-binary blind spot: URL+SHA256 pins in scripts (the package.ps1 `Ensure-*` skip-if-present pattern) are invisible to `outdated`/`cargo_outdated`/Dependabot and never re-evaluated once fetched. Every pin renders STALE / current / MANUAL-CHECK (upstream unresolvable — surface to the user) / NO-INTEGRITY-PIN (download with no hash); MANUAL-CHECK counts as a finding, never "clean" |
| debt_markers | `git grep -nIE "(ponytail:\|TODO\|FIXME\|HACK\|XXX)"` | git repo |
| runtime *(app-only)* | `audit-runtime --url <dev-server>` — boots a headless browser, sweeps surfaces, measures per-keystroke AND per-click scripting + long tasks + React commit bursts + console/visual per surface (typing pass + in-panel click pass; destructive controls excluded, JS dialogs auto-dismissed) | a `qa:browser` / dev server exists (else skipped: no runnable surface) |

## Report shape (`report.json`)

```json
{
  "schema_version": 2,
  "kind": "repository-audit-report",
  "generated_at": "<ISO>", "workspace": "<root>", "commit": "<sha>", "incomplete": false,
  "lenses_ran": ["doc-drift","architecture","correctness","ai-slop","naming","dead-file","schema","security","minimize","performance","a11y","data-safety","resilience","platform-parity","release-readiness"],
  "constraints_surface": [
    {"scope":"runtime|deployment|compatibility|team-convention|exception",
     "constraint":"<constraint or unknown>","evidence":"<path:line, config key, or unknown>",
     "status":"verified|inferred|unknown"}
  ],
  "decomposition_assessments": [
    {"file":"src/x.ts","trigger":{"loc":640,"bytes":22000},
     "verdict":"not-needed|confirmed|undetermined","rationale":"...",
     "evidence":["src/x.ts:20-180"],"findingId":"ra-017|null"}
  ],
  "triage_top": ["ra-002","ra-001"],
  "findings": [
    {"id":"ra-001","category":"security|architecture|correctness|ai-slop|naming|dead-file|schema-drift|doc-drift|minimize|performance|a11y|data-safety|resilience|platform-parity|release-readiness|ui-ux",
     "subtype":"decomposition|null",
     "severity":"critical|high|medium|low",
     "evidence_strength":"verified|strong-inference|possible",
     "judgment":"objective|interpretive",
     "status":"open|disputed|resolved|accepted-risk",
     "tier":"AUTO|GUIDED|MANUAL",
     "file":"<path>","line":42,"evidence":"deps_cve.log | src/x.ts:42",
     "caused_by":["<upstream-finding-id>"],
     "title":"...","detail":"...","action":"<one-line remediation>","fix":"<diff or steps>",
     "effort_minutes":15,"sources":["gitleaks","security-lens"],
     "decomposition_plan":{"verdict":"confirmed","current_responsibilities":[],
       "keep_in_place":{},"target_components":[],"steps":[],"behavior_contracts":[],
       "risks":[],"architect_decision_ref":"docs/plans/...md"}}
  ],
  "summary": {"total":0,"critical":0,"high":0,"medium":0,"low":0,"by_category":{},"by_tier":{}}
}
```

**Field semantics:**
- **`evidence_strength`** — `verified` means a deterministic check or repro supports the finding;
  `strong-inference` means named evidence supports the reasoning but no repro exists; `possible`
  means the observation still needs verification. This field never carries dispute state.
- **`judgment`** — `objective` for measurable/reproducible conditions; `interpretive` for design,
  naming, maintainability, or trade-off judgments. Interpretive does not mean unimportant.
- **`status`** — workflow state, separate from evidence: `open`, `disputed`, `resolved`, or
  `accepted-risk`. A cross-lens contradiction is `status: disputed`, not low confidence.
- **`caused_by`** — zero or more upstream finding IDs. Store one direction only and derive affected
  descendants in the renderer; real causes may form a DAG, not a tidy tree.
- **`decomposition_assessments` / `decomposition_plan`** — every runtime size candidate receives a
  factual verdict. `confirmed` is valid only when the linked `subtype: decomposition` finding carries
  the complete Architect target design defined in the canonical workflow doc; otherwise the report
  is INCOMPLETE and its health score is withheld.
