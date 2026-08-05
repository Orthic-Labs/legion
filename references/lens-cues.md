# Lens cues + CodeRabbit absorption (canonical)

Extracted from SKILL.md (2026-07-18) unchanged. The fan-out feeds each lens its cue set from here;
the absorption table is the ownership map proving no separate CodeRabbit round is needed.

## CodeRabbit absorption (no separate CodeRabbit round)

`/audit` covers CodeRabbit's review surface across existing lenses — running the CLI afterward is
redundant. The mapping (own it; if a CodeRabbit class isn't here, the lens is under-running, not the
audit under-scoped):

| CodeRabbit class | Owned by lens |
|---|---|
| Logic bugs, edge cases, races, unhandled errors, resource leaks, regressions | `correctness` (the fold) — backed by `tsc`/lint + tests |
| Security (injection, authz/IDOR, secrets, SSRF, crypto) | `security` + the scanners (`gitleaks`/`semgrep`/`audit`) |
| Performance (N+1, re-renders, blocking I/O, bundle) | `performance` (static cue + the runtime pass that *measures* it) |
| Best-practice / code smells / duplication | `ai-slop` (+ `jscpd` dup) |
| Over-engineering / dead flexibility / cut suggestions | `minimize` (full ponytail) |
| Missing tests / CI / coverage gaps | `negative_space` scanner (existence) + the **test-run gate** in the fix loop (behavior) + `/commit` coverage-on-the-change check (CodeRabbit's "you changed code, nothing tests it") |
| Diff-awareness (review just the change) | `--dir` / `--type` / `--base` scope flags (the CLI ergonomics) |

CodeRabbit's edge is that it *runs a suite of OSS analyzers and is diff-aware by default* — `/audit`
matches the first with its own scanner pool (`gitleaks`/`tsc`/`eslint`/`knip`/`jscpd`/`semgrep`/…) and
the second with the scope flags. What it does NOT do that the CLI also does: post inline GitHub PR
comments. If you want PR-inline delivery specifically, use the built-in `/review` GitHub PR
workflow (CodeRabbit as an external reviewer is retired); that is not a coverage gap in `/audit`.

## Lens cues (high-signal heuristics, applied within the relevant lens)

- `ai-slop` / `minimize`: swallowed exceptions (catch only to log + continue), functions with >3 boolean args, single-implementation interfaces that only forward, comments that restate the code, **identical comment blocks repeated across files** (LLM copy-paste tell), commented-out code blocks.
- `minimize`: tool sprawl — two deps doing the same job (e.g. two HTTP clients) or conflicting versions of a core lib (read the `outdated` + dependency list).
- `architecture`: stack suitability (is the tech overkill/misfit for the domain?) and the `negative_space.missing` list — absent tests / CI / lockfile / LICENSE are real findings, not nitpicks.
- `doc-drift`: compare doc/JSDoc/docstring params against the actual signature; flag empty docstrings that only restate the name; check README setup commands/env vars still exist.
- `doc-drift` (plan-implementation drift — the inverse direction): sweep `docs/plans/` + design docs for named symbols/identifiers and grep the tree — an approved plan whose symbols have ZERO code hits is drift, deterministic to detect. Same for commit-claim drift: when a recent commit/changelog claims "fix X", enumerate every path X implicates and verify each — a fix covering one of three paths is an open finding, not a fixed one. Public/marketing-claim files (GTM docs, site copy in-repo) are in scope: a shipped claim the code disproves is a launch-blocker class.
- `doc-drift` / `correctness` (business-constant consistency — verify-before-propagate as a lens): grep propagated values (prices, seat/device counts, wake word, version strings, URLs, key IDs) across code + tests + docs + config; any divergence is a finding citing both loci. Cheap and greppable.
- `correctness` / `performance` (desktop/Tauri targets): apply the concurrency/lock-discipline + IPC-waterfall cue sets in `references/desktop-tauri-checklist.md` §1-§2 — `Mutex::lock().unwrap()` in async, locks held across `.await`/transactions, sync `#[tauri::command]` doing I/O, missing `spawn_blocking`, sequential `await invoke()` chains, event→full-refetch storms. Every cue is one `rg` away.
- `performance` / `data-safety` (embedded-DB targets — SQLite/SQLCipher in deps): apply `references/sqlite-local-first.md` — PRAGMA posture, WAL checkpoint policy + placement, FTS5 UNINDEXED invariants, leading-wildcard LIKE, missing ANALYZE, EXPLAIN-QUERY-PLAN regression tests, unbounded history growth.
- `resilience` / `data-safety` (observability — can a prod failure be *diagnosed*, not just logged?): catch blocks that swallow an error with NO log AND no telemetry (silent catch — distinct from the `ai-slop` log-only cue: this leaves zero signal), production entry points with no crash reporter (Sentry/Crashlytics) initialized, and PII/secrets leaking into log or telemetry payloads (full request bodies, tokens, emails). Greppable: `catch {}`/`catch(e){}` with no report/log call inside; analytics/log calls passing a raw request/user object.
- `security` (desktop): env-var escape hatches + Tauri config posture per `references/desktop-tauri-checklist.md` §3-§4 — release-reachable `std::env::var` behavior switches without `#[cfg(debug_assertions)]`, prod CSP with dev origins, `facts.checks[contract_mirror]` uncalled-handler surface, `facts.checks[tauri_capabilities]` broad-grant flags (allow-all/default on fs·shell·http·process, shell exec/spawn, wide `**` scopes) + exposed-command count.
- `security` (positive assurance): answer a fixed question set WITH grep evidence, not just emit findings — does anything disable TLS/cert-validation? does any secret/token reach a log sink? do all mutating routes/commands enforce auth/validation? A cited clean answer is a deliverable; silence is not.
- `security` (invariant falsification): extract THIS app's own stated security invariants from its docs ("renderer receives opaque grants", "history never leaves the device"), then test each against the command/IPC/network surface. A doc-drift × security hybrid — the app's claims are the checklist.
- `negative_space` / `correctness` (test quality): tests that assert source-code substrings or are snapshot-only are FALSE coverage — classify, don't count. Read `meta.test_skew` (code-vs-test file counts per subtree): heavy skew on a critical subsystem is a finding; `meta.unsafe_sites` clusters with no error-path test likewise.
- `security` / `minimize`: read `debt_markers.meta` — surface `ponytail:` shortcuts with no upgrade trigger and TODO/FIXME density.
- `security` (app-level — beyond the scanners): reason over the application-security taxonomy in `references/security-checklist.md` (100 checks: authn, authz/**IDOR**, injection classes, XSS/CSP, CSRF/CORS, **SSRF**, crypto, uploads, API hardening). The scanners catch secrets/CVEs/SAST patterns; this catches the *logic* they miss. Every finding still needs a real `file:line`. Deterministic backers where the project configures them: `eslint-plugin-security`, semgrep app-sec rulesets — absent tool = NOT-SCANNED, never "clean".
- `performance` (static, catch the smell — the runtime pass then *measures* it): React re-render hazards — unmemoized Context provider `value={{...}}`, inline object/array/arrow props to memoized children, state/context lifted so high all consumers re-render on every change, missing `React.memo`/`useMemo`/`useCallback` on hot paths, a component defined inside another component's render, `key={index}`, unvirtualized large lists, derived state recomputed in render. Deterministic backers (if the project configures them in eslint): `@eslint-react/no-unstable-context-value`, `react/no-unstable-nested-components`, `react/no-array-index-key`, `react-hooks/exhaustive-deps`, `@arthurgeron/react-usememo/require-usememo`.
- `performance` (full-stack — the cue above is FRONTEND-only): for the server side the static lens is blind to, reason over `references/performance-checklist.md` — **database (N+1 / missing indexes / full-table loads / no pooling)**, network waterfalls + un-parallelized requests, caching strategy (Cache-Control, server/edge/SWR, invalidation), bundle/assets (code-split, tree-shake, image/font), backend (blocking I/O, cold starts, background jobs), and Core Web Vitals (LCP/CLS/INP + a CI perf budget). N+1 and missing indexes are the highest-yield catches and are greppable (ORM calls inside loops, query sites without an index migration).
