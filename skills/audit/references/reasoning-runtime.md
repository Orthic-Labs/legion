# Audit reasoning runtime

`legion audit run-reasoning --run <run-dir> [--claude <path>] [--model <id>]` runs frozen reasoning
packets with native Claude. It is the current Stage 2 interface; `legion audit` freezes and scans,
then this command runs lenses, verifies findings, ingests receipts, and recomputes the report.

## Scope and source

Run packets bind the selected provider plan and immutable source snapshot. Supported scopes include
whole repository (`all|repo`), local changes (`local`), legacy unstaged-only (`uncommitted`), staged,
committed, `commit:<ref>`, `branch[:base]`, `range:<base>..<head>`, `since-last`, and attested PR
scopes. `--dir` restricts a path prefix. `local` includes committed-but-unpushed, staged, unstaged,
and untracked changes; `uncommitted` intentionally keeps legacy unstaged-only meaning. The plan
records selected/baseline identities, changed paths, and snapshot digests. Reasoning tools read this
snapshot, not live repository files. Source drift, unavailable content, symlinks, submodules, or
other snapshot gaps remain visible and can make a run incomplete. PR acquisition is bounded to
attested metadata and object-only fetch into an isolated bare cache; it does not update repository
refs or index.

`since-last` uses the last validated completed report; history advances only after full reconciliation.
An incomplete run cannot become the next baseline.

## Host boundary and lifecycle

The host preflights Claude CLI capabilities and starts one-turn processes with native tools, MCP,
shell, plugins, subagents, and session persistence disabled. The only model-call tools are
host-provided read-only operations over the frozen snapshot: `audit.read_file`, `audit.search_code`,
`audit.list_files`, `audit.read_diff`, and lexical `audit.find_callers`. Reads and replies have
bounded size, lines, file count, elapsed time, and snapshot identity. Caller results are lexical
evidence, not a semantic call graph. Missing safe controls or native executable produces a typed
incomplete result; no API provider fallback is used.

For the requested bounded Ember run, freeze a 50,000-token total budget across input and output, a
10,000-token total per physical model call (including at most 2,500 output tokens), at most 5 calls,
and width 1. These are run-scoped caps, not general CLI defaults. Each call reserves budget before
transport; observed usage and cost are reconciled afterward. Estimates govern admission and are not
actual usage or spend. Missing usage/cost remains unknown, never zero; every additional call requires
its own reservation. Planning admits at most four initial author calls and reserves at least one fresh
verification call. Deterministic host gathering uses no model call; optional cheap gathering requires
separate admission. The runtime retains partial findings and gaps when budget or runtime work stops. The reserved fresh Oracle verifier
runs at balanced-executor tier, without the author's context or tools. It may uphold with anchored
evidence, contradict with anchored counterevidence, or leave the claim unresolved; unresolved findings
are retained as unverified. Findings left outside verification admission remain present and unverified.
Authenticated usage and cost persist across calls and retries. Ingested receipts are authenticated and the report is recomputed. `done`
requires complete applicable work, no unresolved runtime/snapshot/report gaps, and final report
reconciliation.

The renderer's findings and status remain the machine source of truth. A completed run is not a
claim that semantic recall or provider accuracy has been benchmark-qualified.

## Explicit continuation

After an operator explicitly resumes a stopped audit, use
`legion audit continue --run <parent-run> --out <child-run> --operator-instruction <exact-resume-text>`.
This prepares evidence only; inspect its remaining admission before running `run-reasoning` against
the child. It reuses frozen source, scope, inventory, and deterministic evidence, without rescanning
or resetting spend. Parent artifacts remain immutable; the child binds their digests, inherits charged
reservations and physical-call/retry counts, and admits only remaining work under original ceilings.
Unknown usage/cost, changed source or ancestry, an existing sibling, or unavailable fresh-verifier
capacity refuses recovery. A historical per-call overrun remains an incomplete budget-history gap;
successful later work cannot retroactively make that call compliant. Unsupported continuation states
fail closed rather than creating a fresh allowance.

## Offline scanner prerequisites

Named security scanners run only when their frozen provider is selected and applicable. The runner
requires each executable on host `PATH`; a missing binary is `tool-missing:<tool>`, never clean.
Current named integrations are Squawk, Zizmor, ShellCheck, TFLint, Kubeconform, Kube-Linter,
Brakeman, and GolangCI-Lint. Kubeconform additionally requires a host-pinned local schema tree with
recorded version and digest; remote schema fetching is not a fallback. Project/root grouping and
file applicability are provider-specific. Install/readiness checks belong to `legion doctor`; an
absent tool remains a coverage gap.

Pattern cards refine existing lens review and are selected only when lens metadata and repository
applicability match. See [canonical pattern cards](pattern-cards.md) and
[lens routing](lens-routing.md).
