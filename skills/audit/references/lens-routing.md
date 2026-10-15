# Audit lens routing

Read this file before Stage 2 of `/audit` or every iteration of `/audit-fix`.

## Execution boundary

Reasoning runs through `legion audit run-reasoning`, which launches fresh, one-turn native Claude
processes under host-enforced settings. It is not a subagent fan-out. Each call receives a bounded
snapshot-only toolbox; shell, edits, MCP, plugins, and subagents are disabled. Runtime lifecycle,
scope, usage, and prerequisite behavior live in [reasoning runtime](reasoning-runtime.md).

The read-only lenses are `doc-drift`, `architecture`, `correctness`, `ai-slop`, `naming`,
`dead-file`, `schema`, `security`, `minimize`, and `performance`, plus conditional `a11y`,
`data-safety`, `resilience`, `platform-parity`, and `release-readiness`. The frozen provider plan
determines eligible lenses. Pattern cards only refine matching existing lenses; see
[pattern cards](pattern-cards.md). They do not add broad domains or bypass scope/applicability.

## Input contract

For each lens, pass the lens question, its redacted `facts.json` slice, the scoped file excerpts it
needs, and the report schema from `SKILL.md`. The native runner redacts secrets in logs. The
security lens receives scanner summaries and safe excerpts, never raw `.env` or key material.

**Excerpt compression:** use skeleton excerpts for `naming` & `dead-file` surveys.
Keep RAW, secret-redacted excerpts for `architecture`, `ai-slop`, `doc-drift`, `security`,
`schema`/contract-drift, `correctness`, `performance`, & `minimize`: semantic review needs
implementation bodies & exact citations. Never skeletonize these lanes (`minimize`/ponytail judges
`yagni`/`delete` — a one-impl trait vs a real DI seam, a wrapper that only delegates vs one that
adds logic — which a skeleton strips out; guessing from a skeleton is exactly the false-positive
trap `references/ponytail-lens.md` forbids).
When Blueprint Phase 2 exists, pass `understanding.json.architecture.coverageGaps` to the
`architecture` lens. Under an explicit best-shape/completeness request, every material
`partial|missing|undetermined` flow must appear in the lens output with its evidence and an
`architect` handoff; absence of a code file is the evidence for a documented-but-missing flow.

## Semantic routing

When explicit specifications or standards are present, preserve two independent contracts:

- Route SPEC fidelity to `correctness`, with only exact requirements, acceptance criteria, public
  contracts, applicable ADR consequences, and scoped implementation evidence. Preserve per-
  requirement `satisfied|partial|wrong|missing|unrequested|unproven` status and exact citations.
- Route STANDARDS to `ai-slop`, with repository-local standards, config/lint policy, documented
  exceptions, and relevant code shape. Its verdict and report stay separate from SPEC. Do not
  substitute generic taste for a missing standard.

Absent spec/standards input is typed `unproven` unless whole-repo non-applicability is explicitly
justified with searched scope and reason. Present but incomplete or inaccessible input is typed
`unproven` with missing evidence. Neither is silently clean, and one axis never closes the other.

## Model selection

The runtime accepts a native Claude model override with `--model`; capability preflight must pass
before execution. It does not silently downgrade tiers or substitute another provider. An unavailable
binary/model or missing safe control leaves reasoning incomplete; see [reasoning runtime](reasoning-runtime.md).
- `minimize` reads raw bodies and `references/ponytail-lens.md`; a skeleton alone cannot distinguish
  dead abstraction from a real DI, test, or extension seam.
- Semantic lanes read [semantic review](semantic-review.md) for test-quality, design-smell,
  attribution, and change-risk rules; preserve DI seams and framework conventions.

## Glob-routed rubric packs

Beyond the lens cues in [lens-cues.md](lens-cues.md), give each lens the short rubric pack whose glob
matches the files in its scope. A pack adds concrete checks; it never widens the frozen provider
plan, and a pack that matches no scoped file is simply not loaded.

| Glob | Pack | Primary lenses |
|---|---|---|
| `**/*.rs` | [rubrics/rust.md](rubrics/rust.md) | `correctness`, `security`, `resilience`, `performance` |
| `**/*.swift` | [rubrics/swift.md](rubrics/swift.md) | `correctness`, `security`, `resilience`, `platform-parity` |
| `.github/workflows/*.y{,a}ml` | [rubrics/github-workflow.md](rubrics/github-workflow.md) | `security`, `release-readiness` |
| `**/Cargo.toml` | [rubrics/cargo-toml.md](rubrics/cargo-toml.md) | `security`, `release-readiness`, `minimize` |

## Finding verification

Every proposed finding is sent to an independent, fresh verifier context without the author's
conversation or tools. It must uphold with frozen-source anchors and a concrete case, contradict
with anchored counterevidence, or remain unresolved. Unresolved findings are retained as unverified;
they are not silently withdrawn. This verifier is separate from any later product-level reproduction.

## Reconciliation

The runtime ingests verified lens output, then recomputes the report. The final report remains
authoritative; incomplete runtime, snapshot, scanner, or verification evidence prevents completion.
