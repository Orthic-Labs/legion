# Audit lens routing

Read this file before Stage 2 of `/audit` or every iteration of `/audit-fix`.

## Execution boundary

The reasoning lenses run on native host subagents or inline in main session, never on external
model APIs. This is the locked audit-specific exception: prior provider limits and network
registration repeatedly hung full audit runs. Do not route lenses through an external model worker
or HTTP model provider.

The read-only lenses are `doc-drift`, `architecture`, `correctness`, `ai-slop`, `naming`,
`dead-file`, `schema`, `security`, `minimize`, and `performance`, plus conditional `a11y`,
`data-safety`, `resilience`, `platform-parity`, and `release-readiness`. Fan the applicable lenses
out in one parallel wave.

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

When explicit specifications or standards are present, run two independent contracts in the same
parallel wave:

- Route SPEC fidelity to `correctness`, with only exact requirements, acceptance criteria, public
  contracts, applicable ADR consequences, and scoped implementation evidence. Preserve per-
  requirement `satisfied|partial|wrong|missing|unrequested|unproven` status and exact citations.
- Route STANDARDS to `ai-slop`, with repository-local standards, config/lint policy, documented
  exceptions, and relevant code shape. Its verdict and report stay separate from SPEC. Do not
  substitute generic taste for a missing standard.

Absent spec/standards input is typed `unproven` unless whole-repo non-applicability is explicitly
justified with searched scope and reason. Present but incomplete or inaccessible input is typed
`unproven` with missing evidence. Neither is silently clean, and one axis never closes the other.

## Model routing

- Tier follows the kind of reasoning, not a blanket floor: judgment lenses carry the false-negative
  risk, so a lowest-tier seat is not acceptable for them. (Restored: the all-lowest-tier rule of
  2026-09-19 left every lens on the cheapest model and the judgment lenses under-reasoned.)
- `security`, `architecture`, and `correctness` run on the strongest available native tier. They
  decide exploitability, structural shape, and real bugs, and a miss there is expensive.
- `schema`, `minimize`, `doc-drift`, `data-safety`, `resilience`, `release-readiness`, `ai-slop`, `naming`, and `performance` are judgment lenses and run on at least the mid tier; they receive raw logic, exact contracts, or failure-mode evidence. `ai-slop` carries the suite's highest false-positive risk, so its findings stay capped as `manual.md` states.
- `dead-file`, `a11y`, and `platform-parity` are mechanical:
  the lowest available native tier is fine. They receive scoped evidence; a11y and platform parity
  still receive relevant raw excerpts.
- If a tier is unavailable on the host, use the next tier down and record the downgrade in the lens
  output; never silently relabel a lowest-tier run as a judgment-tier run.
- Conditional lenses spawn only when their trigger fires.
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

## Correctness verify-pass

Correctness lenses can over-claim. Every correctness finding must survive either a deterministic
reproduction run by the main agent or an adversarial skeptic pass prompted to refute it. A claim
without verification does not render as a finding.

## Reconciliation

The main session reads every lens output, deduplicates across lenses and scanners, re-checks every
`file:line` locally, assigns severity/evidence/fixability, resolves contradictions, and owns the
final report. Review seats suggest findings; scanner evidence and local verification decide.

If parallel seats are unavailable or constrained, run the lenses inline over `facts.json` and the
scoped reads. Preserve the same evidence and verification rules.
