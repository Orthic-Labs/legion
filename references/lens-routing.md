# Audit lens routing

Read this file before Stage 2 of `/audit` or every iteration of `/audit-fix`.

## Execution boundary

The reasoning lenses run on native host subagents or inline in main session, never on external
model APIs. This is the locked audit-specific exception: prior provider limits and network
registration repeatedly hung full audit runs. Do not rebuild the retired `api-worker.py --batch`
path inside this skill.

The read-only lenses are `doc-drift`, `architecture`, `correctness`, `ai-slop`, `naming`,
`dead-file`, `schema`, `security`, `minimize`, and `performance`, plus conditional `a11y`,
`data-safety`, `resilience`, `platform-parity`, and `release-readiness`. Fan the applicable lenses
out in one parallel wave.

## Input contract

For each lens, pass the lens question, its redacted `facts.json` slice, the scoped file excerpts it
needs, and the report schema from `SKILL.md`. `collect-facts.mjs` redacts secrets in logs. The
security lens receives scanner summaries and safe excerpts, never raw `.env` or key material.

**Excerpt compression:** compress the excerpts for structure/survey lenses (`architecture`,
decomposition, can-it-be-better, `ai-slop`, `naming`, `dead-file`) by running source files through
`skel <file>` (tree-sitter skeleton, ~78% fewer tokens) — those lenses reason about shape, not
bodies. Keep RAW excerpts for `security`, `schema`/contract-drift, `correctness`, `performance`,
and `minimize`: they need the exact tokens, never skeletonize (`minimize`/ponytail judges
`yagni`/`delete` — a one-impl trait vs a real DI seam, a wrapper that only delegates vs one that
adds logic — which a skeleton strips out; guessing from a skeleton is exactly the false-positive
trap `references/ponytail-lens.md` forbids).
When Blueprint Phase 2 exists, pass `understanding.json.architecture.coverageGaps` to the
`architecture` lens. Under an explicit best-shape/completeness request, every material
`partial|missing|undetermined` flow must appear in the lens output with its evidence and an
`architect` handoff; absence of a code file is the evidence for a documented-but-missing flow.

## Model routing

- Use strongest available judgment-capable seat for `architecture`, `security`, `schema`, `correctness`, `minimize`,
  `doc-drift`, `data-safety`, `resilience`, and `release-readiness` because these require raw logic,
  exact contracts, or failure-mode reasoning.
- Use a mechanical/fast seat for `ai-slop`, `naming`, `dead-file`, `performance`, `a11y`, and
  `platform-parity`. A11y and platform parity still receive the relevant raw excerpts.
- Conditional lenses spawn only when their trigger fires.
- `minimize` reads raw bodies and `references/ponytail-lens.md`; a skeleton alone cannot distinguish
  dead abstraction from a real DI, test, or extension seam.

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
