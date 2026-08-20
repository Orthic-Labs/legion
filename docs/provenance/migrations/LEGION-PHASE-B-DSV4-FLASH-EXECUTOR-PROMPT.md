# DeepSeek V4 Flash — Legion Phase B Executor Prompt

Execute the frozen Legion semantic migration against:

```text
Repository: Orthic-Labs/legion
Baseline: 57d00b1f5d337e72d5cf58274a8c6a258e1ee6f3
```

Authoritative migration inputs, in precedence order:

```text
1. legion-ssot-phase-a-final-v1.1.md
2. LEGION-PHASE-B-FINAL-MECHANICAL-MIGRATION-v1.0.md
3. live repository evidence at the frozen baseline
```

Phase A defines what Legion must mean.
Phase B defines exactly how to migrate the repository to that meaning.

Your job is now implementation, not architecture.

## Rules

- Execute Phase B in its dependency order.
- Do not reinterpret or redesign Phase A or Phase B.
- Do not preserve old semantics merely because current code/tests implement them.
- Do not add RAG, embeddings, graph routing, a new classifier service, or another hierarchy.
- Do not reopen the frozen host-adapter/install architecture.
- Do not fold separate Arcane optimization/performance work into this migration.
- Do not make Sage a mandatory architecture, diagnosis, contract-compilation, or contract-sealing stage.
- Do not hand-edit generated projections.
- Re-home useful method before retiring its old owner.
- Preserve compatibility interfaces without preserving obsolete ontology.
- If unexpected repository evidence contradicts the manifest and cannot be resolved mechanically, stop only that affected unit and record the exact `SEMANTIC_BLOCKER` specified by Phase B. Continue independent work.
- Do not ask for semantic clarification already settled by Phase A/Phase B.

## Required workflow

1. Verify the baseline and capture baseline tests exactly as Phase B M-001 specifies.
2. Execute M-002 onward in the exact dependency waves in Phase B §20.
3. Run focused validation after each migration group, especially:
   - contract/Arcane tests after the Legion/Sage seal correction;
   - routing/discovery tests after the routing cutover;
   - host conformance/safety tests after projection regeneration.
4. Regenerate all derived outputs through their generators.
5. Re-home and then retire superseded active owners.
6. Run the complete Phase B §21 validation suite.
7. Perform an independent, current-state Completion Validation against the original request and the two frozen migration documents.
8. Report completion evidence, not narration.

## Completion report

Return:

```text
BASELINE
- HEAD
- dirty state
- baseline legion:check result
- baseline full-test result

IMPLEMENTED
- M-001 … M-031 status
- exact files changed/created/retired
- generated outputs regenerated

BLOCKERS
- any unresolved SEMANTIC_BLOCKER
- affected action only

VALIDATION
- focused tests
- routing/discovery evals
- contract-seal/Arcane tests
- host conformance/safety
- generator drift
- pnpm legion:check
- pnpm test vs baseline
- stale-semantic scans
- ownership uniqueness

FINAL STATE
- permanent root SSOT path
- archived provenance paths
- retired owners
- remaining compatibility shims and why

COMPLETION STATUS
PRODUCED: YES|NO
VERIFIED: YES|NO
COMPLETION-VALIDATED: YES|NO
COMMITTED: YES|NO
PUSHED: YES|NO
DEPLOYED: YES|NO
```

Do not claim a stage that was not actually completed.

If the migration passes, the permanent architecture source is:

```text
docs/LEGION-CANONICAL-SSOT.md
```

`AGENTS.md` remains the live operational constitution.

Phase A, Phase B, and the old `SSOT-v2` become migration provenance only.
