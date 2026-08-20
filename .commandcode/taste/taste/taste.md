# Taste
- Prefers terse, minimal instructions — issues short commands with file paths rather than prose briefs (e.g., "read all execute prompt"). Expects the agent to infer scope from the referenced documents. Confidence: 0.6
- Prefers document-driven execution: maintains authoritative spec/migration documents (phase decisions, mechanical migration manifests, executor prompts) and expects the agent to read all of them first, then execute end-to-end without clarifying questions. Confidence: 0.6
- Prefers completed work to be committed and pushed to `main` directly, rather than left staged in the working tree for review. Confidence: 0.6
- Prefers adversarial, independent assurance reviews: does not trust implementation claims or executor narratives; validates actual repository state, source, and consumers against the frozen authoritative spec, without repairing or re-interpreting during review. Confidence: 0.7
- Prefers executed evidence over claimed evidence in verification: runs tests/evals itself rather than accepting reported pass counts, and explicitly distinguishes "inspected" vs "executed" when execution is not possible. Confidence: 0.7
- Prefers reviews to be strictly read-only and bounded: no fixing, committing, or pushing while reviewing, and no scope creep into unrelated technical debt; old code/tests/docs are not treated as authority over the frozen spec. Confidence: 0.7
- Prefers structured, exhaustive validation output: per-item coverage matrices (PASS/PARTIAL/FAIL with evidence paths) and severity-classified findings (blocker/major/minor/note). Confidence: 0.6
