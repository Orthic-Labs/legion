# `tools/` Path Reconciliation

**Date:** 2026-08-18
**Scope:** Full legion surface — engineering, commercial, research
**Type:** Reference reconciliation only. No behavioural or doctrinal change.

---

## Why

Legion absorbed a set of skills and libraries that previously lived under a workspace root
alongside `tools/`. The absorption moved the files but left references pointing at their
pre-absorption locations, in two legacy forms:

```text
tools/skills/audit-visual/references/design-slop.md      # stale relative prefix
D:/workspace/tools/skills/designer/engine/scripts/detect.mjs # hardcoded Windows absolute path
```

Neither resolves from a legion checkout. The practical effect was that skill guides cited
gates, detectors, and references by paths that no longer existed, while the providers that
replaced some of them went uncited.

This pass reconciles those references against the real tree. It rewrites nothing else.

---

## Method

1. Inventory every `tools/...` and `D:/workspace/tools/...` occurrence across the repository
   (1,532 raw matches).
2. Classify each against the current tree: resolves as-is, resolves after prefix strip,
   relocated elsewhere, absent, or not a path at all.
3. Exclude record, evidence, and fixture surfaces from any rewrite (see below).
4. Rewrite only the operational-documentation subset where the target provably exists.
5. Verify every rewritten path resolves; confirm no test regression.

---

## What was excluded from rewriting, and why

These surfaces carry `tools/` paths as **recorded fact**. Rewriting them would falsify a
record or invalidate a digest.

| Surface | Refs | Reason |
|---|---:|---|
| `docs/rights-audit/inventory.json` | 605 | Rights/provenance inventory keyed by original paths |
| `qualification/**` | 361 | Frozen evidence lanes, gate results, run logs |
| `_audit/**` | 29 | Audit records |
| `lib/orthic_transcripts/tests/fixtures/*.jsonl` | — | Captured real transcripts used as fixtures |
| `skills/*/examples/*`, `skills/*/evals/*` | — | Receipt-backed example artifacts; the receipts contain `sha256` digests over these files and record the original absolute `route_path` |
| `bench/corpora/**` | — | Benchmark corpora |

**Not paths at all.** `tools/list` and `tools/call` in `integrations/mcp/server.mjs` and
`tests/integrations/mcp.test.mjs` are MCP JSON-RPC method names. Excluded from the analysis
entirely; an earlier pass wrongly counted them as broken references.

---

## What was changed

**50 files, 118 references rewritten.** Every rewrite is a prefix normalisation to a
legion-root-relative path whose target exists:

```text
tools/skills/audit-visual/references/design-slop.md  ->  skills/audit-visual/references/design-slop.md
D:/workspace/tools/skills/designer/engine/scripts/detect.mjs  ->  skills/designer/engine/scripts/detect.mjs
tools/lib/minimize/minimize_gate.py  ->  lib/minimize/minimize_gate.py
```

Distribution:

| Area | Refs rewritten |
|---|---:|
| `skills/designer` | 52 |
| `doctrine/bundles` | 26 |
| `references/` | 8 |
| `skills/audit-visual` | 6 |
| `skills/writing` | 5 |
| `skills/seo` | 5 |
| `skills/content` | 5 |
| `skills/commit` | 3 |
| `lib/goalroute` | 3 |
| `skills/ads` | 2 |
| `UPGRADE-PLAN.md` | 2 |
| `skills/tasklist` | 1 |

Three references were relocations rather than plain strips, resolved by unique basename match:

```text
tools/skills/audit/bench/run-bench.mjs        ->  bench/run-bench.mjs
tools/skills/audit/audit_provider.py          ->  audit_provider.py
tools/skills/audit/references/lens-cues.md    ->  references/lens-cues.md
```

---

## What remains unresolved

These references were **left untouched** because the target does not exist anywhere in legion.
They are recorded here as open items, not silently rewritten.

### Class A — cited by skill guides, absent from legion

Each of these is named by an operational guide as something to run or read. They did not come
across in the absorption.

| Reference | Cites | Cited by |
|---|---:|---|
| `tools/lib/auto-jury.mjs` | 18 | `designer/specialists/static-creative`, `writing`, others — an opt-in external jury |
| `tools/skills/_shared/anti-slop.md` | 8 | `writing/references/manual.md` (**mandatory** gate), `designer`, `audit-visual` |
| `tools/skills/_shared/parametric-design.md` | 8 | `writing/references/manual.md` (**mandatory** gate), `audit-visual` |
| `tools/lib/design-gate.mjs` | 3 | `designer/specialists/surface-design` Phase 5d |
| `tools/lib/OKF-OUTPUT.md` | 3 | — |
| `tools/lib/CONTEXT-ENGINEERING.md` | 3 | — |
| `tools/skills/_shared/illustrate/GUIDE.md` | 2 | `designer/SKILL.md` illustration route |
| `tools/lib/human-eyes-gate.mjs` | 1 | `designer` Phase 6 |
| `tools/lib/open-for-review.mjs` | 1 | `designer` Phase 6 |
| `tools/skills/.system/imagegen/SKILL.md` | 1 | `content/references/routing.md` |
| `tools/skills/.system/skill-creator/scripts/quick_validate.py` | 1 | `content/specialists/production-routing` |

**Note on anti-slop.** `tools/skills/_shared/anti-slop.md` is absent, but the capability is
present and superseded it: `providers/copy/anti-slop.mjs`, ten registered rules in
`registry/rules/copy/anti-slop.json`, and a corpus at `bench/corpora/copy/anti-slop`. The
guides cite the retired markdown rather than the provider that replaced it. Resolving this is
a guide-to-provider reconciliation, not a missing file — deliberately **not** done in this pass,
which is limited to path normalisation.

### Class B — external toolchain, not absorbed by design

Coherent tooling that appears to live outside legion on purpose, shared with other skills.
Left as-is pending confirmation that this is intended.

```text
tools/agent-rules/manage.py          (8)
tools/review/dual_review.py          (3)
tools/rhook/                         (3)
tools/research-core/ledger.py        (2)   <- cited by skills/research/references/claim-ledger.md
tools/research-core/{independence,contradictions,citecheck}.py
tools/pipelines/transcribe/carousel.py (2)
tools/recipes/video/                 (2)
tools/demo/                          (2)
```

`skills/research/references/claim-ledger.md` names `tools/research-core/ledger.py` as "the
executable validator" for the evidence and claim ledger. No `research-core` exists in legion.
If the research ledger is meant to be self-contained here, this is a gap; if `research-core` is
shared infrastructure, the reference should say so explicitly.

---

## Verification

| Check | Before | After |
|---|---|---|
| `pnpm legion:check` | PASS | PASS |
| `pnpm test` | 730 tests, 716 pass, 14 fail | 730 tests, 716 pass, 14 fail — identical set |
| Rewritten paths resolving | — | 118/118 |

The 14 failing tests are pre-existing and environmental (`ERR_MODULE_NOT_FOUND:
@rightkit/hooks` — `node_modules` not installed in this checkout). The failing set is
byte-identical before and after, so this change introduces no regression.

---

## Follow-up, not done here

1. Confirm Class B is external by design; if so, mark those references as external in the
   citing guides so they stop reading as broken.
2. Decide the fate of each Class A item — restore, or update the guide to cite what replaced it.
3. Reconcile skill guides against `providers/` and `registry/rules/` generally. The anti-slop
   case shows guides can cite retired artifacts while the provider that superseded them goes
   uncited. That is a content change and belongs in its own pass.

---

## Addendum — pass two: non-`tools/` absolute paths

The first pass matched only `tools/`-prefixed references. A follow-up sweep covered every
Windows absolute path in the repository (674 occurrences outside record and fixture surfaces).

**Rewritten: 9 references across 3 files**, normalising two further legacy roots where the
target exists in legion:

```text
D:/workspace/legion/lib/handoff/transcript-handoff.py  ->  lib/handoff/transcript-handoff.py
D:\workspace\tools\skills\qa\scripts\qa-shot.mjs       ->  skills/qa/scripts/qa-shot.mjs
D:/workspace/legion/lib/dispatch-validator/validate-dispatch.py -> lib/dispatch-validator/validate-dispatch.py
```

Files: `skills/handoff/references/manual.md`, `skills/audit-visual/references/visual-qa-capture.md`,
`doctrine/bundles/legion-worker-capsule.md`.

### Deliberately left as-is

| Category | Example | Why |
|---|---|---|
| Windows browser discovery | `C:\Program Files\Google\Chrome\Application\chrome.exe` in `lib/qa-engine/qa.mjs`, `audit-runtime.mjs`, `skills/seo/scripts/render_gap.mjs`, designer CDP detector | Correct platform-specific paths with `process.env.ProgramFiles` fallbacks |
| Path-validator test data | 265 `D:/workspace/...` in `lib/dispatch-validator/test_validate_dispatch.py` and its skills mirror, `lib/goalroute/scripts/test_validate_route.py` | The tests exist to exercise Windows path handling |
| `tests/windows-portability.test.mjs` | 15 | Same reason |
| External application | `D:\workspace\sampleapp\...` in `skills/content/specialists/transcription` | Separate app, not a legion path |
| Studio workspace convention | `D:/workspace/tasks/handoffs/`, `D:/workspace/tasks/dispatches/` | Cross-project output location, not a repo path |
| Receipt-backed examples | `skills/dispatch/examples/`, `skills/tasklist/examples/` | Digests recorded over these files |

### Package scope

`package.json` `files` is an explicit allowlist. The record surfaces excluded from rewriting —
`qualification/` (4.5M), `docs/`, `_audit/`, `bench/` — are outside it and do not ship. The
rewritten files are inside it, so these fixes reach consumers.

### Verification (both passes)

| Check | Before | After |
|---|---|---|
| `pnpm legion:check` | PASS | PASS |
| `pnpm test` | 730 / 716 pass / 14 fail | 730 / 716 pass / 14 fail — identical set |
| Rewritten paths resolving | — | 127/127 |

Unresolved items are tracked in `docs/open-issues.md`.
