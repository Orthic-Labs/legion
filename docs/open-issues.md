# Open Issues

Tracked items found during the 2026-08-18 path reconciliation that could not be fixed in place.
Each entry states what is broken, what depends on it, and what would close it.

---

## 1. Missing artifacts cited by operational guides

These are named by skill guides as things to run or read. No copy exists anywhere in legion, and
`git log --all` confirms none has ever been committed here — they did not come across in the
absorption rather than being deleted afterwards.

| Artifact | Cites | Depended on by | Severity |
|---|---:|---|---|
| `skills/_shared/anti-slop.md` | 8 | `writing/references/manual.md` marks it a **mandatory** gate for every prose deliverable; also cited by `designer`, `audit-visual` | See note below |
| `skills/_shared/parametric-design.md` | 8 | `writing/references/manual.md` marks it a **mandatory** gate | High |
| `lib/auto-jury.mjs` | 18 | `designer/specialists/static-creative`, `writing` — opt-in external jury | Low (opt-in) |
| `lib/design-gate.mjs` | 3 | `designer/specialists/surface-design` Phase 5d, a **hard gate** | High |
| `lib/human-eyes-gate.mjs` | 1 | `designer` Phase 6 | Medium |
| `lib/open-for-review.mjs` | 1 | `designer` Phase 6 | Medium |
| `skills/_shared/illustrate/GUIDE.md` | 2 | `designer/SKILL.md` illustration route | Medium |
| `lib/OKF-OUTPUT.md` | 3 | — | Low |
| `lib/CONTEXT-ENGINEERING.md` | 3 | — | Low |
| `skills/.system/imagegen/SKILL.md` | 1 | `content/references/routing.md` | Low |
| `skills/.system/skill-creator/scripts/quick_validate.py` | 1 | `content/specialists/production-routing` | Low |

### Note on anti-slop — not actually missing

The capability is present and superseded the cited markdown:

```text
providers/copy/anti-slop.mjs
registry/rules/copy/anti-slop.json     (10 registered rules)
bench/corpora/copy/anti-slop
```

The guides cite the retired file rather than the provider that replaced it. **Closing this is a
guide edit, not a file restoration.** The same is plausibly true of other rows above — each needs
checking against `providers/` and `registry/rules/` before anyone restores a file.

---

## 2. `research-core` is absent and cannot be verified from this session

`skills/research/references/claim-ledger.md` states:

> The durable truth for a run is `evidence.jsonl` plus `claims.jsonl` … The executable validator
> is `src/lib/research-core/ledger.py`.

It further names `independence.py`, `contradictions.py`, and `citecheck.py` as deriving
independence clusters, contradiction views, and citation-to-sentence support.

**None of these exist in legion, and none appear anywhere in its git history.**

This matters more than the other rows: the claim/evidence ledger is the backbone of the research
skill and the epistemic floor that the writing skill inherits. As it stands, the guide documents a
validation pipeline that cannot run from a legion checkout.

### Could not check the other repository

The suspicion is that `research-core` remained in the personal `claude` workspace repository under
a different owner and was never migrated. That repository is visible to this account but **could
not be attached to this session** — cross-owner repository adds are not supported once a session
already holds sources from another owner:

```text
add_repo: cross-tier adds are not supported in v1
```

**To resolve:** start a fresh session with that repository as the initial source and search it for
`research-core/`. If found, decide between:

- **(a) absorb** — move `research-core/` into legion (e.g. `lib/research-core/`) and update
  `claim-ledger.md` to the new path; or
- **(b) declare external** — mark it explicitly in `claim-ledger.md` as shared infrastructure that
  lives outside legion, so the reference stops reading as broken.

Until one of those happens the research skill's central contract is undocumented as to where its
validator actually lives.

---

## 3. Other external toolchain references, unconfirmed

Left untouched pending confirmation that they are external by design. If they are, the citing
guides should say so explicitly.

```text
tools/agent-rules/manage.py            (8)
src/lib/review/dual_review.py            (3)
tools/rhook/                           (3)
tools/pipelines/transcribe/carousel.py (2)
src/lib/media-recipes/video/                   (2)
tools/demo/                            (2)
D:\workspace\sampleapp\...              (7)  external app, skills/content/specialists/transcription
D:/workspace/tasks/handoffs/, /dispatches/     studio workspace convention, not a legion path
```

---

## 4. Publication policy gate cannot run

```text
$ node scripts/check-publication-policy.mjs --channel public
publication blocked: release/publication-policy.json is absent
```

`MANIFEST.package.json` defines `forbiddenContentMarkers` (including Windows user-profile and Unix home-directory prefixes, and
a legacy plans path) but the policy file the checker requires is not in the repo. The marker list
is also narrower than the problem it targets: it forbids one specific `D:\workspace\docs\plans\`
path rather than legacy absolute path roots generally.

**Suggested:** add a repo-root-relative path check to CI so absolute workspace paths cannot
re-enter shipped files. The reconciliation pass fixed the existing ones; nothing currently
prevents new ones.

---

## 5. Pre-existing test failures (environmental)

14 of 730 tests fail in a clean checkout:

```text
Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@rightkit/hooks'
  imported from packages/arcane/host/claude-code-adapter.mjs
```

Not path-related. The failing set is byte-identical before and after both reconciliation passes.
Listed here only so it is not mistaken for regression.


---

## Verified against the workspace repository

The earlier passes could not attach `operator/claude` (`add_repo: cross-tier adds are not
supported in v1`) and so left §1–§3 as suspicions. That repository was inspected directly at
commit `05580e67`. Each artifact was checked both on disk and against `git log --all
--diff-filter=D` to distinguish "never existed" from "deleted after the absorption".

**Result: nothing was lost in the absorption.** Twelve of the thirteen §1 artifacts are present
in the workspace and were simply not carried across. One never existed in either repository.

| Artifact | Status |
|---|---|
| `skills/_shared/anti-slop.md` | Present in workspace — **superseded**, see below |
| `skills/_shared/parametric-design.md` | Present in workspace, no legion equivalent |
| `skills/_shared/illustrate/GUIDE.md` | Present in workspace, no legion equivalent |
| `lib/auto-jury.mjs` | Present in workspace, no legion equivalent |
| `lib/human-eyes-gate.mjs` | Present in workspace, no legion equivalent |
| `lib/open-for-review.mjs` | Present in workspace, no legion equivalent |
| `lib/OKF-OUTPUT.md` | Present in workspace, no legion equivalent |
| `lib/CONTEXT-ENGINEERING.md` | Present in workspace, no legion equivalent |
| `research-core/{ledger,independence,contradictions,citecheck}.py` | **All present in workspace** |
| `lib/design-gate.mjs` | **Absent from both repositories, and from the full history of each** |
| `skills/.system/**` | A generated sync tree, untracked in the workspace since `fbb938e1` |

### §2 research-core — answered

`research-core/` did remain in the workspace, exactly as suspected. All four modules named by
`skills/research/references/claim-ledger.md` exist there. This is option **(b)**: the code is not
lost, it is external. `claim-ledger.md` should say so explicitly rather than citing a path that
resolves in neither a legion checkout nor a legion install.

### §1 design-gate.mjs — the one real void

`lib/design-gate.mjs` is cited by `designer/specialists/surface-design` Phase 5d as a **hard
gate**. It exists in neither repository and appears in neither repository's history. A guide
declares a mandatory gate backed by nothing. This is the only entry here that is a genuine loss
rather than a migration gap, and it cannot be closed by copying a file.

### §1 anti-slop — mechanism migrated, content did not

The note in §1 was right, and the reconciliation it called for has been done. `providers/copy/
anti-slop.mjs` exports `detectAntiSlop(items, options)`, its ten rules are registered in
`registry/rules/copy/anti-slop.json`, and `bench/corpora/copy/anti-slop` is its fixture corpus;
`tests/content-l3.test.mjs` and `tests/content-l3-b6-013.test.mjs` cover it (14/14 pass). The
eight guides that cited the retired markdown now cite the provider, and
`skills/writing/references/manual.md` documents the callable interface and states that every rule
is `interpretive` under `bounded-review` — a candidate to adjudicate, not an automatic edit.

Note that the provider is reachable only by direct import: it is **not** registered in
`registry/providers.json` (63 providers, none in the `copy` family) and so does not participate in
the frozen audit provider plan. The guides are now accurate about what exists; wiring the copy
family into the registry is separate work.

**Correction — do not read the repointed citations as proof of parity.** An earlier revision of
this section called the row "closed". That was too strong, and the 2026-08-18 system audit
(`SHR-002`) is right to challenge it. The provider replaced the retired file's *mechanism*, not its
*content*:

```js
for (const ban of options.explicitBans ?? []) { … detectorKind: 'deterministic' }
```

The deterministic banned-phrase path is a socket that legion ships **empty**. All ten registered
rules are `interpretive`. The retired `skills/_shared/anti-slop.md` carried roughly 35 banned terms, 11
often-empty intensifiers, and 15 often-empty phrases — that vocabulary is exactly what populates
`explicitBans`, and nothing in this package supplies it.

So the mandatory editorial contract has silently narrowed: guides that once cut a fixed vocabulary
outright now raise only interpretive candidates. Closing this properly means either shipping the
vocabulary as a rules file that feeds `explicitBans`, or making an explicit decision to narrow the
contract and saying so in the guides. Repointing the citations was necessary — they pointed at a
file this package does not carry — but it is not the parity decision.

---

## 6. Skill validator was never repointed at legion

`_audit/validate_skills.py` still hardcoded the pre-absorption workspace:

```python
REPO_ROOT = Path("D:/workspace")
SKILL_ROOT = Path("tools/skills")
AUDIT_DIR   = Path("legion/_audit")
```

Run from a legion checkout it reported `MISSING_SKILL_ROOT: D:/workspace/tools/skills` — the tool
that exists to catch exactly this class of drift was itself a casualty of it, which is why the
absorption read as complete.

**Fixed in this pass.** The root now derives from the file's own location, and `resolve_layout()`
detects a legion checkout (`skills/`, `_audit/`) or a workspace checkout (`tools/skills/`,
`legion/_audit/`) so both consumers keep working. Alias targets now resolve against the skill tree
as well as the catalogue.

`docs/SKILL-ARCHITECTURE.md` — which records the router/direct split — lives in the workspace and
has no legion equivalent. That split cannot be reconstructed from the package (manifests carry
`provenance`, not routing role), so its absence is reported as typed degradation
(`SKILL_INDEX_UNAVAILABLE`, warning) and the dependent checks are skipped rather than failing
every skill as unindexed. Establishing a legion-native catalogue would close it properly.

### Regression it immediately caught

`skills/qa/SKILL.md` frontmatter did not parse:

```yaml
description: Add, run, or audit local web or Tauri app QA: hidden servers, ...
```

The unquoted `QA:` makes the YAML mapping invalid, so the skill had **no parseable description and
no discoverable frontmatter at all**. The pre-absorption file at `c1c7e818^` was correctly quoted;
the quotes were dropped when the description was rewritten during the move. Restored. The
validator now reports 0 errors against a legion checkout.

---

## 7. `_audit/test_skill_regression_contracts.py` asserts pre-absorption skill bodies

The file computed its own root as `parents[3]` with `SKILLS = ROOT / "tools" / "skills"`, which
from `<legion>/_audit/` resolved to `/home/user/tools/skills` — outside the repository entirely.
Every assertion therefore died on `FileNotFoundError` before reaching its subject, so the suite
reported failures that told you nothing.

**Fixed in this pass (paths only):** `ROOT` is now `parents[1]` and `SKILLS = ROOT / "skills"`, and
the four `render-report.mjs` call sites point at the legion root where that file now lives.

**Still open (content):** with the paths correct the assertions now reach real files and fail on
substance, because they encode skill bodies that the absorption deliberately replaced:

| Test | Asserts | Why it fails |
|---|---|---|
| `test_council_preserves_jury_independence_and_ship_gate` | `skills/council/SKILL.md` | `council` was retired into `covenant` (`c1c7e818`) |
| `test_eval_manifests_match_current_public_contracts` | `skills/council/evals/evals.json` | same |
| `test_commit_uses_shared_axes_and_fast_clean_path` | the string `Fast clean path` | present in `6cd56ca`, removed when `/commit` became a thin package router |
| `test_architect_uses_blast_radius_not_single_file_absolutes` | pre-absorption architect body | skill rewritten |
| `test_audit_v2_contract_is_rendered_and_legacy_reports_still_work` | pre-absorption audit body | skill rewritten |
| `test_workspace_skill_surface_is_consolidated_and_routes_are_live` | workspace skill surface | that surface moved here |

These were **not** rewritten in this pass. Deciding what the packaged skills should now guarantee
is a contract decision, not a path fix, and inventing replacement assertions would produce a test
suite that asserts whatever the code already does. They need an owner.

`_audit/test_audit_harness.py` is a different story and is now **fixed**: its fixture wrote
`capability-aliases.json` and `compatibility-matrix.json` to
`<tmp>/tools/skills/legion/_audit/`, a path the validator never resolved under either layout.
Corrected to `<tmp>/legion/_audit/`; the suite passes 10/10, having failed before this pass.
