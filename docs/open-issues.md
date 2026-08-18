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
| `_shared/anti-slop.md` | 8 | `writing/references/manual.md` marks it a **mandatory** gate for every prose deliverable; also cited by `designer`, `audit-visual` | See note below |
| `_shared/parametric-design.md` | 8 | `writing/references/manual.md` marks it a **mandatory** gate | High |
| `lib/auto-jury.mjs` | 18 | `designer/specialists/static-creative`, `writing` — opt-in external jury | Low (opt-in) |
| `lib/design-gate.mjs` | 3 | `designer/specialists/surface-design` Phase 5d, a **hard gate** | High |
| `lib/human-eyes-gate.mjs` | 1 | `designer` Phase 6 | Medium |
| `lib/open-for-review.mjs` | 1 | `designer` Phase 6 | Medium |
| `_shared/illustrate/GUIDE.md` | 2 | `designer/SKILL.md` illustration route | Medium |
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
> is `tools/research-core/ledger.py`.

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
tools/review/dual_review.py            (3)
tools/rhook/                           (3)
tools/pipelines/transcribe/carousel.py (2)
tools/recipes/video/                   (2)
tools/demo/                            (2)
D:\Claude\scraperight\...              (7)  external app, skills/content/specialists/transcription
D:/Claude/tasks/handoffs/, /dispatches/     studio workspace convention, not a legion path
```

---

## 4. Publication policy gate cannot run

```text
$ node scripts/check-publication-policy.mjs --channel public
publication blocked: release/publication-policy.json is absent
```

`MANIFEST.package.json` defines `forbiddenContentMarkers` (including Windows user-profile and Unix home-directory prefixes, and
a legacy plans path) but the policy file the checker requires is not in the repo. The marker list
is also narrower than the problem it targets: it forbids one specific `D:\Claude\docs\plans\`
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
