**REVISE.** Verified false-clean paths require changes before implementation. All three challenging seats returned usable reviews; UNRESOLVED is not triggered. No files changed.

My requirement trace, derived from T1–T4 before weighing seats:

- **T1 — PARTIAL:** deliver completed whole-repository Ember audit, using Mac fallback if needed. Design specifies acceptance; packet supplies no completed run. “Full” does not independently require every lens to inspect every line.
- **T2 — MET at design level:** explain large-repository failure causally. Packet identifies repeated work, packet multiplication & completion constraints.
- **T3 — MISSING explicit answer:** establish whether Audit uses RightKit fsearch. Current Rust engine has no fsearch/fsindex/search integration references. RightKit’s [fsindex backend](<workspace>/rightkit/crates/rightkit-fsindex/src/backend/macos.rs:1) incorporates fsearch code; that does not establish Audit integration.
- **T4 — PARTIAL:** design addresses index-first execution, shared reads, other inefficiencies, competitor research, review styles & revision scopes. Installed behavior remains acceptance work; Ponytail research omitted its primary skill. Supplied record contains Sage/architect work followed by Council.

Convener framing is broadly faithful. Treating scaled design as context cannot exempt inherited, load-bearing assumptions from review. Council adjudication is authorized; recording decisions follows adjudication. Read-only instruction controls this turn. Packet’s committed/uncommitted descriptions conflict; inspected checkout is now `f70455c`, distinct from packet’s `1b802f52`. C8 is a proposal to decide, not evidence extraction already works.

Verification below addresses every numbered finding. **VERIFIED** can establish an omission without proving its predicted failure.

| Seat | Finding-by-finding ruling |
|---|---|
| **Wonder** | **F1 WRONG as stated:** §6 already gates P1 behind P0; explicit seam acceptance remains useful. **F2 VERIFIED:** pinned cache API fit is unevidenced. **F3 UNGROUNDED:** missing staffing/minimum corpus does not establish delivery failure. **F4 UNGROUNDED:** language ordering is optimization advice. **F5 VERIFIED:** alias comparison semantics need specification. **F6 VERIFIED:** reflection lacks explicit budget. **F7 VERIFIED:** Windows proof comes late; moving smoke coverage is optional. |
| **DeepSeek** | **F1 WRONG:** Astra D2 expressly approved labelled sampling. **F2 WRONG:** Council rulings & subsequent decision records are compatible. **F3 VERIFIED packet omission, now resolved:** cited doctrine prohibits single-PR review; report contract is versioned. **F4 VERIFIED:** compatibility/reversion unspecified. **F5 VERIFIED:** ownership records lack consumer. **F6 VERIFIED for optional debt ledger; WRONG for learnings**, explicitly required by chosen threshold. **F7 VERIFIED scheduling alternative**, not proven dependency freedom. **F8 VERIFIED:** revision descriptions conflict. |
| **Kimi** | **F1 UNGROUNDED as “dependency-free”:** scopes still need shared snapshot/tool contracts; earlier parallel development is viable. **F2 VERIFIED:** lockfile divergence produces incomplete runs; auto-install remedy rejected. **F3 WRONG for T1:** Mac explicitly satisfies authorized fallback; Windows portability still needs evidence. **F4 VERIFIED:** pinned cache fit remains unproven. **F5 VERIFIED:** packet lacks measured pre-change reproduction. **F6 VERIFIED:** additions are optional. **F7 VERIFIED:** observable gates exist; preserving their exact wording is unjustified. |
| **Fable** | **F1 VERIFIED:** failed medium anchors can leave `pass`. **F2 VERIFIED:** reflection can remove status weight without resolving evidence. **F3 VERIFIED with correction:** key already contains `rulesetDigest`, but resolved rules/database freshness & environment are unspecified. **F4 VERIFIED omission:** PR merge-base semantics absent; reverse-diff failure is conditional. **F5 VERIFIED provenance omission; cap violation UNGROUNDED** unless mandatory coverage actually shrinks. **F6 VERIFIED compatibility/baseline gaps; mandatory flag/numeric target UNGROUNDED. F7 VERIFIED** undefined history window & optional Git writes; inevitable digest divergence unproven. **F8 VERIFIED** snapshot lifecycle/staged-resolution gaps; rebuild prediction ungrounded. **F9 VERIFIED:** stale premise, missing budgets & retry termination. |
| **GLM** | **F1 VERIFIED:** global storage/recovery policy absent. **F2 VERIFIED:** custom-command trust boundary unspecified. **F3 VERIFIED:** concurrent writers/lock recovery unspecified. **F4 VERIFIED specification gap:** `ls-files -s` alone cannot establish worktree cleanliness; “Git is broken” inference rejected. **F5 VERIFIED:** operational cache metrics unspecified. **F6 VERIFIED:** PR acquisition failure semantics unspecified. **F7 VERIFIED:** snapshot installation executes PR-controlled code without defined containment. **F8 VERIFIED:** old redacted excerpts persist absent eviction policy. |
| **GLM Flash** | **F1 VERIFIED optional surface**, downgraded from defect. **F2 WRONG:** execution efficiency directly serves T4; deferral remains an option. **F3 VERIFIED:** pinned cache fit unresolved. **F4–F7 VERIFIED as optional alternatives**, not required removals: result caching, selective fixes, carry-forward & crate placement. **F8 UNGROUNDED:** corpus inadequacy/excess unmeasured; calibrating statistical sensitivity is sensible. |

Contradictions resolve from evidence:

- Sampling approval exists in [decisions.md](<workspace>/decisions.md:25). Neither another approval nor exhaustive-only Ember acceptance is required.
- [Report contract](engine/crates/legion-contracts/src/report.rs:32) explicitly validates version 1. Schema uncertainty is closed; migration design remains open.
- Fresh [Ponytail skill](https://raw.githubusercontent.com/DietrichGebert/ponytail/main/skills/ponytail-review/SKILL.md) requires connected-code review & concrete cases; it recognizes both marker conventions. Renderer formatting alone cannot establish parity.
- CodeRabbit excludes untracked files unless requested; C6 is Legion’s deliberate behavior choice, not exact parity. `--no-untracked` also does not restore unstaged-only behavior. [Official CLI documentation](https://docs.coderabbit.ai/cli)
- Git status can write index metadata; fetch can update tags/mapped refs despite suppressing `FETCH_HEAD`. Both need explicit controls. [Status](https://git-scm.com/docs/git-status), [fetch](https://git-scm.com/docs/git-fetch)

Merged findings, with final tiers/classifications:

| Final finding | Attribution | Tier / classification |
|---|---|---|
| Failed anchors/disputes can become clean; verified location also does not prove scanner claim’s semantics. | Fable F1/F2; adjudicator | **P0 / IN_SCOPE_DEFECT** |
| Cache equivalence lacks complete input/provenance bindings. `audited.json` inside deletable cache additionally changes `since-last` scope after deletion. | Fable F3/F5/F7; GLM F4; adjudicator | **P1 / IN_SCOPE_DEFECT** |
| Scoped bytes/comparison rules need precision. Changed-line-only counting misses regressions manifesting in unchanged callers. | Wonder F5; Fable F4/F8; Kimi F2; adjudicator | **P1 / IN_SCOPE_DEFECT** |
| PR execution, shared storage, concurrency & recovery boundaries are incomplete. Writable hardlinks/dependency links can also modify source state. | GLM F1–F3/F7/F8; adjudicator | **P1 / IN_SCOPE_DEFECT** |
| Baselines, pinned cache compatibility, schema migration, resumable driver termination & total reasoning budgets need explicit acceptance. | Wonder F2/F6; DeepSeek F4/F8; Kimi F4/F5; Fable F6/F9; Flash F3 | **P1 / MISSING_EVIDENCE** |
| Explicit fsearch integration answer must replace adjacent-product inference. | Own trace; Wonder | **P1 / MISSING_REQUIREMENT** |
| Earlier scope delivery, smaller config, deferred author records/result caching/selective fixes & calibrated corpus are valid simplifications. | Helpful seats; Flash F1/F4–F8 | **P2 / OPTIONAL_VALUE** |

Unadopted dissents: reject exhaustive-only acceptance, excluding Council from solvable decisions, automatic PR dependency installation, blanket P2 deletion, mandatory fallback flags & arbitrary corpus counts. Their premises are contradicted, unsafe, or unmeasured. Do not retain impossible guarantees merely because they are measurable: external scanners/builds reread files, while fresh model runs need not produce identical reports.

Binding rulings:

| Decision | Ruling |
|---|---|
| **C1** | **APPROVE WITH CHANGES.** Reuse only deterministic providers with complete content, configuration, platform/environment & resolved external-data bindings, plus authenticated provenance. Report `reused` separately from executed; retain `--fresh` & test/build exclusions. |
| **C2** | **APPROVE WITH CHANGES.** Lexical imports remain labelled ranking/context signals. Bind extractor, configuration, scoped content & graph provenance; absence never proves non-use. Graph replacement must respect actual coverage. |
| **C3** | **APPROVE.** One engine/skill supports repository & diff review. Update contradictory doctrine alongside scope delivery; style claims require behavioral acceptance, not renderer goldens alone. |
| **C4** | **APPROVE WITH CHANGES.** Failed required anchors & unresolved material disputes force incomplete evidence. Confidence requires semantic justification; an anchored tool hit is not automatically proven. Version contract & preserve compatible readers. |
| **C5** | **REJECT as written.** Count regressions caused by scoped changes, including unchanged locations; exclude only established pre-existing issues. Specify PR merge-base semantics, durable incremental baselines & explicit unresolved re-anchoring states. |
| **C6** | **APPROVE.** Uncommitted means staged + unstaged + untracked, with explicit exclusion option. Document behavioral change & test combinations, including partially staged files. |
| **C7** | **APPROVE WITH CHANGES.** Creation remains request-driven. Bound/validate instructions & learnings; preserve original severity/status. PR-controlled configuration cannot grant execution authority; use trusted policy, Guard & isolated execution. |
| **C8** | **APPROVE WITH CHANGES.** Extract one versioned Blueprint core/CLI; Membrane pins it, Legion pins optional host compatibility. Until available, ship index-first Audit with labelled lexical floor & unproven graph-dependent claims. Bind freshness to scoped bytes; resident transport is not prerequisite. |

Before implementation, amend design with these rulings, complete cache/snapshot identities, durable incremental state, trust boundaries, migration & failure semantics. Limit cold/warm equality to deterministic artifacts with frozen inputs; measure index/excerpt I/O separately from provider I/O.

Phase order:

1. Freeze reviewed revision, record C1–C8 with this adjudicator’s delegated approval, capture bounded pre-change evidence & seed benchmark.
2. Finish P0 closure/packet/ingest work; prove installed Ember completion with truthful coverage.
3. Develop minimal persistent index & core PR/range/commit/staged scopes in parallel after shared snapshot contracts settle; test Mac & Windows.
4. Deliver semantic verification, review renderers & installed PR acceptance; then measured execution optimizations, optional caching/config expansion & selective fix reruns. Run Blueprint extraction separately against its versioned integration contract.
