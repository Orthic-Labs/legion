# Commit — guarded, autonomous commit + push

```text
PRIMARY_DELIVERABLE: Frozen diff disposition, focused checks, plus bounded repair result.
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: One applicable lens wave plus focused checks finish with at most two repair or recheck cycles.
```

Use only frozen candidate paths or hunks. Do not widen callers, tests, history, branch policy, rebuilds, durable-memory writes, commit, or push without a matching manifest capability.

`/commit` is `audit-fix` aimed at the **git diff specifically**, then it commits and pushes. It is the
pre-commit safety net: the same lenses `/audit` runs whole-repo, scoped to just what's changing, fixed
autonomously, so broken or over-engineered code never lands. It uses **our own audit engine** —
`correctness` is the CodeRabbit fold, `minimize` is the full ponytail hunt — **not** the external
CodeRabbit or ponytail binaries (those aren't required; the engine absorbs both, see
`skills/audit/SKILL.md` "CodeRabbit absorption" + `references/ponytail-lens.md`).

## When to use / not

- **Use:** "/commit", "review then commit", "fix this diff and push", any guarded commit-and-ship.
- **Not:** whole-repo health → `/audit` / `audit-fix`. PR-inline GitHub comments → the built-in
  `/review` GitHub PR workflow (external CodeRabbit is retired). Designing a refactor →
  `architect`. A trivial doc-only typo commit needs no gate —
  just commit (still add the co-author trailer).

## Procedure

1. **Scope the diff — one explicit delivery unit, not a union of everything lying around.**
   `--type local` enumerates ALL local changes (committed-but-unpushed ∪ staged ∪ unstaged ∪ new
   untracked). **Treat that as an inventory, not automatically as one commit.** Those four states can be
   four different tasks from four different sessions; silently fusing them produces a commit whose
   message is true of nothing. Narrow with `--type uncommitted` (working tree only), `--type committed`
   (last commit), `--base <branch>`, or an explicit path/hunk set. Do NOT use `--type all` here — in
   the audit engine `all` means *whole-repo* (no diff scope) and returns an empty `changed_files`.
   ```bash
   audit-facts <root> --type local
   ```
   Reads `scope.changed_files` from `facts.json` (mode `diff`) — every later step operates on THAT set only.
   If the change set is empty, stop: nothing to commit (`git diff --name-only` + `git diff --cached --name-only`).

   **Mixed-intent detection.** Before accepting the set as one commit, look for unrelated clusters —
   different package/workspace boundaries, unrelated directories, or two distinct semantic changes
   (a feature *and* an unrelated refactor). When they are clearly separable, propose splitting into
   two commits (or a stacked sequence) rather than shipping one incoherent unit. Say which files fall
   into which cluster and let the user pick.

   **Freeze the candidate tree before validating anything.** Analysis runs on a mutable working tree: a
   formatter, a pre-commit hook, a watcher, or an editor autosave can change a file between the moment
   a lens read it and the moment it gets committed. Then you shipped something nothing validated.
   ```bash
   git add -- <the files in scope> && CAND=$(git write-tree)   # frozen candidate identity
   # … validate, fix, re-validate; after committing:
   test "$(git rev-parse HEAD^{tree})" = "$CAND" || echo "TREE DRIFT — do not push"
   ```
   A mismatch means the committed content is not the validated content: re-run the gate, do not push.
   Record `candidateTree` in the gate artifact (step 8).

   **Blast radius via the Cortex graph (when `.agent/index.json` exists in the repo).** Run
   `cortex graph impact` over the changed files/symbols. Two uses, both diff-scoped:

   (a) **bigger-scheme check** — callers/dependents of the changed symbols that are NOT in the diff
   are the risk surface; if impact shows heavy fan-in onto a changed public contract, escalate the
   correctness/schema lens to those call sites instead of trusting the diff boundary. (b) **doc-claim
   drift, both directions** — any doc claims the graph links to changed files get a drift check NOW
   (does the claim still hold after this diff?). **And the reverse: when a doc is itself in the diff,
   re-verify its claims against the code it references, even though that code did not change.** A
   README rewrite that claims behaviour the untouched code does not have passes every code-side check
   and is exactly the drift this gate exists to catch. This is the "sync docs as part of done" rule
   made mechanical.

   **`CODE-FELL-SHORT` on the diff.** If a doc in or linked to this change says done / shipped /
   implemented / verified, sweep the code backing that claim for debt markers:
   ```bash
   git grep -nIE "(TODO|FIXME|unimplemented!\(\)|todo!\(\)|NotImplemented|raise NotImplementedError|throw new Error\(['\"]not implemented)" -- <files backing the claim>
   ```
   A "done" claim over a file carrying an unimplemented marker is a hard finding, not generic drift.
   Cortex catches this repo-wide; here it catches it before the claim ships.

   **Graph freshness, not just graph existence.** Run `cortex doctor` first. A **stale** graph is
   worse than no graph — it answers impact queries with last week's structure and manufactures
   confidence. Trust impact when doctor is `ready`; mark it low-confidence and lean on the post-fix
   re-check when `degraded`; treat `stale`/`broken`/`corrupt` as no graph.

   Because `/commit` runs *pre*-commit, the committed graph does not contain the change under review.
   Where the engine supports it, query with the working-tree overlay so impact reflects the candidate
   content; otherwise state that impact is computed against the pre-change graph. **Never build or
   rebuild the graph mid-commit.**

   **No graph is a recorded gap, not a silent pass.** For a low-risk diff, skip and note it. But when
   the change touches a **public API, auth, a migration, persisted data, or crosses a package
   boundary**, absent or stale impact evidence must be recorded as `impact: incomplete` and answered by
   *broadening validation* — read the callers directly, widen the test selection — not by proceeding as
   though the risk surface were known to be empty.

2. **Run the diff lenses on the changed files only.** Fan them out as parallel NATIVE subagents (per
   `/audit` "Lens fan-out" — haiku mechanical / sonnet judgment, never opus, NO external model APIs;
   inline in the main session is the fallback and often right for a small diff) over JUST
   `scope.changed_files`, running the lenses that apply to a
   change — **not** the whole-repo ones:

   **Fast clean path:** when deterministic checks and applicable lenses return no findings, do not
   manufacture comments or classification work. Record what ran, run the relevant tests, then
   continue to the commit step. Structure is for real findings, not ceremony.

   **False-positive self-critique (run before surfacing ANY finding).** The dominant failure mode of
   an AI reviewer is the confident wrong comment. Before you surface a finding, force the counter-question
   "why might I be wrong?" against it: is this generated/vendored code, framework-sanctioned behavior, a
   test-only path, an intentional invariant enforced elsewhere, or already handled on a line outside the
   diff window? Re-read the actual body (never judge from the skeleton) and, for a `possible`-strength
   finding, run the counterfactual "if this shipped unchanged, would it actually fail — with what input?"
   If you cannot name the failing input, downgrade to `possible` or drop it. A dropped false positive is
   a better review than a surfaced guess.

   **Surfaced finding format (CodeRabbit-style):** emit this only for a finding that changes the
   fix/ship decision.
   ```text
   File: <path>:<line>
   Problem: <one-line issue>
   Why it matters: <impact>
   Suggested fix: <concrete change>
   Category: correctness | security | performance | maintainability | style
   Severity: critical | high | medium | low
   Evidence strength: verified | strong-inference | possible
   Fixability: AUTO | GUIDED | MANUAL
   ```
   These axes are independent: severity is impact; evidence strength is certainty; fixability is
   who can safely apply the change. A verified mechanical security fix can be AUTO when narrowly
   scoped and covered by a test; leaked credentials, authz changes, ambiguous policy changes, and
   destructive fixes are hard stops. Interpretive/style findings never auto-fix unless an existing
   formatter or repo rule makes the change deterministic.

   **A finding may point outside the diff — say where it was caused and where it will manifest.** The
   defect in a changed contract often surfaces in an *unchanged* caller, serializer, config consumer, or
   downstream package. Forcing every finding onto a changed line hides exactly the dangerous ones. Use
   two fields:
   ```text
   causedByChangedSpan: <path>:<line>      # in the diff — the change that introduces the risk
   manifestedAtSpan:    <path>:<line>      # may be OUTSIDE the diff — where it breaks
   linkedBy:            <graph edge / import / call path that connects them>
   ```
   The out-of-diff location must be connected by real evidence (a graph edge, an import, a call path
   you verified), never by suspicion. `causedByChangedSpan` is always required; that is what keeps this
   diff-scoped.

   **Risk level drives scrutiny — compute it, don't eyeball it.** Score from: fan-in on changed
   symbols, count of changed symbols with no test, membership of a sensitive path (auth, payments,
   crypto, migrations, concurrency, permissions, public contracts, persisted data), and whether a
   status-bearing doc claim links to the change.

   | Level | Required before commit |
   |---|---|
   | **low** | applicable lenses + fast suite |
   | **medium** | + focused regression test on the changed behaviour |
   | **high** | + read the out-of-diff callers impact named; widen test selection to them |
   | **critical** | + user-gated: surface the risk and the evidence, do not autonomously push |

   Sensitive-path membership alone floors the level at **high**.
   | run on the diff | skip (whole-repo only) |
   |---|---|
   | `correctness` (CodeRabbit fold — bugs/edge/races/leaks, RAW bodies, sonnet) | `negative_space` (repo-wide presence) |
   | `security` (injection/authz/secrets in the change, sonnet) | repo-wide `dead-file` sweep |
   | `minimize` (FULL ponytail on the change — RAW bodies, sonnet) | `doc-drift` (unless docs are in the diff) |
   | `ai-slop` (dup/slop introduced) · `schema` (contract/serialization drift) | `performance` **runtime** pass (no app boot here) |
   | `performance` **static** (N+1 / re-render introduced by the change — these ARE diff-introducible) | repo-wide lenses on unchanged files |
   | `a11y` — only if the diff touches UI (JSX/markup/templates) | |
   | `data-safety` — only if the diff touches a migration or raw/ORM SQL (see `references/migration-safety.md`) | |
   The **lens set is chosen by diff profile**, using the same policy `/audit` applies (see
   `skills/audit/SKILL.md` → "Lens selection policy") so the two skills cannot drift apart:
   doc-only, config-only, code non-test, test-only, migration/SQL, new-dependency, UI, public-API,
   performance-targeted. Take the union when several profiles match. Every finding needs a real
   `file:line` per the two-span rule above; verify each locally before acting.
   - **New dependency in the diff?** A `package.json`/`Cargo.toml`/`pyproject` change that ADDS a dep is a
     high-risk event — CVE-check it (`deps_cve`), license-check it, and ponytail-challenge it (`minimize`:
     does stdlib/native already do this? is it one-impl?). Flag a new dep that's unused, redundant, or
     replaceable. Go past the direct entry: diff the **transitive** set the lockfile now resolves (a
     one-line manifest add can pull 40 packages), check whether any **integrity hash changed on an
     existing** dep, whether the registry/source moved, and whether the package runs **install
     scripts**. License-check means comparing the dep's license against *this project's* license
     (a GPL dep in an MIT project is a licensing problem, not a checklist tick). If the dep is kept, run
     the install (`pnpm install` / `cargo fetch` / the repo's own) so the lockfile resolves cleanly
     before committing — never commit a manifest change with a stale or conflicted lockfile.
   - **Coverage on the change** (CodeRabbit's signature catch): if the diff adds or changes a function/branch
     and NO test exercises it, flag it. Existence of a test dir ≠ this change is tested. Report it
     **per file, not as one boolean** — a binary "tests pass" hides which touched symbols are actually
     exercised:
     ```json
     {"file":"src/auth/mfa.ts","touched":["MFA.verify","MFA.challenge"],
      "covered":["MFA.verify"],"uncovered":["MFA.challenge"],
      "tests":["test/auth/mfa.test.ts"],"verdict":"partial"}
     ```
     Aggregate to a ratio: below 0.8 is a high finding, below 0.5 critical, a file with no test
     touching it at all is critical on any non-trivial change. This is a read of the diff against the
     test set — no extra test execution needed. If the repo has no test infrastructure, the per-change
     gate is `UNPROVEN`, never `clean`.
   - **Missing companion change ("what should have changed but didn't").** A diff is often incomplete, not
     wrong. When the change touches a public API/type/contract, a config key, a migration, or user-facing
     behavior, check that its *companions* moved too: the tests, the doc/README/changelog that describes it,
     the type definitions, an `.env.example`, telemetry/analytics for a new flow. A shipped behavior whose
     changelog/decision-doc still describes the old state is a defect (the "sync docs as part of done" rule).
     Flag the absent companion, not just the present code.

3. **Fix autonomously (diff-scoped audit-fix).** Same tiers + loop as `audit-fix`:
   - **AUTO** — `eslint --fix`/`ruff --fix`/formatter, remove the unused import/dep the scanner named.
   - **GUIDED** — apply when the evidence makes the fix unambiguous.
   - **MANUAL** — bounded ones in the working tree; decompose/architecture in the diff go **via
     `architect`**. Slice until safe; never park by size.

   **Any fix that touches a file outside the diff's own tree, or adds/removes a file, is user-gated.**
   Show the affected paths first. AUTO stays same-file; GUIDED may reach a sibling only when the
   evidence makes it unambiguous; anything wider is MANUAL by definition — a pre-commit gate that
   quietly edits files the user did not change is doing something other than guarding a diff.

   Re-run step 1-2 after fixing. Loop until the diff is clean or no-progress is proven.
   **No-progress needs stable fingerprints, not identical text** — lens wording varies run to run, so
   byte-equality is too strict, while identical finding *IDs* are too loose (they hide a severity drop
   or a partial fix). Declare no-progress when the fingerprint set is unchanged AND no severity fell
   AND no affected-span count shrank AND the same gates still fail. Decomposition/minimize are
   deterministic — they reappear until truly fixed.

   **Then run the tests — scanners clean ≠ behavior intact (the gate before any commit).** Run the
   project's fast/unit suite, or the tests covering the changed files (`pnpm test`/`cargo test`/`pytest`
   — the repo's own command). A green suite is what proves your fixes didn't break behavior. A **red
   test is a HARD STOP — do not commit, do not push**; fix it or revert and report. Do NOT auto-run
   integration/e2e suites that hit a live DB/network (the `prod-db-guard` exists for a reason) — if only
   those cover the change, say so and treat shipping as user-gated, never silently skip.

4. **Commit message — intent-linked, not diff-summarized.** A message derived only from the diff
   restates *what the code now says* and loses *why*, which is the part a future reader cannot recover.
   Pull the "why" from the task, issue, plan, or acceptance criteria this change serves, and reference
   it. Changelog voice, what + why, never a file list. If there is no stated intent to link, say what
   problem it solves in one clause — "because X was silently failing" beats "update handler".

   **Discover the repo's commit policy rather than assuming it.** Check whether this repo requires a
   DCO `Signed-off-by`, GPG/SSH commit signing (`git config commit.gpgsign`, branch rulesets), or its
   own trailer convention, and comply. Never fabricate co-authorship or a signoff on someone's behalf.

   Stage ONLY the files this run touched (`git add <those>`), never `git add -A` over unrelated dirty
   state. Commit with the running agent's co-author trailer — this skill is shared, so use the trailer
   for whoever is executing, not a hardcoded one:
   ```
   <summary line>

   <what changed and why>

   <co-author trailer for the running agent>
   ```
   - **Claude Code:** `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` (per its harness rule).
   - **Codex / other:** its own trailer, or none — never stamp the Claude trailer on a Codex commit.
   - **PR walkthrough (only when this change will become a PR** — a feature branch, or the user asks).
     Skip for a direct-to-`main` workspace commit (it would be noise). When warranted, save a
     CodeRabbit-style summary to `.audit/<ts>/pr-walkthrough.md` for reuse as the PR body: a 2–3 sentence
     high-level "what/why" walkthrough, a bulleted Changes-by-area list, and a Test Coverage note
     (tests added/changed, or the coverage-on-the-change gap). This is the walkthrough CodeRabbit is
     loved for; the git commit message stays the terse changelog line above.

5. **Push — fetch first, never force by default.** Record the remote ref before and after so the push
   is verified rather than assumed:
   ```bash
   git fetch origin <branch>
   BEFORE=$(git rev-parse origin/<branch>)          # what the remote was
   git push origin <branch>                          # plain push; NEVER --force
   git rev-parse origin/<branch>                     # confirm it moved to your commit
   ```
   A rejected push means the remote moved: fetch, integrate, re-run the gate. **Never** `--force`.
   History rewrite requires explicit user authorization *and* the expected-value form
   `--force-with-lease=<ref>:$BEFORE`, so a concurrent push cannot be silently destroyed.
   If no upstream is set, set it (`git push -u origin <branch>`) only when the branch is clearly this
   work's branch.

   **Pushed is not shipped.** Report the delivery state honestly and never conflate these:
   `local-validated` → `committed` → `pushed` → `remote-CI-passed` → `review-approved` → `merged` →
   `deployed` → `verified-in-production`. `/commit` gets you to **pushed**. It cannot observe CI,
   review, merge, or deploy, so it must not describe its own success as "shipped", "live", or "done".
   Saying "pushed; CI not yet observed" is the accurate close.
   - **GitHub inline handoff.** If the remote is GitHub and this change is (or is becoming) a PR, offer
     to bridge local findings to the PR: "Push done — run `/review` to post these as inline GitHub PR
     comments?" On yes, pass `.audit/<ts>/pr-walkthrough.md` as the PR body and the diff-scoped findings
     as inline comments. This closes the one real gap vs. CodeRabbit — GitHub-native delivery — without
     giving up the local test-execution + fix-before-it-leaves-the-machine advantage.

6. **Graph freshness (post-push, non-blocking).** If the repo has a Cortex index
   (`.agent/index.json`), refresh it now so the graph tracks reality: `cortex build` in the
   background (or queue it). Never block or fail the commit/push on this — a rebuild error is
   reported as residue, not a gate. Repos without an index are left alone; adopting Cortex is a
   deliberate per-repo decision, not a commit side effect.

7. **Knowledge extraction (only for a genuinely durable pattern).** Reviews should improve future
   reviews. If a fix in this run corrected a mistake you'd expect to recur across the project — a
   repeated anti-pattern, a repo convention you had to be corrected on, a "never do X here" — capture it
   as a durable rule through a durable-memory capability, if the host provides one, so it surfaces
   next time. Do NOT log one-off, change-specific fixes; the bar is "a standing preference a future
   agent should know," not a changelog of this diff. Casual/one-time fixes are noise.

   **A commit-time inference is a low-authority candidate, not a user instruction.** One incident
   observed by an agent is weaker evidence than something the user actually said, and it must not enter
   durable memory at the same authority. Emit it as an evidence-backed candidate (`source: commit`,
   scoped to this repo) for normal admission and promotion. The direct high-authority write is reserved
   for a rule the **user** authored.

8. **Emit Minimize commit authority.** Write `.audit/minimize/commit-review.json` for exact staged
   tree using `lib/minimize/minimize_gate.py commit init-review`, update it with actual lens
   findings/new files/new dependencies, require `CLEAN`, then write
   `.audit/minimize/commit-receipt.json`. Re-run `commit verify` immediately before every commit.
   Missing, stale, open-finding, policy-drift, validator-drift, or staged-tree mismatch blocks commit.
   Never use `--no-verify`.

9. **Emit the gate artifact.** Write `.audit/<ts>/commit-gate.json` so the run is auditable after the
   fact instead of living only in a scrolled-away chat turn:
   ```json
   {"scope":{"type":"local","files":[],"clusters":[]},"candidateTree":"<sha>","committedTree":"<sha>",
    "riskLevel":"low|medium|high|critical","impact":{"state":"ready|incomplete","fanIn":0},
    "lensesRequired":[],"lensesRan":[],"findings":[],"fixesApplied":[],
    "coverage":{"ratio":0.0,"perFile":[]},"tests":{"command":"","passed":true},
    "hardStops":[],"deliveryState":"pushed","pushedOid":"<sha>"}
   ```
   This is also what makes the next run able to say "this finding is back" (see the fingerprint rule in
   step 3) rather than rediscovering it as if it were new.

## Hard stops — surface, do NOT push

Pushing is outward-facing. Refuse to push (and say why) when:
- A **secret** is in the diff (gitleaks hit) that auto-fix can't resolve — never push a leaked key.
- A **test is failing** (or the only coverage is an integration/e2e suite that needs live services) — never push red.
- A **`data-safety` finding** confirms data loss or a prod-locking migration (`references/migration-safety.md`) — surface it, don't push.
- Fixes **won't converge** (no-progress with findings still open) — report the open findings, don't ship a broken state.
- The current branch is a **protected / shared default branch** and the repo's norms require a PR.
  **Discover the norms, don't assume them** — a shared skill cannot carry one machine's habits as a
  parenthetical. Read the actual remote/default branch, branch protection or rulesets, required status
  checks, CODEOWNERS, and signing policy (`git remote`, `git symbolic-ref refs/remotes/origin/HEAD`,
  `gh api repos/{owner}/{repo}/rulesets` or `/branches/{b}/protection`, a `CODEOWNERS` file). Where
  direct-to-default is genuinely the norm for that repo, proceed; where protection or a required check
  exists, open a PR. When it cannot be determined, ask.
- The **candidate tree does not match the committed tree** (step 1) — the content that shipped is not
  the content that was validated. Re-run the gate; do not push.
- A **non-code-risk gate** trips: credentials, payments, legal/compliance, destructive data ops, external accounts, or business positioning — those are the user's call, per `audit-fix`.
- The push target or remote is ambiguous/unverified.

## Relationship to /audit

`/commit` = `audit-fix` ∩ the diff, plus the commit + push. Same engine, same lenses, same fix tiers,
same `architect` decompose route — just scoped to changed files and ending in a shipped commit. Run
`/audit` for whole-repo health; run `/commit` to guard a specific change on its way out.
