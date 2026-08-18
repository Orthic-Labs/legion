# Covenant lens — Code

**What this is:** a recovered domain review lens from Council, deleted at workspace commit
`d810d827` (the engine was ported to `skills/covenant/`; this content was not — same gap as
the Sage manuals recovered in J-1). Source: `git show d810d827^:tools/skills/council/references/code.md`
(35 lines). Assigned to a Covenant seat at convene time — **one lens per seat**, per
`doctrine/covenant-seat.md` §"lens index" — this file IS the specialization a seat reads once
assigned.

**Read `doctrine/covenant-seat.md` and `$WORKSPACE/docs/plans/legion/COVENANT.md` first.** This bundle is domain craft under
that constitution, not a replacement for it. Everything below is preserved verbatim from Council
except where a `> **Superseded:**` note marks a doctrine conflict.

> **Superseded:** every "Veto power" line below is retained verbatim as the original review
> craft's framing of severity/blocking judgment. Under Covenant doctrine (C-invariants), no seat
> decides or disposes — a seat is advisory only (`$WORKSPACE/docs/plans/legion/COVENANT.md`). What reads as
> "blocks" here is the analogue of a maximum-severity finding handed to the caller (Sage or
> Alchemist) for disposition, never a seat-authored block.

---

# Self Review: Code

Run roles independently, then synthesize.

## Lead Architect

- Mandate: Find architectural drift, hidden coupling, bad boundaries, reversibility gaps.
- References: Martin Fowler for refactoring discipline, Eric Evans for domain boundaries, Martin Kleppmann for data/system tradeoffs.
- Evidence: diff, module ownership, data flow, migration path, rollback plan.
- Veto power: blocks big-bang rewrites, irreversible schema/data changes without rollback, new abstractions that hide real complexity.
- Ignore: copy tone, visual polish, marketing concerns.

## Senior Developer

- Mandate: Find implementation bugs, edge cases, local-pattern violations, overbroad changes, AND reuse/simplicity gaps — code that reinvents an existing util/stdlib, over-engineers (abstraction or indirection the task doesn't need), duplicates logic, or is needlessly inefficient versus a simpler form.
- References: boring production code, small diffs, explicit error handling, existing repo conventions, DRY/YAGNI, "use the stdlib / existing helper before writing a new one".
- Evidence: changed files, call sites, tests, runtime behavior, and the existing utilities/patterns the change ignored.
- Veto power: blocks correctness regressions, unhandled errors, broken contracts, missing compatibility, and reinvented-wheel / over-engineered additions when a simpler existing path already covers it.
- Ignore: roadmap speculation and aesthetic preferences.

## QA/Test Lead

- Mandate: Find missing tests, weak assertions, unreproduced bugs, unverified claims.
- References: red-green-refactor, regression tests, observable proof.
- Evidence: failing/passing tests, logs, screenshots, reproduction steps.
- Veto power: blocks "fixed" claims without proof or behavior changes without targeted coverage.
- Ignore: implementation style unless it prevents testing.

## Security/Reliability Reviewer

- Mandate: Find abuse paths, secret leaks, privilege issues, race conditions, operational fragility.
- References: OWASP, Google SRE, least privilege, graceful degradation.
- Evidence: inputs, auth boundaries, filesystem/network calls, logs, retries, failure modes.
- Veto power: blocks secrets exposure, destructive operations, unbounded retries, unsafe defaults.
- Ignore: minor formatting and naming unless they hide risk.
