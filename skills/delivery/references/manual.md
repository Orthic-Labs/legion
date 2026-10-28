# Bounded engineering delivery

## Intent, ownership and stop conditions

Resolve the target from live user intent before effects. A branch-pushed request ends at the
verified remote head. A PR-ready-for-user request ends with an open, non-draft, current PR whose
required checks, reviews and unresolved-thread policy are satisfied, verification and independent
review match its exact head/base, and no auto-merge or queue can merge it after handoff. Explicit
merge authorization permits the existing host's merge action within that scope; no assessment
executes or authorizes it. Never infer deployment authorization from merge authorization.

The integration owner serializes HEAD/index changes, final evidence and outward effects. Workers
produce bounded source changes; they do not race the integration owner for commits, pushes or
review closure. Dispatch owns assignment method at `../../dispatch/SKILL.md`. Commit owns its
frozen-diff method at `../../commit/SKILL.md`; Delivery does not enlarge Commit's four external
requests or move Commit's terminal endpoint beyond identity-proven push. PR observation is a
separate Delivery operation after that endpoint, except the required pre-push check for existing
merge automation. If its safety cannot be determined, do not push into a handoff PR.

Fix only authorized outcome/safety defects and direct acceptance failures. Preserve distinct
finding identities, scope and evidence across revisions. Use at most the declared review budget;
Commit retains its smaller repair/recheck cap. A pending check, missing reviewer or unresolvable
conflict is a blocker with a next action, never a reason to invent authority or start an unbounded
retry. Only an explicit user resume resets exhausted or failed work. A real authorized host event
can advance pending follow-through within its existing scope; it does not reset a stop budget.

## Native commands and evidence

The installed native CLI supplies deterministic diagnostics:

```text
legion work-plan validate --input work-plan.json
legion review-loop assess --input review-ledger.json
legion delivery assess --input delivery-snapshot.json
legion delivery observe --repository owner/name --pr 42 --proofs proofs.json --head <SHA> --base <SHA> --goal user-handoff
```

Use `merge-requested` only for an explicitly authorized merge goal. Observer defaults are five
pages per collection, 120 seconds total and a 900-second maximum evidence age; bounded overrides
are `--max-pages`, `--timeout-seconds` and `--max-age-seconds`. It makes one observation, including
revision/policy binding before and after collection. It reads GitHub PR identity, checks, reviews,
threads and supported branch policy. Incomplete pagination or unsupported/unknown policy cannot
be treated as clear. It contains no merge command, queue manager, daemon or polling scheduler.

Live observation uses the declared `github-read` host capability: GitHub network access and a
credential authorized by the trusted host through the provider SDK/Guard boundary. The host may
inject `LEGION_AUTHORIZED_CREDENTIAL_PROVIDER=github` and `LEGION_GITHUB_TOKEN`; setting environment
variables is not itself a Guard authorization receipt. Never solicit or print token values, place
them in evidence, or transmit them to a host other than the observer's fixed GitHub API origin.
Without authorized access, stop live observation and state which facts remain unobserved. An
imported snapshot can still be assessed as imported assertions; it is no live-access substitute.

Every command returns a versioned envelope carrying provenance. Imported assessments carry an
`inputDigest`; the live observer carries an `observationDigest` and an optional `proofInputDigest`.
A digest binds bytes, not their truth. The imported work-plan, review and delivery assessments do
not authenticate authors/reviewers, execute tests or grant effects. Native observation authenticates its transport
through host credentials; imported verification/review proof records remain caller assertions.
Retain that distinction in the handoff. Reobserve after head/base or policy changes and replace
stale proof; never relabel an earlier review as covering new code.

Readiness is conservative: stale/future observations, head/base drift, incomplete policy/checks/
reviews/threads, missing or nonpassing required checks, required human review, conflicts, draft
state, unresolved threads and nonmatching verification or independent review block readiness.
Match check identity including application identity when required by policy. Neutral/skipped check
results satisfy requirements only when policy expressly permits them. Unknown is not success.

## User handoff and authorized merge

For user handoff, provide the PR link, head/base, checks and review status, evidence limitations,
and the exact remaining user action. Confirm auto-merge is off and no merge queue entry is active.
Observation alone cannot disable either; use an already authorized host action or return that
blocker. Inspect these states before push as well, because a push can satisfy existing automation.

For a merge goal, readiness merely establishes eligibility. The integration owner confirms current
request scope and Guard admission, rechecks the frozen head/base, then invokes the host's supported
merge method. Do not bypass branch rules or required reviews. Confirm merged state and its merge
commit through a fresh bounded read. If the host cannot merge, report ready-for-merge-request with
the unperformed action; do not claim merged. A closed unmerged PR is not a successful delivery.

Use `../../wake/SKILL.md` for event-triggered continuation and the existing Oracle entrypoint at
`../../oracle/SKILL.md` for independent assurance; Oracle authority and method remain owned by
`../../../src/roster/oracle.md` and `../../../doctrine/oracle.md`. The integration owner may record
the returned verdict as an imported ledger assertion; Oracle itself creates no durable artifact.
Council stays advisory under its existing method; this workflow does not create another
review authority. Wake without external events permits one bounded inspection and then returns;
do not use sleeping chats, repeated API calls or agents as a substitute event source.

## Modernize and takeover

**Modernize** reconstructs the original requested behavior against the current base. Read the
original intent, patch and changed contracts, then adapt the implementation to the new interfaces
and conventions. A textual rebase alone is not semantic verification. Keep the original goal and
scope, identify any material change in meaning, and refresh affected tests/review and revision
bindings. Material unresolved tradeoffs route to Sage under existing selection rules.

**Takeover** first recovers original intent, author contributions, current owner and incomplete
evidence. Preserve original authorship and attribute retained work through the repository's normal
commit/PR conventions; never fabricate signoffs or coauthors. Record the actual integration-owner
transfer and distinguish inherited work from the current changes. Neither takeover nor modernize
permits force-push, merge, extra scope, erased attribution or new persistent automation by default.
