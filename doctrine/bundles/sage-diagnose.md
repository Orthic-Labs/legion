# Sage — Diagnose route bundle

**What this is:** the recovered method manual for Sage's Diagnose route (the "establish material
facts, root cause" route named in `doctrine/sage.md`'s three internal routes). Recovered verbatim
from git history — retained from the original review craft. Source:
`git show d810d827^:skills/debugger/references/manual.md` (292 lines). Loaded by: Sage,
when the task requires reproducing a failure, separating symptom from cause, testing hypotheses, or
establishing root cause before any fix is authored.

**Read `doctrine/sage.md` first.** This bundle is the craft underneath that constitution, not a
replacement for it. Where this manual's routing language conflicts with current doctrine, a
`> **Superseded:**` note marks the change inline; everything else is preserved as originally
written, including its own internal skill name (`debugger`) and file paths from its era.

**S10 handoff override:** Diagnose produces frozen evidence, decisions, & a Sage handoff; it never
performs product effects. The handoff binds acceptance IDs, ownership, cutover obligations,
event/checkpoint requirements, deficits, & an explicit diagnosis trigger. Alchemist does not
continue diagnosis unless that trigger fires; otherwise it returns `BLOCKED` with observed
evidence. Execution DAGs follow actual file/artifact consumption, not stage order.

---

# /debugger — Hypothesis-Driven Debugging

```text
MODE: EXECUTE
PRIMARY_DELIVERABLE: Root-cause finding plus tested minimal fix or unresolved evidence.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read, focused_check, output_write
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen reproduction and hypothesis checks identify a cause, tested fix, or exact unresolved evidence.
```

> **Superseded:** `EFFECT_PROFILES: ... output_write` describes running probes and tests to
> establish truth — epistemic, not the product-source effect. Sage may author the tested fix as an
> artifact; it never performs the effect itself. The artifact routes to Alchemist via a minimal
> contract per `doctrine/sage.md` Boundaries.

## Iron law

No fixes without root cause investigation first. If the root cause is not known, the next action is evidence gathering, not implementation.

**One carve-out, and only one: an active production incident.** While users are being harmed, a
*reversible* containment action — rollback, feature-flag disable, traffic shift, scale-out — may
precede diagnosis. Label it **containment, not a fix**, in the same breath: it stops the bleeding and
proves nothing about cause. Diagnosis continues immediately afterward, and the iron law applies in
full to any permanent causal fix. Containment without follow-through is how a bug ships twice.

## Phase 0 — classify before you run the loop

Do not run the same ceremony for a typo and a heisenbug. Name the class first; it selects the route,
the evidence, and the depth.

| Class | Tell | First move |
|---|---|---|
| **Trivial/local** | nameable in one sentence, one file, one line | fast path below |
| **Deterministic** | fails 1/1 | reproduce → bisect |
| **Regression** | worked at a known commit | `git bisect run` |
| **Intermittent/flaky** | fails N/100 | oracle + stress, never a single run |
| **Crash/memory** | segfault, OOM, leak | sanitizers, heap diff |
| **Concurrency** | order-dependent, load-dependent | race detector, not reasoning |
| **Performance** | "slow", regression in p95 | baseline first — see below |
| **Data/DB** | wrong or missing rows, corrupt state | invariant + write path |
| **Environment** | works here, not there | diff the environments, not the code |
| **Multi-component** | crosses a process/service boundary | instrument each boundary |
| **Build/CI** | fails only in CI | compare CI env to local, cache state |

### Fast path — earn the ceremony

When **all** of these hold: the bug is nameable in one sentence, the fix is local to one file, a
regression test takes minutes, and no contract or architecture changes — then write the failing test,
fix it, go green, run the suite, done. No hypothesis table, no post-mortem. The ceremony below exists
for bugs that defeat this path, and applying it to an off-by-one wastes the discipline.

### Before Phase 1 — check what is already known

Cheap, in this order: Crypt recall for a standing rule on this symptom; `git log`/`git blame` on the
failing file for a past fix to the same thing; recent Audit findings. Any hit is a **hypothesis seed,
never a conclusion** — reverify it against the active commit, working tree, environment, and
reproduction before treating it as current evidence.

> **Superseded:** "recent Audit findings" means Oracle's finding records.

## The 5 phases

### 1. Reproduce

**The target is a stable diagnostic oracle, not necessarily a 100% repeatable case.** Any of these is
a valid oracle, and naming which one you have prevents both false passes and false failures:

- **deterministic** — fails 1/1;
- **probabilistic** — fails N/100 over a stress run (record N and the run count);
- **performance** — p95 exceeds a stated baseline;
- **trace-signature** — span A present, expected span B absent.

Then:
- **Capture before you minimize.** For a rare or hard-to-trigger failure, save the artifact first —
  logs, recording, exact input, core dump. Shrinking a failure you have not preserved is how the only
  instance of a bug gets lost.
- Strip the case to the minimum that still trips the oracle.
- Note inputs, env, timing, dependencies, seed.

### 2. Isolate

- **Ground first when mapped:** run `cortex doctor`; trust generated evidence when doctor is
  `ready`, or when doctor is `degraded` while the graph is explicitly fresh and doctor reports no
  blocker/error — carry every degradation warning into the diagnosis instead of treating it as clean
  (same trust rule as `/audit`). If the graph exists, confirm `cortex graph status`, then use `graph search|resolve` to
  identify the failing nodes, `graph path` to trace the suspected call/data route, `graph neighbors`
  for the local dependency boundary, and `graph impact` to find callers/consumers that may reproduce
  the failure. Read the generated `<repo>/docs/architecture.md`
  and `docs/product.md` (Cortex no longer writes `START-HERE.md`) plus current `verdicts.json` for
  orientation and doc traps. Graph output narrows hypotheses; exact source, logs, and the reproduction establish cause.
  If graph coverage is unsupported/stale/unavailable, record `graph-unavailable` and bisect with
  direct code/log evidence instead.
- **Time-box the graph, and never rebuild it mid-debug.** Doctor plus status is a couple of minutes of
  orientation, not a project. Run `graph impact` once you have a suspect symbol — it is a
  blast-radius query, not a place to go looking for one. A mid-session rebuild changes the ground
  under an investigation in progress.
- Bisect: where does the failure first appear in the path?
- Binary-search the code, the time, the data, or the env. For a **regression** with a known last-good
  commit and a deterministic reproduction, let Git do it: `git bisect start <bad> <good>` then
  `git bisect run <test-cmd>` pinpoints the breaking commit; read that commit's diff to ground the hypothesis.
  **When the predicate is not scriptable** (a symptom with a known timestamp but no automatable
  pass/fail), fall back to reading the commits between last-known-good and first-bad rather than
  abandoning bisection. When the failing file is known but the cause is not, `git log --name-only` over
  its history shows which files historically change *with* it — a useful candidate list, not evidence.
- Confirm where the failure stops AND where it doesn't appear

> **Superseded:** "`/audit`" means Oracle's audit route.

#### Evidence ladder — cheapest and least invasive first

1. query evidence that already exists (logs, traces, metrics, crash reports);
2. inspect recorded state (dumps, snapshots, DB rows, artifacts);
3. add **non-invasive** instrumentation (a log line, a span, a counter);
4. change input or config in a controlled way;
5. **patch code last.**

Reaching for a code change to test a hypothesis is a real intervention: it perturbs timing and can
mask the very race or ordering bug being chased. Earn step 5.

| Evidence needed | Reach for |
|---|---|
| Where time goes | profiler / flame graph; never guess a hotspot |
| Memory growth, leaks | heap snapshot diff, LeakSanitizer, Valgrind |
| Memory corruption, UB | AddressSanitizer, UBSan |
| Data races, deadlock | ThreadSanitizer, Go `-race` — **not** reasoning |
| Syscalls, file/network I/O | strace/dtruss, lsof, tcpdump |
| Network/API behaviour | request logs, HAR, retry/backoff traces |
| DB behaviour | query log, `EXPLAIN`, txn/lock inspection |
| One-off native/browser failure | record/replay (`rr`, Replay.io) — capture once, debug the recording |
| Input-driven crash | property/fuzz testing (Hypothesis, fast-check, proptest, cargo-fuzz) |
| Production-only behaviour | telemetry — see fields below |

> **Membrane boundary.** Cortex is the current-repository truth producer; Audit may contribute
> current diagnostic evidence; Architect designs a future state only when the investigation exposes
> an architectural change. Crypt is durable memory, not current execution proof. The Membrane
> planner/gateway, final packets/receipts, typed Audit store, and cross-client federation are
> **[Target — do not invoke]**. `cortex graph candidates` and `planner-status` do not make the
> planner live.

> **Superseded:** "Audit" → Oracle; "Architect" → Sage's Architect route
> (`doctrine/bundles/sage-architect.md`), invoked as a route-switch within the same authority, not
> a handoff to a separate agent.

### 3. Hypothesize

- Form *concrete* hypotheses (not "something weird") that would explain **ALL** observations. **Size
  the set to the evidence** — sometimes one cause is obvious, sometimes five fit equally; a forced
  count invents hypotheses or discards real ones.
- Each hypothesis must be testable with one specific change.
- Rank them, and say what would *disconfirm* each. A hypothesis with no disconfirming test is a belief.

#### GoalRoute v2 diagnostic gate

For nontrivial diagnosis (multiple plausible hypotheses, intermittent/performance/concurrency/data/
multi-component failure, or repeated failed fixes), compile a `DIAGNOSTIC` GoalRoute through the
internal engine before
launching new probes. B is a Level-4 proven cause or exact resolved diagnostic decision, never merely
"more information." Candidate paths are complete evidence sequences from current oracle to proof.

Compare expected time to proof including probe duration, retry probability, inconclusive-result
recovery, and instrumentation rework. Existing evidence outranks new collection; non-invasive evidence
outranks perturbing code. Every step must disconfirm at least one live hypothesis or satisfy a required
safety dependency. Validate route artifact/receipt before first new probe and bind the next action to
selected route. A changed observation set or rejected hypothesis invalidates remaining route; recompile
from current evidence. This does not lower Level-4 root-cause bar.

| Symptom class | Default first hypotheses | Discriminating move |
|---|---|---|
| Intermittent | race; resource exhaustion | instrument concurrency, stress |
| Memory growth | retained reference; native handle leak | heap diff across N iterations |
| Perf regression | N+1 query; sync work in an async path | query log, flame graph |
| Works-here-not-there | version/config drift; missing env | diff both environments |
| Wrong data | missing transaction; partial write; race on update | trace the write path |
| Crash under load | unchecked bound; unwrap on absent state | sanitizer + the failing input |

### 4. Test each hypothesis

- One change at a time, observe, confirm/reject.
- If all hypotheses fail, the observation set is incomplete — return to Phase 1 with more
  instrumentation, not to Phase 3 with more guesses.

### 5. Fix + verify

**Prove the cause, don't just satisfy the test.** A passing test after a change is a *validated
patch*; it is not proof of the stated root cause. Know which level you are at:

| Level | Standard |
|---|---|
| 0 | symptom observed |
| 1 | correlated with a location |
| 2 | a mechanism explains it |
| 3 | a discriminating experiment ruled out the alternatives |
| 4 | counterfactual confirmed — the bug appears and disappears with the mechanism |
| 5 | systemic: why it was possible, and what class it belongs to |

Level 4 is the bar for "root cause found." Level 2 with a green test is where a wrong fix hides.

Then:
- Make the smallest fix that resolves the root cause (not the symptom). **Choose the fix strength
  deliberately:** (A) add a check — smallest, the bug can recur elsewhere; (B) fix the contract or type
  so the bug is unrepresentable; (C) fix the structural seam so it is impossible by design. Default to
  A for an instance; escalate to B or C when this is a recurring *class*.
- **Precision check:** files touched outside the mechanism, or edits beyond what the cause requires,
  are a red flag even when the suite is green.
- **Add a regression oracle** — usually a test, but a property test, fuzz seed, invariant check, trace
  assertion, performance budget, or sanitizer run is the right guard for perf, concurrency and data
  bugs where a unit test cannot express the failure.
- When practical, prove it red-green: fail against the broken behavior, pass after the fix.
- Run regression: does anything else break?
- Some incidents have **more than one fault** (a triggering bug, a missing guard, and an observability
  gap). Say so rather than collapsing them into one sentence.
- If 3+ attempted fixes fail, stop — **you are in a local minimum, looping your own failed logic.** The
  next move is a *fresh perspective on the diagnosis*, not fix #4. Two escalation paths: (a) the root
  cause is structural (state modelled wrong, coupling forcing the bug, an abstraction that can't
  represent reality) → switch to the Architect route to design the fix, then resume here at Fix + verify; (b) the
  diagnosis itself is uncertain / multiple hypotheses fit equally → escalate to `/covenant` for
  **differential diagnosis** — package it to attack the *diagnosis* (observations, evidence, live +
  rejected hypotheses), not to review code prematurely.

> **Superseded:** "hand to `/architect`" → switch to Sage's own Architect route
> (`doctrine/bundles/sage-architect.md`) — same authority, different internal route, not a handoff.
> Retired Council code route → `/covenant`.

**Then ship it: hand the verified fix to `/commit`.** This skill ends at a proven fix; `/commit` is the
diff-scoped gate that gets it out. Do not push from here.

### Time budgets — advisory, not a trigger

Rough per-phase budgets (reproduce / isolate / hypothesize / test / fix), scaled up for intermittent,
performance and cross-component bugs. Blowing past one by ~2× is a **signal to reconsider the
approach**, not an escalation trigger and not permission to stop. The escalation trigger is the
3-failed-fixes rule above, which is about evidence, not the clock.

### Post-mortem — learning extraction (for a non-obvious bug)
When the root cause was a genuine gotcha a future agent would hit again (an API that needs null-handling
under load, a framework footgun, an env-specific trap), capture it as a durable rule via
Use the host's Crypt durable-memory rule tool (an optional host capability, not shipped in this package) to add the rule so Crypt recall prevents the repeat.
The bar is "a standing trap worth remembering," not a log of this one fix. **State the scope** —
language, layer, or condition it applies to — so one incident does not become an unconditional law.

## Optional external review
External review is explicit opt-in. Run `/covenant code <changed-file-or-diff>` only when the operator asks
for Council, a jury, or external review; ordinary fixes close on regression and relevant-suite proof.
(Distinct from the local-minimum escalation above: that attacks a *stuck diagnosis*; this reviews a *finished fix*.)

## Anti-patterns
- "Random change → did it work?" — no isolation, no learning
- **Masking the symptom.** Before accepting a fix, ask in order: does it prevent the bad state or just
  handle it? does it leave the failure visible if it recurs? is there a regression oracle that would
  catch the recurrence? does it change a contract or type? A bare handle-and-hide (try/catch, null
  guard, retry) that answers "just handle it" is rejected — re-investigate.
- "Works on my machine" — env is different from prod, instrument prod
- Adding logs but never reading them
- Calling it fixed without a regression oracle
- "Probably a race condition" — that's a hypothesis, not a diagnosis. **Prove it with a race
  detector** (TSan, Go `-race`), not with more reading.
- Optimizing without a baseline measurement — you cannot claim an improvement you never measured
- Bundling multiple possible fixes in one patch — you lose the causal signal

## When the bug is intermittent (cross-thread / GIL / load)
- Unit tests won't catch it; instrument production telemetry
- Stress-test under representative concurrent load; report failures as N/runs, never "sometimes"
- Look for: queue overflow, log gaps, dropped frames, swallowed exceptions, fallback paths masking the real issue
- **For a flaky test, vary the dimensions that actually cause flake:** random seed, test order,
  timezone and locale, system clock, leftover filesystem or DB state, dependency version, parallelism.
- **Telemetry needs fields to be useful.** Capture trace ID, span ID, environment/deployment,
  service version or revision, structured error (type + message + stack), the active feature flags,
  and a pseudonymous tenant/user key. OpenTelemetry semantic conventions are the default shape.
  "Add logging" without these produces volume, not evidence.

## Performance bugs

Never optimize without a baseline — an unmeasured "improvement" is a guess with extra steps.

1. Measure and record the baseline (p50/p95, throughput, resource use) under a representative load.
2. Profile the failing surface; find the actual hotspot rather than the suspected one.
3. Make the smallest change to that hotspot.
4. Re-measure against the same baseline and load.
5. Where practical, leave a performance budget or guard so the regression cannot return silently.

A perf fix with no before/after number is not verified.

## Data and database bugs

1. State the violated invariant precisely ("every order has exactly one payment row").
2. Trace the full write path: migration, transaction boundary, ORM behaviour, raw SQL, retries.
3. Look for: a missing or too-narrow transaction, a partial write, a lost update / read-modify-write
   race, an unguarded `DELETE`/`UPDATE`, tenant-id confusion, and non-idempotent retries.
4. Fix forward-safely, and check whether existing corrupt rows need a separate, reviewed repair.

Never test a hypothesis by mutating production data. In this workspace the `prod-db-guard` hook will
block it, and the dev instance on port 5433 is the correct target — see
`docs/rules/ssh-server-access.md`.

> **Superseded:** path corrected from `.claude/rules/ssh-server-access.md` (no longer exists) to
> `docs/rules/ssh-server-access.md`, its current location.

## Multi-component systems

For CI → build → signing, client → API → service → database, daemon → UI, or similar chains, instrument each boundary before fixing:

- What enters this component?
- What exits this component?
- Which environment/config values are visible here?
- Where does the first bad value or missing state appear?

Fix at the first failing boundary, not where the exception finally surfaces.
