# Remaining Migration Code Edit Request

## Raw operator correction

> I told you, you forget M4, M5. You forget all these numbers. You look at all the remaining work and you tell me what you can do to start right now. All the pending code updates, file updates. Assume 100 files have to be, I'm giving you an example, assume 100 files have to be edited from here to the end of the migration file. I want you to set four parallel agents to edit 25 each. None of them will run build, cargo, tests, nothing. They will do the code changes. You will then merge it and run the tests. What is that right now? I don't want to see any M numbers from now on. Is my question clear?

## Binding execution interpretation

- Inventory every remaining repository write from current integrated state through migration completion without milestone-label routing.
- Start every code edit that is legal before signed installed-product qualification and deletion gates.
- Use maximum available disjoint Luna workers. Host limit is four active agents including integration owner, so three edit workers run concurrently and a fourth lane queues only when a slot opens.
- Workers only inspect and edit exact owned files. They must not run Cargo, rustfmt, clippy, tests, builds, Node, Python, package managers, signing, qualification, staging, commits, pushes, or integration commands.
- Root integration owner alone merges, runs direct Cargo and all verification at checkpoints, commits, signs, qualifies, and pushes.
- Legacy runtime deletion files remain read-only until exact signed installed-product PASS and absence proof. Post-cut observation remains read-only until deletion completes.
- No Membrane edits. Preserve Node/Python development tooling.

## Current evidence

- Integration checkout: `D:\Claude\legion-m4-m8` at `a32c56b966f71d1b66936b3c2585ac8c2eef52ac` plus seeded uncommitted capability changes.
- Latest root checkpoint found `configured_audit_writes_reconciled_json_and_sarif` failing because fixture coverage expected `0` while frozen selector denominator is `2`.
- Setup/release correction draft exists in `D:\Claude\legion-m3-corrected` at same immutable base and is untrusted until root integration checks.
- Exact current legal edit inventory is twenty-one paths split across four disjoint semantic workers: nine core/release-binding paths, five CLI/application-surface paths, five setup-lifecycle paths, and two installed-product qualification-harness paths. Three run concurrently because root occupies the fourth host slot; the fourth starts immediately when one worker completes.
- Installed-product evidence matrix must not be edited until real signed artifacts and receipts exist.
