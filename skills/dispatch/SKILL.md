---
name: dispatch
description: Create a validated zero-context work packet for another agent or executor while current orchestrator retains responsibility. Use for delegation, parallel workers, or copy-paste executor instructions. Same-agent work stays inline; session continuity uses handoff.
kind: capability
capabilityClass: workflow
discoverability: public
domain: null
operations:
  - route
  - produce
effects:
  - source-read
  - artifact-write
  - process-exec
hostRequirements: []
---

# Dispatch

PRIMARY_DELIVERABLE: Validated zero-context dispatch packet.
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 1
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Packet has disjoint dependency waves, exact file allowlists, checks, recovery, receipt, & adversarial Oracle PASS.

1. Freeze objective, authority, full expected changed-file inventory, integration owner, acceptance checks, & bounded recovery.
2. Partition work into dependency waves (`A`, `B`, ...). Put every currently eligible lane in earliest wave; lanes inside one wave run in parallel and have no mutual dependencies. Add later wave only for concrete output/state dependency.
3. Assign each planned changed file to exactly one lane for end-to-end implementation, tests, docs, fixtures, and generated outputs. Lane `allowlist` contains exact repository-relative file paths: no globs, directory ownership, overlap, later cleanup owner, or integrator edits. READ may overlap; write allowlists may not.
4. Copy `assets/direct-packet.json` to declared packet path and fill dispatch waves, lanes, file-touch ledger, checks, and recovery. Keep smallest sufficient lane count; do not split tightly coupled files solely to create concurrency.
5. Validate with `python3 skills/dispatch/scripts/validate-dispatch.py <packet> --packet-type authority --write-receipt <receipt>`.
6. Send exact validated packet, source inventory, & receipt to fresh Oracle for adversarial review of allowlist completeness, lane disjointness, dependency necessity/acyclicity, earliest-wave placement/maximum safe parallelism, and end-to-end checks. Any packet-byte change invalidates PASS and requires validation plus Oracle rerun.
7. Return packet path, receipt, Oracle PASS, dispatch waves, executors, integration owner, & `TRUE_BLOCKER` only after bounded recovery evidence.

Use `assets/dispatch-template.md` with `--packet-type legacy` only for explicit legacy compatibility. Read `references/manual.md` for experiment, correction, or lifecycle work. Read `references/agent-routing.md` for authority routing. Never rely on unseen chat or delegate user-reserved decisions.
