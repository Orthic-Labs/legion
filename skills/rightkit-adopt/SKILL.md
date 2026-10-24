---
name: rightkit-adopt
description: "Adopt or repin a RightKit package in an app, delete the code it replaces, and place new code by class. Use for adopt rightkit-qa, repin a package, does RightKit already own this, where should this code live, or replace our own version with the shared one."
kind: capability
capabilityClass: workflow
discoverability: public
domain: engineering
operations:
  - analyze
  - decide
  - execute
effects:
  - source-read
  - repository-write
  - process-exec
hostRequirements:
  - rightkit-owns
  - repo-gate
---

# RightKit adopt

1. **Ask the index first.** `rustright owns <capability>` names the owner of one capability; `rustright owns --compact` prints the whole index. An owner exists: integrate it and build only the gap. No index on this host: say so, and mark every build-new decision unverified.
2. **Place code by class.**
   - R1 Foundation: the owner appears in a row of the mandatory set for the app's profile. The app declares every owner at or above the row floor, or lists the row N/A with reason, issue, and expiry.
   - R2 Add-on: any other catalogued capability. If `rustright owns` names an owner, depend on it.
   - R3 App-specific: product domain logic and presentation only, with dependencies inside the repository allowlist.
   - R4 Exception: non-product code stays in the app only through the app's ownership-exceptions file, with the capability, owner package, path or fingerprint (never repo-wide), reason, owner, date, the RightKit issue that moves it, and an expiry within 90 days. RightKit must also list it; a self-authored entry is a finding.
   - R5 Policy: a single-app platform need becomes a RightKit option plus an app declaration, not an exception.
3. **Adopt.** Add or repin the package at the version RightKit publishes, switch the app to its API, and delete the replaced local code in the same change. Update the app's declarations to match.
4. **Gate.** Run Preflight. The check enforces the mandatory set, the exceptions, and the fingerprints.

R1 to R5 is the class test in the workspace rules; where the workspace has not ratified it, the two-consumer admission rule in `decisions.md` still governs what enters RightKit. The owning docs are RightKit's `ADOPTION.md` and `CAPABILITY-MAP.md`; this skill does not restate them.

```text
ADOPT_RESULT
capability: <name>
owner: <package and version, or none>
class: R1 | R2 | R3 | R4 | R5
removed: <local code deleted>
gate: <preflight status>
```
