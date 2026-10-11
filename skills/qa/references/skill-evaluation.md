# QA skill evaluation

This reference preserves the QA-relevant evaluation method from historical `writing-skills`.
The host's skill-creator owns skill authoring and deployment workflow; this file covers only how
to evaluate QA routing and behavior.

## Evaluation loop

Before changing QA guidance, add discriminating cases to `evals/evals.json` using its current
standard schema. Cover:

- **Triggers:** test-only requests for native, backend, and browser/web behavior.
- **Non-triggers:** diagnosis/repair, qualitative design, rendered-state coverage, or another
  capability's owned work.
- **Output quality:** runner and nearby conventions, behavioral contract, selected test shape,
  truthful red/green status, and tests-only boundary.
- **Safety and pressure:** attempts to accept decorative coverage, skip repository discovery, or
  fix product code while being asked to author a test; combine realistic deadline, sunk-cost, or
  authority pressure where a stated rule could otherwise be rationalized away.
- **Compatibility:** explicit commands and aliases whose ownership or spelling changes.

For meaningful behavioral changes, replay the same scenario before and after the guidance change
when the host can run a baseline without that guidance. Record the baseline choice or failure,
including any rationalization that defeats the intended behavior; then check whether the updated
guidance changes that result. Use concrete constraints and force an actionable choice rather than
asking the model to recite the skill. If a baseline cannot be isolated or replayed, mark it unrun;
do not imply that static eval cases prove model behavior.

Use pressure cases for rules likely to be bypassed under cost or urgency, not for every test shape.
The goal is to tell apart correct QA test authorship from adjacent routes while preserving the
existing runtime-QA route and report behavior.

## Provenance

The test-authoring method in `references/manual.md` recovers `tools/skills/test-author/SKILL.md`
from parent commit `640d569d8`. This evaluation loop preserves the pressure, baseline, trigger,
and compatibility method from `tools/skills/writing-skills/` at parent commit `9803b173e`, while
leaving skill authoring to the host's skill-creator capability.
