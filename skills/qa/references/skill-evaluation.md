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

## Host-native specification review

`legion-dev run-skill-evals` checks explicit aliases separately from behavioral scores. Without
observations, semantic routing remains `requires-model`. Optional `--observations <path>` accepts
`legion-skill-routing-observations/v1`: each row binds source path, category, case ID, prompt and
fixture hashes, source-bundle hash, producer/model configuration, output/trace references, and
six observed routing dimensions. The scorer compares only dimensions declared by the fixture; it
does not invoke a model. Routing observations never establish output quality, safety, pressure, or
human-quality judgments, which remain `requires-model`. Use the development-only prepare/ingest
path when a case needs host-native Oracle review for specification consistency; it supplements,
and does not replace, behavioral evaluation or become installed end-user runtime.

Prepare one case into a review packet:

```bash
legion-dev prepare-skill-eval --input skills/qa/evals/evals.json --case <case-id> --output /tmp/qa-eval-packet.json
```

Send that packet to a fresh Oracle through the host-native review surface. Judge only whether its
prompt, `expected_behavior`, and assertions form a coherent, discriminating specification. Do not
execute the prompt, launch `claude -p` or another provider, or claim model runtime proof or host
attestation. Return JSON with the packet's exact `input_digest` and one row for every prepared
assertion index:

```json
{
  "input_digest": "sha256:<copy from packet>",
  "results": [
    {"index": 0, "status": "pass", "reason": "Expected behavior is observable and consistent."},
    {"index": 1, "status": "fail", "reason": "Assertion does not discriminate the stated behavior."}
  ]
}
```

Index 0 represents `expected_behavior`; following indexes preserve source assertion order. Each
row needs status `pass`, `fail`, or `unverified` and a non-empty reason. Ingest with:

```bash
legion-dev ingest-skill-eval --packet /tmp/qa-eval-packet.json --results /tmp/qa-eval-results.json --json
```

Ingest rechecks the packet digest, requires the result digest to match, and rejects duplicate or
out-of-range indexes. Missing rows and explicit `unverified` rows remain in the unverified count;
any such row makes the report incomplete. A complete report may contain failed judgments, but the
command exits non-zero for any failure or incomplete review. All
output is labeled spec-consistency evidence only, never model-runtime proof or host attestation.

## Provenance

The test-authoring method in `references/manual.md` recovers `tools/skills/test-author/SKILL.md`
from parent commit `640d569d8`. This evaluation loop preserves the pressure, baseline, trigger,
and compatibility method from `tools/skills/writing-skills/` at parent commit `9803b173e`, while
leaving skill authoring to the host's skill-creator capability.
