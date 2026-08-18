---
name: review-medical
description: Multi-juror adversarial review of a medical protocol decision for the operator. Use when the operator asks "/review-medical <plan>" — runs the doctor pipeline first, then dispatches the cardiologist, endocrinologist, pharmacologist, and skeptic-methodologist jurors in parallel, synthesizes a chairman verdict with explicit dissents. NEVER replaces a clinician. Lower-stakes alternative is /doctor (single research pass without panel).
---

# /review-medical — Multi-juror panel review

Adversarial review of a medical protocol decision. Runs `/doctor` first to build the evidence pack, then runs four jurors in parallel, then synthesizes a chairman verdict.

## When to invoke

- "/review-medical the Week 7 [redacted-drug] transition"
- "/review-medical [redacted-drug] 2mg vs alternatives"
- "/review-medical Tesa+Ipa simultaneous Wk 11 start"
- "/review-medical pioglitazone 15mg as Decision-D fallback"

NOT this skill if:
- User just wants a research pack → use `/doctor`
- User wants the protocol read out → read protocol.md
- User is asking about non-medical work → wrong skill

## Pipeline

### Step 1 — Build evidence pack
Same as `/doctor` but pass `--review`:
```bash
cd D:/workspace/Health/medical-research-system
py -3.11 doctor.py \
  --pico-population "..." --pico-intervention "..." \
  --pico-comparator "..." --pico-outcome "..." \
  --raw-question "..." --review
```
Output JSON includes `juror_files` — the four juror prompt paths.

### Step 2 — If `must_abort: true`, STOP
Output the red-flag block + "Discuss with [specialist] now." Do NOT proceed to jurors.

### Step 3 — Synthesize the doctor evidence pack first
Use `rubrics/question.md`. This produces the candidate verdict the jurors will review.

### Step 4 — Run four jurors IN PARALLEL
Spawn four sub-agents simultaneously (Agent tool, multiple tool_use blocks in one message). Each juror gets:
- The juror prompt from `D:/workspace/Health/medical-research-system/jurors/<role>.md`
- The full evidence pack JSON from step 1
- The synthesized doctor candidate from step 3
- The relevant operator.yaml excerpts

Use the **machine-minimal directive** prefix on every juror prompt (per CLAUDE.md). Jurors are:

1. `cardiologist.md` — CV-prevention lens, signs off on/dissents from CV claims
2. `endocrinologist.md` — endocrine safety + recomp efficacy lens
3. `pharmacologist.md` — drug-drug interactions, transporter overlap, source-quality
4. `skeptic_methodologist.md` — adversarial evidence-quality grade A-F per claim

Use the workspace-approved subagent ceiling for every juror; no spawned subagent may use Opus.
External jurors run only when the operator explicitly invokes this review workflow.

### Step 4.5 — Run output linter on the doctor synthesis

After step 3 produces the candidate doctor synthesis, run EITHER:
```bash
py -3.11 doctor.py --lint-output /tmp/synthesized.md   # unified CLI
# or equivalently:
py -3.11 lint.py /tmp/synthesized.md
```
Fix any errors before passing to jurors. Linter catches: rejected_decision approving mention, planned_protocol-treated-as-current, high-confidence on grep_extracted/chart_derived provenance, absolute terms ("safe", "proven"), missing clinician boilerplate, orphan PMID citations.

### Step 5 — Chairman synthesis
You (the orchestrator) synthesize jurors into:

```markdown
## Specialist panel
| Juror | Verdict | Top concern | Dissent? |
|---|---|---|---|
| Cardiologist | ... | ... | ... |
| Endocrinologist | ... | ... | ... |
| Pharmacologist | ... | ... | ... |
| Skeptic Methodologist | grade A-F | ... | ... |

## Chairman synthesis
- **Majority verdict:** ...
- **Dissents:** ...
- **Open questions panel cannot resolve without more data:** ...
- **Recommended next clinician action:** ...
```

Then append the standard `/doctor` output (PICO, evidence-says, applies-to-me, etc.) so the user gets both the panel + the underlying pack.

## Hard rules

1. Jurors run in PARALLEL not sequential. One message, multiple Agent tool_use blocks.
2. Each juror operates independently — do NOT pre-share their conclusions.
3. Surface dissents prominently. A unanimous verdict with no dissent is suspicious — re-prompt.
4. If the skeptic grades any claim D or F, that claim must be EXCLUDED or downgraded in the final output.
5. Chairman synthesis ends with "This is research, not medical advice. Discuss with [specialist] before [action]."

## Failure modes

- Jurors echoing each other → check for prompt leakage between agents
- Pharmacologist juror missing the JEEP precedent → it's in the prompt, surface it
- Skeptic grading everything F → re-check the evidence pack; jurors should be calibrated
- Cardiologist signing off on biomarker-only evidence → skeptic should catch this; if not, downgrade.

## File locations

- Orchestrator: `D:/workspace/Health/medical-research-system/doctor.py`
- Jurors: `D:/workspace/Health/medical-research-system/jurors/*.md`
- Plan: `D:/workspace/Health/medical-research-system/PLAN.md`
