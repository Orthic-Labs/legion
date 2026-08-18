---
name: research-doctor
description: Generate a doctor-ready evidence packet for one of the operator's protocol questions. Use when the operator asks "/doctor <question>" or anything that maps to "evaluate the evidence for X drug/peptide/dose change against my labs and stack." Loads operator.yaml, runs red-flag checks, retrieves primary medical sources, builds an evidence ledger with the workspace-approved citation verifier, and synthesizes via rubrics/question.md. NEVER replaces a clinician — every output ends with "Discuss with [specialist] before [action]." Hard rules in PLAN.md.
---

# /doctor — Medical Research Doctor

This skill generates an evidence packet for one PICO-scoped clinical question against the operator's actual labs and current protocol.

## When to invoke

User says something like:
- "/doctor should I switch from [redacted-drug] to [redacted-drug] at Week 7?"
- "/doctor [redacted-drug] 2mg vs 4mg for [redacted-lab] <80 given my [redacted-lab]?"
- "/doctor is Tesa+Ipa simultaneous nightly safe with my CAC 81?"
- "/doctor what's the evidence for muvalaplin in [redacted-lab] reduction?"

NOT this skill if:
- User is asking for the protocol itself (read `D:/workspace/Health/protocol.md`)
- User wants brand-voice/marketing/SEO work (different skills)
- User wants a panel/jury review of an existing decision → use `/doctor review`

## How to invoke

1. Reformulate the user's free-text question into PICO. Use the prompt template at `D:/workspace/Health/medical-research-system/pico.py` (function `REFORMULATION_PROMPT`). If you can extract PICO directly from the question, do so.

2. Run the orchestrator from inside the package directory:
```bash
cd D:/workspace/Health/medical-research-system
py -3.11 doctor.py \
  --pico-population "<P>" \
  --pico-intervention "<I>" \
  --pico-comparator "<C>" \
  --pico-outcome "<O>" \
  --pico-timeframe "<timeframe>" \
  --raw-question "<original user question>" \
  [--symptoms "<any symptoms user reported>"] \
  [--retmax 10]
```

3. The orchestrator prints a JSON evidence pack to stdout. Parse it.

4. **If `must_abort: true`**, STOP. Output ONLY the red-flag block + "Discuss with [specialist named] now." Do NOT proceed to synthesis. Do NOT optimize the protocol.

5. **Otherwise**, synthesize the evidence pack into the doctor-output format defined in `D:/workspace/Health/medical-research-system/rubrics/question.md`. Hard rules from that rubric:
   - Every claim cites an evidence-ledger row by `[^N]`.
   - Provenance:protocol_quoted lab values must NOT drive high-confidence claims.
   - Items in `rejected_decisions` are not viable unless user explicitly asks to revisit.
   - `conditional_decisions` are gates, not rejections.
   - Output ends with: "This is research, not medical advice. Discuss with [specialist named] before [action]."

6. For each PMID candidate the orchestrator returns, you (the synthesizing LLM) decide which to ship as ledger rows. For each you ship, write the specific claim being supported (not the article title).

7. **Citation verification (mandatory)**: For each PMID you intend to cite, call:
```bash
py -3.11 -c "from evidence.verify import verify_claim; import json; print(json.dumps(verify_claim('<pmid>', '<DEPERSONALIZED claim text>').to_dict(), indent=2))"
```
   **Privacy contract** (V1.1): claim text MUST NOT contain the operator's name, address, lab barcodes, or patient IDs. Strict-PII gate will refuse to send. Phrase claims generically: "[redacted-drug] reduces [redacted-lab] ~25% over 12 weeks in IR patients" — NOT "the operator's [redacted-lab] 4.23..."

   **Verdict handling (V1.1 stricter policy)**:
   - `SUPPORTS` → keep declared confidence, ship as final-support
   - `PARTIAL` → drop two tiers, capped at low — ship as final-support but at low confidence
   - `DOES_NOT_SUPPORT` / `IRRELEVANT` / `ERROR` → REJECT, exclude from output (log in excluded_log)
   - `MANUAL_REVIEW` → visible as **candidate evidence ONLY**. Place in a separate "Candidate evidence pending verification" section. Cannot support final claims. The user must explicitly promote it after manual abstract review.

8. **Pre-delivery lint (mandatory)**: After synthesizing the final markdown, save it to a temp file and run EITHER:
```bash
py -3.11 doctor.py --lint-output /tmp/synthesized.md   # unified CLI
# or equivalently:
py -3.11 lint.py /tmp/synthesized.md
```
   Linter catches: rejected_decision approving mention, planned_protocol treated-as-current, high-confidence-on-low-provenance, absolute terms ("safe", "proven", "doctor should"), missing clinician boilerplate, PMID cited but not in ledger.

   **Exit code 1 = errors found.** Fix or surface to user before delivering.

8. Surface ALL of these in the final output:
   - The red-flag check result (even if just "no flags")
   - The India-layer status for any drug in I/C
   - Stale guidelines (if any) — `stale_guidelines` from the JSON
   - The rejected-decisions list (don't suggest items on it)
   - The session-errors-to-avoid list (avoid those failures)

## File locations

- Orchestrator: `D:/workspace/Health/medical-research-system/doctor.py`
- Patient yaml: `D:/workspace/Health/medical-research-system/history/operator.yaml`
- Synthesis rubric: `D:/workspace/Health/medical-research-system/rubrics/question.md`
- Interaction rubric: `D:/workspace/Health/medical-research-system/rubrics/interaction_check.md`
- Plan: `D:/workspace/Health/medical-research-system/PLAN.md`

## Hard guardrails (do not violate)

1. NO output without "discuss with [specialist] before [action]."
2. NO claim without an evidence ledger row.
3. NO PMID citation without running verify_claim.
4. NO suggesting items in rejected_decisions.
5. NO confabulated drug procedures, dosing schedules, or insurance/regulatory claims — WebSearch first.
6. If pipeline fails (network down, no PMIDs found), report that honestly. Don't fabricate.

## Failure modes to remember

- `protocol_quoted` lab values ([redacted-lab] 80.7, [redacted-lab] 132, hs-CRP 2.1, Vit D 19.4, B12 162, free T 16.32, LH 11) — these are clamped to confidence:medium. Don't reason from them as if confirmed.
- The 2023-05-17 [redacted-lab] 42.3 reading is an analytical anomaly per the yaml — flag it, don't treat as biological event.
- Pioglitazone is in conditional_decisions, not rejected. It's a real fallback option.
- BPC-157 ORAL only. Injectable contraindicated due to CAC 81.
- Reta ceiling 4mg, hardcoded.
