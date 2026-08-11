---
name: research-domain-medical
description: Internal Research medical route; never a catalog entry.
---

# Medical domain

Medical routes require a patient descriptor and issue.

## Anonymous route

Generic questions set `patient.kind=anonymous`. Do not read `private-history.yaml`, past patient files, or
personal protocol notes. Use current primary medical/regulatory sources and return population-level
evidence with applicability limits.

## Personal route

`self|other-identified` queues explicit route approval. After approval, read only the configured
history source. For the approving human, the canonical source is
`Health/medical-research-system/history/private-history.yaml`; it overrides older Markdown. If missing or
unreadable, block rather than infer drugs, doses, labs, diagnoses, or investigations.

The existing engine at `Health/medical-research-system/` remains authoritative for PICO framing,
red flags, evidence verification, privacy linting, and clinician-review output.

## Evidence extension

Medical evidence requires `study_design`, `pico`, and `applicability` for clinical-effect claims.
Mechanistic claims cap at medium confidence. High confidence for effect-size, adverse-event, or
dosing claims requires two independent primary studies; current guidelines and regulator documents
use their own authority rules.

Never promote a NotebookLM summary, mechanism, animal model, or case report into a clinical effect
without the appropriate qualification.
