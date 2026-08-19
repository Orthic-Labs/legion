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

`self|other-identified` queues explicit route approval. After approval, read only the history
source the consuming project configures for personal medical context (a path or file the
project points this route to). If no such source is configured, or it is unreadable, block
rather than infer drugs, doses, labs, diagnoses, or investigations.

Where the consuming project maintains its own medical-research engine, that engine remains
authoritative for PICO framing, red flags, evidence verification, privacy linting, and
clinician-review output.

## Evidence extension

Medical evidence requires `study_design`, `pico`, and `applicability` for clinical-effect claims.
Mechanistic claims cap at medium confidence. High confidence for effect-size, adverse-event, or
dosing claims requires two independent primary studies; current guidelines and regulator documents
use their own authority rules.

Never promote a NotebookLM summary, mechanism, animal model, or case report into a clinical effect
without the appropriate qualification.
