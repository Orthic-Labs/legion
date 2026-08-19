---
name: research-workflow-legal-india-consumer
description: >
  GUIDE (not a catalog entry). India consumer-commission filing workflow under
  ResearchRoute.domain == "legal" → area == "consumer" → country == "IN".
  Internal route; never appears at the top of the skills catalog.
---

# Workflow — legal / India / consumer

This is one workflow under the legal domain. Loaded only when the legal gate test
resolves `area=consumer` and `country=IN`. This is legal information and drafting
support, not representation.

## Inputs the route requires before drafting

- Parties (complainant + opposite party), with identifiers.
- Jurisdiction (district / state commission) and pecuniary value.
- Dates of transaction, consideration, notices served, and relief sought.
- Evidence index (receipts, correspondence, screenshots, photos).
- Filing status (intake / draft / filed / hearing pending).

If any of those is missing, the route halts and asks **one** clarifying question.

## Process

1. Freeze parties, jurisdiction, dates, transaction, consideration, notices, relief,
   evidence, and filing status.
2. Verify current law, rules, pecuniary jurisdiction, limitation, fees, portal process,
   and authority from primary sources. The Consumer Protection Act 2019, the e-Jagriti
   and e-Daakhil portal rules, and current pecuniary jurisdiction notifications are
   primary sources.
3. Read only needed references in this directory:
   `cp-act-2019.md`, `jurisdiction-and-fees.md`, `ejagriti-filing.md`, or
   `drafting-standards.md`.
4. Read `manual.md` for a full filing pack or end-to-end lifecycle.
5. Separate supplied facts, missing evidence, legal elements, calculations, and
   drafting assumptions.
6. Preserve chronology, exhibit IDs, exact amounts, and requested relief across every
   document.
7. Use `../../../../../../../src/lib/research-core/workflows/legal/india/consumer/scripts/generate_pack.py` for
   deterministic pack assembly.
8. Flag limitation, jurisdiction, service, evidence, privacy, or professional-review
   risks before filing.

## Mutual exclusion

This workflow never loads for `area=criminal`. The criminal workflow lives at
`workflows/legal/india/criminal/` and explicitly refuses any consumer commission or
e-Jagriti reference.
