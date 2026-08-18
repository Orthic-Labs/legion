# Workflow — legal / India / criminal

Loaded only when the legal gate test resolves `area=criminal` and `country=IN`. This
workflow is **mutually exclusive** with the consumer workflow: criminal India never
loads consumer references, e-Jagriti guidance, or deficiency-in-service framings.

## Inputs the route requires before any conclusion

- Facts giving rise to the offence, with dates and locations.
- Sections invoked (IPC / BNS / special statutes) and the stage of proceedings (FIR
  / chargesheet / trial / appeal / quashing / bail).
- Forum (police station, magistrate court, sessions court, High Court, Supreme Court)
  and any interim orders.

## Process

1. Freeze facts, sections, forum, stage, and intended question (bail strategy,
   quashing, defence, appeal framing).
2. Verify current law from primary sources: the statute text, the relevant judicial
   precedents (especially current Supreme Court and the relevant High Court), and any
   recent notification or amendment.
3. Distinguish bailable / non-bailable, cognizable / non-cognizable, compoundable /
   non-compoundable — these decide procedural posture.
4. Separate supplied facts, missing evidence, legal elements, defences, and
   procedural posture.
5. Cite at least two independent primary sources for each actionable claim when
   available.

## What this workflow never does

- References the Consumer Protection Act 2019, the e-Jagriti portal, or any consumer
  commission framing. The router logs the refusal when a user drifts.
- Treats a NotebookLM summary of a judgment as primary evidence; the judgment must
  be opened and the paragraph located (A2 fencing).
- Drafts a private complaint, FIR text, or any document purporting to be a legal
  instrument — that is representation, not information.