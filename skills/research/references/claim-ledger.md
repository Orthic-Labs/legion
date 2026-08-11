---
name: research-claim-ledger
description: Current durable evidence and atomic-claim contract implemented by tools/research-core/ledger.py.
---

# Evidence and claim ledger

The durable truth for a run is `evidence.jsonl` plus `claims.jsonl`; the brief is rendered from those
records. The executable validator is `tools/research-core/ledger.py`.

Every evidence record must identify its source, retrieval date, locator, bounded quote or explicit
paraphrase, discovery provenance (`suggested_by`, `seed_chain`), source role, independence cluster,
and `instructionPolicy: data_only`. OA-recovered or substituted text must carry
`body_is_not_from_source` plus the substitution disclosure.

Every claim is atomic and includes `claim_type`, `source_ids`, `confidence`, `as_of`, and status
(`supported|contested|unresolved|superseded`). Observations, inferences, and recommendations are
separate claim types. Recommendations cannot exceed the weakest supporting claim and cannot render
without support.

Domain extensions are mandatory when applicable:

- Legal: authority type, jurisdiction/forum, precedential status, negative treatment, and
  `current_as_of`.
- Medical: study design, PICO, applicability, and regulator/guideline metadata where relevant.

Automatic independence clustering and contradiction/consensus views are derived by
`tools/research-core/independence.py` and `contradictions.py`. Citation-to-sentence support is checked
against the final draft by `citecheck.py`.
