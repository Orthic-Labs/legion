# Method — scholarly

Loaded when `ResearchRoute.methods` contains `scholarly`.

## Mechanics

- The built-in provider searches Crossref and opens DOI landing pages. A configured provider bridge
  may add PubMed, Europe PMC, OpenAlex, arXiv, SSRN, or licensed indexes without changing the
  Research Core contract.
- A search result or abstract summary is a lead. The source must be opened and the supporting
  passage located before evidence admission.
- Every cited DOI in `verified` assurance is checked fresh through OpenAlex and Crossref at the ship
  gate. Unknown status blocks unless the operator explicitly accepts degraded assurance.
- Primary studies, registrations, regulator documents, corrections, and retraction notices are
  proposition-fit evidence. Reviews are tagged as reviews and do not independently establish an
  effect size.
- If an OA or repository copy substitutes for the source URL, record
  `body_is_not_from_source=true`, the resolver, version, and substitution disclosure.

Each clinical/scientific claim records study design, population/sample, method, result, limitations,
and applicability where relevant. Vendor whitepapers and unattributed summaries may be leads but do
not become primary scholarly evidence.
