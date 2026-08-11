# Method — document

Loaded when `ResearchRoute.methods` contains `document`. Used for local-corpus work:
the user supplies PDFs, transcripts, or reports and the route indexes and queries
them.

## Mechanics

- Local corpus lives under a route-declared root; the route records the root path in
  the manifest for reproducibility.
- Indexing produces one evidence record per chunk with `locator` (page or section),
  `publisher` (the document's author), and `suggested_by` rooted in
  `seed:corpus:<path>`.
- Quotations from the user's own documents are subject to the same 15-word / 1-per-
  source caps as external sources. A paraphrase (`is_paraphrase: true`) is allowed to
  exceed 15 words but must not smuggle a longer verbatim string under the paraphrase
  label.
- The provider is `local-corpus`; no external request is issued unless the route also
  lists `web` in `methods`.
