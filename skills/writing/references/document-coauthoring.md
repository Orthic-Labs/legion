---
name: document-coauthoring
description: Guide collaborative writing of documentation, proposals, technical specs, decision docs, and RFCs through context gathering, section-by-section drafting, refinement, and fresh-reader comprehension checks.
---

# Document Co-authoring

Use for substantial structured documents. Gather the document type, audience, intended impact, template, constraints, and available source material; let the user share context in any order, then ask only questions that resolve important gaps. Keep assumptions visible and do not invent stakeholder views, technical facts, or evidence.

Agree on a useful section structure, starting with the section that has the most uncertainty. For each section, clarify its purpose, identify missing points, draft it, and refine from the user's feedback before moving on. Use focused alternatives when they help resolve a real choice; do not generate brainstorming lists for their own sake. Leave summaries until supporting sections are stable. Re-read the complete document for flow, gaps, contradictions, repetition, and unsupported claims.

## Fresh-reader comprehension check

When the document is meant for readers who lack the authors' context, test it using only the document and realistic reader questions. If a native fresh-context reader is available, dispatch one read-only Oracle with no inherited conversation history or other source material. This branch permits one reader; it does not create a new user chat. Otherwise, provide a compact test prompt the user can run in a fresh conversation:

> Read only the document below. Answer these reader questions using its content. For each answer, quote or point to the supporting section; mark anything the document does not answer. Then list ambiguous terms, assumed background, contradictions, and decisions a reader cannot recover. Do not fill gaps from outside knowledge.

Use questions that test the document's purpose, key decision or recommendation, rationale, implications, and next steps. Fix gaps that affect understanding, then repeat the check on affected questions. Report unresolved questions instead of implying the document passed. For low-stakes or short documents, skip this check unless requested.
