# Method — competitor

Loaded when `ResearchRoute.methods` contains `competitor`. This is a composable Research method, not a delegated skill and not a catalog entry.

## Purpose

Use competitor research to compare products, vendors, alternatives, pricing, positioning, SEO pages, sales claims, and market narratives. The method supports alternative pages, versus pages, battlecards, product teardowns, and decision memos, but it does not bypass the Research route contract.

## Source discipline

- Treat vendor websites, changelogs, pricing pages, docs, terms, public security pages, and official support material as primary sources for vendor claims.
- Treat reviews, Reddit, forums, analyst notes, and social posts as audience or commentary evidence, not primary vendor evidence.
- A search snippet or AI-generated comparison is a lead. The underlying page must be opened and the supporting passage located before evidence admission.
- Record retrieval date, locator, `suggested_by`, `seed_chain`, and independence cluster for every source.
- Never misrepresent a competitor. If a competitor is stronger on a dimension, record that plainly.

## Comparison dimensions

Choose dimensions from the frozen decision, not a generic feature checklist. Common dimensions:

- target user and use case;
- core features and workflow coverage;
- pricing, limits, plan gates, and billing model;
- deployment model, privacy, security, data retention, and compliance posture;
- integrations, file support, automation, API, and ecosystem;
- performance or benchmark claims;
- support, documentation, migration, and lock-in;
- public roadmap or changelog velocity.

## Evidence model

Competitor claims are atomic and dated. Price, feature, security, and benchmark claims require a primary source when possible. Review or community sentiment must be labeled as sample-bound observation, with counts rather than fabricated percentages.

## Output pattern

Render:

1. executive decision summary;
2. comparison table with source IDs per cell when material;
3. honest strengths and weaknesses for each competitor;
4. positioning implications and recommended claims;
5. unsupported or unresolved claims;
6. update risks, especially pricing, plan limits, and recently changed features.
