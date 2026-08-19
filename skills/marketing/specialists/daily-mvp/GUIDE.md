---
name: marketing-mvp
description: >
  Idea-to-shipped-MVP loop in one session. Domain check → landing page → teaser → deploy. Use when user
  says "/marketing mvp", "ship today", "build this idea", "MVP", "landing page for". For rapid validation,
  not production builds.
---

# Daily MVP

## Goal
Idea → live URL with email capture in <4 hours.

## Workflow

### Phase 1 — Validate (30 min)
1. **Idea brief:** problem, audience, why-now, monetization hypothesis
2. `/research` quick-scan: does anyone want this?
3. **Verdict gate:** if no signal, pivot or kill
4. `/marketing ideas domain` — 5 available domain name candidates (the `/marketing ideas` skill loads its own `references/domain.md`)
5. User picks + registers

### Phase 2 — Build (2 hours)
1. `/brand <brand-code>` — apply the project's brand rules, or the generic-sharp default
2. `/designer` — single landing page (Astro/Next.js minimal)
   - Hero + promise + 3-step how-it-works + email capture + footer
3. `/writing` — copy at L2 (teen) for max comprehension
4. `/designer static` — OG image
5. `/seo llms-txt` — even for one-pager

### Phase 3 — Ship (30 min)
2. Connect domain
3. Email capture: ConvertKit form embed = fastest
4. Verify end-to-end. For local/live page QA, use the shared `qa` skill headlessly: project `qa:browser` when available, `qa-shot.mjs` for app/page viewport screenshots, and `qa-functional.mjs` for email-capture click/type/assert flows. Do not use desktop screenshots for routine visual proof.

### Phase 4 — Tease (1 hour)
1. `/designer static` — 3 social variants (1:1, 9:16, 16:9)
2. Optional: a 5-second teaser via the host's media-production capability, when the host provides one
3. `/writing` — 3 caption variants
4. Post manually to relevant communities (use reddit-mining for which)

## Scope discipline
- ONE primary action (email capture, not "buy + signup + book demo")
- NO auth, NO database
- NO custom backend
- NO design-from-scratch (use shadcn)

## Success criteria
- [ ] Live URL
- [ ] Mobile-responsive (375px)
- [ ] OG image renders (opengraph.xyz)
- [ ] Email capture works
- [ ] At least one teaser ready
- [ ] llms.txt deployed

## Anti-patterns
- Scope creep
- Brand obsession before validation
- Custom design when shadcn works
- Skipping validation phase
