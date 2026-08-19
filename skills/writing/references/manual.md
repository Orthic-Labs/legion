# Writing

MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Bounded prose or copy deliverable
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: source_read,output_write
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Return one bounded text artifact; do not widen scope.

Classify by the job the words must do, not by length. Load one primary guide; add a second only when
the requested deliverable truly combines purposes.

## Route

| Writing job | Read next |
|---|---|
| Essay, newsletter, explainer, caption, thread, editorial/long-form prose | `specialists/editorial/GUIDE.md` |
| Research-heavy long-form article that is not a publish-gated SEO blog | `references/research-article.md` |
| Video, carousel, podcast, or narrative script | `references/script.md` |
| Content repurposing/atomization | `references/content-repurposer/reference.md` |
| Blog post, SEO article, blog audit, upgrade, publish QA, internal links/schema | `specialists/blogs/GUIDE.md` and its `references/writing-research.md` when needed |
| Landing/sales page, offer, CTA, ad copy, product copy, bio, DM, persuasive copy | `specialists/copywriting/GUIDE.md` |
| Profile bio or link-in-bio work needing the dedicated profile workflow | `specialists/profile-copy/GUIDE.md` after the copywriting guide |
| Newsletter campaign, lifecycle flow, sequence, cold outreach, transactional email | `specialists/email/GUIDE.md` |
| Release notes or customer-facing changelog from git history | `specialists/changelog/GUIDE.md` |

## Writing contract

1. Load `/brand` first for brand-specific work.
2. Establish audience, purpose, desired action, source/proof constraints, and format before drafting.
3. Never fabricate quotes, statistics, testimonials, founder stories, experience, or product proof.
4. Use research and citations when factual depth matters; distinguish sourced fact from editorial
   judgment.
5. Run the selected guide's anti-slop and quality gate before delivery.
6. If the copy will be judged inside a rendered page or app, flag to the host/orchestrator that
   `audit-visual`/`qa` review is needed next; text alone cannot prove visual hierarchy or CTA placement.
7. **Hard-constraint verification.** When the brief sets a strict length (X-word caption, thread limit,
   meta description ≤ ~155 chars) — LLMs routinely overshoot — count the final output and trim to fit
   before delivery. A piece that violates a hard platform limit is not done.

## Quality gates

- **Anti-slop pass (mandatory).** Every prose deliverable — copy, captions, blog posts, scripts,
  emails, microcopy — passes `skills/_shared/anti-slop.md` before shipping: edit mode when drafting,
  detect mode when reviewing someone else's draft. Brand card precedence stands: brand voice rules
  in the project's brand rules file win over the anti-slop list where they conflict.
- **Parametric contract (mandatory).** Follow `skills/_shared/parametric-design.md`: parametrize tone,
  structure, hook, and evidence-density axes before drafting. For any non-trivial piece, generate
  ≥3 meaningfully different directions (divergent phase) before converging on one. Treat a later
  revision as an axis mutation ("make it bolder" -> `copy_tone ↑`), not a fresh redraft.

## Boundaries

- Commercial direction, launch strategy, positioning process, growth, or CRO decision -> `marketing`.
- Paid-media setup, targeting, bids, budgets, performance audit -> `ads`.
- Social calendar, platform strategy, distribution, cadence -> `social`.
- Website/app implementation or static graphic composition -> `designer`. **Landing-page copy** is
  design-coupled: once approved, offer to route it to `designer` to build the layout — don't leave copy
  in a text file for the user to wire up. Landing copy also gets a search pass: align H1/subheads/meta
  with intent (`/seo`) before finalising, not just persuasion.
