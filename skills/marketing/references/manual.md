# Marketing

MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Bounded commercial strategy or routed specialist brief
DISCOVERY_PROFILE: D3_EXTERNAL
EFFECT_PROFILES: external_research
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: ads,designer,research,seo,social,writing
TERMINAL: Return one bounded decision or specialist brief; do not widen scope.

This router owns commercial decisions before or across execution channels. Select one primary branch
from the user's requested outcome.

## Route

| Primary decision | Read next |
|---|---|
| Establish product, audience, ICP, positioning, proof, and reusable context | `specialists/product-context/GUIDE.md` |
| Campaign, launch, content, SEO, free-tool, visual-story, or GTM strategy | `specialists/strategy/GUIDE.md`, then one matching `references/*.md` |
| Product/market idea validation or first-customer path | `references/graham.md` |
| Offer design, product packaging, value stack, bonuses, pricing, or guarantees | `specialists/offer-design/GUIDE.md` |
| Rapid validation landing/teaser workflow | `specialists/daily-mvp/GUIDE.md` |
| Experiments, analytics, pricing, referrals, lead magnets, revops, partnerships, community | `specialists/growth/GUIDE.md`, then one matching reference |
| Improve conversion in a page, form, signup, onboarding, paywall, popup, or retention flow | `specialists/cro/GUIDE.md`, then one matching reference |
| Generate domain names, campaign concepts, ad/video angles, or divergent marketing options | `specialists/ideas/GUIDE.md`, then one matching reference |

## Precise specialists win

| Execution intent | Route |
|---|---|
| Audience, customer, competitor, lead, Reddit, or trend evidence | `research` |
| Paid-media audit, targeting, bids, budgets, platform optimization | `ads` |
| Technical/content SEO execution or audit | `seo` |
| Social platform strategy, calendar, cadence, distribution | `social` |
| Finished prose/copy/email/blog deliverable | `writing` |
| Page/app/static creative implementation | `designer` |

## Marketing contract

1. Load `/brand` for a known venture. Never apply commercial tooling to Willow and Pine.
2. Start with existing product context when present; update it only when the task changes the facts.
3. Separate evidence gathering from strategy. Use `research` for missing market/customer facts.
4. Define the decision, observable success signal, constraints, and fatal assumption.
5. Prefer the smallest test that can disprove the strategy before committing spend or broad build
   work.
6. Do not fabricate demand, social proof, market size, conversion rates, or customer language.
7. **Analytics grounding for `growth`/`cro`/`analytics` on a live product.** Ask for the actual baseline
   first (PostHog/GA4/Plausible/Vercel — whatever the product uses). A CRO or growth plan without a real
   conversion/retention baseline is theoretical; if the data is unavailable, label the output
   "Hypothetical — requires baseline data," don't present it as optimisation.
8. **Feature verification before promoting a capability.** Do not write copy claiming a feature is live
   until it's confirmed shipped — check `docs/product.md` or `cortex graph search <feature>`. A feature
   that is `planned`/unverified gets "coming soon" framing (route to `writing`), never a live claim.

## Parametrization + Anti-Slop (mandatory)

- Positioning, campaign, and launch deliverables are parametrized per
  `skills/_shared/parametric-design.md`: channel mix, message risk, proof type, and funnel-stage
  weighting are named axes, not a single vibes-driven plan.
- Produce >=3 divergent directions that differ on at least 2 of those axes before converging on
  one recommendation.
- Record the winning parameter vector with the deliverable; a later revision ("more aggressive",
  "lower risk") mutates that vector rather than triggering a fresh redesign.
- All outward-facing copy inside a marketing deliverable (positioning statements, launch copy,
  campaign briefs) gets the anti-slop pass (`skills/_shared/anti-slop.md`) before delivery.
- Never fabricate demand, stats, social proof, or customer language to fill a parameter or
  direction — this reinforces the existing contract rule above; an unsupported claim is cut, not
  invented.

## Boundary with engineering

Engineering architecture and implementation planning -> `architect`. `marketing` may specify the
commercial outcome or experiment, but it does not design the code architecture. **Drive the decision
into execution:** once a strategy is chosen, hand the pieces to their owners — landing/page work →
`designer` then `commit`; copy → `writing`; paid → `ads`; SEO → `seo`; distribution → `social`. Don't
let the strategy die as a doc. When an experiment concludes, capture the durable result (what won, by
how much) through the Morph tool so the next commercial decision starts from it, not from scratch.
