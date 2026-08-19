---
name: marketing-growth
description: >
  Growth branch. Routes to specialized references for experiments, analytics, lead magnets,
  pricing, referral programs, revenue operations, sales enablement, community,
  partnerships, content performance audits, operator content systems, GTM-readiness audits,
  and telemetry/instrumentation audits. Use when user says "/marketing growth",
  "A/B test", "experiment", "analytics", "lead magnet", "pricing", "referral", "revops",
  "sales collateral", "community", "co-marketing", "partnerships",
  "conversion system", "content performance", "content machine", "operator OS", "media team",
  "content leverage", "GTM audit", "launch readiness", "launch strategy", "go-to-market audit",
  "distribution strategy", "telemetry audit", "instrumentation review", "activation funnel audit",
  "are we tracking the right things", or "event hygiene".
argument-hint: "ab-test | analytics | lead-magnets | pricing | referral | community | partnerships | revops | sales-enablement | content-performance | operator-content-os | gtm-audit | telemetry-audit | <freeform>"
---

# Growth - revenue and experiment router

Single entry for measurable growth work. Load only the matching reference.

## Routing

| Intent / phrasing | Read reference |
|---|---|
| A/B test, split test, experiment design, variant setup | `references/ab-test/reference.md` |
| Analytics setup, tracking plan, event schema, attribution | `references/analytics/reference.md` |
| Lead magnet, freebie, checklist, calculator, gated offer | `references/lead-magnets/reference.md` |
| Pricing, packaging, tiers, discounting, offer economics | `references/pricing/reference.md` |
| Referral program, ambassador loop, viral incentive | `references/referral/reference.md` |
| Community-led growth, Discord/Slack/forum strategy, rituals, advocates | `references/community/reference.md` |
| Co-marketing, partner campaigns, directory/listing layer, borrowed audiences | `references/partnerships/reference.md` |
| Revenue operations, CRM, funnel ops, pipeline hygiene | `references/revops/reference.md` |
| Sales collateral, pitch deck, one-pager, enablement docs | `references/sales-enablement/reference.md` |
| Content performance audit, channel/content metrics | `references/content-performance/reference.md` |
| Operator content OS, media team, content machine, leverage/systems for creator-led growth | `references/operator-content-os/reference.md` |
| GTM-readiness audit, launch strategy, distribution audit, why-now narrative, channel strategy, fatal flaw | `references/gtm-audit.md` |
| Telemetry / instrumentation audit, activation funnel coverage, event hygiene, PII scan, vanity metric flags | `references/telemetry-audit.md` |

## Internal Growth Council

Run this internally after the growth lever is identified and before producing the hypothesis or plan. This is not `/review`; it is a role pass to avoid single-lens growth advice.

| Reference | Role pass |
|---|---|
| `ab-test/reference.md` | Experiment designer, statistician, product owner, implementation skeptic |
| `analytics/reference.md` | Tracking architect, analyst, decision maker, data-quality skeptic |
| `lead-magnets/reference.md` | Offer strategist, audience pain miner, distribution lead, conversion writer |
| `pricing/reference.md` | Finance lead, customer psychologist, competitor analyst, simplicity advocate |
| `referral/reference.md` | Incentive designer, fraud skeptic, lifecycle marketer, product-fit lead |
| `community/reference.md` | Community builder, member advocate, ritual designer, health-metrics lead |
| `partnerships/reference.md` | Partner strategist, audience-overlap analyst, offer matcher, ops skeptic |
| `revops/reference.md` | CRM operator, sales lead, data hygiene lead, process simplifier |
| `sales-enablement/reference.md` | Sales manager, buyer skeptic, proof builder, enablement operator |
| `content-performance/reference.md` | Analyst, editor, SEO/social strategist, repurposing lead |
| `operator-content-os/reference.md` | Operator, media-team lead, systems designer, leverage skeptic |
| `gtm-audit.md` | GTM strategist, distribution skeptic, narrative critic, channel prioritizer |
| `telemetry-audit.md` | Data architect, activation auditor, PII watchdog, dashboard designer |

Output standard: measurable hypothesis, target metric, constraint/risk, smallest test, and decision rule.

## Workflow

1. Run `/brand <brand-code>` or read the relevant brand rules for branded work.
2. Identify the growth lever and success metric.
3. Read the matching reference only.
4. Output a measurable hypothesis, concrete next action, and validation plan.

Some ventures are explicitly non-commercial. Do not apply growth tooling to one unless the approving human explicitly asks; the consuming project's per-venture policy governs.
