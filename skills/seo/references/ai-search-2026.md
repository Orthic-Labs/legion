# AI Search Authority — Google, Bing and crawler semantics (2026-09-11)

This is the current correction layer for SEO/AEO/GEO claims. Re-check official sources before high-impact advice because these surfaces change quickly.

## Core rule

For Google, GEO/AEO is not a separate loophole around SEO. Eligibility for AI Overviews and AI Mode rests on normal Google Search crawling/indexing and content quality. Apply SEO fundamentals plus answerability, information gain, factual extractability and source clarity; do not invent AI-only ranking factors.

Keep these evidence classes separate:

1. **Google first-party generative impressions** — Search Console Generative AI Performance.
2. **Bing first-party AI citation activity** — Bing Webmaster Tools AI Performance.
3. **Referral/business outcomes** — analytics/server evidence.
4. **Controlled prompt samples** — observational benchmark, non-exhaustive and non-deterministic.
5. **Third-party AI visibility estimates** — provider observations, not first-party truth.

Never collapse them into one "AI visibility score".

## Google Search Generative AI Performance

Google announced dedicated Search Console Generative AI performance reports on 2026-06-03. As of 2026-08-31 Google says the Search and Discover generative reports are rolled out worldwide, subject to sufficient data/eligibility.

The Search report provides generative-AI **impressions**, including page, country, device and time views for Google Search generative features such as AI Overviews and AI Mode. Discover has a separate generative report.

Operational rules:

- Treat the report as first-party visibility evidence within its documented scope.
- `report unavailable` is not `zero impressions`.
- Preserve report type, property, date range, dimensions, export time and Google-stated limitations.
- Keep generative report data separate from ordinary Search Analytics rows unless Google documents a supported API/schema mapping.
- Prefer authorized UI export/import while no official programmatic endpoint for this dedicated report is documented.
- Do not infer citations, clicks, ranking position or conversions from an impression.
- Do not combine Google generative impressions numerically with sampled prompts or third-party estimates.

Official sources to verify:

- Google Search Central blog: `https://developers.google.com/search/blog/2026/06/gen-ai-performance-reports`
- Search report help: `https://support.google.com/webmasters/answer/16984139`
- Discover report help: `https://support.google.com/webmasters/answer/16983858`
- Google AI optimization guide: `https://developers.google.com/search/docs/fundamentals/ai-optimization-guide`

## Bing Webmaster Tools AI Performance

Bing AI Performance reports citation activity across supported AI experiences including Microsoft Copilot, AI-generated summaries in Bing and select partner integrations.

Current useful evidence:

- total citations;
- cited pages / page-level citation activity;
- average cited pages;
- grounding queries;
- grounding-query <-> cited-page mapping;
- citation trend over time;
- CSV/Excel exports.

Bing explicitly states this is aggregated/sampled citation activity, not ranking, authority, importance, clicks or a complete log. Grounding queries are grouped retrieval phrases, not exact user prompts. Data refreshes daily with processing delay.

Preview capabilities documented in Bing help include **Intents**, **Topics**, **Citation Share**, and **Compare**. Treat preview classifications as provider-derived observations, preserve their preview status, and do not reinterpret Citation Share as market share or traffic share.

Operational rules:

- Track citation count, cited URLs, grounding-query/topic/intent associations and citation share separately.
- Map grounding queries to owned query/topic clusters and page families.
- Use low citation share on a high-value topic as an opportunity signal, not proof that content quality is the cause.
- Preserve Bing's sampling caveats; totals can differ between views.
- Never call citations visits or conversions. Join to analytics only when referral evidence exists.
- Prefer export/import until a documented supported API exposes the AI Performance schema.

Official sources:

- Bing AI Performance help: `https://www.bing.com/webmasters/help/ai-performance-9f8e7d6c`
- Bing announcement: `https://blogs.bing.com/webmaster/February-2026/Introducing-AI-Performance-in-Bing-Webmaster-Tools-Public-Preview`
- Bing Webmaster Guidelines: `https://www.bing.com/webmasters/help/webmaster-guidelines-30fba23a`

Bing notes that legacy SOAP/POX APIs retire on 2026-08-31. New Legion integration work must target supported REST/API surfaces rather than adding legacy dependencies.

## Search eligibility vs model-training controls

Do not conflate crawler purposes.

| Capability claim | Relevant control | Do not substitute |
|---|---|---|
| Google Search / AI Overviews / AI Mode eligibility | Googlebot + normal Search indexability/snippet controls | Google-Extended |
| Google Gemini/Vertex training/grounding use preference | Google-Extended | Googlebot |
| ChatGPT Search citability | OAI-SearchBot | GPTBot |
| OpenAI model-training crawl | GPTBot | OAI-SearchBot |
| Claude search citability | Claude-SearchBot | ClaudeBot |
| Anthropic model-training crawl | ClaudeBot | Claude-SearchBot |
| Apple search discovery | Applebot | Applebot-Extended |
| Apple generative-training opt-out | Applebot-Extended | Applebot |

User-triggered fetchers are a separate class and may not obey robots.txt in the same way as autonomous crawlers. Use current vendor documentation before making access claims.

Google-Extended must never be scored as Google Search/AI Overview readiness. GPTBot must never be scored as ChatGPT Search readiness.

## llms.txt

Treat `llms.txt` as an optional interoperability/documentation artifact, not a Google ranking or citation lever. Google's current AI optimization guidance says special AI text files are not required for Google Search. Presence may be reported; absence is not an SEO failure unless a separate consumer contract requires it.

## AEO method

Build a question inventory from first-party query data first, then PAA/related/autocomplete/Bing/community/support/sales evidence. For each important question record:

`question -> intent -> intended page -> answer present? -> extractable? -> evidence/source? -> current traditional visibility -> current generative visibility`

Prefer direct answer -> evidence -> explanation -> related questions. Question headings and FAQ formatting are means, not goals. Do not manufacture FAQ blocks or schema for questions users do not need.

## GEO method

Evaluate six distinct dimensions:

1. **Eligibility/access** — crawl, index, snippet controls, renderability, WAF/CDN behavior.
2. **Information gain** — original data, methods, tests, examples, product facts, primary documentation, transparent comparisons.
3. **Factual extractability** — explicit entities, dates, units, geography, methodology, sample sizes, limitations and nearby sources.
4. **Entity/corroboration** — consistent first-party entity facts plus legitimate independent mentions; never manufacture mentions.
5. **Answer coverage** — whether high-value questions have authoritative, self-contained answers.
6. **Measured visibility/outcome** — Google generative impressions, Bing citations/share, referral traffic and qualified outcomes kept as separate metrics.

## Controlled prompt benchmark

Prompt sampling complements first-party reports; it does not replace them. Freeze a representative bank across category discovery, brand, comparison, informational and multi-constraint tasks. Record:

`prompt | engine/surface | locale | account state | date/time | repetition | brand mentioned | cited? | citation URL | competitors | claim accuracy`

Use repeated observations and report volatility. Never claim population-level share from a small prompt set.

## Information-gain gate

Before proposing a new page or major expansion, answer: **what useful information will exist after this work that did not already exist in the current competitive result set?**

If the answer is only rephrasing, keyword expansion, generic summaries, synthetic FAQ volume or template multiplication, prefer `WAIT`, `KEEP`, consolidation, a better product/data asset, or original research instead.