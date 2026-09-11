# SEO specialist workflow packs

This reference is the canonical owner for checklist-derived specialist packs that do not justify separate autonomous skills. Activate a pack from target facts and requested claim. Every pack emits evidence objects, coverage, `Pass|Partial|Fail|N/A|Not testable`, prioritized findings, and a validation method. Missing evidence never becomes a pass.

## Policy
Audit search-spam/security/commercial-governance risks: hacked/injected content, deceptive redirects, hidden text/links, manipulative links, UGC spam, scaled-content/site-reputation abuse, structured-data spam, disclosure/privacy exposure, and AI-assisted publishing governance. Separate technical evidence, platform-policy interpretation, legal-review dependency, and unknowns.

## Bot policy
Build a crawler-purpose matrix: search/index, generative retrieval, model training, user-triggered. Test robots, meta/X-Robots, WAF/CDN/rate limiting and private-area authentication. Keep Googlebot/Google-Extended, OAI-SearchBot/GPTBot/ChatGPT-User, Claude-SearchBot/ClaudeBot/Claude-User, Bingbot and other material identities distinct. User-agent or cryptographic identity verification never grants action authority.

## Logs and crawl efficiency
Ingest verified server/CDN/WAF logs when supplied. Normalize verified bot identity, URL/template, status, latency, bytes/resource class and timestamp. Join to crawl, sitemap, internal-link, index, traffic and backlink evidence to identify crawl waste, under-crawled priority pages, stale redirects, errors and AI-crawler access failures. Spoofable user-agent strings alone are insufficient identity evidence.

## Agent readiness
Exercise representative non-binding browser tasks: find, compare, open detail, filter/unfilter, enquire, recover from form error and stop before a binding action. Check semantic links/buttons, accessible names, state/error exposure, modal/focus/consent recovery, duplicate submission prevention and machine-readable success/failure. Binding actions require normal Legion authority.

## Search appearance and Discover
Audit title-link inputs, snippets, site name, favicon, breadcrumb/date/image presentation, rich-result eligibility, mobile/desktop SERP fit and Discover readiness. Distinguish eligibility from guaranteed presentation. Where first-party reports exist, keep Search, Discover, Google News and generative surfaces separate.

## Media
Images: delivery, dimensions, format, alt/caption/context, previews, licensing/rights and structured data. Video: watch pages, thumbnails, transcripts, chapters, sitemaps, VideoObject, player accessibility/performance. Audio/podcast: stable episode pages, feeds, transcripts, structured data, syndication and lifecycle.

## Documents and developer documentation
Cover PDFs, office documents, reports, slides, spreadsheets, datasets and API/reference docs. Decide HTML vs document vs both; verify text extraction, reading order/accessibility, metadata/directives/canonicals/versioning, stable landing pages, dataset licensing, API versions, code samples, secret leakage, deprecations and crawlability.

## Ecommerce
Use `ecommerce-2026.md` plus this pack. Cover category/catalogue architecture, facets, product details, variants, availability/discontinued lifecycle, merchant feeds, reviews/UGC, conversion/performance and visible-page/feed reconciliation for price, currency, availability, shipping, returns, identifiers and selected variant.

## Publisher/news
Audit publisher identity, editorial standards, author/editor profiles, article template, freshness/date integrity, news sitemaps/feeds, topic archives, source/originality quality, Discover/News eligibility, engagement and syndication/republishing canonicals.

## Access states
Compare logged-out/logged-in, consented/non-consented, control/experiment variants, locale, device and cache states for paywalls, login walls, lead gates, personalisation and A/B tests. Detect cloaking, private-content leakage, indexable session/variant URLs and cross-user cache leaks.

## Migration
Create a pre-migration inventory/baseline, one-to-one mapping or explicit 404/410 decision, staging QA, launch controls, old-host retention, rollback and post-launch monitoring. Include HTML, media, documents, subdomains, locales, deep links, canonicals, hreflang, schema, analytics, conversions and CDN/WAF behavior. Blanket redirects fail unless semantically justified.

## Analytics
Validate instrumentation, event one-fire semantics, SPA navigation, environment separation, time zone/currency, referrals, cross-domain tracking, consent, qualified conversions, calls/chat/WhatsApp/bookings, CRM/offline outcomes, deduplication and attribution. Observed, modeled and estimated values stay separate.

## Forecast
Forecast only as low/base/high scenarios with explicit demand, visibility, CTR/no-click pressure, conversion, value, time, cost, dependency and uncertainty assumptions. Never present forecast as an observed outcome.

## Experiment
Define hypothesis, primary metric, guardrails, comparable cohorts/holdouts where possible, pre-trends, seasonality, evaluation window, rollback and causal method. Before/after-only evidence is explicitly weaker than controlled evidence.

## Monitor, release gate and incident
Daily/weekly/monthly/quarterly monitoring follows `operations.md`. Release gates verify changed URLs/templates before deployment claims. Incidents define detection, ownership, severity, containment, rollback/escalation, root cause and preventive-control update. Platform/source review dates are part of governance.

## Accessibility/mobile/PWA/SPA
Check viewport/mobile usability, keyboard/focus/semantic structure, accessible names, error messaging and critical controls. For PWA/SPA, test stale app shells, offline/soft-404 behavior, service-worker/cache effects, client-side route indexability and route-bound analytics/performance evidence.

## Feeds
Reconcile sitemap/news/video/product/podcast or other applicable feeds against canonical URL inventory, lifecycle, timestamps and visible state. A feed may not advertise redirects, errors, noindex pages or stale product availability as canonical current content.

## Vertical extension rule
Automotive/marketplace and future vertical packs extend this kernel; they do not redefine generic SEO status, evidence, authority or outcome semantics.