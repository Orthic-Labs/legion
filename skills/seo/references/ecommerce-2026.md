# Ecommerce SEO — current operating guidance (2026)

Use this reference for product, category, marketplace, Merchant Center, shopping, product schema and AI-commerce search work. Keep product truth source-bound; SEO may detect inconsistencies but must not invent price, availability, shipping, returns, ratings or compatibility.

## Core product-page contract

For every important product/category URL, verify:

- crawl/indexability, canonical and sitemap membership;
- Product/Offer/AggregateOffer/Review schema only when visible content supports it;
- price, currency, availability, variant and shipping facts agree with first-party commerce data;
- Merchant Center feed and page do not materially disagree;
- title/H1 and copy reflect actual product differentiation rather than templated keyword swapping;
- primary product image, supplementary images and media are fetchable and accurately described;
- internal linking connects category -> product -> related/complementary products without orphaning;
- faceted/filter URLs have an explicit indexation/canonical policy;
- discontinued, out-of-stock and replaced products have an intentional lifecycle decision rather than accidental 404/noindex behavior.

## Merchant / shopping surfaces

Treat Merchant Center diagnostics and free-listing/product-result eligibility as their own evidence class. A valid Product schema block is not proof that a product is eligible, approved or visible in shopping surfaces.

Preserve evidence provenance across:

1. page/rendered markup;
2. Merchant Center/feed diagnostics or export;
3. Search Console merchant/product reports where available;
4. Search/Shopping SERP observations;
5. business outcomes.

Never collapse these into a single score.

## AI-generated commerce text

Where a commerce platform/feed requires AI-generated titles/descriptions or assets to be labeled separately, preserve that requirement at the feed/platform layer. Do not assume page copy and feed copy have identical policy treatment.

## Page-type / SERP fit

Use `search-experience.md` for high-value product/category terms. If the SERP overwhelmingly rewards product grids, category pages, tools, marketplaces or local inventory, do not recommend a blog article merely because it can target the words.

## Marketplace intelligence

Marketplace and competitor data may inform pricing/assortment/content decisions, but third-party scraped price/rank data is an estimate with capture time and geography. Never overwrite first-party product truth with marketplace observations.

## Universal Commerce Protocol and emerging commerce interfaces

Emerging machine-readable commerce protocols may be audited as forward-looking opportunities when relevant. Missing support is not automatically an SEO defect or ranking failure unless the target platform documents it as an eligibility requirement. Re-check current Google/Bing/platform primary sources before recommending implementation.

## Scaled catalog safeguards

For large catalogs:

- group near-identical variants intentionally rather than creating index bloat;
- require unique decision-useful product facts, not synthetic prose variation;
- monitor indexed vs intended URL counts and faceted crawl growth;
- measure template-level metadata duplication;
- prefer canonical, noindex, consolidation or navigation changes over generating more text when the page adds no information gain.
