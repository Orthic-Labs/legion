---
name: seo-local
description: >
  Local SEO analysis covering Google Business Profile optimization, NAP
  consistency, citation health, review signals, local schema markup,
  location page quality, multi-location SEO, and industry-specific
  recommendations. Detects business type (brick-and-mortar, SAB, hybrid)
  and industry vertical (restaurant, healthcare, legal, home services,
  real estate, automotive). Use when user says "local SEO", "Google
  Business Profile", "GBP", "map pack", "local pack", "citations",
  "NAP consistency", "local rankings", "service area", "multi-location",
  "local search", "geo-grid", "rank tracking", "GBP audit", "review
  velocity", "competitor radius", "maps analysis", "local rank tracking",
  "Share of Local Voice", or "SoLV".
  (Consolidates former seo-maps skill — includes geo-grid rank tracking,
  GBP profile auditing, review intelligence, cross-platform NAP verification,
  and competitor radius mapping.)
user-invokable: true
argument-hint: "[url]"
license: MIT
metadata:
  author: AgriciDaniel
  version: "1.7.0"
  category: seo
---

# Local SEO Analysis (March 2026)

## Key Statistics

| Metric | Value | Source |
|--------|-------|--------|
| GBP signals share of local pack weight | 32% | Whitespark 2026 |
| Proximity share of ranking variance | 55.2% | Search Atlas ML study |
| Review signals share (up from 16%) | ~20% | Whitespark 2026 |
| Google searches seeking local info | 46% | Industry data |
| Mobile "near me" searches leading to visit in 24h | 76% | Google confirmed |
| ChatGPT/AI usage for local recommendations | 45% (up from 6%) | BrightLocal LCRS 2026 |
| ChatGPT local conversion rate | 15.9% | Seer Interactive |
| Google organic local conversion rate | 1.76% | Seer Interactive |
| Local pack ads growth (Jan 2025 to Jan 2026) | 1% to 22% | Sterling Sky |

---

## Business Type Detection

Detect from page signals before analysis. This determines which checks apply.

### Brick-and-Mortar
- Physical street address visible in page content or footer
- Google Maps embed with pin/directions
- "Visit us at", "Located at", "Come see us"
- Structured address in LocalBusiness schema

### Service Area Business (SAB)
- No visible physical address
- Service area mentions: "serving [city/region]", "service area includes"
- "We come to you", "On-site service", "Mobile [service]"
- `areaServed` in schema without `address.streetAddress`

### Hybrid
- Both physical address AND service area language present
- "Visit our showroom" combined with "We also serve [areas]"

**Impact on checks**: SABs skip embedded map verification and physical address consistency. Brick-and-mortar gets full NAP + map checks.

---

## Industry Vertical Detection

Detect from page signals and GBP category patterns. Routes to industry-specific checks from `references/local-schema-types.md`.

| Vertical | Detection Signals |
|----------|------------------|
| **Restaurant** | /menu, menu items, reservations, cuisine types, food ordering, "dine-in", "takeout" |
| **Healthcare** | insurance accepted, patients, appointments, NPI, medical terms, "Dr.", HIPAA notice |
| **Legal** | attorney, lawyer, practice areas, bar admission, case results, "free consultation" |
| **Home Services** | service area, emergency service, "free estimate", licensed/insured/bonded, "24/7" |
| **Real Estate** | listings, MLS, properties for sale/rent, agent bio, brokerage, "open house" |
| **Automotive** | inventory, VIN, test drive, dealership, service department, "new/used/certified" |

If no vertical detected, use generic `LocalBusiness` analysis path.

---

## Analysis Dimensions

### 1. GBP Signals (25%)

Primary category is the **single most important local pack factor** (Whitespark #1, score: 193). Incorrect primary category is the **#1 negative factor** (score: 176).

**Check for:**
- GBP embed or reference detectable on page (Maps iframe, place ID, reviews widget)
- Primary category appropriateness (infer from page content vs visible GBP data)
- Evidence of secondary categories (optimal: 4 additional per BrightLocal)
- GBP posts presence (no direct ranking impact per WebFX, but triggers Post Justifications)
- Photos/video evidence (45% more direction requests with photos, Agency Jet)
- Q&A content (deprecated Dec 2025, replaced by Ask Maps Gemini AI -- recommend recreating Q&A content as FAQ sections on website; GBP removed existing Q&A with no export available)
- Google Verified badge eligibility (replaced Guaranteed/Screened in Oct 2025)
- GBP link URL strategy: do NOT link to strongest website page (Sterling Sky Diversity Update -- risks suppressing organic rankings)
- Business hours visibility on page (businesses open at search time rank higher, factor #5)

**Scoring guide:**
- Full: GBP embed present, category signals align, posts active, photos present
- Partial: Some GBP signals present but incomplete
- Low: No visible GBP integration on website

### 2. Reviews & Reputation (20%)

Review velocity matters more than total count. The **18-day rule** (Sterling Sky): rankings cliff if no new reviews for 3 weeks.

**Check for:**
- Total Google review count visible on page or schema (magic threshold: 10, Sterling Sky)
- Star rating (31% of consumers only use 4.5+, 68% only use 4+, BrightLocal 2026)
- Review recency indicators (74% only care about reviews in last 3 months)
- `aggregateRating` in schema (ratingValue, reviewCount, bestRating)
- Third-party review presence (consumers use average of 6 review sites, BrightLocal 2026)
- Owner response patterns (88% would use business that responds, BrightLocal)
- Review gating detection: any pre-screening of satisfaction before directing to review platform is prohibited by Google (fake engagement policy) and FTC ($53,088/violation)

**Industry-specific:**
- Healthcare: HIPAA prohibits confirming/denying reviewer is a patient in responses
- Legal: attorney-client privilege considerations in review responses

**Scoring guide:**
- Full: 10+ reviews, 4.5+ stars, recent activity, owner responses, multi-platform presence
- Partial: Some reviews but gaps in recency, rating, or response rate
- Low: <10 reviews, no recent activity, no responses, single platform only

### 3. Local On-Page SEO (20%)

Dedicated service pages = **#1 local organic factor AND #2 AI visibility factor** (Whitespark 2026).

**Check for:**
- Title tag contains city/service keywords
- H1 tag with local intent (city + service)
- NAP (Name, Address, Phone) visible in page HTML (footer, contact section, header)
- Dedicated service pages (one page per core service)
- Location page quality for multi-location sites:
  - **>60-70% unique content** minimum (industry consensus, no Google-confirmed threshold)
  - **Swap test**: if you can swap the city name and content still makes sense, it's a doorway page (RicketyRoo method). HVAC company lost 80% rankings + 63% traffic after March 2024 Core Update for this pattern
  - Local photos, area-specific testimonials, local FAQs
- Embedded Google Map (geographic signal reinforcement, not direct ranking factor -- lazy-load to mitigate speed impact)
- Click-to-call button (`tel:` link) and contact form above the fold
- Internal linking architecture: hub-and-spoke, every critical page within 3 clicks of homepage
- 2-5 contextual internal links per 1,000 words with descriptive anchor text

**Multi-location specific:**
- Store locator with individual crawlable URLs (SSR/SSG preferred over CSR)
- Subdirectory structure: `domain.com/locations/city-name/` (subdirectories consolidate link equity better, Bruce Clay: 50%+ traffic lift)
- Each location page has unique LocalBusiness schema with `@id`

**Scoring guide:**
- Full: City in title + H1, NAP visible, dedicated service pages, no doorway patterns, good internal linking
- Partial: Some local signals but missing service pages or doorway page risk
- Low: Generic title/H1, NAP not visible, thin location pages

### 4. NAP Consistency & Citations (15%)

Citations declining for traditional pack rankings but **3 of top 5 AI visibility factors are citation-related** (Whitespark 2026). Google's July 2025 documentation update removed "directories" from prominence definition.

**Check for:**
- NAP extraction: compare Name, Address, Phone from:
  1. Visible page HTML (footer, contact page)
  2. LocalBusiness JSON-LD schema
  3. Any visible GBP data
  - Flag any discrepancies between these three sources
- Citation presence on Tier 1 directories (check via WebFetch or site: search patterns):
  - Google Business Profile signals on page
  - Yelp: `site:yelp.com "Business Name"`
  - BBB: `site:bbb.org "Business Name"`
  - Facebook business page references
- Apple Business Connect awareness (usage doubled to 27%, BrightLocal 2026 -- recommend claiming)
- Bing Places awareness (powers ChatGPT, Copilot, Alexa -- recommend claiming and optimizing)
- Industry-specific directory recommendations: load `references/local-schema-types.md` for per-vertical citation sources
- Data aggregator awareness: Data Axle, Foursquare, Neustar/TransUnion (recommend submission for downstream distribution)

**Scoring guide:**
- Full: Consistent NAP across page/schema, Tier 1 citations detected, industry directories present
- Partial: NAP present but inconsistencies, some citations missing
- Low: NAP discrepancies, no detectable citations, no schema address

### 5. Local Schema Markup (10%)

Schema is NOT a direct ranking factor (John Mueller confirmed). But enables rich results (43% CTR increase, Webstix case study) and helps AI systems parse business information.

**Check for:**
- LocalBusiness schema presence (extract JSON-LD blocks)
- Required properties: `name`, `address` with PostalAddress sub-properties
- Recommended properties: `geo` (minimum 5 decimal places, Confirmed), `openingHoursSpecification`, `telephone`, `url`, `priceRange` (<100 chars), `image`, `aggregateRating`
- **Correct subtype for industry** -- load `references/local-schema-types.md`:
  - Restaurant using `Restaurant` not generic `LocalBusiness`
  - Legal using `LegalService` not deprecated `Attorney`
  - Auto dealer using `AutoDealer` not deprecated `VehicleListing`
  - Healthcare using `MedicalClinic`/`Hospital`/`Dentist` not generic `MedicalBusiness`
- SAB-specific: `areaServed` with named cities (recommended, not in Google's official list but Schema.org supported)
- Multi-location: each location page has own LocalBusiness with unique `@id`, linked via `branchOf` to Organization on homepage
- Industry-specific schema patterns (per `references/local-schema-types.md`):
  - Restaurant: Menu + MenuSection + MenuItem + ReserveAction
  - Healthcare: Physician (Person) + MedicalSpecialty + sameAs to NPI
  - Legal: LegalService + Person + Service (practice areas)
  - Home Services: Subtype + areaServed + Service
  - Real Estate: RealEstateAgent + Person + RealEstateListing
  - Automotive: AutoDealer + Car + Offer (separate dept schemas)

**Scoring guide:**
- Full: Correct subtype, all recommended properties, industry-specific patterns, valid JSON-LD
- Partial: LocalBusiness present but generic type or missing recommended properties
- Low: No local schema, or schema with errors/placeholder content

### 6. Local Link & Authority Signals (10%)

Links declining for local pack but remain **~26% of local organic ranking** (Whitespark 2026, #2 factor group). "Best of" list placements = **#1 AI visibility citation factor**.

**Check for:**
- Local backlink indicators detectable from page:
  - Chamber of Commerce mentions or links (high Trust Flow, ~80% more consumer visits, GlueUp)
  - BBB accreditation/badge (Google uses BBB for business verification)
  - Local news/press mentions
  - Community involvement signals (sponsorships, local events, partnerships)
- "Best of" list presence (top AI visibility factor per Whitespark 2026)
- Digital PR signals: 66.2% of PR practitioners now track AI citations as KPI (BuzzStream 2026)
- Brand mentions correlate **3x more strongly** with AI visibility than traditional backlinks (Ahrefs: 0.664 vs 0.218 correlation)
- Link velocity benchmark: 5-10 quality local links/month for small businesses (consensus)

**Scoring guide:**
- Full: Local authority signals visible (chamber, BBB, press), community involvement evident
- Partial: Some authority signals but limited local link indicators
- Low: No detectable local authority signals

---

## AI Search Impact on Local

**Do not duplicate seo-geo analysis.** Provide local-specific AI context and recommend `/seo geo <url>` for full analysis.

Key local AI facts:
- AI Overviews appear on up to 68% of local searches (Whitespark Q2 2025)
- ChatGPT converts at 15.9% vs Google organic at 1.76% (Seer Interactive)
- 3 of top 5 AI visibility factors are citation-related (Whitespark 2026)
- ChatGPT does NOT access GBP directly -- sources from Bing index, Yelp, TripAdvisor, BBB, Reddit
- Bing Places is critical: powers ChatGPT, Copilot, Alexa
- AI-powered local packs (mobile US) show only 1-2 businesses, 32% fewer shown (Sterling Sky)

**Recommendation**: Run `/seo geo <url>` for comprehensive AI search visibility analysis including citability scoring, llms.txt check, and brand mention audit.

---

## Reference Files

Load on-demand as needed:
- `references/local-seo-signals.md`: Ranking factors, review benchmarks, citation tiers, GBP feature status, algorithm updates
- `references/local-schema-types.md`: LocalBusiness subtypes by industry, schema patterns, citation sources per vertical

---

## Output

Generate `LOCAL-SEO-ANALYSIS-{domain}.md` with:

1. **Local SEO Score: XX/100** with dimension breakdown table
2. **Business type**: Brick-and-mortar / SAB / Hybrid
3. **Industry vertical detected** + industry-specific findings
4. **GBP optimization checklist** (detected signals vs missing)
5. **Review health snapshot** (rating, count, velocity indicators, response patterns)
6. **NAP consistency audit** (page vs schema discrepancies, cross-source comparison)
7. **Citation presence check** (Tier 1 directory status)
8. **Local schema status** (present/missing/malformed + ready-to-use fix)
9. **Location page quality** (if multi-location: unique content %, doorway risk, store locator)
10. **Top 10 prioritized actions** (Critical > High > Medium > Low)
11. **Limitations disclaimer**: What this analysis could NOT assess (geo-grid ranking, Domain Authority, comprehensive backlinks, GBP Insights data, real-time local pack position) and which paid tools can fill those gaps

---

## Quick Wins

1. Claim and optimize Apple Business Connect (usage doubled to 27%)
2. Claim and optimize Bing Places (powers ChatGPT, Copilot, Alexa)
4. Add LocalBusiness schema with correct industry subtype
5. Add `geo` coordinates with 5+ decimal precision
6. Ensure phone number uses `tel:` link for click-to-call
7. Add city + service keyword to title tag and H1

## Medium Effort

1. Create dedicated page for each core service (Whitespark: #1 local organic factor)
2. Build review generation strategy maintaining 18-day minimum cadence
3. Submit to three data aggregators (Data Axle, Foursquare, Neustar/TransUnion) for downstream distribution
4. Claim industry-specific directory listings (per vertical recommendations)
5. Add industry-specific schema patterns (Menu for restaurants, Physician for healthcare, etc.)

## High Impact

1. Build local digital PR strategy targeting "best of" lists (#1 AI visibility factor)
2. Develop unique, non-swappable content for each location page (>60% unique)
3. Establish presence on platforms ChatGPT sources from (Yelp, TripAdvisor, BBB, Reddit)
4. Pursue Chamber of Commerce and BBB membership (authority + verification signals)
5. Create community involvement content (sponsorships, local events, partnerships)

---

## DataForSEO Integration (Optional)

If DataForSEO MCP tools are available, use `local_business_data` for live GBP data extraction, `google_local_pack_serp` for real-time local pack positions, and `business_listings` for automated citation auditing across directories.

---

## Error Handling

| Scenario | Action |
|----------|--------|
| URL unreachable (DNS failure, connection refused) | Report the error clearly. Do not guess site content. Suggest the user verify the URL and try again. |
| No local signals detected on page | Report that no local business indicators were found. Suggest the user confirm this is a local business and provide the GBP listing URL if available. |
| NAP not found in page HTML | Check schema and meta tags. If still absent, flag as Critical issue. Recommend adding visible NAP to footer and contact page. |
| Industry vertical unclear | Present the top two detected verticals with supporting signals. Ask the user to confirm before applying industry-specific recommendations. |
| Multi-location with 50+ location pages | Apply the quality gates from seo orchestrator: WARNING at 30+ pages (enforce 60%+ unique), HARD STOP at 50+ pages (require user justification before continuing). |

---

## Absorbed from seo-maps

The seo-maps skill provided maps platform intelligence (Google Maps, Bing Places, Apple Maps, OpenStreetMap) via external APIs. Its unique contributions -- geo-grid rank tracking, GBP profile audit via API, review intelligence, competitor radius mapping, cross-platform NAP verification, and schema generation from API data -- are preserved below.

**Boundary note:** The maps analysis below focuses on maps PLATFORMS (via APIs). The seo-local sections above analyze local SEO signals on the WEBSITE (via HTML fetch). They complement each other.

### Maps Quick Reference

| Command | What it does | Tier |
|---------|-------------|------|
| `/seo maps <url>` | Full maps presence audit (auto-selects tier) | 0+ |
| `/seo maps grid <keyword> <location>` | Geo-grid rank scan (7x7, 1 keyword default) | 1+ |
| `/seo maps reviews <business> <location>` | Cross-platform review intelligence | 1+ |
| `/seo maps competitors <keyword> <location>` | Competitor radius mapping | 0+ |
| `/seo maps nap <business-name>` | Cross-platform NAP verification | 0+ |
| `/seo maps schema <business-name>` | Generate LocalBusiness JSON-LD from data | 0+ |
| `/seo maps gbp <business> <location>` | GBP completeness audit | 1+ |

### Three-Tier Capability Detection

Before any maps analysis, detect the available capability tier:

**Tier 0 (Free):** DataForSEO MCP tools NOT available. Capabilities: Overpass API competitor discovery, Geoapify POI search, Nominatim geocoding, static GBP checklist, schema generation, cross-platform NAP guidance. Load: `references/maps-free-apis.md`.

**Tier 1 (DataForSEO):** `business_data_business_listings_search` MCP tool IS available. Everything in Tier 0 PLUS geo-grid rank tracking, live GBP profile audit, review intelligence (velocity, sentiment, distribution), GBP post activity, Q&A data, Tripadvisor/Trustpilot reviews. Load: `references/maps-api-endpoints.md`.

**Tier 2 (DataForSEO + Google Maps Platform):** Tier 1 available AND Google Maps API key in environment. Everything in Tier 1 PLUS Google Places details, real-time business status, AI-powered place summaries, photo analysis. Google ToS restricts storage to `place_id` only; lat/lng cached 30 days max.

Always communicate the detected tier to the user at the start of analysis.

### Geo-Grid Rank Tracking (Tier 1+)

Simulates Google Maps searches from multiple GPS coordinates to show ranking variation across a geographic area.

Load: `references/maps-geo-grid.md` for algorithm, SoLV formula, heatmap format.

**Workflow:**
1. Geocode business address to get center lat/lng
2. Generate grid points (default: 7x7, 5km radius) using Haversine offset formula
3. Display cost estimate and ask for confirmation before proceeding
4. Fire DataForSEO Maps SERP API calls with `location_coordinate` per grid point
5. Find target business rank at each point
6. Calculate SoLV: `(top_3_count / total_points) * 100`
7. Render ASCII heatmap in output

**Cost Warning (REQUIRED):** Before every geo-grid scan, display:
```
Geo-Grid Scan: [keyword] at [location]
Grid: 7x7 (49 points) | Keywords: [N] | Est. cost: $[amount]
DataForSEO credits will be consumed. Proceed?
```

### GBP Profile Audit via API (Tier 1 preferred, Tier 0 manual)

Audits the 25 fields that affect Google Business Profile quality and ranking. Load: `references/maps-gbp-checklist.md` for full checklist and scoring.

**Tier 1 Workflow:**
1. Fetch business profile via DataForSEO My Business Info API (keyword or CID)
2. Map API response fields to 25-field checklist
3. Score each field: Present + Optimized = 2pts, Present = 1pt, Missing = 0pts
5. Normalize to 0-100 scale

**Tier 0 Workflow:**
1. Fetch the business website via WebFetch
2. Extract visible GBP signals (Maps embed, place references, review widgets)
4. Mark undetectable fields as "Unknown (requires DataForSEO for live data)"

### Review Intelligence (Tier 1+)

Cross-platform review analysis: velocity, sentiment, rating distribution, fake detection.

**Workflow:**
1. Fetch Google reviews via DataForSEO Reviews API (sort by newest)
2. Calculate review velocity: reviews per month over last 6 months
3. Check 18-day rule (Sterling Sky): any 3-week gap = ranking risk
4. Analyze rating distribution: healthy = bell curve skewed to 5-star
5. Calculate owner response rate
6. Fetch Tripadvisor and Trustpilot reviews (if available)
7. Cross-platform comparison table

**Fake Review Detection Signals** (flag reviews matching 2+):
- Uniform timing (multiple reviews same day/hour)
- Reviewer accounts with limited history or single review
- Geographic inconsistencies
- Exclusively 5-star velocity spike vs historical baseline
- Identical or near-identical text
- Sudden volume spike without corresponding marketing activity

### Competitor Radius Mapping (Tier 0+)

**Tier 0 (Overpass API):** Load `references/maps-free-apis.md` for query templates.
1. Geocode business address
2. Query Overpass API for businesses with same OSM tag within radius
3. Parse results: name, address, phone, website, distance
4. Sort by distance, present as competitor landscape table

**Tier 1 (DataForSEO):**
1. Use Maps SERP API with business keyword + location
2. Extract top 20 competitors with full profile data
3. Compare: rating, review count, categories, photos, attributes
4. Calculate competitive density score: competitors per km^2

### Cross-Platform NAP Verification (Tier 0+)

1. Search for business name on each platform:
   - Google: infer from GBP data or Maps SERP result
   - Bing: `WebFetch https://www.bing.com/maps?q=BUSINESS+NAME+LOCATION`
   - Apple: manual check (no public API -- recommend Apple Business Connect)
   - OSM: Overpass or Nominatim search
2. Extract NAP from each source
3. Compare: exact match, partial match, missing, or conflicting
4. Flag discrepancies: Critical (name), High (address), Medium (phone)
5. Recommend claiming unclaimed profiles

### Schema Generation from API Data (Tier 0+)

1. Determine most specific schema subtype for the industry
2. Populate required properties: `@type`, `name`, `address`, `image`
3. Add recommended: `telephone`, `url`, `geo`, `openingHoursSpecification`, `priceRange`
4. Add strategic: `branchOf`, `areaServed`, `sameAs` for multi-location
5. Add `aggregateRating` if review data available
6. Output valid JSON-LD block

**Do NOT generate self-serving review markup** -- Google ignores LocalBusiness review markup from the business itself.

### Maps Reference Files

Load on-demand as needed:
- `references/maps-api-endpoints.md`: DataForSEO endpoint details, params, costs
- `references/maps-free-apis.md`: Overpass, Geoapify, Nominatim query templates
- `references/maps-geo-grid.md`: Grid algorithm, SoLV formula, heatmap rendering
- `references/maps-gbp-checklist.md`: 25-field GBP audit with industry weights

### Maps Output Format

Generate `MAPS-ANALYSIS-{domain}.md` with:
1. **Maps Health Score: XX/100** with dimension breakdown
2. **Capability tier detected** with explanation
3. **Geo-grid heatmap** (Tier 1): ASCII grid with SoLV percentage and average rank
4. **GBP profile audit**: field-by-field scoring with industry weights
5. **Review intelligence**: velocity chart, rating distribution, response rate, cross-platform comparison
6. **Competitor landscape**: count in radius, top 5, competitive density
7. **Cross-platform presence**: Google/Bing/Apple/OSM listing status
8. **Schema recommendation**: generated LocalBusiness JSON-LD
9. **Top 10 prioritized actions**
10. **Cost report**: DataForSEO credits consumed (Tier 1 only)
11. **Limitations disclaimer**

### Maps Error Handling

| Scenario | Action |
|----------|--------|
| DataForSEO MCP not available | Drop to Tier 0. Inform user and suggest installing DataForSEO extension for full capabilities. |
| Business not found in Maps SERP | Try My Business Info with keyword. If still not found, report "Business not found in Google Maps for this location." |
| Geocoding fails (Nominatim) | Ask user to provide coordinates or a more specific address. |
| API rate limit hit | Report the limit. Suggest waiting or using standard (queued) method. |
| No reviews found | Report zero review state. Recommend review generation strategy with 18-day cadence. |
| Multi-location detected | Ask which location to analyze, or offer batch mode with per-location cost estimate. |
