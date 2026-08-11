---
name: seo-ahrefs
description: >
  Live SEO data via Ahrefs MCP. Domain Rating, backlinks, referring domains,
  organic keywords, top pages by traffic, rank tracker, SERP overview, site
  audit issues, Brand Radar AI visibility (mentions, SOV, cited domains/pages),
  GSC keyword/page performance, and web analytics. Runs alongside DataForSEO
  when both are present — Ahrefs provides DR history, rank tracking, GSC, Brand
  Radar, and web analytics that DataForSEO does not cover. Use when user says
  "ahrefs", "domain rating", "DR", "rank tracker", "brand radar", "AI mentions",
  "SOV", "share of voice", "GSC data", "web analytics", "referring domains",
  "top pages", "organic keywords", or when Ahrefs MCP is available during a
  full audit.
user-invokable: true
argument-hint: "[command] [domain or keyword]"
license: MIT
metadata:
  author: the approving human
  version: "1.0.0"
  category: seo
---

# Ahrefs: Live SEO Data And Manual UI Exports

Live data via the Ahrefs MCP server (tool prefix `mcp__0e71d0c2-...`).

## Manual Export Mode — Built-In Browser Only

Use this mode when the user asks an agent to navigate Ahrefs while signed in and export data, for example:

- "Use my Ahrefs account and export backlinks."
- "Navigate Ahrefs and download the organic keywords XLSX."
- "Use the logged-in browser to get Ahrefs data."
- "Ahrefs API is not available; manually export the report."

This is not scraping. The agent acts as an attended browser assistant and uses the same visible product controls the user would use.

### Hard Rules

- Use only the host's built-in browser capability:
  - Codex: use the Browser plugin / in-app browser when available.
  - Claude: use the available built-in browser/computer-use browser surface when available.
- Do not use Scrapling, stealth fetchers, proxy rotation, cookie theft, raw HTTP requests, DOM harvesting, hidden XHR/fetch interception, unofficial Ahrefs endpoints, or any technique designed to bypass UI/API/export limits.
- Do not automate Ahrefs unless the user is already authorized to access that account/session and explicitly asks for browser-assisted export.
- Do not scrape tables out of the DOM as the source of truth. Click official Ahrefs export/download controls and use the downloaded CSV/XLSX as the source of truth.
- Do not try to bypass row limits, rate limits, plan limits, watermarks, or disabled export buttons.
- Do not ask the user to paste credentials. If sign-in is required, pause and let the user sign in through the browser.
- Record the export source: Ahrefs report name, filters, date range, target domain/URL/keyword, file path, and timestamp.

### Workflow

1. Open Ahrefs in the built-in browser.
2. Confirm the user is signed in. If not, ask the user to sign in interactively.
3. Navigate to the requested report, such as Site Explorer, Organic Keywords, Backlinks, Referring Domains, Top Pages, Rank Tracker, Site Audit, Content Explorer, or Brand Radar.
5. Click Ahrefs' official export/download button.
6. Save/download to a known local folder.
7. Confirm the downloaded CSV/XLSX exists.
8. Parse the exported file locally.
9. Report the file path, row count, columns, filters, and any limitations shown by Ahrefs.
10. Use the exported file as evidence for SEO analysis.

### Output For Manual Export

```text
Ahrefs manual export
Report: <report name>
Target: <domain/url/keyword>
Filters: <filters/date/location/sort>
Downloaded file: <path>
Rows: <count>
Columns: <list>
Limitations shown in UI: <none or exact note>
Next analysis step: <what to do with the export>
```

### Browser Tool Preference

For this mode, built-in browser beats all other tools. If the built-in browser cannot click/export/download reliably, stop and explain the blocker. Do not fall back to scraping, Scrapling, stealth, raw API calls, or hidden network extraction.

---

## Ahrefs MCP Mode — Live SEO Data

**Availability check:** Before any call, verify Ahrefs MCP is connected by
checking that `site-explorer-metrics` is available. If not, inform the user
the Ahrefs MCP is not connected.

**Use `mcp__0e71d0c2-64ec-439b-be59-0bff867c72ee__doc` to fetch the exact
input schema for any tool before calling it.** The MCP has 100+ tools — always
fetch schema first rather than guessing parameters.

## Quick Reference

| Command | What it does |
|---------|-------------|
| `/seo ahrefs overview <domain>` | Domain metrics snapshot (DR, backlinks, keywords, traffic) |
| `/seo ahrefs backlinks <domain>` | Full backlink profile + referring domains |
| `/seo ahrefs keywords <domain>` | Organic keywords the domain ranks for |
| `/seo ahrefs top-pages <domain>` | Top pages by organic traffic |
| `/seo ahrefs competitors <domain>` | Organic competitors |
| `/seo ahrefs dr <domain>` | Domain Rating + history |
| `/seo ahrefs rank-tracker <domain>` | Rank tracker overview + competitor positions |
| `/seo ahrefs serp <keyword>` | SERP overview for a keyword |
| `/seo ahrefs keywords-explorer <keyword>` | Keyword volume, difficulty, matching/related terms |
| `/seo ahrefs site-audit <domain>` | Site audit issues |
| `/seo ahrefs brand-radar <brand>` | AI mentions, SOV, cited domains, cited pages |
| `/seo ahrefs gsc <domain>` | GSC keyword performance, page performance, CTR |
| `/seo ahrefs analytics <domain>` | Web analytics stats, sources, top pages, devices |
| `/seo ahrefs batch <domains>` | Bulk metrics for multiple domains |
| `/seo ahrefs manual-export <report>` | Built-in browser assisted UI export to CSV/XLSX; no scraping, no hidden XHR, no stealth |

---

## Module Reference

### Site Explorer

Primary domain intelligence. Use `site-explorer-metrics` as the starting point
for any domain analysis.

**Key tools:**

| Tool | Use for |
|------|---------|
| `site-explorer-metrics` | Snapshot: DR, UR, backlinks, refdomains, organic keywords, traffic |
| `site-explorer-metrics-history` | Trend over time for any metric |
| `site-explorer-domain-rating` | Current DR value |
| `site-explorer-domain-rating-history` | DR trend |
| `site-explorer-url-rating-history` | UR trend for a specific URL |
| `site-explorer-referring-domains` | List of referring domains with DR, type |
| `site-explorer-all-backlinks` | Full backlink list |
| `site-explorer-backlinks-stats` | Summary stats: total, dofollow, nofollow, new, lost |
| `site-explorer-broken-backlinks` | Backlinks pointing to 404s (link reclamation) |
| `site-explorer-anchors` | Anchor text distribution |
| `site-explorer-linked-anchors-external` | External anchor text used when linking out |
| `site-explorer-linked-anchors-internal` | Internal anchor text |
| `site-explorer-linked-domains` | Domains the target links to |
| `site-explorer-outlinks-stats` | Outbound link summary |
| `site-explorer-organic-keywords` | Keywords the domain ranks for |
| `site-explorer-organic-competitors` | Competing domains by keyword overlap |
| `site-explorer-top-pages` | Top pages by organic traffic |
| `site-explorer-pages-by-traffic` | All pages ranked by traffic |
| `site-explorer-pages-by-backlinks` | Pages ranked by inbound links |
| `site-explorer-pages-by-internal-links` | Pages ranked by internal links received |
| `site-explorer-pages-history` | Page count change over time |
| `site-explorer-keywords-history` | Keyword ranking count history |
| `site-explorer-total-search-volume-history` | Total search volume trend |
| `site-explorer-metrics-by-country` | Traffic breakdown by country |
| `site-explorer-refdomains-history` | Referring domain count over time |
| `site-explorer-crawled-pages` | Pages Ahrefs has crawled |
| `site-explorer-paid-pages` | PPC landing pages |

**`/seo ahrefs overview <domain>` workflow:**
1. `site-explorer-metrics` → snapshot
2. `site-explorer-domain-rating-history` → DR trend (12 months)
3. `site-explorer-backlinks-stats` → link profile health
4. `site-explorer-organic-competitors` → top 5 organic competitors

**`/seo ahrefs backlinks <domain>` workflow:**
1. `site-explorer-backlinks-stats` → totals
2. `site-explorer-referring-domains` → domain quality breakdown
3. `site-explorer-anchors` → anchor text distribution
4. `site-explorer-broken-backlinks` → reclamation opportunities
5. `site-explorer-refdomains-history` → growth trend

**Anchor text analysis — healthy distribution benchmarks:**

| Anchor type | Target range | Over-optimisation signal |
|-------------|-------------|--------------------------|
| Branded | 30–50% | <15% |
| URL/naked | 15–25% | — |
| Generic | 10–20% | — |
| Exact match | 3–10% | >15% |
| Partial match | 5–15% | >25% |

---

### Keywords Explorer

**Key tools:**

| Tool | Use for |
|------|---------|
| `keywords-explorer-overview` | Volume, KD, CPC, SERP features for a keyword |
| `keywords-explorer-matching-terms` | Keywords containing the seed term |
| `keywords-explorer-related-terms` | Semantically related keywords |
| `keywords-explorer-search-suggestions` | Autocomplete suggestions |
| `keywords-explorer-volume-by-country` | Volume breakdown by country |
| `keywords-explorer-volume-history` | Monthly volume trend |

**`/seo ahrefs keywords-explorer <keyword>` workflow:**
1. `keywords-explorer-overview` → volume, KD, CPC
2. `keywords-explorer-matching-terms` → expansion opportunities
3. `keywords-explorer-related-terms` → semantic cluster
4. `keywords-explorer-volume-history` → trend direction

---

### Rank Tracker

**Key tools:**

| Tool | Use for |
|------|---------|
| `rank-tracker-overview` | Current positions for tracked keywords |
| `rank-tracker-serp-overview` | Full SERP for a tracked keyword |
| `rank-tracker-competitors-overview` | Competitor position summary |
| `rank-tracker-competitors-pages` | Which competitor pages rank |
| `rank-tracker-competitors-stats` | Competitor visibility stats |

**`/seo ahrefs rank-tracker <domain>` workflow:**
1. `rank-tracker-overview` → current positions
2. `rank-tracker-competitors-overview` → gap vs competitors
3. `rank-tracker-serp-overview` → SERP layout for key terms

---

### SERP Overview

**Tool:** `serp-overview`

Returns organic results, SERP features (featured snippet, image pack, PAA,
video carousel, local pack), and competitor pages for a given keyword.

**`/seo ahrefs serp <keyword>` workflow:**
1. `serp-overview` → top 10 results, SERP features, competitor URLs
2. Annotate: which features are present, which competitors own them

---

### Site Audit

**Key tools:**

| Tool | Use for |
|------|---------|
| `site-audit-projects` | List audit projects for the domain |
| `site-audit-issues` | All detected issues with severity |
| `site-audit-page-explorer` | Filter/browse crawled pages |
| `site-audit-page-content` | Full content of a specific crawled page |

**`/seo ahrefs site-audit <domain>` workflow:**
1. `site-audit-projects` → find the project ID
2. `site-audit-issues` → issues by severity (critical → warning → notice)
3. Group into: crawlability, indexability, on-page, performance, links
4. Output prioritised fix list

---

### Brand Radar — AI Visibility

Unique to Ahrefs. Tracks how often a brand appears in AI-generated responses
across platforms (ChatGPT, Perplexity, etc.) and which content gets cited.

**Key tools:**

| Tool | Use for |
|------|---------|
| `brand-radar-mentions-overview` | Total AI mention count, trend |
| `brand-radar-mentions-history` | Mention volume over time |
| `brand-radar-impressions-overview` | Impression count in AI responses |
| `brand-radar-impressions-history` | Impressions trend |
| `brand-radar-sov-overview` | Share of voice vs competitors |
| `brand-radar-sov-history` | SOV trend over time |
| `brand-radar-cited-domains` | Which domains get cited most for the brand/topic |
| `brand-radar-cited-pages` | Which specific pages get cited |
| `brand-radar-ai-responses` | Sample AI responses mentioning the brand |
| `management-brand-radar-prompts` | Prompts used in Brand Radar reports |
| `management-brand-radar-reports` | List of configured Brand Radar reports |

**`/seo ahrefs brand-radar <brand>` workflow:**
1. `management-brand-radar-reports` → find report ID for the brand
2. `brand-radar-mentions-overview` → current mention volume
3. `brand-radar-sov-overview` → share of voice vs top competitors
4. `brand-radar-cited-domains` → which domains Ahrefs cites most (gap analysis)
5. `brand-radar-cited-pages` → specific pages to emulate or outrank
6. `brand-radar-ai-responses` → sample what AI says about the brand
7. `brand-radar-impressions-history` → trend direction

**Output format:**
```
Brand Radar: [Brand]
====================
AI Mentions: X (↑/↓ Y% vs last period)
Impressions: X
Share of Voice: X% (competitors: A=X%, B=X%)

Top cited domains (not ours): [list — link-building targets]
Top cited pages (not ours): [list — content gap targets]

AI response sample: [excerpt]

Trend: [growing / stable / declining]
```

---

### Google Search Console (GSC)

Ahrefs integrates GSC data directly. Covers keyword performance, page
performance, and historical trends.

**Key tools:**

| Tool | Use for |
|------|---------|
| `gsc-keywords` | Top keywords by clicks/impressions |
| `gsc-keyword-history` | Click/impression trend for a keyword |
| `gsc-pages` | Top pages by clicks/impressions |
| `gsc-page-history` | Click/impression trend for a page |
| `gsc-pages-history` | All pages performance over time |
| `gsc-performance-history` | Overall site performance trend |
| `gsc-performance-by-device` | Desktop vs mobile vs tablet |
| `gsc-performance-by-position` | CTR by average position |
| `gsc-positions-history` | Average position trend |
| `gsc-metrics-by-country` | Traffic breakdown by country |
| `gsc-ctr-by-position` | CTR curve by SERP position |
| `gsc-anonymous-queries` | Queries Google hides from GSC |

**`/seo ahrefs gsc <domain>` workflow:**
1. `gsc-performance-history` → overall clicks/impressions trend
2. `gsc-keywords` → top 20 keywords by clicks
3. `gsc-ctr-by-position` → CTR curve (identify positions where CTR drops)
4. `gsc-performance-by-device` → mobile vs desktop split
5. `gsc-metrics-by-country` → geographic concentration
6. Flag: keywords with high impressions but low CTR (title/meta optimisation opportunity)

---

### Web Analytics

First-party traffic data if Ahrefs web analytics is installed on the site.

**Key tools:**

| Tool | Use for |
|------|---------|
| `web-analytics-stats` | Overall stats: sessions, pageviews, bounce rate, duration |
| `web-analytics-chart` | Sessions trend chart |
| `web-analytics-top-pages` | Top pages by sessions |
| `web-analytics-sources` | Traffic sources breakdown |
| `web-analytics-source-channels` | Channel grouping (organic, direct, referral, social, email) |
| `web-analytics-referrers` | Referring sites |
| `web-analytics-countries` | Sessions by country |
| `web-analytics-devices` | Device type breakdown |
| `web-analytics-browsers` | Browser breakdown |
| `web-analytics-entry-pages` | First pages users land on |
| `web-analytics-exit-pages` | Pages users leave from |
| `web-analytics-utm-params` | UTM campaign breakdown |

**`/seo ahrefs analytics <domain>` workflow:**
1. `web-analytics-stats` → headline numbers
2. `web-analytics-source-channels` → channel mix
3. `web-analytics-top-pages` → top 10 pages
4. `web-analytics-countries` → geo distribution
5. `web-analytics-devices` → mobile vs desktop

---

### Batch Analysis

**Tool:** `batch-analysis`

Bulk domain metrics in a single call. Use when comparing multiple domains
simultaneously (competitor audits, link prospect lists).

**`/seo ahrefs batch <domains>` workflow:**
1. `batch-analysis` with array of domains
2. Output table: domain, DR, backlinks, refdomains, organic keywords, traffic

---

### Management Tools

Use these to find project/report IDs needed by other tools:

| Tool | Use for |
|------|---------|
| `management-projects` | List Ahrefs projects |
| `management-project-keywords` | Tracked keywords for a project |
| `management-project-competitors` | Configured competitors for a project |
| `management-locations` | Available location codes |
| `management-keyword-list-keywords` | Keywords in a saved keyword list |

---

## Cross-Skill Integration

When Ahrefs MCP is available alongside other SEO skills, it enriches them:

| Skill | Ahrefs enrichment |
|-------|-------------------|
| **seo-audit** | Spawn as parallel subagent — contributes DR, backlinks, organic keywords, site audit issues |
| **seo-backlinks** | Use `site-explorer-all-backlinks`, `site-explorer-anchors`, `site-explorer-broken-backlinks` as primary source; DataForSEO as secondary |
| **seo-content** | `site-explorer-top-pages` shows what content drives traffic; `keywords-explorer-*` for gap analysis |
| **seo-geo** | `brand-radar-*` is the definitive AI visibility data source — prefer over DataForSEO ai-mentions |
| **seo-google** | `gsc-*` tools complement Google API credentials; use Ahrefs GSC when direct API credentials aren't configured |
| **seo-plan** | `site-explorer-organic-competitors`, `batch-analysis` for competitive landscape |
| **seo-technical** | `site-audit-issues` as primary crawl data source |

**Deduplication rule when both Ahrefs and DataForSEO are present:**
- DR / UR / backlinks → use **Ahrefs** (authoritative source)
- SERP results → use **DataForSEO** (broader engine coverage)
- Keyword volume → use **DataForSEO** (Google Ads data) and note Ahrefs KD alongside
- AI visibility → use **Ahrefs Brand Radar** (more structured) + **DataForSEO LLM mentions** for cross-validation
- GSC data → use **Ahrefs GSC** if available; fall back to Google API credentials

---

## Output Format

Match the broader `/seo` skill output conventions:

- Tables for comparative data
- Priority levels: Critical > High > Medium > Low
- Scores as XX/100 where applicable
- Label data source as "Ahrefs (live)" to distinguish from static analysis
- When running alongside DataForSEO, prefix conflicting metrics with the source:
  `DR: 42 (Ahrefs) | DA: 38 (DataForSEO)`

---

## Error Handling

| Error | Action |
|-------|--------|
| Ahrefs MCP not connected | Report that `site-explorer-metrics` tool is unavailable. Suggest checking MCP server status. |
| Manual export requested | Use built-in browser only. Navigate UI, click official export, parse downloaded CSV/XLSX. |
| Built-in browser cannot export/download | Stop and report the browser/export blocker. Do not fall back to scraping or hidden endpoints. |
| User not signed in | Pause and ask user to sign in interactively in the browser. Never ask for credentials in chat. |
| Tool schema not loaded | Call `mcp__0e71d0c2-64ec-439b-be59-0bff867c72ee__doc` with the tool name to fetch schema first. |
| No data for domain | Domain may be new or very small. Report "insufficient data" — do not fabricate metrics. |
| Brand Radar report not found | Run `management-brand-radar-reports` to list available reports. Ask user to confirm brand name. |
| Rate limit | Report the limit and suggest spacing requests. |
