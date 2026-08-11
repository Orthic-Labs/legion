---
name: seo-backlinks
description: >
  Backlink profile analysis: referring domains, anchor text distribution,
  toxic link detection, competitor gap analysis. Requires DataForSEO extension.
  Use when user says "backlinks", "link profile", "referring domains",
  "anchor text", "toxic links", "link gap", "link building",
  "disavow", or "backlink audit".
user-invokable: true
argument-hint: "<url>"
license: MIT
compatibility: "Requires DataForSEO MCP server (extension)"
metadata:
  author: AgriciDaniel
  version: "1.7.2"
  category: seo
---

# Backlink Profile Analysis

This skill requires the DataForSEO extension:
```bash
./extensions/dataforseo/install.sh
```

**Check availability:** Before using backlink tools, verify the DataForSEO MCP server
is connected by checking if `dataforseo_backlinks_summary` or similar tools are available.
If unavailable, inform the user and provide install instructions.

## Quick Reference

| Command | Purpose |
|---------|---------|
| `/seo backlinks <url>` | Full backlink profile analysis |
| `/seo backlinks gap <url1> <url2>` | Competitor backlink gap analysis |
| `/seo backlinks toxic <url>` | Toxic link detection and disavow recommendations |
| `/seo backlinks new <url>` | New and lost backlinks (recent changes) |

## Analysis Framework

When analyzing a backlink profile, produce all 7 sections below.

### 1. Profile Overview

Use `dataforseo_backlinks_summary` to get:
- Total backlinks and referring domains
- Domain rank / authority score
- Follow vs nofollow ratio
- Historical trend (growing, stable, or declining)

**Scoring:**

| Metric | Good | Warning | Critical |
|--------|------|---------|----------|
| Referring domains | >100 | 20-100 | <20 |
| Follow ratio | >60% | 40-60% | <40% |
| Domain diversity | No single domain >5% | 1 domain >10% | 1 domain >25% |
| Trend | Growing or stable | Slow decline | Rapid decline (>20%/quarter) |

### 2. Anchor Text Distribution

Use `dataforseo_backlinks_anchors` to analyze anchor text patterns.

**Healthy distribution benchmarks:**

| Anchor Type | Target Range | Over-Optimization Signal |
|-------------|-------------|-------------------------|
| Branded (company/domain name) | 30-50% | <15% |
| URL/naked link | 15-25% | N/A |
| Generic ("click here", "learn more") | 10-20% | N/A |
| Exact match keyword | 3-10% | >15% |
| Partial match keyword | 5-15% | >25% |
| Long-tail / natural | 5-15% | N/A |

Flag if exact-match anchors exceed 15% -- this is a Google Penguin risk signal.

### 3. Referring Domain Quality

Use `dataforseo_backlinks_referring_domains` to assess link quality.

Analyze:
- **TLD distribution**: .edu, .gov, .org = high authority. Excessive .xyz, .info = low quality
- **Country distribution**: Match target market. 80%+ from irrelevant countries = PBN signal
- **Language distribution**: Should match site language. Foreign-language links can be spam
- **Domain rank distribution**: Healthy profiles have links from all authority tiers
- **Follow/nofollow per domain**: Sites that only nofollow = limited SEO value

### 4. Toxic Link Detection

Identify potentially harmful backlinks using these patterns:

**High-risk indicators (flag immediately):**
- Links from known PBN (Private Blog Network) domains
- Unnatural anchor text patterns (100% exact match from a domain)
- Links from penalized or deindexed domains
- Mass directory submissions (50+ directory links)
- Comment spam links (forum/blog comment backlinks at scale)
- Link farms (sites with 10K+ outbound links per page)
- Foreign-language links to English sites (unless intentional)
- Paid link patterns (footer/sidebar links across all pages of a domain)

**Medium-risk indicators (review manually):**
- Links from unrelated niches
- Reciprocal link patterns (A links to B, B links to A)
- Links from thin content pages (<100 words)
- Excessive links from a single domain (>50 backlinks from 1 domain)

**Output:**
```
Toxic Link Report
=================
Total backlinks analyzed: X
Potentially toxic: Y (Z%)

High Risk (recommend disavow):
  [list with domain, reason, anchor text]

Medium Risk (review manually):
  [list with domain, reason, anchor text]
```

### 5. Top Pages by Backlinks

Use `dataforseo_backlinks_backlinks` with target type "page" to find:
- Which pages attract the most backlinks
- Pages with high-authority links (link magnets)
- Pages with zero backlinks (internal linking opportunities)
- 404 pages with backlinks (redirect opportunities to reclaim link equity)

### 6. Competitor Gap Analysis

For `/seo backlinks gap <url1> <url2>`:

Use `dataforseo_backlinks_referring_domains` for both domains and compare:
- Domains linking to competitor but NOT to target = link building opportunities
- Domains linking to both = validate existing relationships
- Domains linking only to target = competitive advantage

**Output:**
```
Competitor Gap: example.com vs competitor.com
=============================================
Competitor has links from X domains you don't
You have links from Y domains competitor doesn't

Top 20 Link Building Opportunities:
  [domain, authority, anchor used for competitor, contact suggestion]
```

### 7. New and Lost Backlinks

Use `dataforseo_backlinks_backlinks` with date filters to track:
- New backlinks in last 30/60/90 days
- Lost backlinks in last 30/60/90 days
- Link velocity (new per month trend)

**Red flags:**
- Sudden spike in new links (possible negative SEO attack)
- Sudden loss of many links (site penalty or content removal)
- Declining velocity over 3+ months (content not attracting links)

## Backlink Health Score

Calculate a 0-100 score based on:

| Factor | Weight | Scoring |
|--------|--------|---------|
| Referring domain count | 20% | Scale based on industry benchmarks |
| Domain quality distribution | 20% | % from authority domains (DR 40+) |
| Anchor text naturalness | 15% | Penalty for over-optimization |
| Toxic link ratio | 20% | <2% = full score, >10% = 0 |
| Link velocity trend | 10% | Growing = full, declining = partial |
| Follow/nofollow ratio | 5% | >60% follow = full score |
| Geographic relevance | 10% | % from target market countries |

## Output Format

### Backlink Health Score: XX/100

| Section | Status | Score |
|---------|--------|-------|
| Profile Overview | pass/warn/fail | XX/100 |
| Anchor Distribution | pass/warn/fail | XX/100 |
| Referring Domain Quality | pass/warn/fail | XX/100 |
| Toxic Links | pass/warn/fail | XX/100 |
| Top Pages | info | N/A |
| Link Velocity | pass/warn/fail | XX/100 |

### Critical Issues (fix immediately)
### High Priority (fix within 1 month)
### Medium Priority (ongoing improvement)
### Link Building Opportunities (top 10)

## Error Handling

| Error | Cause | Resolution |
|-------|-------|-----------|
| DataForSEO tools unavailable | Extension not installed | Run `./extensions/dataforseo/install.sh` |
| No backlink data returned | Domain too new or very small | Note: small sites may have <10 backlinks |
| API credits insufficient | DataForSEO balance low | Check balance at app.dataforseo.com |

**Graceful fallback:** If DataForSEO is unavailable:
1. Inform user that backlink analysis requires the DataForSEO extension
2. Offer to check robots.txt and sitemap for basic link signals instead
3. Suggest manual tools: Ahrefs Webmaster Tools (free), Google Search Console Links report

## Reference Documentation

Load on demand (do NOT load at startup):
- `references/backlink-quality.md` -- Detailed toxic link patterns and scoring methodology
