# Pinterest

## When to use
- Brand has visual content + ecommerce or blog
- Want long-tail traffic (pins live for years)
- Audience and purchase intent: take from the brand card's audience section

## Status
- Live data and scheduling need a host `social-data` or `social-scheduler` capability (neither is declared by this package). Without one, deliver creation only; the user posts manually or through their own scheduler.

## Always start with
1. `/brand <brand-code>`
2. **Goal:** traffic to blog post / product page / portfolio
3. **Board strategy** — does brand have boards? If not, plan first

## Board strategy

Each brand gets its own board set, derived from the brand card's pillars. Archetypes to choose from:
- Product pins (the product or collection itself)
- Educational boards that lead to a blog post or guide
- Process or making boards (materials, craft, care)
- Lifestyle boards that show the product in use
- Series boards for recurring content

Name boards with the search terms people type. Do not reuse one brand's board set for another brand.

## Pin creation

1. **Destination URL** — every pin needs a click target
2. **Format:**
   - Standard: 1000×1500px (2:3 vertical)
   - Idea pin: 1080×1920 (9:16)
3. **Hierarchy:**
   - Top 30%: bold headline (5-8 words)
   - Middle: visual proof
   - Bottom 20%: brand mark (subtle) + secondary line
4. **Generate via `/designer static`** with the Pinterest preset
5. **Metadata:**
   - Title: SEO-keyword-rich, 40-100 chars
   - Description: 200-500 chars, natural keywords, ends w/ CTA hint
   - Hashtags: 3-5 relevant
6. **3 variants per piece** — Pinterest rewards fresh creative

## Search optimization
- Pinterest is a SEARCH engine, not a feed
- Keywords: title + description + image alt + board name
- Pinterest Trends (https://trends.pinterest.com) for rising terms
- "How to" + "best" + "ideas" + season = high-intent

## Posting cadence
- Take the daily pin volume from the brand card; if none is set, propose one and label it an untested assumption
- Schedule through the host scheduler capability if present, or the platform's native scheduler
- Posting windows: take from the brand card's audience timezone; if none, label them hypotheses to test

## Output

```markdown
## Pinterest Plan — [brand] — [piece]

### Board(s) targeting
- [Board] — [why]

### 3 pin variants
1. [Headline] — [visual concept] — destination: [URL]

### Title + description
1. T: "..." | D: "..."

### Hashtags pool
[#tag #tag ...]

### Schedule
- Pin 1: [date]
- Pin 2: [+3 days]
- Pin 3: [+5 days]
```

## Anti-patterns
- No destination URL
- One pin per piece (always 3+)
- Square pins (lose 50% real estate)
- Pins that don't say what they're about (no headline)
- Ignoring keywords
