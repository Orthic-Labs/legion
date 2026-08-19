---
name: pinterest-pro
description: >
  Pinterest workflow per brand: pin creation, board strategy, traffic-driving. Use when user says
  "/pinterest", "pins", "pinterest strategy", "boards", "traffic from pinterest". Pinterest API for
  live data (todo.md P1) — without it, creation-only.
---

# Pinterest

## When to use
- Brand has visual content + ecommerce or blog
- Want long-tail traffic (pins live for years)
- Audience: women 25-55, US-skewing, high purchase intent (RH best, then SS, then DD)

## Status
- Live data + scheduling needs Pinterest Business API (todo.md P1)
- Without: creation-only, post manually or via Tailwind

## Always start with
1. `/brand <brand-code>`
2. **Goal:** traffic to blog post / product page / portfolio
3. **Board strategy** — does brand have boards? If not, plan first

## Board strategy

### RH (highest priority)
- Slow Fashion Essentials (product pins)
- Sustainable Wardrobe Basics (educational → blog)
- Textile Science (deep content)
- Outfit Inspiration with [collection] (lifestyle)
- Care & Repair (longevity)

### DD
- EDC Inspiration (product)
- Desk Setups with Fidget Tools (lifestyle)
- Knife Care & Sharpening (educational)
- Handmade Tools (process)

### SS
- Portrait Photography (work)
- Visual Storytelling (BTS + thinking)
- Lighting Studies (technical)
- Per-collection boards for series

## Pin creation

1. **Destination URL** — every pin needs a click target
2. **Format:**
   - Standard: 1000×1500px (2:3 vertical)
   - Idea pin: 1080×1920 (9:16)
3. **Hierarchy:**
   - Top 30%: bold headline (5-8 words)
   - Middle: visual proof
   - Bottom 20%: brand mark (subtle) + secondary line
4. **Generate via /marketing-design** with Pinterest preset
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
- 5-15 pins/day per brand (own + curated)
- Schedule via Tailwind or native scheduler
- Best times: 8-11pm audience timezone, weekends

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
