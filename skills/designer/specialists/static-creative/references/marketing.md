---
name: design-marketing
description: >
  Top-level skill for SOCIAL/PRINT/MARKETING design — flyers, social posts, OG images, banners, ad creatives,
  posters, postcards, gift cards, packaging inserts, lookbook spreads. NOT for web/app interfaces (use
  /designer). Routes to canvas-design, algorithmic-art, ads-photoshoot, ads-generate, slack-gif-creator,
  nano-banana MCP. Use when user says "/designer static", "flyer", "social post", "Instagram graphic",
  "OG image", "banner", "poster", "ad creative", "lookbook", "promo image".
---

# Marketing Design (Static / Social / Print)

For one-off graphics that live on social, in email, in print, or as ad creatives. Web pages use `/designer`.

## Always start with

1. **`/brand <brand-code>`** — load palette, fonts, restrictions
2. **Identify medium + dimensions** (table below)
3. **Identify purpose:** awareness, click, save, share, screenshot

## Medium → dimensions cheat sheet

| Medium | Dims | Aspect | Notes |
|---|---|---|---|
| IG feed square | 1080×1080 | 1:1 | Most universal |
| IG feed portrait | 1080×1350 | 4:5 | Takes more screen |
| IG/FB Reels cover | 1080×1920 | 9:16 | First frame matters |
| IG Story | 1080×1920 | 9:16 | Safe zone: 250px top, 350px bottom |
| Pinterest pin | 1000×1500 | 2:3 | Vertical wins |
| Pinterest idea pin | 1080×1920 | 9:16 | |
| OG image (web preview) | 1200×630 | 1.91:1 | Twitter, LinkedIn, FB share |
| Email hero | 600×300 | 2:1 | Retina = 1200×600 |
| LinkedIn post image | 1200×627 | 1.91:1 | |
| Twitter/X header | 1500×500 | 3:1 | |
| YouTube thumbnail | 1280×720 | 16:9 | Big text, 3 max |
| Print flyer (US Letter) | 2550×3300 @300dpi | 8.5×11" | Bleed: add 0.125" |
| Postcard (4×6) | 1875×1275 @300dpi | 4:6 | |
| Lookbook spread | varies | 2-page | Ask for specs |
| Packaging insert | 100×150mm @300dpi | varies | physical-product orders |

## Tooling routing

| Need | Use |
|---|---|
| Photo enhancement / variations | nano-banana MCP (`mcp__nano-banana__edit_image`) |
| New illustration / generative | algorithmic-art (p5.js with seeded params) |
| Layout-heavy poster / canvas | canvas-design |
| Product photo styling | ads-photoshoot (5 styles per product) |
| Multi-platform ad image batch | ads-generate (reads brand-profile.json) |
| Slack/IG GIF | slack-gif-creator |
| Hero image for blog/OG | seo-image-gen |
| Render TXT-heavy graphics | Remotion stills (`renderStill()`) — code-driven, brand-consistent |

## Workflow

1. **Spec sheet:** medium, dims, hierarchy (what reads first, second, third), CTA
2. **Pick tool** from routing table
3. **Apply brand visual lock** (colors, fonts, motion if animated)
4. **Generate 3 variants** unless user asks for one — A/B options matter
5. **Review against brand restrictions** — no stock/generic look, no hardcoded competitor colors, no fabricated content (testimonials, stats)
6. **Output naming:** `<brand>_<medium>_<topic>_<date>_v<n>.png`
7. **File location:** the consuming project's asset output directory (create it if missing)

## Brand cheat-sheets

Keep one cheat sheet per active venture: background treatment, the one accent color and where it's
allowed, the type pairing, the photography/illustration style, and a short NEVER list. Populate this
from the consuming project's own brand rules — this file ships with the shape only, no example
ventures.

### Venture A marketing design
- Background dominates: state the base treatment (clean vs. dramatic variants)
- One accent color, one place per artifact
- Headline/body/mono type pairing
- Photography or illustration style in one line
- NEVER: list this venture's specific banned looks

### Venture B marketing design
- Background: state the base treatment
- Accent used sparingly — CTAs and emphasis only, never as block color
- Type pairing
- Photography or illustration style in one line
- NEVER: list this venture's specific banned looks

## Anti-patterns

- Generic stock-photo look (silhouettes, handshakes, gradient backgrounds)
- Three+ font weights in one artifact
- Brand color used as flood fill instead of accent
- Text > 60% of canvas (it's design, not a Word doc)
- CTA buried below fold (in vertical formats, CTA must be in middle 50% safe zone)
- Untracked output (always log brand + medium + date in filename)

## Deliverable format

Always output:
1. **Spec recap** (medium, dims, brand, purpose)
2. **3 variant briefs** (1 line each) before generating
3. **Generated assets** (or generation prompts if API not available)
4. **Filenames + save paths**
5. **Posting-ready note** (caption suggestion, hashtag set if for social)

## Optional external jury (explicit opt-in only)

Run this external jury only when the approving human explicitly requests it.

```bash
node -e "import('@orthic-labs/legion/auto-jury').then(m=>m.runAutoJury({
  kind: 'design',
  artifactPath: '<absolute path to output>',
  context: { brand: '<brand-code>', notes: 'design-marketing output' },
  failHard: true
}).then(v=>console.log('verdict:', v.final_verdict||v.verdict||v.decision)).catch(e=>{console.error(e.message);process.exit(1)})"
```

