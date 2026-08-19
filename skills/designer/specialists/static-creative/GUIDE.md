---
name: designer-static
description: >
  Static creative owner — flyers, social posts, OG images, banners, ad creatives, print, packaging inserts.
  Routes websites + product/app UI → /designer, frontend critique → /audit-visual,
  brand systems → /brand-identity. Do NOT use for interactive app/web design or visual QA.
argument-hint: "flyer | social | OG | banner | print | ad creative | <medium>"
---

# Static Creative

`/designer static` owns static creative artifacts: flyers, social posts, OG images, banners, ad creatives, posters,
packaging inserts, print, lookbook spreads. It is NOT the primary route for interactive UI or web pages.

## Hard routing guard — delegate first

| Request type | Route to |
|---|---|
| Product/app/dashboard UI design | `/designer` |
| Marketing site, landing page, web page | `/designer` |
| Frontend visual review / polish / QA | `/audit-visual` (owns the strict rendered frontend/UI audit gate) |
| Brand system, identity, color/type lock | `/brand-identity` |
| Blog/SEO page | `/writing blog` + `/seo` |
| Flyer, social post, OG image, banner, ad creative, print | **this skill → `references/marketing.md`** |

When the request is ambiguous, ask which output type before loading any reference.

## Static creative workflow

1. **`/brand <brand-code>`** — load palette, fonts, restrictions
2. **Identify medium + dimensions** — see `references/marketing.md` cheat sheet
3. **Identify purpose:** awareness / click / save / share / screenshot
4. Read `references/marketing.md` and follow its workflow

## Internal council (static creative only)

| Reference | Role pass |
|---|---|
| `marketing.md` | Brand lead, conversion designer, copy strategist, visual director, production/spec checker |

Output standard: spec recap, 3 variant briefs, generated assets (or prompts), filenames, posting-ready note.

## Optional external jury (explicit opt-in only)

Run this external jury only when the approving human explicitly requests it.

```bash
node -e "import('@orthic-labs/legion/auto-jury').then(m=>m.runAutoJury({
  kind: 'design',
  artifactPath: '<absolute path to output>',
  context: { brand: '<brand-code>', notes: 'design output' },
  failHard: true
}).then(v=>console.log('verdict:', v.final_verdict||v.verdict||v.decision)).catch(e=>{console.error(e.message);process.exit(1)})"
```
