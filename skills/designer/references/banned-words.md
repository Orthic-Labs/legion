# Banned Words — cross-brand

Single source of truth for banned vocabulary across all brands. Per-brand anti-patterns in `Content/<brand>/anti-patterns.md` are **additions only** — never duplicate.

Every entry has a detection pattern (regex or grep). The build fails when hard-block entries match in built HTML or copy sources.

---

## How to use

Native `legion review` runs these patterns against built HTML. Hard-block entries fail review. Soft flags remain warnings.

To add a banned word: append to the relevant section with detection regex + reason + severity. Update this file, not per-brand files.

---

## Structural (all brands — hard block)

| Pattern | Reason | Detection |
|---|---|---|
| `—` (U+2014, em dash) | LLM cadence tell; replace with comma, period, or em-dash-words | `\xE2\x80\x94` |
| `–` (U+2013, en dash) | Same; replace with hyphen or comma | `\xE2\x80\x93` |
| `"..."` (U+201C / U+201D, smart double quotes) | ASCII straight quotes preferred | `[\xE2\x80\x9C\xE2\x80\x9D]` |
| `'...'` (U+2018 / U+2019, smart single quotes) | ASCII apostrophe preferred | `[\xE2\x80\x98\xE2\x80\x99]` |
| `…` (U+2026, ellipsis) | Replace with three ASCII periods | `\xE2\x80\xA6` |

## Vocabulary (all brands — hard block)

| Word / phrase | Reason | Replacement |
|---|---|---|
| "elevate" | Corporate filler; no information | remove, or use specific benefit |
| "leverage" | Corporate-speak | "use" |
| "unlock" | Empty verb in marketing copy | "access," "reveal," "get" |
| "synergy" | Empty in product context | remove |
| "empower" | Abstract; rarely earned | remove, or be specific |
| "the only" | Superlative; usually false | remove |
| "the best" | Same | "one of" or remove |
| "revolutionary" | Inflated | remove |
| "disruptive" | Inflated | remove |
| "game-changing" | Inflated | remove |
| "in today's world" | Empty opener | remove |
| "in an era where" | Empty opener | remove |
| "in a world that" | Empty opener | remove |
| "designed for the discerning" | Pretentious filler | remove or be specific |
| "curated for those who" | Pretentious filler | remove or be specific |
| "limited time" | Pressure tactic | remove (or be specific, like "until Friday") |
| "act now" | Pressure tactic | remove |
| "don't miss out" | Pressure tactic | remove |
| "AI-powered" (unless product literally is AI) | Inflated | remove or be specific |
| Triple adjectives ("premium, hand-crafted, artisan-made") | LLM cadence | pick the one that matters |
| "Welcome to" as section opener | Generic | remove or use specific section name |
| "Introducing" as opener | Generic | remove or be specific |
| "Discover" as opener | Generic | remove or be specific |

## Layout (all brands — hard block)

| Pattern | Reason | Detection |
|---|---|---|
| Centered hero + two buttons + abstract visual | Generic SaaS template | manual review |
| Card-within-card nesting > 2 levels | Visual noise | grep `<article.*<article.*<article` |
| Frosted-glass over imagery | Tired effect | grep `backdrop-filter: blur` over img backgrounds |
| Gradient mesh backgrounds | Tired effect | manual review |
| Blob shapes | Tired effect | manual review |
| 3D mockups of phones/laptops with garbled text | LLM tell | manual review |

## Voice (per brand — hard block)

Each active venture gets its own heading here, with bullets of banned phrases/patterns specific to
that venture's voice. Populate this section from the consuming project's own brand rules — this file
ships with the shape only, no example ventures.

### Venture A
- filler superlatives ("luxury" / "premium") with no specific claim backing them
- cliché positioning lines the brand has explicitly retired

### Venture B
- unverifiable virtue claims ("sustainable" / "eco-friendly" / "conscious") without certification or
  a specific metric
- guilt/shame-adjacent framing used as a selling point

### Venture C
- any locked wake word / trigger phrase drifting to an unretired alternate — keep exactly one live
  wake word per venture and list retired ones so they can't resurface
- framing patterns the brand has explicitly retired (accent, dialect, or identity framing that reads
  as a stereotype)

---

## Soft-flag (warning, not block)

| Pattern | Reason | Severity |
|---|---|---|
| Sentence length > 25 words | Long sentences reduce comprehension | soft-flag |
| Paragraph > 4 sentences | Walls of text | soft-flag |
| More than 2 exclamation marks per page | Shouts at reader | soft-flag |
| More than 1 emoji per 200 words (TS brand allows more) | Visual noise | soft-flag |

---

## Build integration

Native `legion review` runs hard-block patterns against built HTML. Soft flags appear in review evidence as warnings.

Override via `--allow-banned=<pattern>` flag with required reason. Waivers logged in `artifacts/qa/waivers.json`.
