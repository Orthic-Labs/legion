# Anti-Slop + Humanizer Pass (shared reference)

Merged from petergyang/no-ai-slop and blader/humanizer (both MIT, fetched 2026-07-26).
Mandatory final pass for every prose artifact a skill ships: copy, captions, blog posts,
SEO content, scripts, emails, UI microcopy, marketing plans. Detection mode doubles as a
review lens for audit-visual and writing critiques.

## Principles

- **Preserve the real voice.** Note vocabulary, cadence, bluntness, humor, uncertainty before
  editing. Keep personal edge — strong opinions, profanity, honest admissions. Don't homogenize.
- **Minimum effective edit.** Fix patterns, errors, unclear passages. Leave strong sentences alone.
- **Keep the meaning.** Never invent claims, examples, stats, or authorities. Protect specific
  facts; don't smooth details into generic language.
- **Concrete beats abstract.** "Cut deploy time from 40 minutes to 4" beats "improved efficiency."
- **Active voice, working verbs.** "Decided" not "made a decision"; "is/has" not "serves as/boasts."
- **End on the last concrete fact** or next action — never a recap or an upbeat generic close.

## Banned vocabulary (cut outright)

delve, foster, leverage, utilize, facilitate, empower, streamline, robust, cutting-edge,
paradigm shift, game changer, "this changes everything", tapestry, realm, beacon, multifaceted,
meticulous, intricate, paramount, transformative, elevate, embark, supercharge, harness,
ever-evolving, landscape, interplay, enduring, showcase, testament, "stands as", nestled,
vibrant (as filler), breathtaking, "rich cultural heritage".

**Often-empty (cut unless carrying real emphasis/uncertainty):** just, literally, honestly,
simply, actually, truly, fundamentally, importantly, crucially, inherently, inevitably.

**Often-empty phrases:** it's worth noting, it's important to note, at the end of the day,
when it comes to, at its core, in today's world, in the age of, the reality is, the truth is,
in terms of, with regard to, in order to (→ to), due to the fact that (→ because), going
forward, in this article, let's dive in.

## Pattern inventory

### Structure and rhetoric
1. **Binary contrasts** — "It's not X. It's Y." → state the point directly.
2. **Negative listing** — "Not X. Not Y. Z." → just "Z."
3. **Negative parallelisms** — "not only… but also…", tailing negations ("no guessing") → plain phrasing.
4. **Rule-of-three overuse** — unforce artificial triads; use natural rhythm.
5. **False ranges** — "from X to Y" where X,Y aren't a scale → name things directly.
6. **Colon reveals** — "The best part: it learns." → plain sentence.
7. **Dramatic fragmentation / manufactured staccato** — "That's it. That's the whole thing." → complete sentences; one short sentence for emphasis, never a run.
8. **Aphorism formulas** — "X is the Y of Z" → concrete claim about what it does.
9. **Fake-profound kickers** — cut the final "deep" metaphor line; end on the clearest concrete sentence.
10. **Summary-recap endings** — "In conclusion", "Ultimately", generic positive closes → end on substance.
11. **Robotic rhythm** — repeated sentence shapes → vary deliberately.

### Openers and setups
12. **Throat-clearing** — "Here's the thing", "Let me be clear", "I'll be honest" → cut, state point.
13. **Faux-insight setups** — "What nobody tells you…" → let the claim stand.
14. **Rhetorical setups** — "What if I told you", self-answered questions → drop.
15. **Conversational fake-candid hooks** — "Honestly?" → make the point.
16. **Signposting** — "Let's dive in", "Here's what you need to know" → just say the thing.
17. **Fragmented headers** — generic restatement sentence after a heading → cut.

### Substance
18. **Importance puffery** — "pivotal moment", "plays a vital role", significance inflation → state the fact, let the reader judge.
19. **Notability name-dropping** — citation lists without context → one source with real detail.
20. **Superficial -ing analysis** — trailing "highlighting/reflecting/symbolizing…" clauses → direct statement of what it is or does.
21. **Weasel/vague attribution** — "experts agree", "studies show" → name the source or cut the claim.
22. **Promotional language** — sales-speak in informational prose → plain statement of what exists.
23. **Outline-template sections** — formulaic "Challenges and Future Directions" → only specific, sourced problems.
24. **Excessive hedging** — "might possibly could" → "may."
25. **Speculative gap-fill** — invented filler where facts are missing → say what isn't known, or omit.

### Language mechanics
26. **Copula avoidance / fake-strong verbs** — "serves as", "features", "boasts" → "is/has."
27. **Synonym cycling (elegant variation)** — repeat the right word instead of rotating.
28. **Passive voice / subjectless fragments** — "No configuration needed" → "You don't need to configure anything."
29. **Hyphenated-pair overuse** — hyphenate attributive ("high-quality report"), not predicate ("the report is high quality").

### Formatting
30. **Em/en dash clusters** — short copy: none; long drafts: 1–2 max where they beat commas. Never decorative.
31. **Mechanical boldface** — bold only when genuinely needed; never every term/acronym.
32. **Inline-header bullet lists** — "**User Experience:** …" rows → flowing prose where prose is better.
33. **Emoji in headings/bullets** — strip (unless the brand voice explicitly uses them).
34. **Title Case headings** — sentence case.
35. **Headers over 2-sentence sections** — cut the header.

### Chat artifacts
36. **Collaborative asides** — "I hope this helps", "Would you like me to…" → never in a deliverable.
37. **Knowledge-cutoff disclaimers** — cut.
38. **Sycophantic tone** — neutral and direct.
39. **Diff-anchored writing** — describe what exists now, not what changed (except changelogs).

## What NOT to flag (false positives)

Perfect grammar or formal vocabulary alone; bland-but-honest writing; a single em dash;
common transitions; unsourced claims per se; specific hard-to-fabricate details; mixed
feelings; genuine asides; quoted text; brand voices that legitimately use a flagged device
(e.g. Northwind Tools's ALL-CAPS two-beat headlines are brand voice, not slop — brand card wins).

## Workflow

1. **Read the whole draft.** Note the core point and 3–5 voice signals.
2. **Edit mode (default):** minimum effective changes per the inventory; then self-audit —
   "what makes this still obviously AI?" and "does it contain unreasoned facts?" — fix, output
   the edited draft plus a short "what changed" note.
3. **Detect mode (review lens):** name each pattern found, quote the line (≤125 chars), give
   the fix. No rewrite, no authorship guessing.
4. **Embedded mode (inside another skill's pipeline):** apply silently before shipping the
   artifact; report only if findings changed the output materially.

Precedence: brand card (voice/banned-word lists in the consuming project's brand rules file) >
this file > personal taste. Where a brand bans words this file doesn't, both lists apply.
