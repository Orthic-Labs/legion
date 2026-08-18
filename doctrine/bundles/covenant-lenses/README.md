# Covenant lens index

Recovered from `git show d810d827^:tools/skills/council/references/` (J-1b, 2026-08-09) — Council's
engine was ported to `skills/covenant/`, but these sixteen domain review lenses were not
carried over. Each is the specific set of review roles, mandates, and evidence a reviewer needs for
one domain; recovering them restores the specialization BRIEFING-LAYER.md §3 describes.

**These are assigned per-seat at convene time — one lens per seat.** That assignment IS the
specialization mechanism (BRIEFING-LAYER.md §2.3): a `covenant-seat` instance is the same
constitution every time; what makes it a design specialist versus a code specialist is which of
these files it was handed in its packet. Do not load more than one lens into a single seat — that
recreates the "too much information competing for attention" failure the briefing layer exists to
avoid.

| Lens | Assign when reviewing... |
|---|---|
| `ad.md` | Paid ad creative/copy — hook, offer, platform fit, compliance, message-match, brand fit |
| `blogs.md` | Blog drafts — editorial structure, fact-checking, SEO/discovery, brand voice |
| `brand-voice.md` | Voice/tone artifacts against an active brand card — claims, audience fit, cross-brand isolation |
| `business-plan.md` | Business plans — operator reality, unit economics, market/demand proof, GTM, risk inversion |
| `code.md` | Code diffs — architecture, implementation correctness, test coverage, security/reliability |
| `compliance-risk.md` | Regulated/risky commercial work — platform policy, claims substantiation, IP, payments risk |
| `content-strategy.md` | Content calendars/strategy — editorial POV, audience research, distribution, production capacity |
| `design.md` | UI/visual/product design — IA, interaction, visual craft, conversion UX, accessibility, UX copy |
| `idea.md` | Early product/venture ideas — user/problem fit, JTBD, inversion, smallest-test path, market skepticism |
| `image.md` | Generated or produced images — concept, composition, brand fit, production QA, viewer skepticism |
| `launch.md` | Product/feature launches — GTM, product readiness, analytics instrumentation, comms, ops risk |
| `offer.md` | Commercial offers — Hormozi value equation, demand evidence, proof/claims, pricing friction, brand fit |
| `plan.md` | Engineering/execution plans — decision clarity, implementation sequencing, risk inversion, operability, user value |
| `priority.md` | Cross-venture prioritization calls — opportunity cost, cashflow, strategic fit, attention cost |
| `seo.md` | SEO/GEO artifacts — technical foundation, on-page, E-E-A-T, AEO/GEO, schema hygiene, white-hat off-page |
| `video.md` | Video edits — story/hook, edit craft, continuity, production QA, social-viewer skepticism |

## What changed from the Council originals

Review craft is preserved **verbatim** — same roles, mandates, references, evidence, "veto power"
language. Only factually-wrong pointers were adapted, each marked inline with a `> **Superseded:**`
note rather than silently rewritten:

- Every lens: a note explaining that "Veto power" phrasing is retained as the original craft's
  severity framing, but under Covenant doctrine (C-invariants) a seat is advisory only — never
  decides or disposes. What reads as "blocks" here is a maximum-severity finding for the caller
  (Sage or Alchemist) to weigh.
- `seo.md`: a note explaining the retired Council SEO command and retired
  `tools/review/dual_review.py` CLI do not exist in Covenant; the rubric content is preserved, the
  delivery mechanism is not.

`manual.md` (Council's 177-line operating manual — room driver, `dual-review` CLI, disposition
JSON, Jury seats, resumption/routing tables) was **not** recovered into this bundle. It documents
the old engine's own operating procedure end-to-end, and that engine is retired; Covenant's
operating procedure (packets, flows, C-invariants) is authored fresh in `$WORKSPACE/docs/plans/legion/COVENANT.md` and
`doctrine/covenant-seat.md`, which supersede it in full rather than in the piecewise way a lens
does. See J-1b's report for the full reasoning.
