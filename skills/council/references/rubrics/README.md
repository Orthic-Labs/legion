# Council rubrics

A rubric is the shared scoring floor for the Jury (verdict) panel. Every juror scores the same
dimensions and answers the same forced questions; the stance and role card change where each seat
attacks, not what it scores. Council seats do not score.

The convener picks the rubric whose name matches the artifact's domain file in `../lenses/`
(`audit-visual.md` pairs with `design.md`, `image.md`, or `video.md` when real pixels are in the packet).
Embed exactly one rubric in each verdict seat's prompt.

## Conventions

- **Scores** run 1-10 per dimension and overall; 10 is best (safest, clearest, best evidenced) on every
  dimension, including ones named for a risk such as `assumption_density` (10 = few hidden assumptions).
- **Position.** A seat returns SUPPORTED, REVISE, or UNRESOLVED. Each rubric lists its native verdict
  words for reference; map them as: ship/approve/publish/go/run/ready/fund/build/do-now/clear/on-brand
  = SUPPORTED; revise/needs-revision/pause/hold/defer/review/ship-with-fixes/pivot = REVISE; reject/
  kill/block/abort/don't-ship/drop/do-not-run/off-brand = REVISE with at least one P0 finding;
  insufficient evidence = UNRESOLVED. Put the native verdict word in `top_concern` when it helps.
- **Tiers.** P0 invalidates the outcome or safety and must be fixed or explicitly waived; P1 should
  change before ship; P2 is worth knowing. A seat returns at most 8 P1+P2 findings; P0 is unbounded.
- **Forced questions.** Answer every one, in one or two sentences, citing packet evidence. "none found"
  is a valid answer only with what you checked. Answer the stance's own forced question as well.
- **missing_evidence.** Every rubric also asks: what would you need to see that is not in this packet?
  Gaps are findings of class MISSING_EVIDENCE, never reasons to guess.
- **Fail modes** are a checklist of known ways this artifact type fails. Use them to look, not to pad.
- **Framing** is the rubric's default posture. A verdict that departs from the default needs cited evidence.
- Keep `top_concern` under about 120 characters.

| Rubric | Artifact |
|---|---|
| `ad.md` | Paid ad: creative, copy, targeting, landing match |
| `audit-visual.md` | Rendered screenshots of a UI |
| `blogs.md` | Blog drafts and published posts |
| `brand-voice.md` | Content against a brand card |
| `business-plan.md` | Business or go-to-market plan |
| `code.md` | Code change |
| `compliance-risk.md` | Platform policy, claims, IP, disclosure, payments |
| `content-strategy.md` | Content strategy or calendar |
| `design.md` | UI/UX design, mockup, or live page |
| `idea.md` | Early product or venture idea |
| `image.md` | Static image |
| `launch.md` | Launch readiness |
| `offer.md` | Commercial offer |
| `plan.md` | Engineering or architecture plan |
| `priority.md` | Prioritisation against competing work |
| `seo.md` | SEO/GEO page, draft, or audit |
| `video.md` | Video edit |
