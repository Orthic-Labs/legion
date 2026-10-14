# Council rubrics

A rubric is the shared scoring floor for one round. Every seat receives the same rubric and answers
the same forced questions; the stance and role card change where each seat attacks, not what it
scores. Only challenging seats return scores; helpful seats use the rubric for its questions and fail
modes.

The convener picks the rubric whose name matches the artifact's domain file in `../lenses/`
(`audit-visual.md` is used only for rendered UI screenshots; `image.md` and `video.md` keep their own
rubrics). Embed exactly one rubric in each seat's prompt.

## Conventions

- **Scores** run 1-10 per dimension and overall; 10 is best (safest, clearest, best evidenced) on every
  dimension, including ones named for a risk such as `assumption_density` (10 = few hidden assumptions).
- **Position.** A seat returns SUPPORTED, REVISE, or UNRESOLVED. Each rubric lists its native verdict
  words for reference; map them as: ship/approve/publish/go/run/ready/fund/build/do-now/clear/on-brand
  = SUPPORTED; revise/needs-revision/pause/hold/defer/review/ship-with-fixes/pivot = REVISE; reject/
  kill/block/abort/don't-ship/drop/do-not-run/off-brand = REVISE with at least one P0 finding;
  `SHIP-WITH-MONITORING` = SUPPORTED (list the monitoring items as P2); `NEEDS-MEASUREMENT` =
  UNRESOLVED with a MISSING_EVIDENCE finding; insufficient evidence = UNRESOLVED.
  **No image, no verdict:** missing pixels for a visual artifact is always UNRESOLVED, never a
  DON'T-SHIP. Put the native verdict word in `top_concern` when it helps.
- **Tiers.** P0 shows a failed outcome or safety property and must be fixed or explicitly waived (an
  unproven concern is MISSING_EVIDENCE, not an automatic P0); P1 should
  change before ship; P2 is worth knowing. A seat returns at most 8 P1+P2 findings; P0 is unbounded.
- **Forced questions.** Answer every one, in one or two sentences, citing packet evidence. "none found"
  is a valid answer only with what you checked. Answer the stance's own forced question as well.
- **requirement_coverage.** Every rubric also scores this dimension from the seat's requirement trace:
  10 = every verbatim requirement `MET` with evidence. Any `MISSING` requirement is a P0 and makes the
  position REVISE; an `UNPROVEN` one is a MISSING_EVIDENCE finding.
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
