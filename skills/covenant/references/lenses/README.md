# Covenant role cards

Sixteen domain files, each a panel of four to six named reviewers ("role cards"). A role card says
whose expertise a seat brings: its mandate, references, evidence, severity ceiling, and what to ignore.

**The convener assigns one role card from a domain file to each seat.** The card is only half of a
seat's lens. The other half is its stance (`../stances/`), which sets the angle of attack. A seat
gets one stance and one role card, and in a verdict stage also the artifact's rubric (`../rubrics/`).
Never hand a seat a whole file: playing every role in a domain recreates the failure where three
seats share one lens and one blind spot.

Seat lens ids use the form `<stance>/<domain>:<role>`, for example `red-team/code:lead-architect`.

| File | Assign when reviewing... |
|---|---|
| `ad.md` | Paid ad creative/copy: hook, offer, platform fit, compliance, message-match, brand fit |
| `blogs.md` | Blog drafts: editorial structure, fact-checking, SEO/discovery, brand voice |
| `brand-voice.md` | Voice/tone artifacts against an active brand card: claims, audience fit, cross-brand isolation |
| `business-plan.md` | Business plans: operator reality, unit economics, market/demand proof, GTM, risk inversion |
| `code.md` | Code diffs: architecture, implementation correctness, test coverage, security/reliability |
| `compliance-risk.md` | Regulated/risky commercial work: platform policy, claims substantiation, IP, payments risk |
| `content-strategy.md` | Content calendars/strategy: editorial POV, audience research, distribution, production capacity |
| `design.md` | UI/visual/product design: IA, interaction, visual craft, conversion UX, accessibility, UX copy |
| `idea.md` | Early product/venture ideas: user/problem fit, JTBD, inversion, smallest-test path, market skepticism |
| `image.md` | Generated or produced images: concept, composition, brand fit, production QA, viewer skepticism |
| `launch.md` | Product/feature launches: GTM, product readiness, analytics instrumentation, comms, ops risk |
| `offer.md` | Commercial offers: value equation, demand evidence, proof/claims, pricing friction, brand fit |
| `plan.md` | Engineering/execution plans: decision clarity, sequencing, risk inversion, operability, user value |
| `priority.md` | Cross-project prioritization: opportunity cost, cashflow, strategic fit, attention cost |
| `seo.md` | SEO/GEO artifacts: technical foundation, on-page, answer-first, E-E-A-T, white-hat off-page, search skeptic |
| `video.md` | Video edits: story/hook, edit craft, continuity, production QA, social-viewer skepticism |

## Severity wording

A card's "Veto power" line names what that role treats as a maximum-severity finding. Under Covenant
a seat is advisory: it reports that finding as P0 for the decision owner to weigh and never blocks or
disposes.

## Seat mix

`../../SKILL.md` carries the table of which cards go to which stances for each artifact type.
