# Blog Writing Research And Craft

Use this reference when planning, writing, auditing, or upgrading blog posts that need to rank, persuade, and feel written by someone with judgment.

Local sources:

- `D:/Claude/Content/Storytelling/STORYTELLING_GUIDE.md`
- `D:/Claude/Content/Storytelling/SOURCE_MATRIX.md`
- `D:/Claude/tools/skills/writing/specialists/copywriting/references/craft-research.md`
- `D:/Claude/tools/skills/writing/specialists/copywriting/references/hook.md`
- `D:/Claude/SEO/vinay/blog-playbook.md`
- `D:/Claude/tools/skills/seo/references/blog-post-contract.md`

Extracted writing sources:

- Harry Dry `[TUMjnmfsPeM]`: specificity, Three Questions, Zoom-In Worksheet, One-Mississippi test, every word works.
- Callaway `[2byPP_9F0-Q]`: topic clarity, on-target curiosity, speed-to-value, four hook mistakes.
- Romm `[Bt3AACk6dbo]`: But/Therefore editing, conflict, every word chosen for a reason.

Source trace:

- `STORYTELLING_GUIDE.md` section 1.4: hook clarity, pointable proof, speed-to-value, every-word-works.
- `STORYTELLING_GUIDE.md` section 2: why people keep reading.
- `STORYTELLING_GUIDE.md` section 3.2: Callaway hook mistakes - delay, confusion, irrelevance, disinterest.
- `STORYTELLING_GUIDE.md` sections 3.3, 3.5, 3.8: Harry Dry line gate, Zoom-In, One-Mississippi.
- `STORYTELLING_GUIDE.md` section 4.2: Romm But/Therefore edit for long-form structure.
- `SOURCE_MATRIX.md`: identifies the Harry Dry, Callaway, and Romm videos as well-captured/extracted sources.

## Copywriting Corpus Import

`blogs` owns the post. `copywriting` owns the persuasion and line-quality corpus used inside the post.

Use `D:/Claude/tools/skills/writing/specialists/copywriting/references/craft-research.md` for:

- blog titles and H1s
- first sentence and TL;DR
- meta descriptions
- CTA copy
- section hooks and transitions
- claim specificity, proof gaps, and line edits

Use `D:/Claude/tools/skills/writing/specialists/copywriting/references/hook.md` only when the user asks for stronger hooks/openers, social-native promotion, or a scroll-stopping angle for the post.

Do not load `copywriting/references/ad.md` or ad platform specs unless the blog task also asks for ad copy or platform-specific promotion. Blog SEO and article structure stay in `blogs`; sales pages stay in `copywriting`.

## Research Dossier Gate

Before drafting, collect or state assumptions for:

- Local source material: product/engineering decisions, docs, PRDs/specs, ADRs, README/docs, commits, changelogs, tickets/issues, release notes, support logs, transcripts, founder notes, screenshots, diagrams, or product artifacts.
- Public-safety filter: remove secrets, private customer details, security-sensitive implementation, unreleased roadmap, and anything that should stay internal.
- Existing content inventory: current blog posts, docs pages, product/service pages, comparison pages, duplicate/cannibalized URLs, and obvious internal link targets.
- Primary query and intent.
- Real reader questions, preferably from GSC, People Also Ask, forums, customer conversations, support logs, or real-question tools.
- Current primary sources for factual/current/high-stakes claims.
- Brand-owned experience: founder/operator opinions, mistakes seen, customer examples, internal screenshots, photos, prices, timelines, workflows, or decision rules.
- SERP/competitor sameness: what every ranking post and direct competitor already says.
- Information gain: what this post adds that a generic competitor post does not.
- Internal link targets and target action.

Do not draft a serious SEO post from keyword volume alone.

## Local Source Opportunity Scan

Start by asking: "What changed, what did we learn, or what did we build that readers would care about?"

Good blog seeds:

- A product decision with a clear tradeoff.
- An engineering decision that explains a useful workflow, performance fix, architecture choice, or reliability lesson.
- A customer problem that repeatedly appears in support/sales/founder notes.
- A bug or failure that produced a public-safe lesson.
- A before/after product improvement with screenshots or measurable outcome.
- A common objection answered with evidence.
- A local service/process detail competitors explain badly.
- A docs/changelog item that deserves a human-readable guide.

Bad blog seeds:

- Internal-only roadmap.
- Security-sensitive details.
- Thin release notes with no reader question.
- Content that belongs in docs, support, changelog, email, or social instead of search.
- Any story that depends on private customer data.

Decision output:

- Create a new post.
- Refresh an existing post.
- Consolidate/canonicalize because an existing URL already owns the intent.
- Skip and route to docs/changelog/social/email.

## Title And Intro Gate

The title, first sentence, and first paragraph must pass:

1. Topic clarity: the reader knows exactly what this is about.
2. On-target curiosity: the reader sees why this answer matters.
3. Visualizable/falsifiable/ownable: the claim is concrete enough to picture, check, and tie to this brand or author.
4. Speed-to-value: answer the query immediately; do not warm up.

The first sentence should answer the query or define the decision in 40 words or less. If the topic needs context, use a short TL;DR before the intro.

## Section Information-Gain Gate

Every H2 must add at least one of:

- first-hand observation
- concrete example
- current cited fact
- comparison table
- decision rule
- mistake to avoid
- workflow/checklist/template
- visual/image plan
- opinionated tradeoff

Delete or merge sections that only restate generic SERP advice.

## Point, Do Not Claim

Replace broad claims with pointable material:

- example
- quote from a real named source when available
- screenshot/photo/artifact
- measured before/after
- process step
- constraint
- caveat

Never invent proof, experience, customer stories, or expert credentials.

## But/Therefore Sweep

Use this after drafting long sections.

Search for "and" chains. Where the post is flat, introduce:

- but: obstacle, tradeoff, caveat, risk
- therefore: decision, action, consequence, next step

This prevents listicles from becoming equal-weight summaries with no judgment.

## Blog Audit Lens

When auditing an existing post, mark failures as:

- missing local source scan
- missing search intent
- missing research dossier
- no information gain
- title/intro delay
- generic H2
- unsupported claim
- invented or vague experience
- competitor-pasteable advice
- weak internal link plan
- existing-content/cannibalization not checked
- CTA mismatch
- accessibility/preview gap

Good audit feedback includes the failed lens, exact location, and a concrete fix.
