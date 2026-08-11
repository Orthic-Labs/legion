# Social - platform content router

MODE: OUTPUT_ONLY
PRIMARY_DELIVERABLE: Bounded platform strategy or content for frozen account, domain, or source scope.
DISCOVERY_PROFILE: D3_EXTERNAL
EFFECT_PROFILES: external_research, connector
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Requested social deliverable meets frozen D3 source budget.

Single entry for social platform strategy, creation, optimization, and performance review. Load only the matching reference.

## Hard Gates

Before creating or approving social content, verify:

- **Platform-native gate:** format, length, aspect ratio, hook shape, CTA, and cadence fit the platform.
- **Brand gate:** brand voice or `brand-identity` exists; if not, extract a lightweight voice/promise first.
- **Hook gate:** first line/first 3 seconds/thumbnail-title promise is specific enough to stop the intended audience.
- **Proof gate:** claims, numbers, transformation, and examples are supported or removed.
- **Anti-slop gate:** no generic motivational filler, bland carousel headings, or posts that could fit any competitor. Banned AI-copy slop words: leverage, synergy, seamless, elevate, delve, innovative, revolutionary, disruptive, game-changing, unlock. Banned cliché openers: "In today's fast-paced world", "In this day and age", "It's no secret that", "Have you ever wondered". Banned passive CTAs: "Submit", "Click Here", "Learn More" (without specificity). Any of these in copy = revise before delivery.
- **Series gate:** if part of a calendar, it has continuity with prior/next posts and does not repeat the same idea with new wording.
- **Action gate:** the desired action is clear and platform-appropriate.

Failing a gate means revise before delivery.

## Parametrization + Anti-Slop (mandatory)

- Social content is parametrized per `tools/skills/_shared/parametric-design.md`: platform, format, hook
  type, pacing, caption length, hashtag strategy, and risk/experiment level are named axes, not
  a vibes brief.
- Calendars and batches must spread deliberately across those axes — never one template cloned
  per platform with only the copy swapped.
- The social default-region fingerprint is a scored defect even when the copy is clean: hook–
  value–CTA applied identically across platforms, emoji-bullet captions, engagement-bait
  questions.
- Every caption, post, or script gets the anti-slop pass (`tools/skills/_shared/anti-slop.md`, embedded
  mode) before delivery — apply silently, report only if it changed the output materially.
- Brand card precedence stands: brand voice rules (including a brand's own flagged devices,
  e.g. Toxic Sundae's ALL-CAPS headlines) win over the anti-slop list.

## Routing

| Intent / phrasing | Read reference |
|---|---|
| Instagram, IG, Reels, carousel, stories, IG analytics, IG calendar | `references/instagram/reference.md` |
| Pinterest, pins, boards, Pinterest traffic, pin creative | `references/pinterest/reference.md` |
| YouTube, YT, Shorts, video script, title/thumbnail, channel strategy | `references/youtube/reference.md` |
| Twitter/X, tweet draft, thread, algorithm optimization, reach | `references/twitter/reference.md` |
| General social calendar, LinkedIn, multi-platform content, scheduling, engagement | `references/content/reference.md` |

## Internal Social Council

Use a compact role pass for strategy, calendars, or substantial content. For a single caption/post, keep it light.

| Reference | Role pass |
|---|---|
| `instagram/reference.md` | Platform-native producer, visual/story arc lead, audience psychologist, consistency operator |
| `pinterest/reference.md` | Search/intent strategist, pin creative lead, board architecture lead, traffic operator |
| `youtube/reference.md` | Hook/retention strategist, title-thumbnail skeptic, audience promise lead, packaging operator |
| `twitter/reference.md` | Conversation-native editor, thread structure lead, punchiness critic, audience/community lead |
| `content/reference.md` | Calendar strategist, platform adapter, brand voice guard, cadence/reuse operator |

Output should preserve platform-native choices, brand fit, cadence, and success metric.

## Workflow

1. Run `/brand <DD|RH|SS|TS>` for branded work.
2. Identify the platform and task type: create / plan / optimize / review. **For optimize/review of live content, ask for the platform analytics first** (IG Insights, YouTube Studio, X analytics) — "optimise my IG" without reach/saves numbers is guesswork; ground it or label it hypothetical.
3. Read the matching reference only.
4. If the task spans multiple platforms, read `references/content/reference.md` first, then only the platform-specific references needed.
5. **Visual-asset handoff.** For carousels, pins, thumbnails, or story graphics, produce the exact copy + slide-by-slide structure, then offer to route to `/designer` (static) for the actual assets — don't leave "Slide 1: [hook]" as the deliverable. Video scripts → `/content` / the video pipeline.
6. **Distribution boundary.** Source material already exists? Repurpose it, don't rewrite from scratch. Paid ads/budgets/funnel → `/marketing`; deep YouTube search optimisation → `/seo`. A CTA link must resolve (WebFetch) and, for conversion, carry UTM params — never ship a dead or untracked link.

Existing Instagram carousel slide extraction routes to `/content carousel`; social owns concept,
copy, slide sequence, platform fit, publishing strategy, & optimization.

Stunning Strangers is a passion project. Do not apply growth, ads, SEO, or commercialization framing to SS unless the approving human explicitly asks.
