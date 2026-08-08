# Motion Principles

The philosophy that governs every animation decision.

If you only read one file in this skill, read this one. Then re-read it.

This is the heaviest file in the kit on purpose. Patterns and stacks are downstream of these principles. Get the principles right and the rest follows.

---

## 1. Motion serves meaning

Animation is not decoration. It is communication.

Before adding any motion, answer in one sentence:
- What **information** does this convey?
- What **emotion** does this evoke?
- What would the user **understand faster** because of this motion?

If you can't answer, the motion is decorative. Cut it.

**Examples that serve meaning:**

- A button subtly compresses on press → confirms the click is registered
- A modal slides up from the trigger → shows cause and effect
- A chart bar grows from zero → shows growth over time
- An image crossfades into sharper detail → shows zoom or focus
- A persistent object morphs between scenes → shows continuity of identity
- A scroll-locked section pauses the user's pace → signals "pay attention here"

**Examples that don't:**

- A button that spins on hover "because it looks cool"
- A hero section that animates 4 seconds before the headline appears
- A page that fades in every section on scroll regardless of relevance
- Continuous background animation with no semantic purpose
- Multiple competing entrance animations fighting for the same attention

---

## 2. Persistent objects

This is what separates agency-quality work from template output. **Pick this up early** — the persistent object IS the page's narrative.

**Bad pattern:**

```
Hero: Big illustration of a product
Section 2: Completely different illustration
Section 3: Random icon
Section 4: Generic gradient
```

Every section starts from scratch. The page feels disjointed, like a deck of unrelated slides.

**Good pattern:**

```
Hero: A cube, large, center
Section 2: Cube rotates, shrinks, moves left
Section 3: Cube morphs into product photo
Section 4: Cube becomes CTA icon
Footer: Cube, small, persisted
```

One object evolves. Continuity across scenes creates narrative.

**Implementation:**

- Pick **1-3 persistent objects per page**. More than that and the page feels busy.
- Define each object's **initial state, transformations, and final state** in the motion plan.
- Each persistent object must justify its persistence — what is it **symbolically**?

**Common persistent objects:**

- A product (the literal thing being sold)
- A logo mark
- A geometric form (cube, sphere, line, grid)
- A character or avatar
- A typographic element (oversized headline that scales)
- A gradient or color field that bleeds across sections

**When to skip persistence:**

- Content-heavy pages (articles, documentation, dashboards)
- Pages with no clear narrative thread
- Pages where the user is mid-task and shouldn't be guided anywhere

---

## 3. Motion hierarchy

Not everything can move at once. Establish hierarchy explicitly:

```
Global (page-level choreography)
└── Scene (one section of the page)
    └── Section (one viewport within the scene)
        └── Component (one interactive element)
            └── Microinteraction (one hover / click / transition)
```

Rules:
- **Only animate the lowest level necessary.** A page transition should not trigger microinteractions on every component.
- **If everything moves, nothing matters.**
- **Reserve the most dramatic motion** for the primary CTA or the page's narrative climax.
- **Limit simultaneous animations** to **3 distinct motion patterns per viewport**.
- **One attention-grabbing animation per viewport** — anything oversized, overscaled (>1.2x), or with full-color shift.

If you have more candidates than the budget allows, rank them by importance to the narrative. Cut the bottom half.

---

## 4. Motion language (pick one per surface)

The language drives default timing, easing, and distance. Pick by what the brand needs to communicate, not what looks cool.

| Language | Timing | Easing | Distance | Density | Rhythm |
|---|---|---|---|---|---|
| **Authority** | Slow (600-900ms) | Strong ease-out | Large | Low | Deliberate pauses |
| **Playfulness** | Spring (stiffness 200, damping 10) | Bouncy | Medium | High | Quick beats |
| **Luxury** | Long (800-1500ms) | Soft ease-out | Small | Very low | Generous holds |
| **Precision** | Fast (150-250ms) | Sharp ease-out | Tiny | High | Tight, exact |
| **Energy** | Fast (200-400ms) | Strong ease-out | Large | High | Continuous motion |
| **Calm** | Slow (500-800ms) | Soft ease | Small | Very low | Spacious |
| **Technical** | Fast (150-300ms) | Linear or ease-out | Geometric | Medium | Mechanical |
| **Editorial** | Varied (200-1500ms) | Mix of ease-out and ease-in-out | Varied | Medium | Asymmetric |

**Examples:**
- Linear = restrained precision
- Apple = calm luxury
- Arc = energetic
- Stripe = precise editorial
- Nothing = precision with moments of authority
- Vercel = technical with editorial accents

Pick ONE per surface, document in `motion-plan.md`. The defaults flow from the pick.

---

## 5. Rhythm and pacing

Motion has tempo. Establish it explicitly per scene.

### Tempo primitives

| Tempo | Duration | Use for |
|---|---|---|
| Fast | 150-250ms | Microinteractions, hover states, button feedback |
| Standard | 300-450ms | Most UI transitions, modal open/close, tooltip enter |
| Slow | 600-900ms | Page transitions, scene changes, drawer slide |
| Reveal | 1000-1500ms | Hero animations, narrative moments, attention grabs |
| Hold | 200-500ms | Deliberate pause to let the eye rest |
| Repeat | n/a | Loading, ambient — only when semantically meaningful |

### Default values

- **Stagger between siblings:** 60-80ms. Over 100ms feels sluggish. Under 40ms feels chaotic.
- **Pause between scene changes:** 200-400ms. Long enough to register a beat, short enough not to lose momentum.
- **Hover response:** 150-200ms. Anything slower feels broken.
- **Click response:** 80-150ms. Must feel instantaneous.

### Pacing patterns

**Cinematic reveal:** hold 400ms → fast reveal → pause → hold → transition

**List cascade:** item 1 → 60ms → item 2 → 60ms → item 3 → hold

**Confidence pulse:** slow enter → hold → slow exit

**Scroll-driven narrative:** scroll progress 0 → 0.3: enter · 0.3 → 0.7: hold · 0.7 → 1.0: exit

**Anti-pattern: continuous motion.** If everything moves at the same tempo, the page feels restless. Mix tempos deliberately.

---

## 6. Easing library (canonical)

Easing carries meaning. Different curves communicate different things. **Locked values** — these match `tools/skills/audit-visual/references/motion-standards.md`. Drift breaks producer/reviewer contract.

| Curve | CSS value | Motion value | Use when |
|---|---|---|---|
| Linear | `linear` | `linear` | Never for UI. Only continuous loops (loading spinners, marquees). |
| **Strong ease-out** | `cubic-bezier(0.23, 1, 0.32, 1)` | `{ duration: 0.4, ease: [0.23, 1, 0.32, 1] }` | **Default UI entrances.** Confident, clean, professional. |
| ease-in | `cubic-bezier(0.64, 0, 0.78, 0)` | `{ duration: 0.3, ease: [0.64, 0, 0.78, 0] }` | Exit animations. Things leaving the screen. |
| ease-in-out | `cubic-bezier(0.65, 0, 0.35, 1)` | `{ duration: 0.5, ease: [0.65, 0, 0.35, 1] }` | Reversible motion. Things that come and go symmetrically. |
| ease-out-back | `cubic-bezier(0.34, 1.56, 0.64, 1)` | `{ type: "spring", stiffness: 200, damping: 14 }` | Attention-grabbing arrival. Use sparingly. |
| ease-out-expo | `cubic-bezier(0.16, 1, 0.3, -0.05)` | `{ duration: 0.8, ease: [0.16, 1, 0.3, -0.05] }` | Dramatic reveals. Hero animations, scene transitions. |
| Spring (snappy) | — | `{ type: "spring", stiffness: 400, damping: 30 }` | Button presses, toggle switches. |
| Spring (natural) | — | `{ type: "spring", stiffness: 120, damping: 14 }` | Natural-feeling layout transitions, list reorders. |
| Spring (bouncy) | — | `{ type: "spring", stiffness: 200, damping: 10 }` | Playful interactions. Mascots, celebrations. |

**Rules:**
- **Default to ease-out for entrances.** Strong curve at `(0.23, 1, 0.32, 1)` is the canonical UI ease.
- **Default to ease-in for exits.** Symmetric with ease-out entrances.
- **Use ease-in-out for reversible motion** — drawers, accordions, modals.
- **Use springs for physics-based motion** — drag, magnetic, layout transitions.
- **Never stack easings.** One curve per transition.
- **Never use linear for UI motion.** Exception: continuous loops.

---

## 7. Motion tokens (the design system for motion)

```js
// Duration scale (use named tokens, not raw ms)
duration = {
  instant:    '80ms',   // click feedback
  fast:       '150ms',  // hover
  standard:   '300ms',  // most UI
  slow:       '600ms',  // page transitions
  reveal:     '1000ms', // hero
  deliberate: '1500ms'  // cinematic
}

// Distance scale (for translate offsets)
distance = {
  xs: '4px',
  sm: '8px',
  md: '16px',
  lg: '32px',
  xl: '64px'
}

// Easing scale (named curves, canonical values)
easing = {
  'ease-out':       [0.23, 1, 0.32, 1],
  'ease-in':        [0.64, 0, 0.78, 0],
  'ease-in-out':    [0.65, 0, 0.35, 1],
  'ease-out-expo':  [0.16, 1, 0.3, -0.05]
}

// Spring presets
springs = {
  snappy:  { stiffness: 400, damping: 30 },
  natural: { stiffness: 120, damping: 14 },
  bouncy:  { stiffness: 200, damping: 10 }
}

// Opacity scale
opacity = {
  hidden:  0,
  dim:     0.3,
  partial: 0.6,
  full:    1
}

// Delay scale (for staggers)
delay = {
  none:    0,
  tight:   40,
  stagger: 70,
  breath:  200,
  pause:   500
}

// Z-index choreography (for layered motion)
z = {
  background: -1,
  base:       0,
  overlay:    10,
  sticky:     100,
  modal:      1000,
  toast:      1100,
  tooltip:    1200
}
```

**Use tokens, not magic numbers.** Every animation references these scales. Tweaking the system is one-place; every animation follows.

---

## 8. Motion budget (heuristic tiers)

These are heuristics, not hard limits. Treat the typical-max as the default cap; target as the goal; hard-failure requires explicit justification.

| Metric | Target | Typical max | Hard failure |
|---|---|---|---|
| Animation JS (gzipped) | 35KB | 50KB | 80KB (with reason) |
| Cumulative mount work | 30s | 60s | 120s |
| Simultaneous animations per viewport | 2 | 3 | 5 |
| Animation time before user can act | 800ms | 1500ms | 2500ms |
| Attention-grabbing animations per viewport | 0 | 1 | 2 |
| Hover duration | 150ms | 200ms | 250ms |
| Click/active duration | 80ms | 150ms | 200ms |
| Element enter duration | 400ms | 600ms | 800ms |
| Page enter duration | 600ms | 1000ms | 1500ms |
| Scene change duration | 700ms | 1000ms | 1500ms |
| Hero animation duration | 1000ms | 1500ms | 2000ms (value prop must be visible by 1000ms) |

If you exceed any of these, simplify. Cut the bottom candidate. Ship the rest.

---

## 9. Animation architecture (cross-cutting decisions)

These matter more than which library you pick.

- **Timeline ownership.** Who owns the timeline? Page-level, scene-level, component-level. Decide upfront to avoid conflicts.
- **Scene ownership.** Each scene is a unit with its own entrance, persistence, exit. Don't bleed.
- **State-driven motion.** Motion responds to state (open/closed, loading/loaded, hover/idle). State machines + motion, not just triggers.
- **Declarative vs imperative.** Declarative (Motion, Rive) for state-driven; imperative (GSAP timelines) for choreographed sequences.
- **Animation composition.** Combine primitives (fade + slide + scale) into compound patterns. Order matters.
- **Interruptibility.** Rapid triggers (toast, modal) must retarget from current state (transitions/springs), not restart from zero (keyframes).
- **Cancellation.** Can motion be cancelled mid-flight? Users rarely wait.
- **Exit sequencing.** What exits first when a scene closes? Reverse-order is the default, but not always right.
- **Shared transitions.** Same element across routes (e.g., card → detail page) needs shared layout (`layoutId` in Motion).

---

## 10. Choreography (timing relationships)

The art of how multiple animations relate. This separates premium motion from "elements fading in."

- **Lead** — the element that moves first, drawing focus
- **Follow** — elements that move after the lead, supporting it
- **Overlap** — animations that run in parallel vs. sequence
- **Anticipation** — small movement before the main movement (squash before jump)
- **Release** — the moment of arrival or departure, often with hold
- **Focal handoff** — when attention transfers from one element to another (e.g., a button that hands focus to a confirmation message)

Without choreography, the page is a sequence of entrances. With it, the page is a performance.

---

## 11. Failure modes

Train yourself to recognize and avoid these.

- **The Rube Goldberg.** Animation chains 5+ steps to reveal a button. User waited 3 seconds for a CTA.
- **The Perpetual Motion Machine.** Background animation that never stops. Loading spinner ≠ decorative loop.
- **The Hero Tomb.** Hero animation longer than 2 seconds before value prop.
- **The Synesthesia Page.** Every section uses a different motion language.
- **The Mobile Disaster.** Tested on desktop, ships broken on Safari iOS.
- **The Hydration Horror.** Server renders one state, client hydrates another.
- **The CLS Offender.** Content shifts during animation. LCP element moves after first paint.
- **The Keyboard Trap.** Focus disappears during animation. Tab order breaks.
- **The Reduced-Motion Lie.** `@media (prefers-reduced-motion: reduce)` does nothing.
- **The Distraction Stack.** Three animations trigger when the user just wanted to read.
- **The Bundle Bloat.** 5 animation libraries on one page. 200KB of JS to animate a 3KB hero.
- **The Snowflake Section.** One section uses a unique motion language nobody else speaks.

---

## 12. When the answer is no animation

Sometimes the correct motion design decision is **static**.

Skip animation when:
- The page is content-heavy (long-form article, documentation, dashboard, settings page).
- The user is mid-task (checkout, form filling, search, login).
- The animation would compete with the primary action.
- Performance budget is exhausted by other priorities.
- The animation cannot be reduced gracefully for `prefers-reduced-motion`.
- The page has no narrative — it's a list, a reference, a utility.

A static page with strong typography and hierarchy beats an over-animated page every time.

**The test:** If you removed every animation from this page, would the user's experience worsen?

If the answer is "no" or "only slightly" — the animation is decorative. Cut it.

---

## 13. Anti-ego rule

You will be tempted to demonstrate technical capability. Resist every time.

- "Look, I made a 3D particle system on the marketing page" — probably wrong.
- "I added 12 different scroll-triggered animations" — definitely wrong.
- "I used three animation libraries on one section" — almost certainly wrong.
- "The hero has a custom GLSL shader" — almost certainly wrong unless the brand is a graphics company.

The motion director's job is **restraint**. When the brief says "make it more impressive," interpret it as "make it more **intentional**." Every motion must have a job. If you find yourself adding motion to prove you can animate, stop.

Re-read §1.
