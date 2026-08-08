# Finding Animation Opportunities

Absorbs Emil Kowalski's `find-animation-opportunities` skill. Use when the ask is **"what could be
animated here?" / "make this feel more alive"** on an existing surface. Read-only: it proposes
motion with exact values; implementation goes through the normal workflow (SKILL.md steps 5-8).

Posture: a filter as much as a finder. Expect to reject most candidates. A short high-conviction
list beats a wishlist. Cap output at 5-7 suggestions for a whole app, fewer for one view. "Nothing
worth adding" is a valid, good result.

## The gate (all four, in order — record answers)

1. **Frequency** — table in `tools/skills/audit-visual/references/motion-standards.md` §"Should it animate?".
   Keyboard-initiated actions are a hard disqualifier, not a judgment call.
2. **Purpose** — must be one of: feedback, spatial consistency, state indication, preventing a
   jarring change, explanation (marketing/onboarding only), delight (rare-tier only). "Looks cool"
   is not on the list.
3. **Speed** — must fit the duration budgets (UI < 300ms; values in motion-standards.md).
4. **Function** — decoration on functional, information-dense UI hinders. Data the user is reading
   or acting on does not move for style.

## Where to hunt (each seam class: find candidates or explicitly clear it)

- **Feedback gaps** — pressables with no `:active` state → `scale(0.97)`, `transform 160ms ease-out`;
  destructive plain-click confirms → hold-to-confirm `clip-path` fill (2s linear press, 200ms ease-out release).
- **Teleporting state** — conditional renders, route swaps, accordions, list add/remove with no
  bridge → fade/scale from `0.95-0.97`+`opacity:0`, `@starting-style` entries, height+opacity collapses.
- **Missing spatial story** — panels/popovers/menus with no connection to their trigger →
  trigger-anchored `transform-origin`; toasts/sheets exiting a different way than they entered → symmetric paths.
- **Group entrances** — occasional-tier grids popping in all at once → 30-80ms stagger (never blocking input).
- **Gesture seams** — drags/swipes that snap with no physics → springs, velocity dismissal,
  rubber-banding (all values in `fluid.md`).
- **The delight budget** — rare high-emotion moments rendered flat (first-run, empty, success).
  The only tier where bounce and generous stagger are welcome.

Grep sweeps: `{isOpen &&`-style conditional renders with no transition, `onClick` elements without
`:active`/transition styles, accordion markup, drag handlers, `.map(` entering lists, empty-state
and success components.

## Output format

1. **Opportunities table** — `# | location (file:line) | today | purpose | frequency | suggested
   motion` — every suggestion carries exact values (curve, duration, properties) from
   motion-standards.md tokens, plus reduced-motion and hover gating where relevant.
2. **Rejected candidates (REQUIRED, 2-5)** — each with the gate question that killed it. This
   section is what separates the skill from a wishlist.
3. **Verdict** — one paragraph: how much motion this surface actually needs and the single
   highest-leverage suggestion.
