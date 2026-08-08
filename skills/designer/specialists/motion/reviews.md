# Reviews — what every animation must pass

No animation ships without passing every gate below.

If a gate fails, fix it. If it can't be fixed, remove the animation.

This is a hard review, not a polite one.

**Output contract:** every motion task produces `artifacts/motion-gate.json` (schema below) consumed by `/designer` Phase 5 + `/audit-visual` motion lens. Without `verdict: pass`, the build cannot advance.

---

## Motion-gate.json schema

```json
{
  "surface": "<url or path>",
  "register": "product | showpiece",
  "motion_language": "Authority | Playfulness | Luxury | Precision | Energy | Calm | Technical | Editorial",
  "patterns_used": ["<pattern-name>", ...],
  "checks": {
    "narrative": { "status": "pass | fail | waived", "evidence": "<citation>", "waiver_reason": "..." },
    "performance": { "status": "pass | fail | waived", "evidence": "<citation>" },
    "accessibility": { "status": "pass | fail | waived", "evidence": "<citation>" },
    "technical": { "status": "pass | fail | waived", "evidence": "<citation>" },
    "design_quality": { "status": "pass | fail | waived", "evidence": "<citation>" },
    "marketing": { "status": "pass | fail | waived", "evidence": "<citation>" },
    "code_quality": { "status": "pass | fail | waived", "evidence": "<citation>" },
    "visual_consistency": { "status": "pass | fail | waived", "evidence": "<citation>" },
    "interaction_latency": { "status": "pass | fail | waived", "evidence": "<citation>" },
    "cancellation": { "status": "pass | fail | waived", "evidence": "<citation>" }
  },
  "metrics": {
    "lighthouse_perf": 0,
    "lighthouse_a11y": 0,
    "bundle_delta_kb": 0,
    "lcp_ms": 0,
    "cls": 0,
    "inp_ms": 0,
    "interaction_latency_ms": 0
  },
  "evidence_files": [
    "lighthouse.json",
    "axe.json",
    "bundle-delta.json",
    "reduced-variant.png",
    "browser-matrix/{375,414,768,1024,1440}.png"
  ],
  "verdict": "pass | fail",
  "produced_at": "ISO-8601"
}
```

`pass` requires all checks green or explicitly waived with reason. `fail` requires the build to fix and re-run.

---

## A. Narrative

The animation must serve a clear purpose.

- [ ] **Has a stated purpose.** Each animation links to information or emotion it conveys. ("This fade shows the relationship between these two sections.")
- [ ] **Supports the page narrative.** The page has a clear top-to-bottom story, and this animation is a beat in it.
- [ ] **Doesn't repeat itself.** No two animations on the page say the same thing in different ways.
- [ ] **Doesn't fight other animations.** No competing attention grabs in the same viewport.
- [ ] **Passes the register's governing test.** Product: restraint test (if removed, would the
  experience worsen?). Showpiece: choreography test (does every scene advance the one narrative,
  threaded by a persistent object?). Document the answer in the motion plan.

---

## B. Performance

Animation must not degrade the user's experience.

- [ ] **Smooth at the target refresh rate.** Test on representative low/mid-tier hardware and every supported engine. Chrome CPU/network throttling is a diagnostic proxy, not device proof.
- [ ] **No layout thrashing.** Prefer `transform` and `opacity`; any animated layout property has a semantic reason and a target-engine profile showing bounded layout/paint work.
- [ ] **Compositing is measured.** No cargo-cult `translateZ(0)`/`translate3d`. `will-change` exists only for a demonstrated promotion hitch, is narrowly scoped, and is removed afterward.
- [ ] **No CLS contribution.** Cumulative Layout Shift attributable to animation is 0. Test with Lighthouse.
- [ ] **LCP unaffected.** The Largest Contentful Paint element does not animate on first paint. If it must, the animation completes within 600ms.
- [ ] **Animation JS budget met.** Product register: under 50KB gzipped. Showpiece register:
  under 120KB gzipped, one engine family.
- [ ] **No scroll jank.** Frames stay inside the target display interval (about 16.7ms at 60Hz, 8.3ms at 120Hz); no long animation frames over 50ms.
- [ ] **Reduced-motion fallback exists.** `prefers-reduced-motion: reduce` either removes the animation or substitutes a 100–200ms opacity fade. Test it explicitly with the OS setting toggled.
- [ ] **No memory leaks.** Event listeners cleaned up on unmount. Three.js scenes dispose GPU buffers. Rive instances destroyed correctly.
- [ ] **Bundle size delta measured.** Animation adds < 50KB gzipped. Report the exact number in the PR.

---

## C. Accessibility

Animation must not exclude users.

- [ ] **`prefers-reduced-motion` honored.** Every animation has a reduced or removed variant. Verified with the OS-level setting toggled on.
- [ ] **Keyboard navigation preserved.** All interactive elements reachable via Tab in logical order, even mid-animation.
- [ ] **No focus loss.** Focus remains on the active element during transitions. Don't move focus unless the user requested it.
- [ ] **Screen reader compatibility.** Content is announced correctly before, during, and after animation. Use ARIA live regions for dynamic content that changes meaningfully.
- [ ] **Color contrast not reduced.** Animation does not dim text below WCAG AA contrast (4.5:1 for body, 3:1 for large).
- [ ] **No vestibular triggers.** Avoid large-scale background parallax, auto-playing zoom animations, or strobing effects. Reduced-motion fallback is mandatory here.
- [ ] **Pause controls for loops.** Any animation longer than 5 seconds and auto-playing must have a pause button. (This applies to loops like marquees and ambient backgrounds, not loaders.)
- [ ] **Tested with VoiceOver / NVDA.** At least one screen reader pass for any animation that affects content visibility or order.

---

## D. Technical correctness

Animation must work in the real world.

- [ ] **No hydration mismatches.** Server-rendered first frame matches client first frame exactly. Test with React StrictMode and a slow connection.
- [ ] **Works on Safari iOS.** Tested on a real iPhone (not just simulator). WebGL, scroll, and shared layout are the common failure modes.
- [ ] **Works on mid-tier Android.** Tested on a 2020-era Android device (or DevTools 4x CPU throttling as proxy).
- [ ] **Works with browser extensions.** Ad blockers, dark mode extensions, password managers don't break the animation.
- [ ] **Works without JS** (where possible). Page content is readable with JS disabled. Animation is enhancement, not requirement.
- [ ] **Works on slow networks.** Initial animation setup doesn't require loading > 200KB before first paint. Lazy-load heavy animation modules.
- [ ] **Frame budget met.** Each frame fits the actual target refresh interval on representative hardware; profile rather than assuming a universal 16ms budget.
- [ ] **State machine is correct.** If using Rive or a custom state machine, all states are reachable, no dead transitions, exit conditions clear.
- [ ] **Cleanup verified.** Open and close a modal 50 times — no detached listeners, no memory growth.
- [ ] **No console errors or warnings** during animation lifecycle.
- [ ] **SSR-safe.** For Next.js / SSR frameworks: no `window` or `document` references before mount; initial state deterministic.

---

## E. Design quality

Animation must meet the bar.

- [ ] **Restrained (product register).** Could you remove this animation without losing meaning? If yes, remove it. (Showpiece register: replaced by the choreography test in section A.)
- [ ] **Consistent language.** Easing, duration, and motion style match across the page. No random easings.
- [ ] **Hierarchy respected.** The most important motion is the most prominent. Secondary motion is quieter.
- [ ] **Easing is correct.** Entrance uses ease-out. Exit uses ease-in. Reversible motion uses ease-in-out. No `linear` for UI motion. (See `principles.md` §5.)
- [ ] **Timing is correct.** Per `principles.md` §4. Hover ≤ 200ms. Click ≤ 150ms. Page enter ≤ 600ms.
- [ ] **Persistent objects honored.** If a persistent object is part of the plan, it persists across sections as specified.
- [ ] **No gratuitous effects (product register).** No particle systems, no glow, no 3D, no parallax unless the brief explicitly demands it. (Showpiece register: effects are allowed but each must belong to a declared scene in the motion plan — an effect with no scene is the finding.)
- [ ] **Stack discipline.** One primary animation library per page. Per-scene tool choice is fine; per-element library mixing is not.

---

## F. Marketing / business

Animation must serve the goal.

- [ ] **Conversion path is unblocked.** User can reach the primary CTA without waiting for animation to complete.
- [ ] **Time-to-CTA is acceptable.** For hero sections, the value prop is visible within **1 second**. CTA is reachable within **1.5 seconds**.
- [ ] **SEO preserved.** Critical content is in the initial HTML, not loaded via JS. Crawlers see the page without animation.
- [ ] **Analytics fire correctly.** Conversion events fire even when animations are reduced or skipped.
- [ ] **A/B testable.** Animation variants can be toggled without rebuilding.

---

## G. Code quality

Animation code must be maintainable.

- [ ] **Animation logic is separated.** Motion code lives in dedicated components or hooks, not scattered through business logic.
- [ ] **No magic numbers without context.** Timing values reference a shared constants file or token system.
- [ ] **Type-safe (where applicable).** TypeScript types for animation variants, easing curves, and state machine inputs.
- [ ] **Documented.** Each animation has a one-line comment explaining its purpose.
- [ ] **No dead code.** Removed animations are removed from the codebase, not commented out.
- [ ] **Reusable primitives.** Common animations (fade-in, scale-up) are abstracted into shared components, not copy-pasted.

---

## H. Final pre-ship checks

- [ ] **Tested on real devices:**
  - iPhone (Safari) — current or previous generation
  - Android (Chrome) — mid-tier device, not flagship
  - Desktop Chrome
  - Desktop Safari
  - Desktop Firefox (only for major animations)
- [ ] **Tested with reduced motion enabled.**
- [ ] **Tested with slow CPU throttling (4x).**
- [ ] **Tested with slow network (Fast 3G).**
- [ ] **Lighthouse score reviewed.** Performance ≥ 90. Accessibility = 100. Best Practices ≥ 95.
- [ ] **Bundle size delta measured and reported.**
- [ ] **No console errors or warnings** during animation lifecycle.
- [ ] **PR description includes motion plan and review checklist results.**

---

## Review outcome

Every PR with animation must include this section in the description:

```markdown
## Motion Plan
[Brief summary of narrative, persistent objects, key timings, libraries chosen]

## Review Checklist
- [x] Narrative serves purpose
- [x] Performance budget met
- [x] Accessibility verified
- [x] Technical correctness verified
- [x] Design quality meets bar
- [x] Marketing goal supported
- [x] Code quality acceptable
- [x] Final pre-ship checks passed

## Performance Measurements
- Bundle delta: XX KB gzipped
- LCP: X.Xs
- CLS: 0.0XX
- FPS during scroll: 60 maintained on [device]
- Reduced motion tested: yes

## Test Matrix
- iPhone 13 Safari: ✓
- Pixel 6 Chrome: ✓
- Desktop Chrome: ✓
- Desktop Safari: ✓
- Reduced motion: ✓
```

If any box is unchecked, the PR is not ready.

If a box is checked but the reviewer disagrees, the PR is not ready.

If the reviewer can't tell whether a box should be checked, the PR is not ready.
