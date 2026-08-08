# Stack — which library to use when

The right tool is the one that does the job with the least complexity.

Default to the simplest option. Escalate only when justified.

**Three disciplines, separated:**

- **Runtime motion** (this file) — page-level animation that runs in the browser as the user interacts. CSS, Motion, GSAP, Rive, Lottie, R3F.
- **Cinematic motion** — pre-rendered video that plays back, doesn't respond to user input. Remotion, After Effects + Lottie, plain video.
- **Generated video** — AI-generated video from text/image prompts. fal (Veo 3.1), WaveSpeed (Kling, Seedance, HappyHorse), HeyGen. Route it through `content`, not this guide.

These have different stacks, different QA, different costs. Don't conflate.

**Producer/reviewer split:** this file is producer library reference. For reviewer-side escalation triggers, see `tools/skills/audit-visual/references/motion-standards.md`. Both files share easing values from `principles.md` §6.

---

## Step 0a: is this even a web surface?

**This entire file assumes a browser.** If the surface is SwiftUI/AppKit (`.swift`, `NSPanel`,
`NSHostingView`) or Slint (`.slint`), stop reading and load `native.md` — there is no CSS, no DOM, no
library to choose, and the decision tree below will send you somewhere wrong. A native macOS panel in
the same repo as a Tauri app does not belong here either — resolve per surface.

A Tauri frontend IS a browser and does belong here — but read `webview.md` alongside this file. It is
WKWebView on macOS and Chromium on Windows, so a library or CSS feature that this file green-lights
can still no-op on half your users. Everything below assumes an engine you control; Tauri isn't one.

---

## Step 0: do you need a library at all?

Ask this first. Most pages don't.

**Use plain CSS when:**
- Hover states, focus rings, button feedback
- Simple fade / slide / scale on enter/exit (CSS keyframes + `animation-delay`)
- Marquees, simple loops
- Loading states (when not too complex)
- Page transitions on a single-page app (View Transitions API)

CSS handles ~60% of real-world UI motion. If you're reaching for a library reflexively, stop and ask why.

**Use a library when:**
- You need scroll-driven animation tied to scroll position (not just scroll-triggered)
- You need shared layout transitions across components
- You need timeline-based sequencing (A → B → C → D → E)
- You need physics (springs, momentum, decay)
- You need gestures (drag, swipe, pinch)
- You need 3D, WebGL, or shader effects
- You need programmatic control beyond what CSS can express

---

## The decision tree

```
Simple hover / focus / active state
│
└── CSS only. No JS.
─────────────────────────────────────

CSS keyframe animation (fade, slide, scale loop)
│
└── CSS only. No JS. Use animation-delay for stagger.
─────────────────────────────────────

Shared layout morph (one element morphs into another)
│
├── React, simple → Motion (motion/react) LayoutGroup
├── React, complex cross-tree → Motion + shared layoutId
├── Vanilla JS → GSAP Flip plugin
└── Designer-authored, no code → Rive
─────────────────────────────────────

Scroll-triggered enter/exit (animate when element enters viewport)
│
├── Simple → CSS + IntersectionObserver (or Motion whileInView)
├── Staggered list → Motion whileInView with staggerChildren
├── Pinned / scrubbed / scene-based → GSAP ScrollTrigger
└── Marketing site, mixed needs → Motion + whileInView (skip GSAP if you can)
─────────────────────────────────────

Long-form scroll storytelling (narrative tied to scroll progress)
│
├── Marketing site, simple narrative → Motion + scroll progress
├── Marketing site, complex multi-scene → GSAP ScrollTrigger (timeline + scrub)
├── Editor-driven (designer controls timeline) → Rive
└── Multi-scene with mixed 2D/3D → Motion + R3F + GSAP (each owns a scene)
─────────────────────────────────────

Physics-based motion (springs, drag, decay)
│
├── React → Motion (springs, drag, layout transitions)
├── Vanilla JS → Motion standalone or GSAP Physics2D
└── Native HTML drag → Motion's drag prop or dnd-kit
─────────────────────────────────────

Interactive 3D / WebGL
│
├── React → React Three Fiber + drei
├── Vanilla JS → Three.js
├── Designer-authored scene → Spline or Rive
└── Configurator / product viewer → R3F + drei + leva + zustand
─────────────────────────────────────

Designer-authored runtime animation (vector + state machine)
│
├── Interactive with state → Rive
├── Playback only, no interactivity → Lottie (lottie-web)
└── Simple SVG icon → Motion or CSS
─────────────────────────────────────

Video / cinematic content (not interactive)
│
├── Code-driven React composition → Remotion
├── Pre-rendered marketing video → After Effects + Lottie, or video file
└── AI avatar / presenter → HeyGen HyperFrames
─────────────────────────────────────

Particle systems, shaders, procedural visuals
│
├── React → React Three Fiber + custom shaders (GLSL)
├── Vanilla JS → Three.js + GLSL
├── Lightweight 2D particles → tsParticles or Motion path animations
└── Performance-critical → WebGL via Three.js (do not try this in CSS)
```

---

## Tool reference

### CSS (no library)

**Use when:** hover, focus, simple enter/exit, marquees, loading states.

**Don't use when:** scroll progress beyond viewport enter, shared layout, physics, gestures, anything that needs JS-driven timeline control.

**Performance:** Usually the smallest runtime path; actual layout, paint, and compositing cost depends
on the properties and target engine.

**Bundle cost:** 0KB.

**Gotchas:**
- Do not add `will-change` preemptively. Use it only for a measured promotion hitch, scope it to the
  animating element/property, and remove it afterward.
- Avoid animating `box-shadow` directly; animate an `::after` pseudo-element with `opacity` instead.
- For staggered children, prefer `animation-delay` over JS.

---

### Motion (motion.dev, formerly Framer Motion)

**Use when:** shared layout, springs, gestures, drag, scroll-linked animation, simple timelines, React micro-interactions.

**Don't use when:** complex multi-scene scrubbed storytelling (GSAP ScrollTrigger is more battle-tested here).

**Performance:** Excellent. Uses `transform` and `opacity` by default.

**Bundle cost:** Measure the pinned build. Current official guidance lists `useAnimate` mini at about
2.3KB, hybrid at about 17KB, the full `motion` component around 34KB, and `m` + `LazyMotion` under
4.6KB before feature bundles. Prefer the smallest entry that covers the interaction.

**Notable:** Has the official **AI Kit** for AI agents — https://motion.dev/docs/ai-kit. Read it before implementing.

**React-specific:** `motion/react`. The de facto standard for React animation in 2025–2026.

**Vue / Svelte:** Motion has framework-specific packages. Use them.

---

### GSAP (gsap.com)

**Use when:** long-form scroll storytelling, complex timelines, scrubbed scenes, physics, FLIP for non-React contexts, MorphSVG, SplitText.

**Don't use when:** simple hover states, basic React micro-interactions (overkill), anything that doesn't need its timeline power.

**Performance:** Good. ScrollTrigger is well-optimized. MorphSVG and SplitText are heavier.

**Bundle cost:** Measure the pinned core + exact plugins in `bundle-delta.json`; plugin combinations,
module format, and bundler tree-shaking make fixed prose estimates decay quickly.

**License:** Since April 2025, GSAP and formerly members-only plugins such as MorphSVG and SplitText
are free for commercial projects under GSAP's standard no-charge license. The license restricts
competitive no-code visual animation builders; check that clause if building an authoring product.

**Notable:** ScrollTrigger is the most reliable scrubbed-scroll library. If you need pixel-perfect scrubbed storytelling on a marketing site, GSAP wins.

---

### React Three Fiber + drei + three.js

**Use when:** interactive 3D, WebGL scenes, custom shaders, configurators, product viewers, generative visuals.

**Don't use when:** 2D UI motion, simple scroll animations (massive overkill).

**Performance:** Demanding. Mobile fallback or LOD is mandatory. Test on mid-tier Android.

**Bundle cost:**
- three.js: ~150KB
- @react-three/fiber: ~20KB
- @react-three/drei: ~50KB (tree-shake; import only what you use)

**Gotchas:**
- WebGL context loss on mobile — design for it.
- Battery drain on complex shaders.
- Design for mid-tier devices explicitly; do not assume a desktop GPU.

---

### Rive (rive.app)

**Use when:** designer-authored interactive animations with state machines. Hero scenes, mascots, interactive product demos, animated logos.

**Don't use when:** pure code-driven UI motion (you're paying for designer-authored assets you don't have), or any animation without a Rive-capable designer on the team.

**Performance:** Excellent. WASM runtime, GPU-accelerated.

**Bundle cost:** Runtime ~30KB. Asset size depends on the .riv file.

**Gotchas:**
- Requires a designer producing Rive files. Not a code-only tool.
- State machine logic must be designed deliberately — don't ship an interactive scene with no clear state transitions.

---

### Lottie (lottiefiles.com, lottie-web)

**Use when:** designer-authored playback-only animations (no interactivity). Icon animations, illustrations, marketing visuals, animated stickers.

**Don't use when:** interactive animations (use Rive instead), or animations requiring runtime decision-making.

**Performance:** Good for short, simple animations. Struggles with complex paths at 60fps on mid-tier mobile.

**Bundle cost:** Runtime ~50KB. JSON asset size variable.

**Gotchas:**
- Animations must be authored in After Effects + Bodymovin. If you don't have a designer, don't use Lottie.
- Test playback on mobile explicitly — a Lottie that runs at 60fps on desktop can drop frames on Android.

---

### Remotion (remotion.dev)

**Use when:** programmatic React video composition. Dynamic marketing videos, social media exports, data-driven video, personalized video at scale.

**Don't use when:** on-page interactive animation (Remotion renders to video, not interactive DOM).

**Performance:** Render-time only — no runtime cost on the page.

**Bundle cost:** Server-side only. Output is MP4. No runtime cost to the user.

**Gotchas:** Remotion is React-only. If your team doesn't already know React, the learning curve is steep.

---

### HeyGen HyperFrames

**Use when:** AI avatar / presenter on a landing page. Sales pages, personalized intros, explainer videos.

**Don't use when:** brand-sensitive content (avatars feel generic unless heavily styled), or when a real presenter video is available.

**Performance:** Network-bound (video streams). Use as background or side-content, not foreground.

**Bundle cost:** 0KB JS to the user (hosted video). API costs per render.

---

### Anime.js

**Use when:** lightweight timeline-based animation in vanilla JS. Smaller than GSAP for simple cases.

**Don't use when:** React (use Motion), scrubbed scroll (use GSAP ScrollTrigger).

**Performance:** Comparable to GSAP for similar tasks. Slightly better for path animations.

**Bundle cost:** ~10KB. Smaller than GSAP, MIT licensed.

**Use case:** When you want GSAP-like timelines without the GSAP bundle cost or commercial license. Particularly good for SVG path animations.

---

## Default stacks by page type

### Marketing landing page (most common)

**Default:** CSS + Motion. Total budget: ~35KB.

Escalate to GSAP ScrollTrigger only if scrubbing is required (~50KB total).

Escalate to R3F only for 3D hero (~200KB — justify it).

### Product / app UI

**Default:** CSS + Motion. Total budget: ~35KB.

No GSAP, no R3F, no Lottie. UI motion is not the place for elaborate libraries.

### Long-form storytelling site

**Default:** Motion + GSAP ScrollTrigger. Total budget: ~50–70KB.

Use Motion for component-level animations and GSAP only for scroll-driven choreography.

### 3D / configurator

**Default:** R3F + drei + three.js. Total budget: ~200KB.

Justify the bundle cost with a clear product or brand need. Mobile fallback is mandatory.

### Designer-driven marketing site (Rive author)

**Default:** CSS + Motion + Rive. Total budget: ~65KB.

Use Rive for the hero or featured scenes. Use Motion for everything else.

---

## React + Next.js specifics

For React Server Components (Next.js App Router):

- **Animation components must be client components** (`"use client"` at the top).
- **Initial animation state must be deterministic** — same on server and first client paint.
  - No `Math.random()` in initial state.
  - No `Date.now()` in initial state.
  - No `window` / `document` checks before hydration.
  - No `localStorage` reads before hydration.
- **Use `useReducedMotion()` from Motion** to respect user preference. Don't read `window.matchMedia` directly.
- **Wrap scroll listeners in client components.** Lazy-import heavy animation libs.
- **Hydration mismatches from animation are the #1 bug class.** Test the first frame on a slow 3G connection.

For Next.js specifically:
- **Don't** lazy-load Motion below the fold — it blocks first paint.
- **Do** lazy-load Three.js, GSAP MorphSVG, Rive runtime, and other heavy modules with `next/dynamic`.
- **Do** use `ssr: false` only for components that genuinely cannot render server-side (e.g., WebGL canvas, motion-heavy hero).
- **Don't** ship animation logic in Server Components — it won't run.

---

## Performance vs complexity matrix

| Need | Library | Approximate cost |
|---|---|---|
| Hover, focus, simple enter/exit | CSS | 0KB |
| React micro-interactions, shared layout | Motion | ~35KB |
| Scroll-triggered enter/exit with stagger | Motion | ~35KB |
| Scroll storytelling (scrubbed) | GSAP ScrollTrigger | ~40KB |
| Long-form scrubbed narrative | GSAP + ScrollTrigger + SplitText | ~70KB |
| Interactive 3D | R3F + drei + three | ~200KB |
| Designer-authored runtime | Rive | ~30KB + assets |
| Designer-authored playback | Lottie | ~50KB + JSON |
| AI avatar / presenter | HeyGen | 0KB (hosted video) |

If your page exceeds 100KB of animation-related JS, audit. You probably don't need everything you're loading.
