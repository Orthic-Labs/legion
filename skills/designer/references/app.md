# App-UI surface — gates and tests (absorbs the retired /app skill)

Product/application UI: desktop apps, SaaS dashboards, tools, editors, inboxes, queues, settings,
forms, data tables, workflows, modals, stateful repeated-use screens. Design SERVES the product —
weight task clarity, repetition efficiency, and state completeness over first-impression drama.
Avoid marketing heroes inside app UIs.

## Phase 0a — Toolkit (resolve first, it changes the mechanics)

The phases below are toolkit-agnostic (task truth, IA, states, density, keyboard model all hold
everywhere). The *implementation* is not. Resolve which one you are in before writing code:

| Evidence | Toolkit | Design reference | Motion + geometry |
|---|---|---|---|
| `.tsx`/`.vue`/`.html`, browser target | web | this file | `motion/stack.md` |
| `src-tauri/` + React/Qwik/Vue frontend | embedded WebView | this file + **`native-app.md` §7** | `motion/stack.md` + **`motion/webview.md`** |
| `.swift`, `NSPanel`/`NSHostingView`, `.xcodeproj` | SwiftUI + AppKit | **`native-app.md` §1–§5** | **`motion/native.md` §1–§4** |
| `.slint` markup + Rust/C++/JS host | Slint | **`native-app.md` §6** | **`motion/native.md` §5** |

`native-app.md` covers what changes without a DOM: macOS container vocabulary (window vs sheet vs
panel vs popover vs inspector), Liquid Glass and `NSVisualEffectView` materials, semantic-vs-brand
colour, the system-face-in-chrome typography rule, Slint's missing control layer, and Tauri shell
chrome.

For native toolkits, `motion/native.md` §0 is mandatory reading before ANY animated window, panel,
sheet, HUD, or palette work: it owns the single-animation-owner rule, presentation-vs-model geometry,
anchor preservation, and the ban on resizing a window after its visual transition has settled. Native
surfaces also skip the web-only checks (CLS, hydration, bundle budget) and use `native.md` §4 instead.
Tauri is a browser, so those checks DO apply there — but per-OS engine differences do too.

## Phase 0 — Task truth

> "This app helps [user] complete [repeated task] by [core interaction], and the interface must
> make [state/decision] obvious."

## Phase 1 — Workspace signature (HARD GATE)

Invent a product-specific interaction mechanism for the app surface. It must pass:

- **Task-truth:** based on the real task, not decoration.
- **Non-transplant:** cannot be pasted onto a different app and still be true.
- **Stateful:** shows data, progress, selection, processing, result, or decision state.
- **Efficient:** helps repeated use.
- **Nameable:** can be described concretely.

Categories (not menus): triage deck, command strip, timeline spine, inspector rail, queue ledger,
split compare, review bench.

## Phase 2 — Information architecture (HARD GATE)

Define before styling: primary routes/views, navigation model, main work surface, secondary
panels/inspectors, data density, empty/loading/error/success/disabled/selected/hover/focus states,
keyboard and mouse workflows, permissions/auth/settings surfaces. **Fail if the UI only designs the
happy path.**

## Phase 3 — Three UI registers (major work; then PARK)

Present three distinct registers using the same workspace signature — pick from: operational/dense,
calm/editorial, technical/console, swiss/utilitarian, visual/creative, assistant-led. Each includes
type, color, density, layout, motion, states, risks, and best fit. Registers must differ in
base/accent/density, not just type — the shared Option Divergence Gate (SKILL.md) applies; run the
App Color Gate independently per register.

## App color gate

App color must improve repeated use. It is not a brand poster. Define before styling:

- **Base environment:** light, dark, neutral, paper, high-contrast, or dense utility — chosen for
  the task and fatigue profile. Dark vs light is never a default; write one sentence of physical
  scene (who uses this, where, under what light, in what mood) until the answer is forced.
- **Semantic roles:** primary action, secondary action, selection, focus, hover, disabled, error,
  warning, success, loading, data/category, unread/new, risky/destructive, proof/verified.
- **Accent behavior:** where strong color appears, what it means, when it is withheld.
- **Sibling/category differentiation:** what prevents generic-SaaS-dashboard or sibling lookalike.

Pass requires: no default pale blue / SaaS blue / purple-blue gradients / mood-only palettes unless
product-truth demands them; tinted neutrals over plain gray; vivid accents carry state, command,
proof, urgency, or selection — never decoration; repeated controls keep stable dimensions across
color/state changes; color never the only state indicator; all text and control states (incl.
disabled, hover, selected, error) meet accessible contrast.

## Phase 4 — Build with domain-appropriate controls

Icons for common tool actions · tables/lists for scan/comparison · segmented controls for modes ·
toggles/checkboxes for binary settings · sliders/inputs/steppers for numerics · menus for option
sets · tabs only for sibling views · stable dimensions for repeated controls.
`references/design-reference-library.md` is taste calibration only.

## Phase 5 — State and interaction QA (HARD STOP until all exist)

- Loading state
- Empty state
- Error state with recovery
- Success/completed state
- Disabled state
- Focus state
- Hover/press state
- Selected/active state
- Long-content behavior
- Offline/auth failure behavior where relevant
- Keyboard path for repeated workflows
- Identity/model labels come from live state or an explicit neutral fallback; no developer names,
  stale model aliases, or fabricated account labels appear in rendered screenshots.
- Global status is internally consistent: a connected/healthy indicator cannot present a failed
  headline, and every failure names the failed subsystem plus a recovery action.
- Brand accent is visibly present on command, selection, and focus states in both themes; semantic
  success color is not used as a substitute for product identity.
- Advanced operational controls use progressive disclosure; the default pane is a task-oriented
  summary, not a permanent wall of raw inputs.

Use `/qa` for hidden/background QA (project `qa:browser` contract, `qa-functional.mjs` for
hover/click/type/key/assert, `qa-shot.mjs` for app-viewport screenshots). No foreground native
windows or desktop screenshots by default.

## Phase 6 — audit-visual gate

Run `/audit-visual` with app context: repeated-use product surface, so weight action count, task
clarity, keyboard/focus, state completeness, and micro-interaction fidelity more heavily than
first-impression drama.
