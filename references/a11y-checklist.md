# a11y lens — semantic accessibility checklist (app/web only)

The `a11y` lens covers what `audit-visual` cannot: structural/semantic accessibility that lives in the
markup, not the pixels. `audit-visual` (vision models) already catches obvious contrast and broken
states; this lens reads the JSX/HTML/template + `eslint-plugin-jsx-a11y` + the **axe-core** results from
the runtime pass. Only runs for a UI target — skip pure backend/library. Every finding cites a real
`file:line` (or a surface + axe rule id). Deterministic backers:
- **`eslint-plugin-jsx-a11y`** (static, when the project configures it).
- **axe-core in the runtime pass** — `audit-runtime.mjs` now injects axe and runs WCAG 2 A/AA per
  surface when `axe-core` is resolvable in the target (`npm i -D axe-core` enables it; `--axe <path>`
  overrides). Results land in `runtime.json` per surface (`findings[].a11y[]`) + `a11y_violations_total`,
  and surface as `a11y` findings via the runtime fold.

Both backers absent → the lens still reads the markup, but say NOT-SCANNED for the deterministic layer,
never "clean." axe finds the machine-checkable ~30-40% (missing alt/label/name, contrast, ARIA misuse);
the checklist below is the human/LLM judgment layer for the rest (focus order, keyboard traps, meaningful
names, dynamic announcements).

## What to flag

**Names & labels**
- Interactive element with no accessible name — icon-only button/link with no `aria-label`/visible text.
- Form control with no associated `<label>` (or `aria-labelledby`); placeholder used AS the label.
- Image conveying meaning with no `alt`; decorative image missing `alt=""`.

**Semantics over `div`-soup**
- `onClick` on a `<div>`/`<span>` instead of `<button>`/`<a>` (not keyboard-focusable, no role).
- Custom widget missing its role/ARIA (a fake checkbox/tab/menu without `role` + state attrs).
- Heading structure skips levels or there is no `<h1>`; landmarks (`<main>`/`<nav>`) missing.

**Keyboard & focus**
- Not reachable or operable by keyboard; `tabindex` > 0 (breaks natural order).
- Keyboard trap — focus enters a widget/modal and can't leave; modal doesn't return focus on close.
- No visible focus indicator (`outline:none` with no replacement).
- Click-only interactions (hover menus, drag) with no keyboard equivalent.

**ARIA correctness**
- ARIA attribute on the wrong role, invalid value, or `aria-hidden` on a focusable element.
- State not reflected (`aria-expanded`/`aria-checked`/`aria-selected` static while the UI changes).

**Dynamic content**
- Async updates / toasts / validation errors with no `aria-live` region — screen readers miss them.
- Error messages tied to fields only by color/position, not `aria-describedby`.

**Media & motion**
- Video/audio without captions/transcript affordance.
- Motion/animation with no `prefers-reduced-motion` respect (also a perf cue).

## Output

One finding per issue: `<a11y-class>: <what> — <fix>. [file:line]`. Prefer the native-element fix
(`<button>` over `role="button"`) over piling on ARIA — "no ARIA is better than bad ARIA." If the
target has no UI surface, the lens reports `not applicable (no UI)`, not "clean."
