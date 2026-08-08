# Interaction Design

## The Eight Interactive States

Every interactive element needs these states designed:

| State | When | Visual Treatment |
|-------|------|------------------|
| **Default** | At rest | Base styling |
| **Hover** | Pointer over (not touch) | Subtle lift, color shift |
| **Focus** | Keyboard/programmatic focus | Visible ring (see below) |
| **Active** | Being pressed | Pressed in, darker |
| **Disabled** | Not interactive | Reduced opacity, no pointer |
| **Loading** | Processing | Spinner, skeleton |
| **Error** | Invalid state | Red border, icon, message |
| **Success** | Completed | Green check, confirmation |

**The common miss**: Designing hover without focus, or vice versa. They're different. Keyboard users never see hover states.

## Focus Rings: Do Them Right

**Never `outline: none` without replacement.** It's an accessibility violation. Instead, use `:focus-visible` to show focus only for keyboard users:

```css
/* Hide focus ring for mouse/touch */
button:focus {
  outline: none;
}

/* Show focus ring for keyboard */
button:focus-visible {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}
```

**Focus ring design**:
- High contrast (3:1 minimum against adjacent colors)
- 2-3px thick
- Offset from element (not inside it)
- Consistent across all interactive elements

## Form Design: The Non-Obvious

**Placeholders aren't labels.** They disappear on input. Always use visible `<label>` elements. **Validate on blur**, not on every keystroke (exception: password strength). Place errors **below** fields with `aria-describedby` connecting them.

## Loading States

**Optimistic updates**: Show success immediately, rollback on failure. Use for low-stakes actions (likes, follows), not payments or destructive actions. **Skeleton screens > spinners**: they preview content shape and feel faster than generic spinners.

## Modals: The Inert Approach

Focus trapping in modals used to require complex JavaScript. Now use the `inert` attribute:

```html
<!-- When modal is open -->
<main inert>
  <!-- Content behind modal can't be focused or clicked -->
</main>
<dialog open>
  <h2>Modal Title</h2>
  <!-- Focus stays inside modal -->
</dialog>
```

Or use the native `<dialog>` element:

```javascript
const dialog = document.querySelector('dialog');
dialog.showModal();  // Opens with focus trap, closes on Escape
```

## The Popover API

For tooltips, dropdowns, and non-modal overlays, use native popovers:

```html
<button popovertarget="menu">Open menu</button>
<div id="menu" popover>
  <button>Option 1</button>
  <button>Option 2</button>
</div>
```

**Benefits**: Light-dismiss (click outside closes), proper stacking, no z-index wars, accessible by default.

## Dropdown & Overlay Positioning

Dropdowns rendered with `position: absolute` inside a container that has `overflow: hidden` or `overflow: auto` will be clipped. This is the single most common dropdown bug in generated code.

### CSS Anchor Positioning

The modern solution uses the CSS Anchor Positioning API to forge an overlay to its trigger without JavaScript:

```css
.trigger {
  anchor-name: --menu-trigger;
}

.dropdown {
  position: fixed;
  position-anchor: --menu-trigger;
  position-area: block-end span-inline-end;
  margin-top: 4px;
}

/* Flip above if no room below */
@position-try --flip-above {
  position-area: block-start span-inline-end;
  margin-bottom: 4px;
}
```

Because the dropdown uses `position: fixed`, it escapes any `overflow` clipping on ancestor elements. The `@position-try` block handles viewport edges automatically. **Browser support**: Chrome 125+, Edge 125+. Not yet in Firefox or Safari - use a fallback for those browsers.

### Popover + Anchor Combo

Combining the Popover API with anchor positioning gives you stacking, light-dismiss, accessibility, and correct positioning in one pattern:

```html
<button popovertarget="menu" class="trigger">Open</button>
<div id="menu" popover class="dropdown">
  <button>Option 1</button>
  <button>Option 2</button>
</div>
```

The `popover` attribute places the element in the **top layer**, which sits above all other content regardless of z-index or overflow. No portal needed.

### Portal / Teleport Pattern

In component frameworks, render the dropdown at the document root and position it with JavaScript:

- **React**: `createPortal(dropdown, document.body)`
- **Vue**: `<Teleport to="body">`
- **Svelte**: Use a portal library or mount to `document.body`

Calculate position from the trigger's `getBoundingClientRect()`, then apply `position: fixed` with `top` and `left` values. Recalculate on scroll and resize.

### Fixed Positioning Fallback

For browsers without anchor positioning support, `position: fixed` with manual coordinates avoids overflow clipping:

```css
.dropdown {
  position: fixed;
  /* top/left set via JS from trigger's getBoundingClientRect() */
}
```

Check viewport boundaries before rendering. If the dropdown would overflow the bottom edge, flip it above the trigger. If it would overflow the right edge, align it to the trigger's right side instead.

## Destructive Actions: Undo > Confirm

**Undo is better than confirmation dialogs.** Users click through confirmations mindlessly. Remove from UI immediately, show undo toast, actually delete after toast expires. Use confirmation only for truly irreversible actions (account deletion), high-cost actions, or batch operations.

## Keyboard Navigation Patterns

### Roving Tabindex

For component groups (tabs, menu items, radio groups), one item is tabbable; arrow keys move within:

```html
<div role="tablist">
  <button role="tab" tabindex="0">Tab 1</button>
  <button role="tab" tabindex="-1">Tab 2</button>
  <button role="tab" tabindex="-1">Tab 3</button>
</div>
```

Arrow keys move `tabindex="0"` between items. Tab moves to the next component entirely.

### Skip Links

Provide skip links (`<a href="#main-content">Skip to main content</a>`) for keyboard users to jump past navigation. Hide off-screen, show on focus.

## Gesture Discoverability

Swipe-to-delete and similar gestures are invisible. Hint at their existence:

- **Partially reveal**: Show delete button peeking from edge
- **Onboarding**: Coach marks on first use
- **Alternative**: Always provide a visible fallback (menu with "Delete")

Don't rely on gestures as the only way to perform actions.

---

**Avoid**: Removing focus indicators without alternatives. Using placeholder text as labels. Touch targets <44x44px (see the native note below — macOS is the deliberate exception). Generic error messages. Custom controls without ARIA/keyboard support.

---

## Native apps (desktop + mobile)

Everything above is the **web** interaction bar. Desktop and mobile apps add a feedback layer the
web has no equivalent for — haptics, OS-level reduced-motion settings, and per-platform control
minimums that genuinely conflict with each other.

Canonical values live in **`audit-visual/references/native-feedback.md`**. Build to it rather than
duplicating numbers here, so the builder side and the review side never drift apart.

The four things that most often get built wrong:

1. **Haptics are semantic, not decorative.** `UINotificationFeedbackGenerator` means an outcome
   (success/warning/error), `UISelectionFeedbackGenerator` means movement through discrete values,
   impact means a collision. Reusing one to mean something else is a documented Apple anti-pattern.
   In SwiftUI prefer `.sensoryFeedback(_:trigger:)` (iOS 17+; `.pathComplete` is 17.5+).
2. **Spinners below 1 second make things feel slower.** The thresholds are 0.1 s (result only),
   1 s (no spinner needed), 10 s (progress + cancel required). Measure before adding a loading state.
3. **Reduced motion is three different APIs** — `UIAccessibility.isReduceMotionEnabled` on iOS,
   `NSWorkspace.accessibilityDisplayShouldReduceMotion` on macOS, and a registry bitmask on Windows
   that a Tauri app usually reaches only through `prefers-reduced-motion` in its WebView. Honouring
   it on one OS does not honour it on the other. Substitute fades for x/y/z movement; tighten
   springs rather than deleting them.
4. **44 pt is iOS's default, not a universal floor.** macOS defaults to 28 × 28 pt (min 20 × 20) and
   44 pt controls look oversized against system chrome. visionOS wants 60 × 60. WCAG 2.2 AA's floor
   is only 24 × 24 CSS px — that is a compliance minimum, never a design target.
