# State Patterns

UI state transitions. The category most used in app UI.

**Default motion language fit:** Precision, Calm, Editorial.

---

## modal-open

**Use when:** a modal dialog appears. Center-screen overlay, focus-trapped.

**Avoid when:** the modal is for a destructive action with no confirmation (the motion makes it feel lighter than it is).

**Defaults:**
- Duration: 200-300ms
- Easing: strong ease-out (or spring for "alive" feel)
- Scale: 0.95 → 1
- Origin: center (modals are exempt from the trigger-anchored origin rule)
- Backdrop: opacity 0 → 1 in parallel
- Opacity: 0 → 1

**Reduced motion:** instant appear, no scale.

**Performance:** GPU-only. Lock body scroll while open. Trap focus.

---

## drawer-slide

**Use when:** a side panel slides in. Right-side settings, left-side nav, bottom sheet on mobile.

**Avoid when:** the content is critical and not also accessible from elsewhere (drawers hide things).

**Defaults:**
- Duration: 250-400ms
- Easing: ease-in-out (reversible)
- Direction: from the side (right, left, bottom)
- Distance: full width (or 80% for mobile bottom sheet)
- Backdrop: optional, opacity 0 → 0.5 in parallel

**Reduced motion:** instant slide, no animation.

**Performance:** GPU-only via `transform: translateX()`. Lock body scroll while open.

---

## toggle-flip

**Use when:** a toggle switch changes state. On/off, dark/light, enabled/disabled.

**Avoid when:** the toggle's new state isn't immediately clear (animate the indicator AND the background).

**Defaults:**
- Duration: 150-200ms
- Easing: strong ease-out (forward) / ease-in (reverse)
- Property: indicator position (translateX) + background color crossfade
- Implementation: shared layout (Motion `layoutId`) or two-state animation

**Reduced motion:** instant flip, no animation.

**Performance:** GPU-only. Cheap.

---

## popover-origin

**Use when:** a popover, dropdown, or tooltip appears anchored to its trigger. Right-click menus, autocomplete suggestions, filter dropdowns.

**Avoid when:** the popover is the entire content area (use modal). When the trigger-anchor relationship is unclear.

**Defaults:**
- Duration: 150-250ms
- Easing: strong ease-out
- Scale: 0.95 → 1
- Origin: trigger element (NOT center) — `transform-origin: var(--trigger-x) var(--trigger-y)` or equivalent
- Distance: 4-8px from trigger
- Opacity: 0 → 1

**Reduced motion:** instant appear.

**Performance:** GPU-only. Calculate trigger-anchored origin in JS or via CSS custom property from the trigger.

---

## toast-slide

**Use when:** a notification slides in. Success, error, info messages.

**Avoid when:** the toast is for a critical action the user must act on (use modal). When toasts stack and compete for attention.

**Defaults:**
- Duration: 200-300ms
- Easing: strong ease-out (in) / ease-in (out)
- Direction: from edge (top-right, bottom-center)
- Distance: 16-32px (md or lg token)
- Auto-dismiss: 3-5 seconds; manual dismiss always available
- Pause on hover: yes (user might be reading)

**Reduced motion:** slide becomes fade.

**Performance:** GPU-only. Manage stacking carefully — multiple toasts in flight can drop frames.

---

## Canonical code

```tsx
// modal-open — Motion; backdrop + panel in parallel, centered origin (modals are exempt)
<AnimatePresence>
  {open && (
    <>
      <motion.div className="fixed inset-0 bg-black/50" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} />
      <motion.div role="dialog" aria-modal className="fixed inset-0 m-auto h-fit w-fit"
        initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.97 }}
        transition={{ duration: 0.25, ease: [0.23, 1, 0.32, 1] }} />
    </>
  )}
</AnimatePresence>
```

```css
/* popover-origin — scale from the trigger (Radix/Base UI custom property) */
.popover { transform-origin: var(--radix-popover-content-transform-origin, var(--transform-origin));
  animation: pop 0.18s cubic-bezier(0.23, 1, 0.32, 1); }
@keyframes pop { from { opacity: 0; transform: scale(0.95); } }

/* toast-slide — @starting-style entry, transition (not keyframes) so stacking retargets */
.toast { opacity: 1; transform: translateY(0);
  transition: opacity 0.4s ease, transform 0.4s cubic-bezier(0.32, 0.72, 0, 1);
  @starting-style { opacity: 0; transform: translateY(100%); } }

/* drawer-slide — iOS-like curve, reversible */
.drawer { transform: translateX(100%); transition: transform 0.35s cubic-bezier(0.32, 0.72, 0, 1); }
.drawer[data-open] { transform: translateX(0); }

@media (prefers-reduced-motion: reduce) {
  .popover { animation: fade 0.12s ease; } .toast, .drawer { transition: opacity 0.15s ease; transform: none; }
  @keyframes fade { from { opacity: 0; } }
}
```
