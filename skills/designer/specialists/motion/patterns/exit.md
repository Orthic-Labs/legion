# Exit Patterns

Elements leaving. Often paired with the inverse entrance pattern (slide-up enters, slide-down-exit leaves).

**Default motion language fit:** all languages (exit should match entrance's register).

---

## fade-out

**Use when:** a single element disappears without movement. Closing a modal, dismissing a toast, hiding content.

**Avoid when:** the element should suggest motion away (use slide instead).

**Defaults:**
- Duration: 150-200ms (shorter than entrance — exits feel faster)
- Easing: ease-in `(0.64, 0, 0.78, 0)` — symmetric to ease-out entrance
- Distance: 0
- Opacity: 1 → 0

**Reduced motion:** skip or 80ms opacity fade.

**Performance:** minimal. GPU-only.

---

## slide-down-exit

**Use when:** an element that entered from below should leave downward. Toasts, dropdowns, content sections.

**Avoid when:** the spatial context is ambiguous (use fade-out).

**Defaults:**
- Duration: 150-200ms (shorter than entrance)
- Easing: ease-in
- Distance: 8-16px (mirror the entrance)
- Opacity: 1 → 0

**Reduced motion:** skip translation, keep 100ms opacity fade.

**Performance:** GPU-only. Safe.

---

## scale-down

**Use when:** a popover, modal, or button closes by shrinking back. Mirrors scale-up entrance.

**Avoid when:** scaling to `scale(0)` — stop at `scale(0.95)`.

**Defaults:**
- Duration: 150-200ms
- Easing: ease-in
- Scale: 1 → 0.95
- Origin: element center (or trigger anchor)
- Opacity: 1 → 0

**Reduced motion:** skip scale, keep 100ms opacity fade.

**Performance:** GPU-only. Safe.

---

## mask-collapse

**Use when:** an image or visual that revealed via mask-reveal should close the same way. Symmetric with mask-reveal.

**Avoid when:** exit should be quick — mask-collapse can feel slow.

**Defaults:**
- Duration: 300-500ms (faster than reveal)
- Easing: ease-in
- Mask direction: reverse of entrance (bottom-to-top if entrance was top-to-bottom)

**Reduced motion:** skip mask, fade out over 150ms.

**Performance:** same as mask-reveal. Test on mid-tier mobile.

---

## Canonical code

```tsx
// Motion — enter/exit pair; exits shorter + ease-in, enters longer + ease-out
<AnimatePresence initial={false}>
  {open && (
    <motion.div
      initial={{ opacity: 0, y: 12, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1, transition: { duration: 0.3, ease: [0.23, 1, 0.32, 1] } }}
      exit={{ opacity: 0, y: 8, scale: 0.97, transition: { duration: 0.16, ease: [0.64, 0, 0.78, 0] } }}
    />
  )}
</AnimatePresence>
```

```css
/* CSS — interruptible exit via transition (not keyframes), driven by a data attribute */
.item { opacity: 1; transform: translateY(0); transition: opacity 0.18s cubic-bezier(0.64, 0, 0.78, 0), transform 0.18s cubic-bezier(0.64, 0, 0.78, 0); }
.item[data-leaving] { opacity: 0; transform: translateY(8px); }
@media (prefers-reduced-motion: reduce) { .item { transition: opacity 0.1s ease; transform: none !important; } }
```
