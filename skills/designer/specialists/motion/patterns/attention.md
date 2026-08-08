# Attention Patterns

Drawing focus. Use sparingly — attention is a budget.

**Default motion language fit:** Playfulness, Energy (rarely Precision or Calm).

---

## pulse

**Use when:** an element needs to suggest "live" or "active" without strong motion. Status indicators, live badges, recording dots.

**Avoid when:** the element is decorative (no semantic purpose). When the user is mid-task (constant pulse is distracting).

**Defaults:**
- Duration: 1000-2000ms per cycle
- Easing: ease-in-out (symmetric)
- Scale: 1 → 1.05 → 1 (subtle)
- Opacity: optional, 1 → 0.7 → 1
- Repeat: infinite (with semantic justification)

**Reduced motion:** static; no pulse.

**Performance:** GPU-only. Cheap.

---

## glow

**Use when:** an element needs to feel "lit" or "active". CTAs in their hover/active state, focused inputs, highlighted options.

**Avoid when:** multiple elements glow at once (competing for attention). When the brand voice is restraint-first (glowing everything dilutes the signal).

**Defaults:**
- Duration: 200-400ms
- Easing: strong ease-out
- Property: `box-shadow` (animate `::after` `opacity` instead for performance) or filter glow
- Intensity: subtle (4-12px blur, 0.3-0.6 opacity)

**Reduced motion:** static glow (no animation, just a steady state).

**Performance:** `box-shadow` animation is expensive. Animate `::after` with `opacity` or `filter` instead.

---

## count-up

**Use when:** a number needs to animate from 0 to its final value. Stats, metrics, financial data, prices.

**Avoid when:** the value is already visible and meaningful (don't animate just to animate). When the count-up is so slow it competes with reading.

**Defaults:**
- Duration: 800-1500ms
- Easing: ease-out (the count-up should decelerate at the end)
- Trigger: when the number enters the viewport
- Format: same format throughout (commas, decimals, currency)

**Reduced motion:** show the final value with no animation.

**Performance:** minimal. Triggers rAF-based number updates; verify no main-thread impact.

---

## badge-ping

**Use when:** a notification badge or indicator needs to call attention. New message dot, unread count, status update.

**Avoid when:** the badge is always-on (constant ping is annoying). When the user is mid-task.

**Defaults:**
- Duration: 1500-2500ms per cycle
- Easing: ease-out
- Scale: 1 → 1.5 (the ping ring grows)
- Opacity: 0.6 → 0 (the ping fades)
- Repeat: 2-3 times, then static

**Reduced motion:** static badge, no ping.

**Performance:** GPU-only. Use `::after` pseudo-element for the ping ring.

---

## Canonical code

```css
/* pulse — live/recording indicator */
.pulse { animation: pulse 1.6s ease-in-out infinite; }
@keyframes pulse { 50% { transform: scale(1.05); opacity: 0.7; } }

/* badge-ping — ring grows and fades, 3 cycles then static */
.badge::after { content: ''; position: absolute; inset: 0; border-radius: inherit;
  background: var(--accent); animation: ping 1.8s cubic-bezier(0.23, 1, 0.32, 1) 3; }
@keyframes ping { from { transform: scale(1); opacity: 0.6; } to { transform: scale(1.5); opacity: 0; } }

/* glow — animate ::after opacity, never box-shadow directly */
.cta::after { content: ''; position: absolute; inset: -2px; border-radius: inherit; z-index: -1;
  background: var(--accent); filter: blur(10px); opacity: 0; transition: opacity 0.3s cubic-bezier(0.23, 1, 0.32, 1); }
.cta:hover::after { opacity: 0.45; }

@media (prefers-reduced-motion: reduce) { .pulse, .badge::after { animation: none; } }
```

count-up: rAF + ease-out-cubic implementation in `designer/references/components/social-proof.md` (CountUp).
