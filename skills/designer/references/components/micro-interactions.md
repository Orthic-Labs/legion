# micro-interactions

**Intent:** the small physics that make a surface feel built — magnetic CTA, tilt card, press
compress, hover underline. Use 2-3 per site, consistently; never all at once.
**Register:** both (magnetic/tilt lean showpiece). **Engine:** Motion / CSS.
**Brand-swap points:** tokens; intensity values per brand's motion language.

## 1. Magnetic button (pointer-fine only)

```tsx
'use client';
import { useRef } from 'react';
import { motion, useMotionValue, useReducedMotion, useSpring } from 'motion/react';

export function MagneticButton({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion();
  const x = useSpring(useMotionValue(0), { stiffness: 220, damping: 18 });
  const y = useSpring(useMotionValue(0), { stiffness: 220, damping: 18 });

  const onMove = (e: React.PointerEvent) => {
    if (reduced || e.pointerType !== 'mouse') return;
    const r = ref.current!.getBoundingClientRect();
    x.set((e.clientX - r.left - r.width / 2) * 0.28);
    y.set((e.clientY - r.top - r.height / 2) * 0.28);
  };
  const reset = () => { x.set(0); y.set(0); };

  return (
    <motion.div ref={ref} style={{ x, y }} onPointerMove={onMove} onPointerLeave={reset}
                className={`inline-block will-change-transform ${className}`}>
      {children}
    </motion.div>
  );
}
```

## 2. Tilt card (CSS-first)

```css
@media (hover: hover) and (pointer: fine) and (prefers-reduced-motion: no-preference) {
  .tilt { transition: transform 0.25s cubic-bezier(0.23, 1, 0.32, 1); transform-style: preserve-3d; }
  .tilt:hover { transform: perspective(800px) rotateX(2deg) rotateY(-3deg) translateY(-4px); }
}
```

## 3. Press compress + hover lift (the default button feel)

```css
.btn { transition: transform 0.15s ease-out; }
@media (hover: hover) and (pointer: fine) { .btn:hover { transform: translateY(-2px); } }
.btn:active { transform: translateY(0) scale(0.98); transition-duration: 0.08s; }
.btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
@media (prefers-reduced-motion: reduce) { .btn, .btn:hover, .btn:active { transform: none; } }
```

## 4. Hover underline (origin-aware)

```css
.link-underline { position: relative; }
.link-underline::after {
  content: ''; position: absolute; inset-inline: 0; bottom: -2px; height: 1px;
  background: var(--accent); transform: scaleX(0); transform-origin: left;
  transition: transform 0.2s cubic-bezier(0.23, 1, 0.32, 1);
}
.link-underline:hover::after, .link-underline:focus-visible::after { transform: scaleX(1); }
@media (prefers-reduced-motion: reduce) { .link-underline::after { transition: none; } }
```

## Adaptation notes

- Magnetic pull factor 0.28 is assertive; luxury/authority brands drop to 0.15, energy brands up to 0.35.
- Magnetic + tilt on the same element is noise — pick one per component class.
- Everything here is transform-only, hover-gated, reduced-motion-safe; keep those guards when adapting.
- Consistency beats variety: the same press/hover values on every interactive element is what reads
  as "designed."
