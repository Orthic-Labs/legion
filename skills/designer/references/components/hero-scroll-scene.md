# hero-scroll-scene

**Intent:** pinned, scroll-scrubbed hero scene — the section pins while scroll drives a product
visual through scale/position states and swaps narrative lines. The Awwwards-style opener.
**Register:** showpiece. **Engine:** GSAP ScrollTrigger (+ Lenis smooth scroll, optional).
**Brand-swap points:** tokens, fonts, copy lines, the visual, scrub length.

```tsx
'use client';
import { useLayoutEffect, useRef } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);

const LINES = [
  'One sentence that states the product truth.',
  'A second beat that sharpens it.',
  'The payoff line the CTA hangs on.',
];

export function ScrollScene() {
  const root = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const ctx = gsap.context(() => {
      const mm = gsap.matchMedia();
      // Full scene: desktop, motion allowed
      mm.add('(min-width: 768px) and (prefers-reduced-motion: no-preference)', () => {
        const tl = gsap.timeline({
          scrollTrigger: { trigger: root.current, start: 'top top', end: '+=250%', scrub: 0.6, pin: true },
          defaults: { ease: 'none' }, // linear mapping scroll→progress reads most natural
        });
        tl.fromTo('.scene-visual', { scale: 1.25, yPercent: 8 }, { scale: 0.9, yPercent: -4 }, 0);
        LINES.forEach((_, i) => {
          if (i > 0) tl.fromTo(`.scene-line-${i}`, { opacity: 0, y: 32 }, { opacity: 1, y: 0, duration: 0.18 }, i / LINES.length);
          if (i < LINES.length - 1) tl.to(`.scene-line-${i}`, { opacity: 0, y: -32, duration: 0.18 }, (i + 0.7) / LINES.length);
        });
      });
      // Fallback: mobile or reduced motion — no pin, static stacked scene
      mm.add('(max-width: 767px), (prefers-reduced-motion: reduce)', () => {
        gsap.set('.scene-visual, [class*="scene-line-"]', { clearProps: 'all', opacity: 1 });
      });
    }, root);
    return () => ctx.revert();
  }, []);

  return (
    <section ref={root} className="relative min-h-screen overflow-hidden bg-[var(--bg)]">
      <div className="mx-auto flex h-screen max-w-6xl flex-col items-center justify-center gap-10 px-6">
        <div className="relative h-[46vh] w-full">
          <div className="scene-visual h-full w-full will-change-transform">
            {/* real product visual: app frame, canvas, video — never an abstract render */}
          </div>
        </div>
        <div className="relative h-24 w-full max-w-3xl text-center">
          {LINES.map((line, i) => (
            <p key={i}
               className={`scene-line-${i} absolute inset-0 font-[family-name:var(--font-display)] text-[clamp(1.6rem,3.5vw,2.6rem)] leading-tight text-[var(--text)] ${i > 0 ? 'opacity-0' : ''}`}>
              {line}
            </p>
          ))}
        </div>
      </div>
    </section>
  );
}
```

Optional Lenis smooth scroll (site-wide, load once; skip under reduced motion):

```tsx
'use client';
import { useEffect } from 'react';
import Lenis from 'lenis';

export function SmoothScroll() {
  useEffect(() => {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const lenis = new Lenis({ lerp: 0.12 });
    lenis.on('scroll', () => (window as any).ScrollTrigger?.update?.());
    const raf = (t: number) => { lenis.raf(t); requestAnimationFrame(raf); };
    requestAnimationFrame(raf);
    return () => lenis.destroy();
  }, []);
  return null;
}
```

## Adaptation notes

- Scrub length: `end: '+=250%'` ≈ 2.5 viewports of story. 4+ viewports is a slog; shorten before cutting lines.
- Content stays real DOM text (SEO safe); the pin only transforms, no layout properties.
- Mobile + reduced motion get the unpinned static scene via `matchMedia` — never ship the pin to touch
  without testing it on a real device.
- Budget: GSAP core + ScrollTrigger ≈ 45KB gz, Lenis ≈ 4KB. This lives in the showpiece register's
  120KB ceiling — one showpiece engine per site, not per section.
- Pair with `text-effects.md` scroll-fill for the section after the pin; don't run two pinned scenes
  back-to-back.
