# hero-load-choreography

**Intent:** page-load choreography for a hero — eyebrow → headline (per-word mask reveal) → subcopy
→ CTA row → hero visual, one orchestrated sequence. This is the "premium landing" opener.
**Register:** product or showpiece. **Engine:** Motion (`motion/react`).
**Brand-swap points:** tokens, fonts, copy, the visual slot (`<HeroVisual/>`), headline length.

```tsx
'use client';
import { motion, useReducedMotion, type Variants } from 'motion/react';

const EASE = [0.16, 1, 0.3, 1] as const; // ease-out-expo-ish, the load-choreography workhorse

const parent: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.09, delayChildren: 0.15 } },
};
const rise: Variants = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.7, ease: EASE } },
};
const word: Variants = {
  hidden: { y: '110%' },
  show: { y: '0%', transition: { duration: 0.8, ease: EASE } },
};

function MaskedHeadline({ text }: { text: string }) {
  return (
    <h1
      className="font-[family-name:var(--font-display)] text-[clamp(2.6rem,6vw,4.8rem)] leading-[1.02] tracking-[-0.02em] text-[var(--text)]"
      aria-label={text}
    >
      {text.split(' ').map((w, i) => (
        <span key={i} className="inline-block overflow-hidden pb-[0.08em] align-bottom" aria-hidden>
          <motion.span className="inline-block will-change-transform" variants={word}>
            {w}&nbsp;
          </motion.span>
        </span>
      ))}
    </h1>
  );
}

export function Hero({ eyebrow, headline, sub, cta, secondary, visual }: {
  eyebrow: string; headline: string; sub: string;
  cta: { label: string; href: string }; secondary?: { label: string; href: string };
  visual: React.ReactNode;
}) {
  const reduced = useReducedMotion();
  return (
    <section className="bg-[var(--bg)]">
      <motion.div
        className="mx-auto grid max-w-6xl items-center gap-12 px-6 pb-20 pt-28 md:grid-cols-[1.1fr_1fr]"
        variants={reduced ? undefined : parent}
        initial={reduced ? false : 'hidden'}
        animate="show"
      >
        <div>
          <motion.p variants={rise} className="mb-5 font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.18em] text-[var(--accent)]">
            {eyebrow}
          </motion.p>
          <MaskedHeadline text={headline} />
          <motion.p variants={rise} className="mt-6 max-w-[46ch] text-lg leading-relaxed text-[var(--muted)]">
            {sub}
          </motion.p>
          <motion.div variants={rise} className="mt-9 flex flex-wrap items-center gap-4">
            <a href={cta.href}
               className="rounded-md bg-[var(--accent)] px-6 py-3 font-medium text-[var(--accent-contrast)] transition-transform duration-150 ease-out hover:-translate-y-0.5 active:translate-y-0 active:scale-[0.98] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]">
              {cta.label}
            </a>
            {secondary && (
              <a href={secondary.href} className="px-2 py-3 font-medium text-[var(--text)] underline-offset-4 hover:underline">
                {secondary.label}
              </a>
            )}
          </motion.div>
        </div>
        <motion.div
          variants={reduced ? undefined : { hidden: { opacity: 0, scale: 0.96, y: 24 }, show: { opacity: 1, scale: 1, y: 0, transition: { duration: 0.9, ease: EASE } } }}
          className="will-change-transform"
        >
          {visual}
        </motion.div>
      </motion.div>
    </section>
  );
}
```

## Adaptation notes

- **The visual slot is the differentiator.** Per website.md Phase 1, `visual` should be the live
  signature mechanism (product demo, interactive canvas, real UI) — never a blob or stock render.
  A type-only hero is allowed if deliberately defended: drop the grid, widen the headline measure.
- Keep: the mask-reveal (`overflow-hidden` span + `y: 110%`), `EASE`, ~0.09s stagger — these are
  the "expensive feel". Total sequence lands < 1.2s; CTA visible well inside 1.5s.
- Value prop is in initial HTML (words are real DOM text, only transformed) — SEO/LCP safe.
- Layout variants: swap grid to single centered column ONLY with a defended type-led design;
  centered headline + two buttons + abstract visual is a banned default.
- Reduced motion: `useReducedMotion` disables all variants (content renders static). Do not remove.
