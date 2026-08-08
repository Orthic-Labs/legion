# pricing

**Intent:** pricing section — billing toggle with a shared-layout pill, cards with in-view stagger,
one featured tier carrying the accent.
**Register:** both. **Engine:** Motion (`motion/react`).
**Brand-swap points:** tokens, tier data, toggle labels (or remove toggle for one-time pricing).

```tsx
'use client';
import { useState } from 'react';
import { motion, useReducedMotion, type Variants } from 'motion/react';

const EASE = [0.23, 1, 0.32, 1] as const;
const list: Variants = { hidden: {}, show: { transition: { staggerChildren: 0.08 } } };
const card: Variants = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: EASE } } };

type Tier = { name: string; price: Record<string, string>; note: string; features: string[]; cta: string; featured?: boolean };

export function Pricing({ heading, periods, tiers }: { heading: string; periods: [string, string]; tiers: Tier[] }) {
  const [period, setPeriod] = useState(periods[0]);
  const reduced = useReducedMotion();
  return (
    <section className="bg-[var(--bg)] py-24">
      <div className="mx-auto max-w-6xl px-6">
        <h2 className="mb-10 text-center font-[family-name:var(--font-display)] text-[clamp(1.8rem,3.6vw,2.8rem)] tracking-[-0.01em] text-[var(--text)]">
          {heading}
        </h2>
        <div className="mb-12 flex justify-center">
          <div className="flex rounded-full border border-[var(--border)] bg-[var(--surface)] p-1" role="tablist">
            {periods.map((p) => (
              <button key={p} role="tab" aria-selected={period === p} onClick={() => setPeriod(p)}
                      className="relative rounded-full px-5 py-1.5 text-sm font-medium text-[var(--text)]">
                {period === p && (
                  <motion.span layoutId="billing-pill" className="absolute inset-0 rounded-full bg-[var(--accent)]"
                               transition={reduced ? { duration: 0 } : { type: 'spring', stiffness: 400, damping: 32 }} />
                )}
                <span className={`relative ${period === p ? 'text-[var(--accent-contrast)]' : ''}`}>{p}</span>
              </button>
            ))}
          </div>
        </div>
        <motion.div className="grid gap-5 md:grid-cols-3" variants={reduced ? undefined : list}
                    initial={reduced ? false : 'hidden'} whileInView="show" viewport={{ once: true, amount: 0.25 }}>
          {tiers.map((t) => (
            <motion.article key={t.name} variants={card}
              className={`flex flex-col rounded-lg border p-7 ${t.featured
                ? 'border-[var(--accent)] bg-[var(--surface)] shadow-[0_8px_40px_-12px_color-mix(in_srgb,var(--accent)_35%,transparent)]'
                : 'border-[var(--border)] bg-[var(--surface)]'}`}>
              <h3 className="text-sm font-medium uppercase tracking-wide text-[var(--muted)]">{t.name}</h3>
              <p className="mt-4 font-[family-name:var(--font-display)] text-4xl text-[var(--text)]">{t.price[period]}</p>
              <p className="mt-1 text-sm text-[var(--muted)]">{t.note}</p>
              <ul className="mt-6 flex-1 space-y-2.5 text-sm text-[var(--text)]">
                {t.features.map((f) => (
                  <li key={f} className="flex gap-2.5">
                    <span aria-hidden className="mt-0.5 text-[var(--accent)]">—</span>{f}
                  </li>
                ))}
              </ul>
              <a href="#" className={`mt-8 rounded-md px-5 py-2.5 text-center text-sm font-medium transition-transform duration-150 ease-out hover:-translate-y-0.5 active:translate-y-0 ${t.featured
                ? 'bg-[var(--accent)] text-[var(--accent-contrast)]'
                : 'border border-[var(--border)] text-[var(--text)]'}`}>
                {t.cta}
              </a>
            </motion.article>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
```

## Adaptation notes

- One tier carries the accent (border + CTA + glow); the rest stay quiet — attention logic, not
  accent sprinkling. Never two featured tiers.
- Numbers in `price` must be real, verified prices from the source of truth — never invented
  (verify-before-propagate applies to pricing above everything).
- One-time pricing (HR-style Free/Pro): drop the toggle, keep the layout; put the founders→standard
  framing in `note`.
- The `layoutId` pill is the only "clever" motion here; the cards just stagger in once.
