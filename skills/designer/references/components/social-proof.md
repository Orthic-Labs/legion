# social-proof

**Intent:** testimonial columns with in-view stagger plus a count-up stat row. Proof presented as
material, not decoration.
**Register:** both. **Engine:** Motion (`motion/react`).
**Brand-swap points:** tokens, quotes (REAL ones only — fabrication is banned), stats, column count.

```tsx
'use client';
import { useEffect, useRef, useState } from 'react';
import { motion, useInView, useReducedMotion, type Variants } from 'motion/react';

const EASE = [0.23, 1, 0.32, 1] as const;
const col: Variants = { hidden: {}, show: { transition: { staggerChildren: 0.1 } } };
const item: Variants = { hidden: { opacity: 0, y: 18 }, show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: EASE } } };

function CountUp({ to, suffix = '', duration = 1.4 }: { to: number; suffix?: string; duration?: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, amount: 0.6 });
  const reduced = useReducedMotion();
  const [value, setValue] = useState(reduced ? to : 0);
  useEffect(() => {
    if (!inView || reduced) return;
    let raf = 0; const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min((now - start) / (duration * 1000), 1);
      setValue(Math.round(to * (1 - Math.pow(1 - p, 3)))); // ease-out cubic
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, reduced, to, duration]);
  return <span ref={ref}>{value.toLocaleString()}{suffix}</span>;
}

type Quote = { body: string; name: string; role: string };

export function SocialProof({ stats, quotes }: {
  stats: { value: number; suffix?: string; label: string }[];
  quotes: Quote[];
}) {
  const reduced = useReducedMotion();
  return (
    <section className="bg-[var(--bg)] py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 grid grid-cols-2 gap-8 border-y border-[var(--border)] py-10 md:grid-cols-4">
          {stats.map((s) => (
            <div key={s.label}>
              <p className="font-[family-name:var(--font-display)] text-4xl text-[var(--text)]">
                <CountUp to={s.value} suffix={s.suffix} />
              </p>
              <p className="mt-1 text-sm text-[var(--muted)]">{s.label}</p>
            </div>
          ))}
        </div>
        <motion.div className="columns-1 gap-5 md:columns-3" variants={reduced ? undefined : col}
                    initial={reduced ? false : 'hidden'} whileInView="show" viewport={{ once: true, amount: 0.15 }}>
          {quotes.map((q, i) => (
            <motion.figure key={i} variants={item}
              className="mb-5 break-inside-avoid rounded-lg border border-[var(--border)] bg-[var(--surface)] p-6">
              <blockquote className="text-[15px] leading-relaxed text-[var(--text)]">“{q.body}”</blockquote>
              <figcaption className="mt-4 text-sm text-[var(--muted)]">
                <span className="font-medium text-[var(--text)]">{q.name}</span> · {q.role}
              </figcaption>
            </motion.figure>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
```

## Adaptation notes

- **Quotes and stats must be real.** Fabricated testimonials/statistics are banned across every
  brand; use `[YOUR STORY]`-style placeholders in drafts and flag them loudly.
- Stat count-up runs once, ~1.4s, ease-out; under reduced motion the final number renders directly.
- CSS columns give the masonry feel with zero JS; if quote count < 4, switch to a single row.
- Variant: swap the quote cards for press pull-quotes or review-score chips; the stagger + stat
  row carry over unchanged.
