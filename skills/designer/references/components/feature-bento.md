# feature-bento

**Intent:** bento feature grid — asymmetric cells, in-view stagger, restrained hover lift. Replaces
the banned uniform 3-card feature row.
**Register:** both. **Engine:** Motion (`motion/react`).
**Brand-swap points:** tokens, cell count/spans, per-cell visual slots, copy.

```tsx
'use client';
import { motion, useReducedMotion, type Variants } from 'motion/react';

const EASE = [0.23, 1, 0.32, 1] as const;
const grid: Variants = { hidden: {}, show: { transition: { staggerChildren: 0.07 } } };
const cell: Variants = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: EASE } },
};

type Item = { title: string; body: string; visual?: React.ReactNode; span?: 'wide' | 'tall' | 'base' };
const SPAN = { wide: 'md:col-span-2', tall: 'md:row-span-2', base: '' };

export function FeatureBento({ eyebrow, heading, items }: { eyebrow: string; heading: string; items: Item[] }) {
  const reduced = useReducedMotion();
  return (
    <section className="bg-[var(--bg)] py-24">
      <div className="mx-auto max-w-6xl px-6">
        <p className="mb-3 font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.18em] text-[var(--accent)]">{eyebrow}</p>
        <h2 className="mb-12 max-w-[24ch] font-[family-name:var(--font-display)] text-[clamp(1.8rem,3.6vw,2.8rem)] leading-[1.08] tracking-[-0.01em] text-[var(--text)]">
          {heading}
        </h2>
        <motion.div
          className="grid auto-rows-[minmax(180px,auto)] gap-4 md:grid-cols-3"
          variants={reduced ? undefined : grid}
          initial={reduced ? false : 'hidden'}
          whileInView="show"
          viewport={{ once: true, amount: 0.2 }}
        >
          {items.map((it, i) => (
            <motion.article
              key={i}
              variants={cell}
              className={`group flex flex-col justify-between overflow-hidden rounded-lg border border-[var(--border)] bg-[var(--surface)] p-6 transition-transform duration-200 ease-out will-change-transform ${reduced ? '' : 'hover:-translate-y-1'} ${SPAN[it.span ?? 'base']}`}
            >
              {it.visual && <div className="mb-5 min-h-24">{it.visual}</div>}
              <div>
                <h3 className="mb-2 text-lg font-medium text-[var(--text)]">{it.title}</h3>
                <p className="text-sm leading-relaxed text-[var(--muted)]">{it.body}</p>
              </div>
            </motion.article>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
```

## Adaptation notes

- Spans encode importance — the hero feature gets `wide` or `tall`; if every cell is `base`, it's a
  generic card grid again (banned). Structure is information.
- Per-cell `visual` should show the actual feature (mini UI state, real data, diagram) — not icons
  from a set. An icon-only bento is a banned default in disguise.
- Keep stagger ≤ 0.08s and cells ≤ 8 per grid; over that, split into two sections.
- Hover lift is transform-only and gated by `useReducedMotion`; wrap in
  `@media (hover:hover) and (pointer:fine)` semantics if converting to CSS.
