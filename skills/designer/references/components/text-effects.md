# text-effects

**Intent:** typographic motion — split-text word reveal on view, scroll-scrubbed text fill, type-on.
The showpiece register's cheapest wow-per-KB.
**Register:** showpiece mostly (word reveal fits product too). **Engine:** Motion / CSS.
**Brand-swap points:** tokens, fonts, copy.

## 1. Split-text word reveal (in-view)

```tsx
'use client';
import { motion, useReducedMotion } from 'motion/react';

const EASE = [0.16, 1, 0.3, 1] as const;

export function RevealText({ text, as: Tag = 'h2', className = '' }: {
  text: string; as?: any; className?: string;
}) {
  const reduced = useReducedMotion();
  if (reduced) return <Tag className={className}>{text}</Tag>;
  return (
    <Tag className={className} aria-label={text}>
      {text.split(' ').map((w, i) => (
        <span key={i} className="inline-block overflow-hidden pb-[0.08em] align-bottom" aria-hidden>
          <motion.span
            className="inline-block will-change-transform"
            initial={{ y: '110%' }}
            whileInView={{ y: '0%' }}
            viewport={{ once: true, amount: 0.7 }}
            transition={{ duration: 0.7, ease: EASE, delay: i * 0.05 }}
          >
            {w}&nbsp;
          </motion.span>
        </span>
      ))}
    </Tag>
  );
}
```

## 2. Scroll-scrubbed text fill (words brighten as you scroll through them)

```tsx
'use client';
import { useRef } from 'react';
import { motion, useReducedMotion, useScroll, useTransform } from 'motion/react';

function Word({ children, progress, range }: { children: string; progress: any; range: [number, number] }) {
  const opacity = useTransform(progress, range, [0.18, 1]);
  return (
    <span className="relative mr-[0.28em] inline-block">
      <span className="absolute opacity-[0.18]" aria-hidden>{children}</span>
      <motion.span style={{ opacity }}>{children}</motion.span>
    </span>
  );
}

export function ScrollFillText({ text }: { text: string }) {
  const ref = useRef<HTMLParagraphElement>(null);
  const reduced = useReducedMotion();
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start 0.85', 'end 0.45'] });
  const words = text.split(' ');
  if (reduced) return <p className="scroll-fill">{text}</p>;
  return (
    <p ref={ref} className="scroll-fill flex flex-wrap font-[family-name:var(--font-display)] text-[clamp(1.5rem,3.2vw,2.4rem)] leading-snug text-[var(--text)]">
      {words.map((w, i) => (
        <Word key={i} progress={scrollYProgress} range={[i / words.length, (i + 1) / words.length]}>{w}</Word>
      ))}
    </p>
  );
}
```

## 3. Type-on (CSS, for terminal/mono moments only)

```css
.type-on {
  display: inline-block; overflow: hidden; white-space: nowrap;
  border-right: 2px solid var(--accent);
  animation: typing 1.6s steps(28, end), caret 0.9s step-end infinite;
}
@keyframes typing { from { width: 0 } to { width: 100% } }
@keyframes caret  { 50% { border-color: transparent } }
@media (prefers-reduced-motion: reduce) { .type-on { animation: none; border-right: none; width: auto; } }
```

## Adaptation notes

- Word reveal: 0.05s/word stagger; over ~12 words, reveal by line instead (wrap lines in the same
  mask structure) or the sequence outlasts the reader's patience.
- Scroll-fill suits a manifesto/statement section — one per page. Real text stays in DOM (both
  layers render the words), so SEO and copy-paste survive.
- Type-on only where a terminal/mono metaphor is product-true (dev tools, transcription). Steps
  count = character count for clean stops.
