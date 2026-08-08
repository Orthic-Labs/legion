# marquee-logos

**Intent:** continuous logo/proof marquee. CSS-only, pauses on hover, degrades to a static wrapped
row under reduced motion.
**Register:** both. **Engine:** CSS only.
**Brand-swap points:** tokens, logo set, speed, label copy.

```tsx
export function LogoMarquee({ label, logos }: { label: string; logos: React.ReactNode[] }) {
  const track = [...logos, ...logos]; // duplicate for the seamless loop
  return (
    <section className="border-y border-[var(--border)] bg-[var(--bg)] py-10">
      <p className="mb-6 text-center font-[family-name:var(--font-mono)] text-xs uppercase tracking-[0.18em] text-[var(--muted)]">
        {label}
      </p>
      <div className="marquee relative overflow-hidden" aria-hidden>
        <div className="marquee-track flex w-max items-center gap-16 pr-16">
          {track.map((logo, i) => (
            <div key={i} className="opacity-60 grayscale transition-opacity duration-200 hover:opacity-100">{logo}</div>
          ))}
        </div>
      </div>
      {/* Accessible fallback list for screen readers */}
      <ul className="sr-only">{logos.map((_, i) => <li key={i} />)}</ul>
    </section>
  );
}
```

```css
.marquee { mask-image: linear-gradient(to right, transparent, black 8%, black 92%, transparent); }
.marquee-track { animation: marquee 32s linear infinite; will-change: transform; }
.marquee:hover .marquee-track { animation-play-state: paused; }

@keyframes marquee {
  from { transform: translateX(0); }
  to   { transform: translateX(-50%); }
}

@media (prefers-reduced-motion: reduce) {
  .marquee-track { animation: none; flex-wrap: wrap; justify-content: center; width: auto; }
  .marquee { mask-image: none; }
}
```

## Adaptation notes

- Speed: 28-40s per loop. Faster reads as anxious; a marquee is ambience, not a message.
- Hover-pause satisfies the pause-control rule for >5s loops without adding a button.
- The duplicated track must be at least one viewport wide or the loop will show a gap — pad the
  logo set or raise `gap`.
- Works for any repeating proof strip: press quotes, star ratings, spec chips — not only logos.
