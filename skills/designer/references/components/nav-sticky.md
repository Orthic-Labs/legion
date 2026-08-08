# nav-sticky

**Intent:** sticky navigation that condenses and gains material (blur + hairline) once the page
scrolls — the quiet cue that the surface is layered and alive.
**Register:** both. **Engine:** Motion (`motion/react`).
**Brand-swap points:** tokens, logo slot, link set, CTA label.

```tsx
'use client';
import { useState } from 'react';
import { motion, useMotionValueEvent, useScroll } from 'motion/react';

export function Nav({ logo, links, cta }: {
  logo: React.ReactNode;
  links: { label: string; href: string }[];
  cta: { label: string; href: string };
}) {
  const { scrollY } = useScroll();
  const [scrolled, setScrolled] = useState(false);
  useMotionValueEvent(scrollY, 'change', (y) => setScrolled(y > 24));

  return (
    <motion.header
      className="fixed inset-x-0 top-0 z-50"
      animate={scrolled ? 'solid' : 'top'}
      initial="top"
      variants={{
        top:   { backgroundColor: 'color-mix(in srgb, var(--bg) 0%, transparent)', backdropFilter: 'blur(0px)' },
        solid: { backgroundColor: 'color-mix(in srgb, var(--bg) 82%, transparent)', backdropFilter: 'blur(12px)' },
      }}
      transition={{ duration: 0.3, ease: 'easeOut' }}
      style={{ borderBottom: scrolled ? '1px solid var(--border)' : '1px solid transparent' }}
    >
      <nav className={`mx-auto flex max-w-6xl items-center justify-between px-6 transition-[padding] duration-300 ease-out ${scrolled ? 'py-3' : 'py-5'}`}>
        <a href="/" className="shrink-0">{logo}</a>
        <ul className="hidden items-center gap-7 md:flex">
          {links.map((l) => (
            <li key={l.href}>
              <a href={l.href}
                 className="group relative py-1 text-sm text-[var(--muted)] transition-colors duration-150 hover:text-[var(--text)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--accent)]">
                {l.label}
                <span className="absolute inset-x-0 -bottom-0.5 h-px origin-left scale-x-0 bg-[var(--accent)] transition-transform duration-200 ease-out group-hover:scale-x-100" />
              </a>
            </li>
          ))}
        </ul>
        <a href={cta.href}
           className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-[var(--accent-contrast)] transition-transform duration-150 ease-out hover:-translate-y-0.5 active:translate-y-0">
          {cta.label}
        </a>
      </nav>
    </motion.header>
  );
}
```

## Adaptation notes

- The condense (py-5 → py-3) + blur + hairline is the whole trick; resist adding more motion here.
- Dark-first brands: raise the mix to ~70% so text stays AA over imagery.
- Header height stays modest — the detector's `oversized-header` structure rule applies.
- Mobile menu is brand-specific (sheet vs full-screen); build it with `state.md` drawer-slide values.
- Reduced motion: color/blur transitions are fine to keep (non-positional); padding change is subtle
  enough to keep, or gate it if the brand's variant policy is strict.
