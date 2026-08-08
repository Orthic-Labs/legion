# Glass Material

## Purpose

Use this guide for readable, brand-safe, internal glass-material UI. Treat glass as a material
recipe, not a dependency or visual gimmick.

For product UI, prefer restrained glass:

- A dark or light tinted base with enough opacity for text contrast.
- A 1px edge, an inner top highlight, and a soft outer shadow.
- Backdrop blur and saturation as enhancement only.
- Brand accent on the edge, focus ring, selected state, or live state.
- No meaning carried only by transparency, blur, refraction, or chromatic effects.

## Workflow

1. Classify the surface.
   - Compact controls: pills, toolbars, popovers, command palettes.
   - Reading surfaces: dialogs, cards, side panels.
   - Decorative surfaces: hero chrome, product mockups, art direction.

2. Pick the material tier.
   - `solid-glass`: high readability, dark translucent background, subtle blur.
   - `soft-frost`: moderate readability, stronger blur, muted edge.
   - `optical-glass`: experimental refraction or distortion; only for non-critical decoration and only after explicit approval.

3. Set the contrast floor before styling.
   - Body text must remain readable on the busiest expected background.
   - Buttons must have visible hover, active, disabled, and focus states.
   - Fine text over glass needs a darker base, larger text, or less transparency.
   - Use the brand accent on rim, focus, state, or selection.
   - Do not let generic green success styling replace brand-specific success/status language.
   - Color can support state, but text/icon shape must also identify the state.

5. Verify rendered reality.
   - Capture the real surface in light and dark/busy contexts when possible.
   - Check text legibility, edge visibility, focus states, and mobile/compact sizing.
   - Reduce transparency first if readability fails.

## Platform Model

Apple's Liquid Glass is a native system material, not just a CSS blur. Native SwiftUI,
UIKit, and AppKit controls can get adaptive lensing, tint, shadow, motion, and
accessibility behavior from the platform. A React or WebView surface should not
claim to be true Liquid Glass unless it is using native platform APIs.

For cross-platform React/Tauri surfaces, use CSS glass/acrylic:

- `backdrop-filter` plus `-webkit-backdrop-filter` for WKWebView/Safari family.
- A mostly opaque tint layer as the readability floor.
- Inner highlight, subtle blue edge, and shadow as the material definition.
- Accessibility fallbacks for reduced transparency, higher contrast, forced colors,
  and missing backdrop-filter support.
- Platform-specific native acrylic/mica only for large Windows chrome or native
  window backgrounds; compact WebView pills and popovers should stay CSS-only
  unless the app already owns a native material layer.

Use platform divergence only when:

- The surface is native app chrome, not React content.
- Windows transparency, battery saver, high contrast, or deactivated-window behavior
  needs native Acrylic/Mica semantics.
- macOS needs true system material/lensing through AppKit/SwiftUI rather than a
  WebView overlay.

For HeardRight-style always-on-top pills, prefer one shared React/CSS material with
small platform tuning. The pill is transient control chrome, so glass is appropriate,
but it must remain legible over arbitrary desktop content.

## Premium Glass Checklist

- It reads as a surface before it reads as an effect.
- The base tint is strong enough that white text survives busy content underneath.
- The top edge has a small highlight and the lower edge has enough shadow to lift.
- The brand color appears in the rim or selected state, not as a giant glow wash.
- The material has a solid fallback; transparency is an enhancement, not a dependency.
- There is no glass-on-glass stacking unless the upper layer becomes a simple fill.
- Reduced-transparency and high-contrast preferences remove or darken blur.
- Motion is short and physical; no slow shimmer, bokeh, rainbow fringe, or fake optics
  on primary controls.

## CSS Recipes

Readable dark glass:

```css
.glass-surface {
  color: rgba(247, 244, 239, 0.94);
  background: linear-gradient(180deg, rgba(4, 8, 14, 0.90), rgba(2, 3, 6, 0.78));
  border: 1px solid color-mix(in srgb, var(--accent-blue), transparent 62%);
  box-shadow:
    0 18px 42px -24px rgba(0, 0, 0, 0.92),
    inset 0 1px 0 rgba(255, 255, 255, 0.16),
    inset 0 0 0 1px rgba(255, 255, 255, 0.06);
  backdrop-filter: blur(18px) saturate(140%);
  -webkit-backdrop-filter: blur(18px) saturate(140%);
}

.glass-surface::before {
  content: "";
  position: absolute;
  inset: 1px;
  border-radius: inherit;
  pointer-events: none;
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.14), transparent 36%),
    radial-gradient(circle at 20% 0%, rgba(90, 160, 255, 0.18), transparent 46%);
}

@supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px))) {
  .glass-surface {
    background: rgba(2, 3, 6, 0.96);
  }
}

@media (prefers-reduced-transparency: reduce), (prefers-contrast: more) {
  .glass-surface {
    background: rgba(2, 3, 6, 0.98);
    backdrop-filter: none;
    -webkit-backdrop-filter: none;
  }
}
```

Compact brand pill:

```css
.glass-pill {
  color: rgba(247, 244, 239, 0.94);
  background: linear-gradient(180deg, rgba(8, 12, 18, 0.96), rgba(3, 5, 8, 0.90));
  box-shadow:
    inset 0 0 0 1px color-mix(in srgb, var(--accent-blue), transparent 58%),
    inset 0 1px 0 rgba(255, 255, 255, 0.14),
    0 14px 36px -22px rgba(0, 0, 0, 0.96);
}
```

Button over glass:

```css
.glass-button {
  color: rgba(247, 244, 239, 0.92);
  background: rgba(255, 255, 255, 0.10);
}
.glass-button:hover {
  background: color-mix(in srgb, var(--accent-blue), transparent 72%);
}
.glass-button:focus-visible {
  outline: none;
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent-blue), transparent 35%);
}
```

## Boundaries

- Do not add remote scripts, remote assets, package installs, or outside links for glass styling.
- Do not vendor an external glass/refraction implementation unless the user explicitly approves copying code and preserving its license notice.
- Do not use large optical filters on primary app surfaces, text-heavy dialogs, or always-on overlays.
- Do not use green as the default success/status material unless it is the product's brand language.
- Prefer CSS-only glass for production UI. Use JS-generated refraction only for small decorative pieces and only after performance verification.

## Reference

Read `references/source-scan.md` when the task asks about the scanned liquid-glass inspiration or whether an implementation is safe to copy.
