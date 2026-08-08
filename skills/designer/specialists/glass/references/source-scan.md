# Glass Source Scan

The scanned inspiration repo contains:

- One JavaScript file implementing DOM glass/refraction with canvas-generated displacement maps, SVG filters, `backdrop-filter`, and `ResizeObserver`.
- A demo folder with one HTML demo and one screenshot image.
- A README and an MIT license.
- No package manifest and no package-manager dependency list.
- No runtime imports or module dependencies.
- External references only in documentation comments/README/demo image links, not as runtime code dependencies.

Use it as conceptual inspiration only unless user explicitly asks to copy or vendor code. Keep glass guide link-free, dependency-free, & portable.

Implementation guidance:

- For production app UI, prefer CSS-only translucent material.
- Use JS/SVG refraction only for small non-critical decoration and only with explicit approval.
- If code is ever copied from the scanned source, preserve the MIT copyright and license notice in the copied file.
- Never make refraction, chromatic fringe, or blur carry required product meaning.
