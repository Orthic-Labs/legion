# Platform Fidelity — per-OS rendered checks for desktop and mobile apps

Lens 15's reference. Apps are judged per shipped OS; a screenshot from one OS never clears
another. The code-side twin is `/audit`'s `platform-parity` lens (per-OS `#[cfg]` branches, CI,
stubs — `tools/skills/audit/references/desktop-tauri-checklist.md` §6); THIS lens judges the
rendered result. Canonical implementation contract: `docs/RIGHT-SUITE-CROSS-PLATFORM.md`.

## Coverage rule

For a cross-platform app, the region × lens matrix gains an OS dimension: each shipped OS is
audited from ITS OWN capture or explicitly marked untested. "Looks right on Windows" says nothing
about macOS traffic lights. The verdict must name which OSes were actually inspected.

## macOS (desktop)

- Native overlay traffic lights (`titleBarStyle: Overlay`) — present, correctly padded, not
  overlapped by app content; hover shows the native glyphs.
- No custom-drawn fake traffic lights.
- Shortcuts render as mac chords (`⌘⌥⌃⇧` via `<Kbd>`), never "Ctrl+…" strings.
- Menu-bar/dock behavior matches app type; fullscreen transition doesn't break the titlebar.
- Font smoothing applied at root (see `typography.md`); mac renders text heavier by default.

## Windows (desktop)

- Custom right-side caption buttons (minimize/maximize/close) in the app's own chrome — present,
  hit-target ≥ standard, hover/pressed states, close button red-hover convention.
- **Never fake mac traffic lights on Windows** — automatic fail (suite rule).
- Shortcuts render as `Ctrl`/`Alt`/`Shift` text chords.
- Window resize/snap (Win+arrow, Aero snap) doesn't break layout; maximized state has no
  phantom 1px borders or clipped edges.
- Scrollbars: styled consistently or native — not a mac-only overlay style that renders as a
  permanent wide gutter on Windows.

## Divergence check (mac ↔ win)

Same screen captured on both OSes: layout, spacing, type scale, and feature surface must match
except the deliberate per-OS chrome above. Any other divergence (missing panel, different control,
different copy) is a finding — cite both captures. Stubbed per-OS features that silently no-op are
`/audit platform-parity` findings; if one is visible in the UI (dead button on one OS), report it
here too.

## iOS

- Safe areas respected (notch/Dynamic Island/home indicator) — no content or tap targets under
  system UI; keyboard avoidance works.
- Touch targets ≥ 44pt (HIG); no hover-dependent affordances — every hover-revealed action has a
  tap path.
- Native gestures don't conflict: edge-swipe back, pull-to-refresh, scroll bounce.
- Text respects Dynamic Type at least one step up without clipping.
- Share/import flows use native sheets; permission prompts appear in context, not at launch.
- Dark mode follows the system trait, not an in-app-only toggle that ignores it.

## Android (when shipped)

- System back button/gesture handled at every depth — never exits the app from a nested screen.
- Material-adjacent controls or deliberately custom — not iOS-styled switches and sheets.
- Status/navigation bar colors match the theme; edge-to-edge insets handled.
- Touch targets ≥ 48dp.

## Automatic fails

- Fake mac traffic lights on Windows (or any cross-OS chrome cosplay).
- Wrong modifier-key rendering for the OS (`Ctrl+S` shown on macOS).
- Content or controls under iOS safe-area system UI.
- A shipped OS with zero captures claimed as passing.
