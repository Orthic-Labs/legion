# Native app surface — SwiftUI / AppKit / Slint / Tauri chrome

Loaded from `references/app.md` Phase 0a when the toolkit is not a plain browser. Everything in
`app.md` (task truth, workspace signature, IA, state completeness, density, keyboard model) still
governs — it is toolkit-agnostic. This file covers what changes when there is no DOM.

Motion, window geometry, and transitions are **not** here: `motion/native.md` (SwiftUI/AppKit/Slint)
or `motion/webview.md` (Tauri). This file is composition, materials, controls, and chrome.

---

## §1 — The governing principle

> A native app that looks like a website is a worse website and a broken app.

Web design optimizes first impression, scroll narrative, and novelty. App design optimizes repeated
use, muscle memory, and state legibility. On a native surface a third pressure applies: **the user's
other apps set the expectations, and you do not get to reset them.** Someone using a macOS app has
Finder, Mail, and Xcode open. Your sidebar, your traffic lights, your sheet behavior, and your
keyboard shortcuts are compared against those, continuously, whether you intended a comparison or
not.

Concretely, this bans three things designers reach for reflexively:

1. **A marketing hero inside app chrome.** Already banned by `app.md`; on native it is louder because
   nothing else on the user's screen has one.
2. **Hand-rolled replacements for system controls.** A custom picker, menu, or text field loses
   accessibility, full-keyboard access, IME/dead-key input, dictation, right-click services, and
   Dynamic Type — all of which you get free from the system control and would have to rebuild
   correctly. Restyle system controls; replace them only when the interaction genuinely does not exist
   in the system vocabulary (which is what `app.md`'s workspace-signature gate is for).
3. **Brand display type in app chrome.** See §5 — this one collides directly with the Right Suite
   brand lock and is worth reading before you set a single font.

---

## §2 — macOS structure vocabulary

Pick the container from the job, not from what is easiest to build. Getting this wrong is the most
common "it feels off but I can't say why" cause on macOS.

| Container | Use for | Do NOT use for |
|---|---|---|
| **Window** (`WindowGroup`) | Independent documents/contexts the user may want side by side | Transient choices |
| **Sheet** (`.sheet`) | Modal work that belongs to *one* window and must be completed or cancelled | Anything the user needs to reference the parent to answer |
| **Panel** (`NSPanel`, `.floating`) | Persistent auxiliary tools, HUDs, palettes, inspectors that outlive one interaction | Modal decisions |
| **Popover** (`.popover`) | Contextual, anchored to a control, dismisses on outside click | Long forms, anything with its own sub-navigation |
| **Alert** (`.alert`) | Consequential, irreversible confirmations only | Routine confirmation, success messages |
| **Inspector** (`.inspector`, macOS 14+) | Properties of the current selection, trailing edge | Primary navigation |
| **NavigationSplitView** | 2–3 column primary navigation (sidebar → content → detail) | Wizards / linear flows |
| **Toolbar** (`.toolbar`) | Verbs acting on the current view | Navigation between top-level sections |
| **Menu bar / commands** (`.commands`) | App-wide, document-wide, and frequently reused commands; shortcut-labelled where assigned | Purely contextual actions that are meaningless without the visible control/selection |

Two rules that follow:

- **Every app-wide or document-wide toolbar command needs a menu/command equivalent.** A genuinely
  contextual control may remain in the toolbar, but it still needs an accessible label, keyboard
  route where appropriate, and discoverable help. Do not duplicate meaningless selection-only
  actions merely to satisfy a checklist.
- **A panel is not a sheet with different styling.** If dismissing it loses work, it is a sheet.

iOS differs: tab bar for peer sections, `NavigationStack` for drill-down, sheets with
`.presentationDetents` for progressive disclosure. Do not port a macOS sidebar to iPhone.

---

## §3 — Materials: Liquid Glass (macOS 26 / iOS 26+)

Apple's current design language, introduced at WWDC25 and shipped September 2025 with iOS 26 and
macOS Tahoe 26. It is an adaptive material for controls and navigational chrome, not a decorative
overlay.

```swift
// Apply glass to a custom view
.glassEffect()

// Group glass elements so they merge and morph as one material
GlassEffectContainer {
    Capsule().glassEffect().glassEffectID("shell", in: namespace)
}
```

`GlassEffectContainer` + `glassEffectID` gives **native morphing between glass shapes** — the system
blends and re-forms the material as elements change. If you are building an expanding hub, palette,
or action cluster, this is the supported path and it removes the hand-built
`matchedGeometryEffect`-plus-window-resize construction that causes the two-owner bug in
`motion/native.md` §0. Reach for it before building a morph by hand.

Fallback materials (pre-26, and still correct for large surfaces):
`.ultraThinMaterial` → `.thinMaterial` → `.regularMaterial` → `.thickMaterial` → `.ultraThickMaterial`.

AppKit equivalent is `NSVisualEffectView`, where the blending mode is the real decision:
`.behindWindow` samples the desktop and other apps (correct for window backgrounds, sidebars, HUD
panels); `.withinWindow` samples only your own content (correct for a layer floating over your
scroll view). Choosing `.withinWindow` for a panel background is why a panel can look flat and
"pasted on" against the desktop.

**Discipline, all platforms:** glass is for *chrome* — bars, sidebars, floating controls, panels.
Content sits on opaque surfaces. Glass over glass is muddy. Text on glass needs a contrast check
against the worst-case backdrop, not the screenshot backdrop. `specialists/glass/GUIDE.md` owns deeper material rules
and the CSS-side implementation; this section is the native-API entry point to it.

---

## §4 — Color and appearance

**Chrome uses semantic system colors. Brand accent is yours.** This split is the whole rule.

```swift
// Chrome — adapts to light/dark, increased contrast, and accent tinting automatically
Color(nsColor: .windowBackgroundColor)   // .controlBackgroundColor, .separatorColor
.foregroundStyle(.secondary)             // not a hardcoded grey
// Brand — hardcoded per .claude/rules/brands.md, intentionally
Color(hex: "#FF5630")                    // HeardRight ember
```

Hardcoding chrome greys breaks dark mode, Increase Contrast, and the user's accent colour, and it is
the fastest way to make a native app look like a ported web page. Hardcoding the **brand accent** is
correct and required — the Right Suite locks exact hexes per app, in both light and dark, already
WCAG-AA-verified on their bases. Do not "fix" a brand accent into a semantic colour.

Both themes ship on every platform. Every app in the suite has a locked dark AND light set; a native
app that only implements one is incomplete, not a scoping decision.

---

## §5 — Typography (read before setting any font)

**App chrome uses the system face. Brand display faces are for marketing surfaces and the wordmark.**

On Apple platforms the system face (SF Pro/SF Compact) carries optical sizing, Dynamic Type, the
full weight range, and correct localisation across every script the OS supports. A brand display
face substituted into controls, labels, list rows, and menus loses all of that and reads as a
non-native app.

This collides with the Right Suite brand lock, so state it precisely: **Tanker is the suite-wide
display and wordmark face** (`.claude/rules/brands.md`, locked 2026-07-20). In a *native app* that
means Tanker appears in the wordmark, onboarding/hero moments, and empty-state headlines — not in
toolbars, sidebars, inspectors, list rows, form labels, or menus. Per-app body faces (Hanken
Grotesk, Geist, Author, General Sans, Sentient) are website faces; in-app body text uses the system
face unless the app is a *reader* whose content font is a user-facing choice (ViewRight's Sentient
reader option is exactly this exception, and it is scoped to the reading surface).

```swift
Text("Ready").font(.body)          // text style — scales, never a hardcoded point size
Text("HeardRight").font(.custom("Tanker", size: 34, relativeTo: .largeTitle))  // wordmark only
```

Never hardcode point sizes on Apple platforms. Use text styles, or `relativeTo:` when a custom face
is genuinely warranted, so the type still responds to accessibility sizing.

---

## §6 — Slint

Slint provides `std-widgets` with platform-selected styles (`cupertino`, `fluent`, `material`, `qt`,
and others), but these are rendered Slint widgets rather than the OS's native control objects.
Consequences:

- **Budget custom-control semantics explicitly.** Standard widgets provide behavior; custom components
  still need focus order, keyboard activation, `accessible-role`, labels, state, and actions. Desktop
  accessibility must be tested with Accessibility Inspector/Insights; Slint-on-Wasm currently lacks
  screen-reader accessibility.
- Use `Palette` and the built-in styling for anything you are not deliberately customizing; a
  half-themed Slint app is more jarring than an unthemed one.
- Default styles morph to the system light/dark setting; `Palette.color-scheme` exposes or overrides
  it. Reduce Motion is still a host-provided property that must be wired to animation `enabled:`
  (see `motion/native.md` §5).
- There is no Slint material/vibrancy primitive. A painted glass approximation will not sample the
  desktop; true translucency requires explicit host/native window integration. Treat that as a mixed
  surface with one material owner, not as a Slint styling toggle.

---

## §7 — Tauri chrome

The frontend is web, so `references/app.md` and `references/website.md` craft rules apply. What does
not come free is the *shell* — a Tauri window with default chrome and a web layout reads as a
website in a frame.

- Adopt the CLAUDE.md §14 cross-platform pattern: native overlay traffic lights on macOS
  (`titleBarStyle: Overlay`), custom right-side caption buttons on Windows, one codebase, runtime
  branching via `usePlatform()` (`@tauri-apps/plugin-os`) — never `navigator.platform`.
- Never fake macOS traffic lights on Windows.
- Render one chord per OS via `<Kbd>` (⌘⌥⌃⇧ vs Ctrl/Alt/Shift).
- Decide the material once per surface: native vibrancy (constant, cheap, OS-integrated) or CSS
  `backdrop-filter` (animatable, costlier on WKWebView) — never stacked. `motion/webview.md` §4.
- The menu-bar rule from §2 still applies on macOS. A Tauri app is still a Mac app to its user.

---

## §8 — Native design gate

Additional to `app.md`'s gates. Web-only checks (CLS, hydration, bundle budget) do not apply to
SwiftUI/Slint surfaces; they DO apply to Tauri.

- [ ] Container type justified per §2 for every modal/auxiliary surface.
- [ ] macOS: complete menu bar; app/document-wide toolbar commands have menu equivalents and assigned
      shortcuts are shown.
- [ ] No hand-rolled replacement for a system control without a stated reason.
- [ ] Chrome colours are semantic; brand accent is the locked hex; both themes implemented.
- [ ] System face in chrome; brand display face confined to wordmark/hero; no hardcoded point sizes.
- [ ] Glass on chrome only, content on opaque surfaces, no glass-on-glass, contrast checked against
      the worst-case backdrop.
- [ ] `NSVisualEffectView` blending mode deliberately chosen (`.behindWindow` for window backgrounds).
- [ ] Light + dark + Increase Contrast captured.
- [ ] Full-keyboard-access pass: every action reachable, focus ring visible at each stop.
- [ ] Slint: control-layer accessibility work explicitly scoped, not assumed.
- [ ] iOS verified on the **connected physical device**, never a simulator (CLAUDE.md §4B).
- [ ] the approving human's eyes on the rendered surface before any ship claim (CLAUDE.md §8).
