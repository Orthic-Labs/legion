# WebView motion — Tauri, WKWebView, WebView2, WebKitGTK, Android System WebView

Load this **in addition to `stack.md`** for any Tauri/embedded-webview surface. `stack.md` is still
correct — you are in a browser, library choice applies, the web hard rules apply. This file covers
what the browser *is*, which is not the same browser on every platform.

Not for SwiftUI/AppKit/Slint — that is `native.md`.

---

## §1 — There is no "the webview"

Tauri renders through the OS's webview. It does not ship an engine (that is the whole point of the
96%-smaller bundle, and it is also the whole cost).

| Platform | Engine | Update model | Consequence |
|---|---|---|---|
| macOS / iOS | **WKWebView** (WebKit) | Serviced with OS updates, not an independent app runtime | Test the oldest supported OS, not only current Safari. |
| Windows | **WebView2 Runtime** (Chromium) | Evergreen by default; can lag offline or be admin-pinned; Fixed Version also exists | Feature-detect recent APIs and test the deployed runtime mode. |
| Linux | **WebKitGTK** | Distro-dependent, lags WebKit proper | Worst case. The Right Suite ships mac + Windows (CLAUDE.md §14), so this is out of scope unless a target is added. |
| Android | **Android System WebView** (Chromium) | Updated through Google Play on typical devices, but the installed provider/version is not app-controlled | Test the minimum Android/API level and feature-detect provider capabilities. |

**The operative rule:** record the minimum OS and runtime policy for every shipped platform, use
capability detection where available, and test the built app on each actual engine. A Chrome browser
run is a useful frontend baseline; it is not WKWebView or WebView2 evidence.

---

## §2 — Engine-gated features that bite motion specifically

Verify each against your minimum macOS before designing motion that depends on it.

| Feature | WKWebView | WebView2 | Motion consequence |
|---|---|---|---|
| `backdrop-filter` | Unprefixed in Safari 18+; older supported Safari/WebKit needs `-webkit-backdrop-filter` | Unprefixed | Keep the prefix pair only when the minimum macOS/iOS includes pre-18 WebKit; always keep an opaque fallback. |
| Same-document View Transitions | Safari 18+ | Yes | Below Safari 18 the transition is skipped and the DOM swap is instant. Must still be a legible state change. |
| Cross-document `@view-transition` | Safari 18.2+ | Yes | Below Safari 18.2 navigation falls back without the transition; preserve state legibility and test the minimum OS. |
| Scroll-driven animations / newer CSS | Version-dependent | Version-dependent | Use `CSS.supports`/`@supports`; never infer support from the Tauri version. |
| WebGL / complex canvas | Different support level | Different support level | R3F and shader work is the highest-risk category in Tauri. Prototype on WKWebView before committing. |

**Rule: motion may never be the sole carrier of a state change.** If an engine skips the animation,
the user must still see that something happened. This is the same discipline as
`prefers-reduced-motion` — reuse the reduced variant as the engine-gated fallback rather than
authoring a third path.

Gate every modern feature with the appropriate mechanism (`@supports`, `CSS.supports`, or a JS/API
presence check) and make the fallback a *real* state, not an absent one:

```css
@supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px))) {
  .panel { background: var(--surface-solid); }   /* opaque, still legible — not "no style" */
}
```

---

## §3 — Performance is engine-, device-, and effect-dependent

The core web rules in `SKILL.md` transfer, but promotion and filter cost are implementation details.
Treat these as hypotheses to profile, not guaranteed rankings:

- Large or changing `backdrop-filter` regions are high-risk. Prefer a fixed blur surface and animate
  content above it; cross-fade fixed-blur layers when the visual result permits.
- Animate a filter value only when target-runtime profiling proves it stays inside the frame budget;
  otherwise the cross-fade is the fallback.
- More promoted layers can increase memory and compositing cost. Add `will-change` only after a
  measured first-frame hitch and remove it afterward.
- Measure each built target. A Windows Lighthouse run is not macOS, Linux, or Android evidence.

---

## §4 — Window chrome, transparency, and vibrancy

Tauri window config that motion work has to respect:

```jsonc
// tauri.conf.json
{ "app": { "windows": [{ "transparent": true, "decorations": false }],
           "macOSPrivateApi": true } }   // required for a transparent macOS window
```
```css
html, body { background: transparent; }
```

Tauri warns that `macOSPrivateApi` prevents Mac App Store acceptance. Do not enable it merely for
motion polish; choose it only when the distribution lane permits private APIs.

Tauri v2 exposes platform window effects through its window APIs; projects may also use the separate
`window-vibrancy` crate. Exact material support and resize/drag performance are OS-version-specific.

**The motion-critical consequence: native vibrancy is not a CSS layer.** Frontend CSS cannot style it;
changing it requires a Tauri/native command. So:

- Panel blur that must **animate continuously** → prefer CSS only after target-engine profiling.
- Panel blur that is **constant** → native vibrancy (cheaper, better-integrated, matches the OS).
- Choose one per surface. Stacking CSS blur over native vibrancy double-blurs and reads as muddy.

This is `native.md` §0's single-owner rule reappearing at the webview boundary: one system owns the
material, for the whole duration.

**Drag regions:** `data-tauri-drag-region` applies only to the element carrying it; descendants need
their own attribute. Prefer a static drag-region parent and animate a child. If the drag region itself
moves or transforms, verify hit testing in the built app on every target; Tauri does not document a
cross-engine transformed-hit-region guarantee.

**Titlebar:** per CLAUDE.md §14 — native overlay traffic lights on macOS (`titleBarStyle: Overlay`),
custom right-side caption buttons on Windows. Never fake mac traffic lights on Windows. A fully
custom macOS titlebar (`decorations: false`) forfeits native window moving and snapping; prefer the
transparent/overlay style unless the design genuinely requires the full custom frame.

---

## §5 — WebView review gate

In addition to the web `reviews.md` gates:

- [ ] Every engine-gated feature (§2) has the appropriate CSS/JS capability check and a legible fallback.
- [ ] Motion is not the sole carrier of any state change.
- [ ] Prefix policy matches the declared minimum WebKit: prefix pair for pre-Safari-18 support,
      unprefixed is sufficient at Safari 18+, and an opaque fallback always exists.
- [ ] Any animated filter value has target-runtime frame evidence; otherwise fixed blur/cross-fade.
- [ ] Exactly one blur owner per surface — CSS or native vibrancy, never both.
- [ ] Drag-region hit testing is verified after any transform or geometry animation.
- [ ] **Captured in every built target runtime.** The hidden Chrome QA loop is the functional baseline,
      not engine proof; WKWebView/WebView2/WebKitGTK/Android evidence comes from the packaged app.
- [ ] Performance measured in every supported built target, not inferred from Chrome/Lighthouse alone.
- [ ] Windows runtime mode (Evergreen or Fixed Version) is recorded; recent WebView2 APIs are
      feature-detected, and long-running apps handle a newly available runtime version appropriately.
- [ ] Minimum supported macOS stated, and features verified against *that* WebKit — not against
      current Safari.
