# Native Feedback — haptics, response budgets, and per-platform motion

The native counterpart to `motion-standards.md`. That file is the **web** bar (CSS easing, duration,
springs, `prefers-reduced-motion`). This one covers what a **desktop or mobile app** owes the user:
tactile feedback, per-OS reduced-motion APIs, platform motion tokens, and the response budgets that
decide whether a spinner is required at all.

Cited by Lens 10 (Motion and micro-interactions) and Lens 15 (Platform fidelity).

**Rule of use:** cite the exact value and its platform. "Feels slow" is not a finding; "no feedback
at 1.4s, budget is 1.0s" is. Where a platform publishes no number, say so — do not invent one, and
do not borrow another platform's number without labelling the borrow.

---

## Response budgets — the three thresholds

Miller (1968), popularised by Nielsen; reaffirmed by Card, Robertson & Mackinlay (1991). These are
perceptual constants, not fashions — they have not moved in 55 years.

| Tier | Threshold | What the UI owes the user |
|---|---|---|
| Instantaneous | **0.1 s** | Nothing but the result. Feels like direct manipulation. |
| Flow preserved | **1.0 s** | Still no spinner. The user notices the wait but keeps their train of thought. A spinner here *adds* perceived latency. |
| Attention lost | **10 s** | Percent-done indicator **and** a way to cancel. Past this the user task-switches. |

Source: <https://www.nngroup.com/articles/response-times-3-important-limits/>

**How this converts to findings.** The common defect is a spinner on a 200 ms action — it makes a
fast interaction feel broken, because the flash of a loading state reads as a stall. The mirror
defect is a 4 s action with no indicator at all. Both are Lens 10 findings; measure before claiming.

Feedback ladder by measured duration:

- **< 100 ms** — result only. No spinner, no skeleton, no shimmer.
- **100 ms – 1 s** — optimistic/immediate state change (button depresses, row inserts). Still no spinner.
- **1 – 10 s** — determinate progress if the total is knowable; indeterminate only if it is not.
- **> 10 s** — progress + cancel + (if possible) let the user leave and be notified.

---

## Target sizes — five competing floors, pick deliberately

| Authority | Minimum | Unit | Applies to |
|---|---|---|---|
| WCAG 2.2 **2.5.8** Target Size (Minimum) — **AA** | **24 × 24** | CSS px | The legal accessibility floor. Not a design target. |
| WCAG 2.2 **2.5.5** Target Size (Enhanced) — **AAA** | **44 × 44** | CSS px | Optional higher tier. |
| Apple — button hit region | **44 × 44** (visionOS **60 × 60**) | pt | HIG Buttons, verbatim: a button needs a hit region of at least this. |
| Windows / Fluent 2 | **40 × 40** (32 tall if ≥120 wide); **44 × 44** touch-optimised, ≥4 spacing | epx | WinUI targeting guidance. |
| Android / Material 3 | **48 × 48**, ≥ **8** between adjacent targets | dp | ≈9 mm physical, density-independent. The visual element may be smaller (a 24 dp icon is fine) as long as padding fills the full 48 dp hit area. |

Apple's Mobility table gives a **default and a minimum per platform** — the 44 pt figure is iOS's
default, not a universal floor, and macOS is materially smaller:

| Apple platform | Default control | Minimum control |
|---|---|---|
| iOS, iPadOS | 44 × 44 pt | 28 × 28 pt |
| macOS | 28 × 28 pt | 20 × 20 pt |
| tvOS | 66 × 66 pt | 56 × 56 pt |
| visionOS | 60 × 60 pt | 28 × 28 pt |
| watchOS | 44 × 44 pt | 28 × 28 pt |

**iPadOS trackpad pointer:** add ~**12 pt** of padding around elements that have a bezel, ~**24 pt**
around elements without one. visionOS: button centres ≥ 60 pt apart, or +4 pt padding to stop hover
effects overlapping.

2.5.8's five exceptions, verbatim in intent: **Spacing** (a 24 px circle centred on each target does
not intersect another), **Equivalent** (a conforming control does the same job elsewhere), **Inline**
(target sits in a sentence or is line-height constrained), **User Agent Control** (author did not
style it), **Essential** (the presentation is required).

Sources: <https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html> ·
<https://developer.apple.com/design/human-interface-guidelines/accessibility> ·
<https://learn.microsoft.com/en-us/windows/apps/develop/input/guidelines-for-targeting>

**Cross-platform resolution:** no single 44 target clears every authority — Android's 48 dp floor
sits above it. **48 × 48** (px / pt / dp / epx) is the one number that satisfies all five at once;
use it as the design target and treat 24 × 24 as the WCAG compliance floor you never actually
design to. On Apple-only surfaces 44 pt remains the HIG figure. The one place to consciously
diverge downward is a **macOS-only** surface, where even 44 pt controls look oversized against
system chrome — 28 pt is Apple's own default there.

Sources: <https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html> ·
<https://developer.apple.com/design/human-interface-guidelines/accessibility> ·
<https://developer.apple.com/design/human-interface-guidelines/buttons> ·
<https://developer.apple.com/design/human-interface-guidelines/pointing-devices> ·
<https://learn.microsoft.com/en-us/windows/apps/develop/input/guidelines-for-targeting>

---

## Haptics — semantics first, intensity second

The defect this section catches is **haptics used decoratively**. Each generator has a documented
meaning; reusing one for an unrelated event teaches the user nothing and dilutes every other buzz.

### UIKit — `UIFeedbackGenerator` subclasses

`UIFeedbackGenerator` is abstract. Never instantiate it; use a concrete subclass.

| Generator | Documented meaning |
|---|---|
| `UIImpactFeedbackGenerator` | A collision — "when a user interface object collides with another object." |
| `UISelectionFeedbackGenerator` | "Movement through a series of discrete values" — picker detents, slider steps. |
| `UINotificationFeedbackGenerator` | Outcome of a task: `.success`, `.warning`, `.error`. |

`UIImpactFeedbackGenerator.FeedbackStyle` — `.light` / `.medium` / `.heavy` describe the *size and
weight of the colliding elements* (iOS 10+). `.soft` / `.rigid` describe *compression and elasticity*
(iOS 13+, Mac Catalyst 13.1+).

### SwiftUI — `.sensoryFeedback(_:trigger:)`

iOS/iPadOS/tvOS 17.0+, macOS 14.0+, watchOS 10.0+, visionOS 26.0+. Declarative wrapper; it does
**not** deprecate `UIFeedbackGenerator` — both are current, and this one is preferred in SwiftUI-only
code. Plays when the equatable `trigger` changes.

Cases: `.success` · `.warning` · `.error` · `.selection` · `.impact` (plus
`.impact(weight:intensity:)` with `.light`/`.medium`/`.heavy`, and `.impact(flexibility:intensity:)`
with `.rigid`/`.solid`/`.soft`) · `.start` · `.stop` · `.alignment` (a dragged item aligned) ·
`.levelChange` (discrete pressure levels, trackpad force click) · `.increase` / `.decrease` (value
crossed a significant threshold) · `.pathComplete` — **iOS 17.5+, later than the rest; gating on 17.0
will not compile against it.**

### Android — `HapticFeedbackConstants`

Android's constants are **event-named**, so the semantic mapping is more explicit than Apple's. The
ones that carry real meaning (value, min API):

| Constant | API | Meaning |
|---|---|---|
| `CONFIRM` (16) / `REJECT` (17) | 30 | Success / failure signal — the `.success`/`.error` analogue. |
| `TOGGLE_ON` (21) / `TOGGLE_OFF` (22) | 34 | Switch flipped. |
| `SEGMENT_TICK` (26) | 34 | Moving between discrete choices — list items, slider stops. |
| `SEGMENT_FREQUENT_TICK` (27) | 34 | Dense choices; expected very soft, may be suppressed if hardware can't go soft enough. |
| `GESTURE_THRESHOLD_ACTIVATE` (23) / `_DEACTIVATE` (24) | 34 | Swipe/drag crossed, or re-crossed back under, its activation threshold. |
| `DRAG_START` (25) | 34 | Drag-and-drop target picked up. |
| `LONG_PRESS` (0) · `VIRTUAL_KEY` (1) · `KEYBOARD_TAP` (3) · `CLOCK_TICK` (4) · `CONTEXT_CLICK` (6) | 3–23 | Classic input events. |
| `NO_HAPTICS` (-1) | 34 | Explicitly perform none. |

`FLAG_IGNORE_GLOBAL_SETTING` (2) is **deprecated as of API 33** and privileged-apps-only — an app
overriding the user's global haptic preference is a defect, not a feature.

`VibrationEffect` predefined effects (all API 29): `EFFECT_TICK` (2, lighter than click) ·
`EFFECT_CLICK` (0, the baseline) · `EFFECT_HEAVY_CLICK` (5) · `EFFECT_DOUBLE_CLICK` (1). These are
device-tailored and fall back to a generic pattern where no hardware-specific implementation exists.

Sources: <https://developer.android.com/reference/android/view/HapticFeedbackConstants> ·
<https://developer.android.com/reference/android/os/VibrationEffect>

### When haptics are wrong

Apple's own constraints, and each is a findable defect:

- **Reused pattern, different meaning.** If a documented pattern does not fit, do not repurpose it.
  The same haptic for a failure and a level-completion is explicitly called out as confusing.
- **No causal link.** There must be "a clear, causal relationship between each haptic and the action
  that causes it." Ambient or decorative buzzes fail this.
- **Long-running haptics** dilute meaning and distract — games excepted.
- **Not optional.** The app must remain fully usable with haptics off or muted.
- **Sensor interference.** Vibration must not disrupt the camera, gyroscope, or microphone — which
  makes haptics-during-recording an active bug in any dictation or capture app, not a polish issue.

Sources: <https://developer.apple.com/documentation/uikit/uifeedbackgenerator> ·
<https://developer.apple.com/documentation/swiftui/sensoryfeedback> ·
<https://developer.apple.com/design/human-interface-guidelines/playing-haptics>

---

## Pointer vs touch — hover has no touch equivalent

`hover` is binary: `hover` | `none`. `pointer` is three-valued: `fine` (mouse, trackpad, stylus) |
`coarse` (finger) | `none`.

`any-hover` / `any-pointer` report the **union across all attached devices** — a touchscreen laptop
with a mouse is `pointer: coarse` *and* `any-pointer: fine` simultaneously. Never gate behaviour on
the primary-input query alone and assume it describes the hardware.

The failure this catches: **content reachable only through `:hover`**. On touch, a tap fires `:hover`
and `:active` together and then neither, so hover-revealed menus, tooltips, and hover-to-show
controls are simply unreachable. Anything gated behind hover needs a tap-to-reveal or
always-visible fallback under `(hover: none)` / `(pointer: coarse)`.

Sources: <https://developer.mozilla.org/en-US/docs/Web/CSS/@media/pointer> ·
<https://developer.mozilla.org/en-US/docs/Web/CSS/@media/any-pointer>

---

## Reduced motion — four different mechanisms

| Platform | How to read it |
|---|---|
| **iOS / iPadOS** | `UIAccessibility.isReduceMotionEnabled` (Bool, iOS 8+). SwiftUI: `@Environment(\.accessibilityReduceMotion)` (iOS 13+, macOS 10.15+). Also `UIAccessibility.prefersCrossFadeTransitions` (iOS 14+) — true when Reduce Motion **and** "Prefer Cross-Fade Transitions" are both on. |
| **macOS** | `NSWorkspace.shared.accessibilityDisplayShouldReduceMotion` (Bool). Setting: ≤ macOS 15 → Accessibility › Display › Reduce motion; macOS 26 Tahoe+ → Accessibility › **Motion** › Reduce motion. |
| **Windows** | `UISettings.AnimationsEnabled` (WinRT `Windows.UI.ViewManagement`, readable from Win32/WinUI/Windows App SDK) — Microsoft's composition-tailoring guidance tells apps to read it and respond. Setting: Win 10 → Ease of Access › Display › "Show animations"; Win 11 → Accessibility › Visual Effects › "Animation effects". Backed by a bitmask in `HKCU\Control Panel\Desktop\UserPreferencesMask`, shared with other visual-effect bits. |
| **Android** | `Settings.Global.getFloat(cr, Settings.Global.ANIMATOR_DURATION_SCALE)` — the system "Remove animations" toggle drives it to `0f`, which means reduced motion is on. Siblings: `TRANSITION_ANIMATION_SCALE`, `WINDOW_ANIMATION_SCALE`. |
| **WebView shell** (Tauri/Electron) | `prefers-reduced-motion` resolves through the host WebView. WKWebView reads the `NSWorkspace` flag; WebView2/Chromium reads the Windows animation setting. **The exact WebView2→registry wiring is not guaranteed in primary docs — verify empirically per runtime version rather than assuming.** |

Sources: <https://developer.apple.com/documentation/appkit/nsworkspace/accessibilitydisplayshouldreducemotion> ·
<https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion> ·
<https://learn.microsoft.com/en-us/windows/apps/develop/composition/composition-tailoring>

**Asymmetry worth knowing:** macOS and Windows both give native code a queryable flag
(`NSWorkspace` / `UISettings.AnimationsEnabled`), but a WebView-shell app does not get either for
free — `prefers-reduced-motion` must resolve through each host WebView, and the WebView2 wiring is
the unverified link. For a Tauri app shipping both, that is per-OS verification, not one
abstraction — a review that finds reduced motion honoured on mac must still verify Windows
separately.

Reduced motion means **gentler, not zero** — substitute cross-fades for movement. Killing animation
entirely destroys the spatial continuity that told the user where things went.

**Android gives it to you free — up to a point.** Every `Animator`-framework animation is zeroed
system-wide automatically, and Jetpack Compose has honoured the setting since **1.2.0**. Lottie's
Android component checks it and shows the first frame. What is *not* covered: video players, GIFs,
and hand-rolled canvas loops. Those must read the scale themselves and substitute a static frame
at `0f`. That gap is where the finding usually is.

Apple's specific substitutions when Reduce Motion is on, each directly checkable:

- **Replace x/y/z-axis transitions with fades.**
- **Tighten animation springs** to cut bounce (rather than removing the spring).
- **Track animations to the gesture** instead of firing them autonomously.
- **Do not animate depth changes** across z-axis layers; avoid animating into or out of blurs.
- Reduce automatic and repetitive motion generally — zooming, scaling, peripheral movement.

Source: <https://developer.apple.com/design/human-interface-guidelines/accessibility>

---

## Motion tokens — what each platform actually publishes

### Windows / Fluent 2 — verified against the Microsoft doc

| ThemeResource | Value |
|---|---|
| `ControlNormalAnimationDuration` | 250 ms |
| `ControlFastAnimationDuration` | 167 ms |
| `ControlFasterAnimationDuration` | 83 ms |

| Easing | Curve | Use |
|---|---|---|
| Fast Out, Slow In | `cubic-bezier(0, 0, 0, 1)` | Objects **entering** — navigating in or spawning. |
| Slow Out, Fast In | `cubic-bezier(1, 0, 1, 1)` | Objects **exiting** — getting out of the user's way. |

Source: <https://learn.microsoft.com/en-us/windows/apps/design/motion/timing-and-easing>

### Material 3 — read the status flag before citing anything

**M3's easing-and-duration system is explicitly "no longer maintained."** Expressive migrated to a
spring/physics system; the duration and easing tokens survive only for transitions and for teams
who haven't moved to GM3 Expressive. Citing them as current M3 guidance is wrong — cite them as the
legacy transition system, or cite the springs.

Duration tokens `md.sys.motion.duration.*` step in 50 ms increments: `short1–4` = 50/100/150/200,
`medium1–4` = 250/300/350/400, `long1–4` = 450/500/550/600, `extra-long1–4` = 700/800/900/1000.

Easing tokens:

| Token | CSS `cubic-bezier` |
|---|---|
| `emphasized` | **None — no single-bezier equivalent exists.** Android-only composite two-segment path; fall back to Standard on web/iOS. |
| `emphasized.decelerate` | `0.05, 0.7, 0.1, 1.0` |
| `emphasized.accelerate` | `0.3, 0.0, 0.8, 0.15` |
| `standard` | `0.2, 0.0, 0, 1.0` |
| `standard.decelerate` | `0, 0, 0, 1` |
| `standard.accelerate` | `0.3, 0, 1, 1` |

**Widespread error to check for:** many third-party summaries label plain *Emphasized* as
`cubic-bezier(0.2, 0, 0, 1)`. That value is **Standard**. Plain Emphasized has no valid single-bezier
form at all. There is also no M3 token named `legacy`; the nearest thing is MDC-Android's
`motionEasingLinearInterpolator` = `cubic-bezier(0, 0, 1, 1)`.

Official pairing — easing to duration to transition class:

| Easing | Duration | Use |
|---|---|---|
| Emphasized | 500 ms | Begins and ends on screen |
| Emphasized decelerate | 400 ms | Entering the screen |
| Emphasized accelerate | 200 ms | Exiting **permanently** — reads as unretrievable |
| Standard | 300 ms | Begins and ends on screen |
| Standard decelerate | 250 ms | Entering |
| Standard accelerate | 200 ms | Exiting |

Exiting **temporarily** (a drawer that can come back) uses plain Emphasized, not accelerate — it
ends at rest just off-screen, which reads as retrievable. Exits are shorter than enters because they
need less attention than the user's next task; duration scales with the area being transformed.

**Springs (Expressive).** Tokens are `md.sys.motion.spring.{fast|default|slow}.{spatial|effects}` —
spatial covers position/rotation/size/shape and may overshoot; effects covers colour/opacity and
never does. Numeric defaults are published only for **MDC-Android**, which ships one unified scheme:
fast spatial `damping 0.9 / stiffness 1400`, default spatial `0.9 / 700`, slow spatial `0.9 / 300`;
effects `damping 1` at stiffness `3800 / 1600 / 800`.

Jetpack Compose's real Expressive vs Standard constants are **not published** as a spec — they live
in AndroidX source. What Google does publish is a web-fallback curve+duration fit per token, e.g.
Expressive default spatial `cubic-bezier(0.38, 1.21, 0.22, 1.00)` @ 500 ms; Standard default spatial
`cubic-bezier(0.27, 1.06, 0.18, 1.00)` @ 500 ms. The `dampingRatio 0.6` figures circulating in the
M3 Expressive blog post are an illustrative **custom** scheme, not the defaults — do not cite them
as canonical.

Sources: <https://m3.material.io/styles/motion/easing-and-duration/tokens-specs> ·
<https://m3.material.io/styles/motion/easing-and-duration/applying-easing-and-duration> ·
<https://m3.material.io/styles/motion/overview/specs> ·
<https://github.com/material-components/material-components-android/blob/master/docs/theming/Motion.md>

### Apple — no duration constants, but real spring defaults

The HIG publishes **no** numeric
duration or easing values for sheets, popovers, or window chrome; it publishes principles (motion is
intentional, keeps the user oriented, preserves **spatial continuity** — the canonical example being
a window animating into the Dock so the user tracks where it went). Do not fabricate Apple duration
numbers.

But SwiftUI's API *does* declare defaults, and these are citable because they are Apple's own
declared default arguments:

| API | Declared defaults |
|---|---|
| `Animation.spring(response:dampingFraction:blendDuration:)` | `response: 0.5`, `dampingFraction: 0.825`, `blendDuration: 0` |
| `Animation.interactiveSpring(...)` | `response: 0.15`, `dampingFraction: 0.86`, `blendDuration: 0.25` |
| `Animation.smooth` / `.snappy` / `.bouncy(duration:extraBounce:)` | `duration: 0.5`, `extraBounce: 0.0` |
| `Animation.default` | iOS 17 / macOS 14 / tvOS 17 / watchOS 10 **and later**: a spring — `response: 0.55`, `dampingFraction: 1.0`, `blendDuration: 0`. **Earlier OSes**: `easeInOut`, no published duration. |
| `Animation.easeInOut()` | **No published default duration.** |

Two defaults that get conflated — keep them apart: `Animation.spring()`'s declared default response
is **0.5**; `Animation.default` is documented as a **0.55**-response spring (damping 1.0) on current
OS versions. Citing 0.55 as the `.spring()` default, or 0.5 as the `.default` response, mixes the
two APIs. Cite the API, not the blog post.

Sources: <https://developer.apple.com/design/human-interface-guidelines/motion> ·
<https://developer.apple.com/documentation/swiftui/animation/spring(response:dampingfraction:blendduration:)> ·
<https://developer.apple.com/documentation/swiftui/animation/default>

---

## Apple surface constraints that cap what motion is even legal

- **Live Activities** — content-update animations have a **2 s maximum duration**, and no animation
  plays on Always-On displays at reduced luminance. Designed for activities under **8 hours**.
  Standard Lock Screen margin **14 pt**; Dynamic Island corner radius **44 pt**. On end, removed
  immediately from the Dynamic Island but lingers up to **4 h** on the Lock Screen unless
  `dismissalDate` is set (15–30 min is usually right). Push update budget: Apple publishes **no
  number** — priority `10` counts against it, priority `5` is exempt, and
  `NSSupportsLiveActivitiesFrequentUpdates` raises it.
- **Dynamic Type** — iOS body text runs xSmall 14 pt → **Large 17 pt (default)** → xxxLarge 23 pt,
  then accessibility sizes **AX1 28 → AX2 33 → AX3 40 → AX4 47 → AX5 53 pt**. Aim to show as much
  useful text at AX5 as at xxxLarge, without truncating. SF Symbols scale automatically. Support at
  least **200 %** enlargement (140 % on watchOS). **macOS does not support Dynamic Type** — its
  default body is 13 pt, minimum 10 pt.

A layout that only survives to xxxLarge is a Lens 15 finding: the accessibility sizes are where
real breakage happens, and they are five steps further out.

Sources: <https://developer.apple.com/design/human-interface-guidelines/live-activities> ·
<https://developer.apple.com/design/human-interface-guidelines/typography>

---

## WCAG criteria that bite specifically on motion and interaction

| SC | Level | Requirement |
|---|---|---|
| **2.2.2** Pause, Stop, Hide | A | Moving/blinking/scrolling content that starts automatically, lasts > 5 s, and runs in parallel with other content must be pausable, stoppable, or hideable — unless essential. Same for auto-updating content. |
| **2.5.7** Dragging Movements | AA | Any drag operation must also be achievable with a single pointer without dragging — unless dragging is essential or UA-controlled. |
| **2.3.3** Animation from Interactions | AAA | Interaction-triggered motion animation must be disableable unless essential. |
| **2.4.11** Focus Not Obscured (Min) | AA | A focused component must not be *entirely* hidden by author-created content (sticky headers are the usual culprit). |
| **2.4.13** Focus Appearance | AAA | Indicator ≥ a 2 CSS-px perimeter of the component, ≥ 3:1 contrast between focused and unfocused states. |

Sources: <https://www.w3.org/WAI/WCAG22/Understanding/pause-stop-hide.html> ·
<https://www.w3.org/WAI/WCAG22/Understanding/dragging-movements.html> ·
<https://www.w3.org/WAI/WCAG21/Understanding/animation-from-interactions> ·
<https://www.w3.org/WAI/WCAG22/Understanding/focus-not-obscured-minimum>

**2.5.7 is the one teams miss.** Drag-to-reorder, drag-to-resize, and slider handles all need a
non-drag path — arrow keys, a menu action, a numeric input. It is AA, not AAA.

---

## Focus visibility by input modality

`:focus-visible` is a **UA heuristic**, not a fixed rule, and behaves differently per modality:

- **Keyboard** — always matches; the ring shows.
- **Mouse click** — a clicked button generally does *not* show a ring, but a text input that expects
  typing *does*, even when reached by mouse.
- **Touch** — focus moved to an element that does not expect text input does not match.
- **User override** — if the OS or browser has "always show focus indicator" set, the UA must honour
  it regardless of modality.

No spec fixes exact per-OS differences between native focus rings and WebView `:focus-visible`.
A finding here must name the modality it was observed under.

Sources: <https://developer.mozilla.org/en-US/docs/Web/CSS/:focus-visible> ·
<https://github.com/WICG/focus-visible/blob/main/explainer.md>

---

## Automatic fails

- Spinner or skeleton on an action measured under 100 ms.
- No progress indicator on an action over 10 s, or no way to cancel it.
- Any control reachable only via `:hover` with no touch fallback, in an app that ships a touch target.
- Drag-only functionality with no single-pointer alternative (2.5.7, AA).
- Reduced motion honoured on one OS of a cross-platform app and untested on the other — untested is
  a fail, not a pass.
- Interactive target below 24 × 24 CSS px with none of the five 2.5.8 exceptions applying.
- Apple motion "constants" cited with numbers Apple does not publish.
- A haptic fired with no causal link to a user action, or one documented pattern reused to mean
  something else (success haptic on a failure, notification haptic for a selection change).
- Haptics that cannot be turned off, or that fire during microphone/camera capture.
- `.pathComplete` used behind an iOS 17.0 availability gate — it is 17.5+.
- A layout tested only to xxxLarge and never to AX5 on a platform that supports Dynamic Type.
- Live Activity update animation longer than 2 s.
- Android target under 48 × 48 dp, or adjacent targets under 8 dp apart.
- `FLAG_IGNORE_GLOBAL_SETTING` used to override the user's haptic preference (deprecated API 33).
- A non-`Animator` animation on Android — video, GIF, custom canvas loop — that ignores
  `ANIMATOR_DURATION_SCALE == 0f`.
- Plain M3 *Emphasized* easing cited as `cubic-bezier(0.2, 0, 0, 1)` — that is *Standard*.
- M3 duration/easing tokens presented as current guidance without noting the system is no longer
  maintained and Expressive uses springs.
