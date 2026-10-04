# SwiftUI composition, glass, & refactoring

## Structure

Order view source as environment, stored inputs, state, non-view computed values,
initializer, body, view builders, helpers. Keep body declarative; move non-trivial
actions, async side effects, and business logic into private methods/services. Extract
dedicated subview types when body exceeds roughly one screen or a section has its own
state/async/preview; pass narrow inputs. Prefer MV-style composition over a new view
model for local state. If an existing view model is required, initialize a non-optional
instance in init and preserve behavior.

Keep one stable root view tree; localize conditions to sections/modifiers rather than
swapping entire branches. Use `@State` for owning iOS 17+ `@Observable`, explicit
properties for children, and `@StateObject`/`@ObservedObject` only for iOS 16 legacy
targets. Add deterministic `#Preview` states for loaded, empty/loading/error with all
dependencies injected; no network, auth, DB, or global singleton.

## Liquid Glass & transitions

For iOS 26+, apply native glass after layout/appearance modifiers, use consistent shapes,
`.interactive()` only on controls, and group adjacent effects in `GlassEffectContainer`.
Use tint/prominent glass for hierarchy, `glassEffectID` + namespace only for animated
hierarchy morphs, and supply an earlier-OS material fallback. For source-to-detail
continuity, use stable IDs with matched transition source/zoom on iOS 26+ or
`matchedGeometryEffect` within one hierarchy; animate state changes and avoid duplicate
hit targets.

For scroll reveals, derive one normalized progress from measured offset/secondary
height; drive opacity, blur, position, toolbar, and snapping from it. Measure actual
height, clamp zero, avoid same-axis nested scrolling, disable conflicts such as zoom,
and use anchor interpolation for one morphing control. Add threshold haptics sparingly.

## Native patterns

Use adaptive/flexible LazyVGrid, `safeAreaBar(.top)` on iOS 26 with inset fallback,
compact ToolbarTitleMenu, native `TabView`/TabSection placement where target supports,
and `NavigationSplitView` or manual split only when columns require it. Keep controls
accessible, labels visible, keyboard dismissal deliberate, and top/bottom overlays
lightweight and dismissible. Avoid AnyView in list rows, broad `@Environment` reads,
global routers without ownership, and multiple booleans for mutually exclusive sheets.
