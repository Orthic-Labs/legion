# SwiftUI window management

Start from scene ownership, then apply scene/window modifiers before bridging to AppKit.
The following APIs are version-sensitive; check active SDK and deployment minimum and
guard or provide an older-target path:

- `.toolbar(removing: .title)` keeps logical title metadata while hiding drawn title;
- `.toolbarBackgroundVisibility(.hidden, for: .windowToolbar)` hides toolbar material;
- `.toolbarVisibility(.hidden, for: .windowToolbar)` removes toolbar entirely;
- `WindowDragGesture()` plus `.allowsWindowActivationEvents(true)` restores drag/activation
  when titlebar or toolbar chrome is removed;
- `.containerBackground(.thickMaterial, for: .window)` supplies adaptive utility-window
  material;
- `.windowMinimizeBehavior(.disabled)` fits fixed utility surfaces;
- `.restorationBehavior(.disabled)` fits transient/About/welcome surfaces, while primary
  document/navigation windows should retain normal user restoration;
- `.defaultLaunchBehavior(.presented)` expresses intentional launch presentation;
- `.defaultWindowPlacement` controls first placement of a new window;
- `.windowIdealPlacement` controls Zoom/Option-click sizing;
- `.windowStyle(.plain)` creates borderless chrome and therefore needs an obvious drag and
  close path.

For placement, call `content.sizeThatFits(.unspecified)`, read
`context.defaultDisplay.visibleRect`, clamp to usable display bounds, and preserve aspect
ratio for media. Treat first placement and zoom placement as separate policies; account
for external, rotated, and narrow displays. Keep logical titles meaningful for menus and
accessibility even when visually hidden.

These placement modifiers are macOS 15 SDK APIs. Keep an older scene branch when the
deployment minimum predates them:

```swift
@available(macOS 15.0, *)
struct PlayerScene: Scene {
    var body: some Scene {
        WindowGroup("Player", id: "player") { PlayerView() }
            .defaultWindowPlacement { content, context in
                let ideal = content.sizeThatFits(.unspecified)
                let bounds = context.defaultDisplay.visibleRect
                let size = CGSize(width: min(ideal.width, bounds.width),
                                  height: min(ideal.height, bounds.height))
                return WindowPlacement(size: size)
            }
            .windowIdealPlacement { content, context in
                let ideal = content.sizeThatFits(.unspecified)
                let bounds = context.defaultDisplay.visibleRect
                return WindowPlacement(size: fittedAspectRatio(ideal, in: bounds.size))
            }
    }
}
```

`defaultWindowPlacement` controls first appearance; `windowIdealPlacement` controls
Zoom/Option-click. Keep `fittedAspectRatio` project-owned so media policy is testable.
For older targets, omit these modifiers or use the existing AppKit placement owner. Do
not reference macOS 15-only symbols from an unguarded shared path.

Inspect click-then-drag behavior when a background window is inactive. Keep overlays out
of controls that need pointer input. Do not disable restoration on primary windows or
hard-code one monitor size. If modifiers cannot express required titlebar, panel, tabbing,
or lifecycle behavior, use a narrow `NSWindow`/`NSPanel` bridge with explicit ownership.

Primary references: [defaultWindowPlacement](https://developer.apple.com/documentation/swiftui/scene/defaultwindowplacement(_:)),
[WindowDragGesture](https://developer.apple.com/documentation/swiftui/windowdraggesture),
and [macOS 15 SwiftUI release notes](https://developer.apple.com/documentation/macos-release-notes/macos-15-release-notes).
