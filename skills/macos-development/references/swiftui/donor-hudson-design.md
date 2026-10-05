# Design

## Creating a uniform design in this app

Prefer to place standard fonts, sizes, colors, stack spacing, padding, rounding, animation timings, and more into a shared enum of constants, so they can be used by all views. This allows the app’s design to feel uniform and consistent, and be adjusted easily.


## Requirements for flexible, accessible design

- Never use `UIScreen.main.bounds` or another device-screen read to size a Mac window. Prefer the
  proposed container size, `containerRelativeFrame()`, `visualEffect()`, or `GeometryReader`
  when measurement is genuinely required.
- Prefer to avoid fixed frames unless content can fit neatly inside a resizable window. Use
  flexible container layout, preserve Dynamic Type, and let native controls establish their
  platform-appropriate hit targets and keyboard focus behavior.


## Standard system styling

- Strongly prefer to use `ContentUnavailableView` when data is missing or empty, rather than designing something custom.
- When using `searchable()`, you can show empty results using `ContentUnavailableView.search` and it will include the search term they used automatically – there’s no need to use `ContentUnavailableView.search(text: searchText)` or similar.
- If you need an icon and some text placed horizontally side by side, prefer `Label` over `HStack`.
- Prefer system hierarchical styles (e.g. secondary/tertiary) over manual opacity when possible, so the system can adapt to the correct context automatically.
- When using `Form`, wrap controls such as `Slider` in `LabeledContent` so the title and control are laid out correctly.
- `LabeledContent` also works outside `Form` for any title-value display; it might be necessary to define a custom `LabeledContentStyle` for consistent layout across views.
- When using `RoundedRectangle`, the default rounding style is `.continuous` – there is no need to specify it explicitly.


## Ensuring designs work for everyone

- Use `bold()` instead of `fontWeight(.bold)`, because using `bold()` allows the system to choose the correct weight for the current context.
- Only use `fontWeight()` for weights other than bold when there's an important reason - scattering around `fontWeight(.medium)` or `fontWeight(.semibold)` is counterproductive.
- Avoid hard-coded values for padding and stack spacing unless specifically requested.
- Use SwiftUI semantic `Color` or asset catalog colors. When an AppKit bridge requires a native
  semantic color, use `NSColor`/`Color(nsColor:)`; do not carry `UIColor` into macOS code.
- The font size `.caption2` is extremely small, and is generally best avoided. Even the font size `.caption` is on the small side, and should be used carefully.

