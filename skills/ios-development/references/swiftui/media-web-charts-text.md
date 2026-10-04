# SwiftUI images, web, charts & text

## Source-aligned detail

For concrete loaders, display-scale/downsampling, WebKit, Charts, and rich-text examples, read [image optimization](donor-lee-image-optimization.md),
[WebKit](donor-lee-webkit-integration.md), [Charts](donor-lee-charts.md), and [styled text](donor-lee-styled-text-editing.md).

## Images

Handle every `AsyncImagePhase` (`empty`, `success`, `failure`) with a stable placeholder/error
and an accessible label. For repeated/large remote images, use a cancellation-aware `URLSession`
loader, request caching, and downsample to display size before decoding. Read
`@Environment(\.displayScale)` at the consuming view; do not use global screen state. `UIImage`
and `NSImage` decoding may retain large buffers; use an actor/controlled `NSCache` only when
measurement shows benefit. Prefer generated asset symbols when configured and use SF Symbols
with text/semantic labels.

## WebKit

On iOS 26+ `WebView`/`WebPage` is the native path; gate it and keep a `WKWebView` representable
for older deployments. Configure data store/process pools intentionally, cancel or replace
loads on identity changes, and decide navigation policy explicitly. Bridge only needed actions;
avoid arbitrary JavaScript injection. Export PDF/image via WebKit APIs and constrain custom URL
schemes to known hosts/actions.

## Charts

Import `Charts`, use `Identifiable` data with stable plottable values, and choose marks that
match meaning. Label axes/marks and expose a textual summary or accessibility chart descriptor;
color alone is insufficient. Use `ChartProxy`/selection for interactions, constrain domains,
and avoid expensive mark computation in `body`. Gate iOS 18+ plot/selection and iOS 26+
`Chart3D`; offer a textual/list fallback when charts are unavailable or inaccessible.

## Text and styled editing

Use `Text` format styles and interpolation, never concatenation with `+` or C-style formatting.
Use `TextField(axis: .vertical)` for bounded multiline entry; use `TextEditor` for full-screen
or rich text. On supported SDKs bind `TextEditor` to `AttributedString`, preserve selection
while transforming attributes, and resolve fonts through environment. Keep plain text fallback
when rich editing APIs are unavailable.
