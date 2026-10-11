# Simulator browser mirror & SwiftUI preview host

## Mirror an app

This mirror requires a host-provided `serve-sim` tool. It is not declared in the route
resources; if the host does not provide it, skip the browser mirror, report it unrun, and
capture simulator frames with native `legion apple simulator.screenshot` instead. When it
is available, resolve simulator UDID first, then run one long-lived `serve-sim` session
scoped to that UDID. Clean only stale helper state for that simulator before starting, and use
a process-exit trap to clean it. Keep terminal alive while browser is open; when done,
stop it and wait for exit so cleanup runs. Never issue an unscoped kill because another
session may own a different simulator. Opening a URL is not proof: verify a live frame
renders, then capture browser-visible screenshot when evidence is requested.

## Package preview host

Use a repository-approved launcher or native helper only when user asks for package
previews. Pass absolute
`Package.swift`, explicit regular package target, and explicit simulator UDID. The
disposable host must live outside source tree, import the selected package module,
and preserve the package's minimum iOS target while using a host minimum that supports
its observation/runtime needs. Do not edit `.xcodeproj`, workspace, manifest, scheme,
or build settings to force preview support.

The host discovers preview registrations from the selected package target, supports
optional comma-separated case-insensitive regex filters over type/group/display names,
and shows variants in a paged UI with accessible controls. Validate that a real frame
renders and retain build/install/launch logs.

## Hot reload proof

Watch package sources with a short debounce; ignore `.build`, `.git`, and `.swiftpm`.
Build a replacement preview plugin dylib into disposable derived data, write a unique
manifest into host Documents, signal the host, and wait for status `reloaded`. Serialize
reloads; if edits race, queue one follow-up. Keep host PID and require it to remain
unchanged, proving hot swap rather than relaunch. A failed reload must leave watcher
alive for a later edit and report host error/status. Keep loaded dylibs alive for the
host process lifetime. Clean generated project, app, dylib, and data after session.

## Runtime shape

The generated host may use a C ABI bridge: count previews, return allocated UTF-8 IDs
and display names, construct boxed `AnyView`, and export a matching free function.
Copy strings before freeing and deallocate boxed view storage only after moving its
value. Treat preview registration and hot reload as main-actor work; serialize status
writes through an actor and write status atomically. Empty preview sets should render
an explicit unavailable state, not claim success.
