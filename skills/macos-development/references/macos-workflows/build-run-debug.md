# Build, run, and debug

Discover the repository before choosing a command. Check whether an Xcode workspace,
project, or `Package.swift` is the real entrypoint; enumerate schemes or products when
there is more than one; record configuration, destination, app/process name, SDK, and
minimum OS. Reuse existing scripts and host architecture. A repeatable project-local
runner is useful, but no host-specific app integration or repository initialization is
required by this reference.

For a small local loop, keep one `script/build_and_run.sh` with a default path of:

1. stop only the named prior process, tolerating an absent process;
2. build with the repository's Xcode or SwiftPM command;
3. launch the fresh artifact.

Optional explicit modes can attach `lldb`, stream logs, filter telemetry, or verify a
process after launch. Keep the no-argument path short and keep runner code outside app
source. Never kill by a broad pattern or launch an unknown artifact by accident.

SwiftPM products need a product-type decision. A real command-line executable can run
from SwiftPM's bin path. A SwiftUI/AppKit executable needs a project-local `.app`:
create `Contents/MacOS`, copy the built product, set executable permissions, and write
minimal bundle metadata (`CFBundleExecutable`, identifier/name, `CFBundlePackageType`
`APPL`, `LSMinimumSystemVersion`, and `NSPrincipalClass` `NSApplication`) using values
from the project. Launch with `/usr/bin/open -n` so Dock, activation, and bundle identity
behave like a Mac app. Do not use raw executable launch as proof of GUI behavior.

If a staged GUI app opens without a foreground window, inspect app activation policy and
entrypoint timing. A regular Dock app may need `NSApp.setActivationPolicy(.regular)` and
`NSApp.activate(ignoringOtherApps: true)`; an intentionally menu-bar-only app should
retain its documented accessory policy. A missing window can also be a scene/restore
policy issue, so inspect that before changing activation.

Classify failures from raw output: compiler or module resolution, package graph, linker,
build settings/SDK, signing, script, launch/activation, crash, or runtime behavior.
Preserve exit status and the first actionable diagnostic. A build proves compilation;
launch proves process startup; a focused interaction proves native behavior. Use LLDB,
Console, or `log stream` only for a concrete hypothesis and keep credentials/private
payloads out of logs.

For Xcode, adapt the same loop to `xcodebuild -list`, a named scheme, workspace/project,
configuration, and deterministic DerivedData/output location. Verify the launched bundle
path and PID so an older installed app is not mistaken for the current build.
