# SwiftPM on macOS

Read `Package.swift` and resolve products, targets, resources, platforms, dependencies,
and test targets before building. Distinguish library-only packages, command-line
executables, and GUI executables. Use the package's existing tools and configuration;
do not add an Xcode project merely to make a package look familiar.

Use `swift build` for a normal development build, `swift build -c release` only when
release behavior is requested, and `swift test` with a target/filter for focused proof.
Use `swift run <product>` for a CLI product. For GUI products, build then stage a
bundle as described in the build/run reference; use `open -n` on that bundle. This
keeps resources, Info.plist identity, activation, and AppKit lifecycle testable.

When resources fail, inspect target resource declarations, bundle lookup, and copied
paths rather than assuming current working directory. When imports fail, separate
package resolution, target membership, platform conditions, and compiler language mode.
When linking fails, inspect product type, framework linkage, architecture, and SDK. A
successful package build does not prove a GUI bundle, signing, or distribution artifact.

If several executable products exist, choose only from explicit user/project context and
report selection. If package output is library-only, report that it has no direct app
launch path. Keep generated bundle directories in the project's intended ignored/output
location and avoid destructive cleanup outside that location.
