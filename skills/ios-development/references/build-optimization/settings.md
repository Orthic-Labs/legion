# Performance build settings

Audit values from `xcodebuild -showBuildSettings` and project/target configuration. Scope is build performance; do not convert language migration into a performance defect.

| Configuration | Key | Usual recommendation | Reason/risk |
| --- | --- | --- | --- |
| Debug | `SWIFT_COMPILATION_MODE` | `singlefile`/Incremental or unset default | Recompile changed files; low risk |
| Debug | `SWIFT_OPTIMIZATION_LEVEL` | `-Onone` | Avoid optimization passes; low risk |
| Debug | `GCC_OPTIMIZATION_LEVEL` | `0` | Avoid C-family optimization; low risk |
| Debug | `ONLY_ACTIVE_ARCH` | `YES` | Avoid extra local slices; low risk |
| Debug | `DEBUG_INFORMATION_FORMAT` | `dwarf` | Avoid dSYM generation for local iteration; confirm debugging needs |
| Debug | `ENABLE_TESTABILITY` | `YES` | Supports `@testable`; minor overhead expected |
| Debug | `SWIFT_ACTIVE_COMPILATION_CONDITIONS` | includes `DEBUG` | Preserve debug guarded code |
| Debug | `EAGER_LINKING` | `YES` | Allows linker overlap; benchmark |
| Release | `SWIFT_COMPILATION_MODE` | `wholemodule` | Runtime optimization; release build tradeoff |
| Release | `SWIFT_OPTIMIZATION_LEVEL` | `-O` or `-Osize` | Optimized distribution binary |
| Release | `GCC_OPTIMIZATION_LEVEL` | `s` | C-family size optimization |
| Release | `ONLY_ACTIVE_ARCH` | `NO` | Include distribution slices |
| Release | `DEBUG_INFORMATION_FORMAT` | `dwarf-with-dsym` | Crash symbolication |
| Release | `ENABLE_TESTABILITY` | `NO` | Avoid internal export overhead |
| All | `COMPILATION_CACHE_ENABLE_CACHING` | `YES` when supported | Reuse Swift/C-family results; measured source range 5–14% clean improvement across 87–1,991 Swift files; validate cached-clean |
| All | `SWIFT_USE_INTEGRATED_DRIVER` | `YES` | Reduce driver scheduling overhead; verify toolchain |
| All | `CLANG_ENABLE_MODULES` | `YES` | Reuse C/ObjC module maps |
| All | `SWIFT_ENABLE_EXPLICIT_MODULES` / experimental Swift equivalent | evaluate | Better visibility/scheduling, possible scan regression |

Check project-level inheritance vs target overrides for compilation mode, optimization, active architecture, debug format, flags, macros, and language mode. Drift can create module variants and repeated `SwiftEmitModule`; do not flag intentional target conditions. Use `[x]` when actual matches, `[ ]` with actual and expected when it does not.
