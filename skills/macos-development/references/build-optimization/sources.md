# Source and evidence map

- [Apple incremental build guidance](https://developer.apple.com/documentation/xcode/improving-the-speed-of-incremental-builds): timing, target dependencies, script I/O, `.xcfilelist`, module maps, option consistency, module scope.
- [Apple coding practices](https://developer.apple.com/documentation/xcode/improving-build-efficiency-with-good-coding-practices): qualified imports, narrow bridging, explicit types/delegates, simpler expressions.
- [Apple explicit modules](https://developer.apple.com/documentation/xcode/building-your-project-with-explicit-module-dependencies) and [WWDC24](https://developer.apple.com/videos/play/wwdc2024/10171/): scan/build/compile stages, parallelism, module variants.
- [SwiftLee build analysis](https://www.avanderlee.com/optimization/analysing-build-performance-xcode/): clean/incremental measurement, timing tools, script guards, warning flags, setting audits.
- Xcode Release Notes feature 149700201: opt-in Swift/C-family compilation cache, especially branch switching and clean builds.
- [Bitrise explicit modules](https://bitrise.io/blog/post/demystifying-explicitly-built-modules-for-xcode) and [cache FAQ](https://docs.bitrise.io/en/bitrise-build-cache/build-cache-for-xcode/xcode-compilation-cache-faq.html): module scan tradeoffs, cache controls and non-cacheable task classes.
- [Swift Forums planning-module case study](https://forums.swift.org/t/slow-incremental-builds-because-of-planning-swift-module/84803): planning, macros, universal `swift-syntax`, `SwiftEmitModule`, assets, platform multiplication, no-op overhead, and Task Backtraces. Treat version/UI claims as conditional on installed Xcode.
- [RocketSim Build Insights](https://www.rocketsim.app/docs/features/build-insights/build-insights/): optional longitudinal monitoring; no dependency or install implied.
