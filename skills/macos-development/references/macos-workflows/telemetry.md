# Logger and runtime evidence

Instrument only a concrete lifecycle or timing question. Prefer `Logger` from `OSLog`
with stable subsystem/category pairs such as `Windowing`, `Commands`, `Sidebar`,
`MenuBar`, `Sync`, or `Import`. Log action boundaries and meaningful transitions at
bounded info/debug levels; never log credentials, tokens, document contents, or private
identifiers. Use signposts only for measured spans and remove temporary noise after proof.

```swift
import OSLog

private let logger = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "App",
    category: "Windowing"
)

logger.info("Opened document window")
```

Verify the path by exercising the actual window/menu/sidebar/menu-bar action, then use
Console.app or a narrow unified-log predicate, for example:

```sh
/usr/bin/log stream --style compact \
  --predicate 'subsystem == "com.example.app" && category == "Sidebar"'
```

Process predicates are useful when subsystem is unknown. A source log statement alone is
not proof it executed; captured output must show the event. Keep telemetry separate from
business state and use it to distinguish window lifecycle, command routing, launch,
fallback, and recovery paths. For crash/backtrace diagnosis, switch to the build/debug
workflow and retain redacted raw diagnostics.
