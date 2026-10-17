# Compose & Kotlin

Use existing architecture; source links were reviewed 2026-10-17. Verify symbols against
project's actual dependencies before adding imports or recommending migrations.

## State & work ownership

Pass screen state into composables & send user actions to its owner. Keep state in one
place at each scope; retain existing ViewModel/repository boundaries. Choose transient
composition state, restorable small UI state or persistent domain state deliberately.
`remember` alone does not survive leaving composition; durable work/data belongs outside
that lifetime. See [UI architecture](https://developer.android.com/develop/ui/compose/architecture).

On Android, collect Flow with lifecycle awareness when supported by existing stack,
using `collectAsStateWithLifecycle`; keep platform-neutral shared Compose collection
distinct. Reuse existing state holders instead of creating duplicate mutable mirrors.
See [Compose state](https://developer.android.com/develop/ui/compose/state).

Run UI-related effects through lifecycle-aware effect APIs. `LaunchedEffect` is cancelled
when leaving composition & restarts when keys change. Choose keys from operation identity;
use cleanup for registered callbacks/resources. A composable body must not start repeated
recordings, network calls or native sessions during recomposition. Long-lived business
work needs its own owner; a UI coroutine is no persistence guarantee. See
[effects](https://developer.android.com/develop/ui/compose/side-effects).

## UI evidence

Keep meaningful semantic roles, labels, state & actions for custom controls. Check
TalkBack interaction & avoid duplicate descriptions of decorative content. Prefer
semantics-based assertions to coordinates. See
[semantics](https://developer.android.com/develop/ui/compose/accessibility/semantics).

For affected layouts, inspect small/large windows, resizing, font scale, keyboard/IME,
system bars & gesture navigation. Consume insets once through existing layout owner;
avoid compensating double padding with offsets. Select adaptive behavior compatible
with current navigation & UI stack.

Profile reproducible jank before changing stability annotations, state derivation or
layout code. Keep input/device/variant fixed between captures. Production performance
conclusions need comparable optimized artifacts under repository admission; debug
timings establish debug behavior only. Broader profiling infrastructure or migration
is separate scope.
