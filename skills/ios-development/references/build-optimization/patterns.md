# Fix patterns

Use examples as shapes; apply only when diagnostics, search, and semantics support change.

## Settings and scripts

```text
DEBUG_INFORMATION_FORMAT = dwarf-with-dsym;  →  DEBUG_INFORMATION_FORMAT = dwarf;
SWIFT_COMPILATION_MODE = wholemodule;       →  SWIFT_COMPILATION_MODE = singlefile;
COMPILATION_CACHE_ENABLE_CACHING = NO;      →  COMPILATION_CACHE_ENABLE_CACHING = YES;
EAGER_LINKING absent;                       →  EAGER_LINKING = YES;
```

Example guard for an existing project-owned Xcode Run Script phase:

```bash
[[ "$CONFIGURATION" != "Release" ]] && exit 0
./scripts/upload-dsyms.sh
```

Declare script inputs such as `$(SRCROOT)/Config/constants.json` and outputs such as `$(DERIVED_FILE_DIR)/GeneratedConstants.swift`; use `.xcfilelist` for long lists.

## Swift

Split `items.map { ... }.filter { ... }.reduce(...)` into typed intermediate arrays and typed result. Split nested `Data(contentsOf: Bundle...url!)` into typed URL, Data, and decoded value. Mark `final` only after searching all subclasses. Tighten `private`/`fileprivate` only after checking file-wide uses. Extract large SwiftUI body into typed `UserHeaderView`, `ItemListView`, and row subviews. Give generic closures explicit parameter/return types.

## Package graph

Replace feature cycle with `SharedContracts` depended on by both features. Separate `NetworkingInterface` from heavy `Networking` implementation so features compile against interface. Confirm all target/product links and package resolution before and after.
