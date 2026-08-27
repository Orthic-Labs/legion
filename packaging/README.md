# Package-manager channels

Homebrew & WinGet channels are unavailable until signed installed-product qualification emits immutable release URLs, checksums, provenance, & publication grants. Repository carries no placeholder formula or pseudo-manifest that could be mistaken for publishable output.

Canonical channel identity lives in `packaging/channels.json`; product version lives in `release/version.json`. RightKit Release owns final Homebrew formula & WinGet manifest generation from qualified release bytes.

`release/distribution-contract.json` is publication SSOT. Release policy, private Node package state, channel ledger, & guards must stay consistent with it. Blocked workflows remain blocked until every required evidence class is satisfied together.
