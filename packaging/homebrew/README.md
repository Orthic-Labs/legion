# Homebrew (status: not yet populated)

Homebrew is an alias distribution channel per `packaging/README.md` and
`release/distribution-contract.json`: an optional future convenience wrapper around the signed
GitHub Releases payload, never an independent build, sign, or manifest authority. It is not
release-readiness evidence.

This directory is intentionally empty today. Populating it would require a Homebrew formula (Ruby
`Formula` subclass) that:

- downloads the exact signed macOS artifact published to GitHub Releases for the requested version
  (never rebuilds from source inside the formula);
- verifies the artifact's published checksum/signature before installing;
- installs the `legion` and `legion-hook` binaries onto `PATH`; and
- is submitted to a tap (`Orthic-Labs/homebrew-legion` or similar) kept in sync with each release.

No formula exists yet. Do not add one ad hoc outside this contract.
