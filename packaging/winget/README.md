# WinGet (status: not yet populated)

WinGet is an alias distribution channel per `packaging/README.md` and
`release/distribution-contract.json`: an optional future convenience wrapper around the signed
GitHub Releases payload, never an independent build, sign, or manifest authority. It is not
release-readiness evidence.

This directory is intentionally empty today. Populating it would require a WinGet manifest set
(version, installer, and locale YAML per the `winget-pkgs` schema) that:

- points at the exact signed Windows artifact published to GitHub Releases for the requested
  version (never rebuilds from source);
- declares the correct SHA256 for that artifact;
- installs the `legion` and `legion-hook` binaries onto `PATH`; and
- is submitted to the `microsoft/winget-pkgs` community repository, kept in sync with each release.

No manifest exists yet. Do not add one ad hoc outside this contract.
