# Distribution channels

Primary public distribution is one branded PowerShell bootstrap command. R2 hosts bootstrap only;
immutable GitHub Releases own signed native payloads. Current channel state is recorded in
`packaging/channels.json`.

Homebrew & WinGet are optional future aliases. They are not release-readiness evidence & cannot
become another payload or manifest authority.

`release/distribution-contract.json` is machine publication SSOT; product architecture lives in
`docs/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md`. RightKit Release owns shared bootstrap,
signed-manifest, immutable GitHub publication, & transaction primitives. Legion owns activation.
