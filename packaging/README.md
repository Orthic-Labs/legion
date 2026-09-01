# Distribution channels

Primary public distribution is one branded PowerShell bootstrap command. GitHub Pages hosts
the custom-domain wrapper; immutable GitHub Releases own signed native payloads. Current channel state is recorded in
`packaging/channels.json`.

No package-manager or vendor distribution lane is supported.

`release/distribution-contract.json` is machine publication SSOT; product architecture lives in
`docs/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md`. RightKit Release owns shared bootstrap,
signed-manifest, immutable GitHub publication, & transaction primitives. Legion owns activation.
