# Codex plugin boundary

Codex installs Legion through native Agent Plugin marketplace `legion@legion-installed`. The
plugin owns bundled skills, MCP, and lifecycle hooks. Codex copies the selected release into its
native plugin cache; setup verifies installed identity and release digests before retiring legacy
copies.

Codex skips bundled hooks until the user trusts the current hook definition. Legion projects only
`UserPromptSubmit` and `Stop`; Codex does not receive Legion pre-tool effect-enforcement hooks.
Doctor reports cache, disabled state, hook-file presence, and recorded host trust independently.
Host-agnostic Legion receipt traces do not prove Codex execution or current-definition trust.

`legion bind --write` separately creates Codex role files and explicit-only invocation policy.
Plugin disablement controls bundled plugin skills, MCP, and hooks; it does not deactivate or remove
those bind-owned role files. See `docs/architecture/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md`
section 4 for installation and ownership details.
