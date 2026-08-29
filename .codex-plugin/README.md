# Codex client boundary

This projection deliberately omits `mcpServers` and `hooks`. Under Codex, Legion ships as Agent
Plugins core (skills only) plus this metadata/policy sidecar — there is no Codex-native equivalent
of Claude Code's plugin hook lifecycle or MCP server wiring, so neither is projected here.

Concretely, under Codex:

- **Arcane's hook enforcement does not run.** `hooks/hooks.json` (SessionStart, SubagentStart,
  UserPromptSubmit, PostCompact, PreToolUse, PostToolUse, PostToolUseFailure, Stop) has no Codex
  counterpart. No lifecycle gate observes or blocks effects.
- **The `legion` MCP server is not wired.** `legion_m1_invoke` / `legion_m1_status` are unavailable;
  nothing in `.codex-plugin/plugin.json` declares an `mcpServers` entry.
- **There is therefore no runtime effect gating under Codex.** Skills route and read/write files
  the same way, but no Arcane receipt, deny, or degradation signal exists in this client.

This is intentional, not drift from `.claude-plugin/plugin.json` — see
`docs/LEGION-DISTRIBUTION-AND-CLIENT-INTEGRATION.md` section 4 ("Agent Plugins & client
boundaries") for the full client-boundary table and ownership split.
