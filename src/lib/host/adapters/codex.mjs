// Codex.
//
// Verified surfaces: Codex reads AGENTS.md as project instructions, and reads
// MCP servers from its config TOML as `[mcp_servers.<name>]`. Both are real,
// implemented, and asserted by the conformance tests.
//
// Skills: Codex has NO native Agent Skills discovery. Legion projects the
// canonical SKILL.md packages to `.agents/skills` and points at them from the
// AGENTS.md instructions block, so the capability content reaches the model —
// but selection is instruction-driven, not host-driven. That loss is exactly
// what `degraded` means here; it is not a claim of native support.
//
// Detection uses Codex-specific evidence only. AGENTS.md is a cross-harness
// convention and is deliberately NOT a Codex signal: it would positively detect
// every repo carrying one as Codex (and as Pi, and as Command Code).
export default {
  id: 'codex',
  displayName: 'Codex',
  installOwner: 'adapter',
  detect: { anyOf: ['.codex', '.codex/config.toml'], env: ['CODEX_HOME', 'CODEX_THREAD_ID', 'CODEX_SESSION_ID'] },
  surfaces: {
    instructions: { fidelity: 'strong', mechanism: { kind: 'agents-md', path: 'AGENTS.md' } },
    skills: { fidelity: 'degraded', mechanism: { kind: 'skills-dir', path: '.agents/skills' }, note: 'no native skill discovery; canonical packages projected to .agents/skills and referenced from AGENTS.md' },
    agents: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'no native subagents' },
    mcp: { fidelity: 'strong', mechanism: { kind: 'toml', path: '.codex/config.toml', table: 'mcp_servers' } },
    hooks: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'no effect-enforcement hook surface; Arcane enforcement is absent, not degraded' },
  },
};
