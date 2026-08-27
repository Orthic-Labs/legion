// Codex.
//
// Verified surfaces: Codex reads AGENTS.md as project instructions, and reads
// MCP servers from its config TOML as `[mcp_servers.<name>]`. Both are real,
// implemented, and asserted by the conformance tests.
//
// Skills: current Codex discovers Agent Skills from `.agents/skills`. Legion
// projects canonical packages there. Fidelity remains degraded until Legion's
// explicit-only invocation policy is projected into a Codex-native control;
// discovery itself is native and host-driven.
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
    skills: { fidelity: 'degraded', mechanism: { kind: 'skills-dir', path: '.agents/skills' }, note: 'native Agent Skills discovery; explicit-only invocation policy is not yet enforceable through this adapter' },
    agents: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'no native subagents' },
    mcp: { fidelity: 'strong', mechanism: { kind: 'toml', path: '.codex/config.toml', table: 'mcp_servers' } },
    hooks: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'no effect-enforcement hook surface; Arcane enforcement is absent, not degraded' },
  },
};
