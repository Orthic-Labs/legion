// Codex — reads AGENTS.md for baseline instructions and registers MCP servers in
// .codex/config.toml ([mcp_servers.<name>]). No native subagents and no
// effect-enforcement hook surface. Skills reach it through the common
// .agents/skills packages (SKILL.md is the interchange format); marked degraded
// because discovery is via the shared surface rather than a first-class API.
export default {
  id: 'codex',
  displayName: 'Codex',
  installOwner: 'adapter',
  detect: { anyOf: ['.codex', 'AGENTS.md'], env: ['CODEX_HOME', 'CODEX_THREAD_ID', 'CODEX_SESSION_ID'] },
  surfaces: {
    instructions: { fidelity: 'strong', mechanism: { kind: 'agents-md', path: 'AGENTS.md' } },
    skills: { fidelity: 'degraded', mechanism: { kind: 'skills-dir', path: '.agents/skills' }, note: 'common Agent Skills surface; SKILL.md packages projected, never forked' },
    agents: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'no native subagents' },
    mcp: { fidelity: 'strong', mechanism: { kind: 'toml', path: '.codex/config.toml', table: 'mcp_servers' } },
    hooks: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'no effect-enforcement hook surface; Arcane enforcement is absent, not degraded' },
  },
};
