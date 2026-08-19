// Pi — baseline instructions via AGENTS.md and skills via the common .agents/skills
// surface. Native-agent and MCP mechanisms are not confirmed for this harness and
// are declared unsupported rather than claimed. Effect enforcement is absent.
// Correcting any surface is a one-line edit to this descriptor.
export default {
  id: 'pi',
  displayName: 'Pi',
  installOwner: 'adapter',
  detect: { anyOf: ['.pi', '.pi/config', 'AGENTS.md'], env: ['PI_HOME', 'PI_SESSION'] },
  surfaces: {
    instructions: { fidelity: 'strong', mechanism: { kind: 'agents-md', path: 'AGENTS.md' } },
    skills: { fidelity: 'degraded', mechanism: { kind: 'skills-dir', path: '.agents/skills' }, note: 'common Agent Skills surface; packages projected, never forked' },
    agents: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'native subagent support unconfirmed for this harness' },
    mcp: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'MCP registration path unconfirmed for this harness' },
    hooks: { fidelity: 'unsupported', mechanism: { kind: 'none' } },
  },
};
