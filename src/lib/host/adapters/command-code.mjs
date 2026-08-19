// Command Code — baseline instructions via AGENTS.md (the cross-harness baseline)
// and skills via the common .agents/skills surface. MCP and native-agent support
// are not confirmed for this harness, so they are declared unsupported rather than
// claimed; correcting them later is a one-line data edit in this descriptor, which
// is the whole point of the data-driven seam. Effect enforcement is absent.
//
// This adapter is deliberately conservative: it installs only what the common
// surfaces guarantee (baseline instructions + projected skill packages), and
// never claims a mechanism it cannot verify.
export default {
  id: 'command-code',
  displayName: 'Command Code',
  installOwner: 'adapter',
  detect: { anyOf: ['.commandcode', '.command-code', 'AGENTS.md'], env: ['COMMAND_CODE_HOME'] },
  surfaces: {
    instructions: { fidelity: 'strong', mechanism: { kind: 'agents-md', path: 'AGENTS.md' } },
    skills: { fidelity: 'degraded', mechanism: { kind: 'skills-dir', path: '.agents/skills' }, note: 'common Agent Skills surface; packages projected, never forked' },
    agents: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'native subagent support unconfirmed for this harness' },
    mcp: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'MCP registration path unconfirmed for this harness' },
    hooks: { fidelity: 'unsupported', mechanism: { kind: 'none' } },
  },
};
