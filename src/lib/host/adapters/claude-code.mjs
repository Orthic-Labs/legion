// Claude Code — installation owner is the packaged plugin (SSOT I-20), so the
// adapter DECLARES full native fidelity and DEFERS install to the plugin rather
// than writing a competing .claude/ tree. verify() confirms the plugin surface.
export default {
  id: 'claude-code',
  displayName: 'Claude Code',
  installOwner: 'plugin',
  detect: { anyOf: ['.claude', '.claude-plugin/plugin.json', 'CLAUDE.md'] },
  surfaces: {
    instructions: { fidelity: 'strong', mechanism: { kind: 'plugin' }, note: 'CLAUDE.md + plugin doctrine' },
    skills: { fidelity: 'strong', mechanism: { kind: 'plugin' }, note: 'plugin ships skills/ natively' },
    agents: { fidelity: 'strong', mechanism: { kind: 'plugin' }, note: 'plugin ships agents/ natively' },
    mcp: { fidelity: 'strong', mechanism: { kind: 'plugin' }, note: 'legion MCP server in plugin.json' },
    hooks: { fidelity: 'strong', mechanism: { kind: 'blocking-hook' }, note: 'Arcane pre/post-tool hooks in hooks.json' },
  },
};
