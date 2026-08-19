// Cline (VS Code) — baseline instructions via a .clinerules file, MCP via
// cline_mcp_settings.json (mcpServers). Skills through the common .agents/skills
// surface. No native subagent primitive and no blocking effect-enforcement hook.
export default {
  id: 'cline',
  displayName: 'Cline',
  installOwner: 'adapter',
  detect: { anyOf: ['.clinerules', '.clinerules/', '.vscode'], env: ['CLINE_ACTIVE'] },
  surfaces: {
    instructions: { fidelity: 'strong', mechanism: { kind: 'native-file', path: '.clinerules/legion.md' } },
    skills: { fidelity: 'degraded', mechanism: { kind: 'skills-dir', path: '.agents/skills' }, note: 'common Agent Skills surface; packages projected, never forked' },
    agents: { fidelity: 'unsupported', mechanism: { kind: 'none' } },
    mcp: { fidelity: 'strong', mechanism: { kind: 'json', path: '.cline/mcp.json', key: 'mcpServers' }, note: 'project-local MCP config; global cline_mcp_settings.json is host-managed' },
    hooks: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'no blocking effect gate' },
  },
};
