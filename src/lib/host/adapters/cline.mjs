// Cline (VS Code).
//
// Verified surface: project instructions via `.clinerules` — Cline reads a
// `.clinerules` file or every file in a `.clinerules/` directory, so
// `.clinerules/legion.md` is a real, native instruction location.
//
// MCP is declared UNSUPPORTED, not strong. Cline's MCP registry lives in the
// extension's own storage (`cline_mcp_settings.json`), which is host-managed and
// outside the repository; Legion does not write it. The previous descriptor
// claimed `strong` MCP at `.cline/mcp.json` — a path Cline does not read, so the
// installer would have written a file that registers nothing. Declaring the
// surface honestly is the point of the fidelity table.
//
// Skills: no native Agent Skills discovery; same projection-plus-pointer
// arrangement as Codex, hence `degraded`.
//
// Detection uses `.clinerules` only. `.vscode` was removed: it is present in a
// large share of repositories regardless of which extension, if any, is in use.
export default {
  id: 'cline',
  displayName: 'Cline',
  installOwner: 'adapter',
  detect: { anyOf: ['.clinerules'], env: ['CLINE_ACTIVE'] },
  surfaces: {
    instructions: { fidelity: 'strong', mechanism: { kind: 'native-file', path: '.clinerules/legion.md' } },
    skills: { fidelity: 'degraded', mechanism: { kind: 'skills-dir', path: '.agents/skills' }, note: 'no native skill discovery; canonical packages projected to .agents/skills and referenced from .clinerules' },
    agents: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'no native subagent primitive' },
    mcp: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'MCP registry is extension-managed (cline_mcp_settings.json), outside the repo; Legion does not install it' },
    hooks: { fidelity: 'unsupported', mechanism: { kind: 'none' }, note: 'no blocking effect gate' },
  },
};
