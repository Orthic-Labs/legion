// MCP host installer per SNIP-MCP-01. Prints the host installer config but
// never edits client config without an explicit command/preview.

import { LEGION_PACKAGE } from '../../lib/version.mjs';

export function mcpInstallConfig({ command = 'legion', args = ['mcp', 'server'] } = {}) {
  return {
    mcpServers: {
      legion: { command, args },
    },
  };
}

export function installPreview({ host, config }) {
  return {
    schemaVersion: 1,
    kind: 'legion-mcp-install-preview',
    host,
    wouldWrite: `${host} MCP client config`,
    config,
    dryRun: true,
  };
}
