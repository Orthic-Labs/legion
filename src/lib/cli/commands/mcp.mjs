import { parseArgs } from 'node:util';
import { EXIT, LegionError } from '../../errors.mjs';
import { mcpInstallConfig, installPreview } from '../../../integrations/mcp/install.mjs';

// PR05: print-config only — the stdio MCP server lands in PR39.
export async function runMcp(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: true });
  const [action] = parsed.positionals;
  if (action === 'print-config') {
    stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      kind: 'legion-mcp-config',
      transport: 'stdio',
      ...mcpInstallConfig().mcpServers.legion,
      tools: ['legion_doctor', 'legion_plan', 'legion_audit', 'legion_verify', 'legion_get_run', 'legion_get_finding', 'legion_explain', 'legion_list_providers', 'legion_list_languages'],
      implemented: true,
    }, null, 2)}\n`);
    return { exitCode: EXIT.PASS };
  }
  if (action === 'install' && argv.includes('--preview')) {
    stdout.write(`${JSON.stringify(installPreview({ host: 'unspecified', config: mcpInstallConfig() }), null, 2)}\n`);
    return { exitCode: EXIT.PASS };
  }
  if (action === 'server') {
    await import('../../../integrations/mcp/server.mjs');
    return new Promise(() => {});
  }
  throw new LegionError('mcp requires print-config or install --preview', { code: 'USAGE', exitCode: EXIT.USAGE });
}
