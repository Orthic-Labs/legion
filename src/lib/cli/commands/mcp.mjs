import { parseArgs } from 'node:util';
import { EXIT, LegionError } from '../../errors.mjs';
import { mcpInstallConfig, installPreview } from '../../../integrations/mcp/install.mjs';

// PR05: print-config only — the stdio MCP server lands in PR39.
export async function runMcp(argv, { stdout }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: true });
  const [action] = parsed.positionals;
  if (action === 'print-config') {
    stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      kind: 'legion-mcp-config',
      transport: 'stdio',
      ...mcpInstallConfig().mcpServers.legion,
      tools: ['legion_m1_status', 'legion_m1_invoke'],
      implemented: true,
    }, null, 2)}\n`);
    return { exitCode: EXIT.PASS };
  }
  if (action === 'install' && argv.includes('--preview')) {
    stdout.write(`${JSON.stringify(installPreview({ host: 'unspecified', config: mcpInstallConfig() }), null, 2)}\n`);
    return { exitCode: EXIT.PASS };
  }
  throw new LegionError('mcp requires print-config or install --preview', { code: 'USAGE', exitCode: EXIT.USAGE });
}
