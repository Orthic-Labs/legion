import { parseArgs } from 'node:util';
import { EXIT, NemesisError } from '../../errors.mjs';
import { mcpInstallConfig, installPreview } from '../../../integrations/mcp/install.mjs';

// PR05: print-config only — the stdio MCP server lands in PR39.
export async function runMcp(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: false });
  const [action] = parsed.positionals;
  if (action === 'print-config') {
    stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      kind: 'nemesis-mcp-config',
      transport: 'stdio',
      ...mcpInstallConfig().mcpServers.nemesis,
      tools: ['nemesis_doctor', 'nemesis_plan', 'nemesis_audit', 'nemesis_verify', 'nemesis_get_run', 'nemesis_get_finding', 'nemesis_explain', 'nemesis_list_providers', 'nemesis_list_languages'],
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
  throw new NemesisError('mcp requires print-config or install --preview', { code: 'USAGE', exitCode: EXIT.USAGE });
}
