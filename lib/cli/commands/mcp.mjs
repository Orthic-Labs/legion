import { parseArgs } from 'node:util';
import { EXIT, NemesisError } from '../../errors.mjs';

// PR05: print-config only — the stdio MCP server lands in PR39.
export function runMcp(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: false });
  const [action] = parsed.positionals;
  if (action === 'print-config') {
    stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      kind: 'nemesis-mcp-config',
      transport: 'stdio',
      command: 'nemesis',
      args: ['mcp', 'server'],
      tools: ['nemesis_doctor', 'nemesis_plan', 'nemesis_audit', 'nemesis_verify', 'nemesis_get_run', 'nemesis_get_finding', 'nemesis_explain', 'nemesis_list_providers', 'nemesis_list_languages'],
      implemented: false,
      note: 'MCP server lands in PR39',
    }, null, 2)}\n`);
    return { exitCode: EXIT.PASS };
  }
  throw new NemesisError('mcp requires print-config', { code: 'USAGE', exitCode: EXIT.USAGE });
}
