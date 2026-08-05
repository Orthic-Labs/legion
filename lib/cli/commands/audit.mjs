import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { EXIT, NemesisError } from '../../errors.mjs';

// Audit runs the canonical pipeline. The complete deterministic core lands in
// PR06/PR07; this wires the existing audit-run.mjs entrypoint as the
// compatibility surface until then.
export async function runAudit(argv, { stdout, stderr, env, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: false });
  const root = resolve(parsed.positionals[0] ?? cwd);
  const { runAuditProviders } = await import('../../../audit-run.mjs');
  const { pathToFileURL } = await import('node:url');
  // Preserve the existing script's CLI surface.
  const child = await import('node:child_process');
  const { spawnSync } = child;
  const args = [new URL('../../../audit-run.mjs', import.meta.url).pathname, root, ...argv.filter((a) => a !== parsed.positionals[0])];
  const result = spawnSync(process.execPath, args, { stdio: 'inherit', env });
  if (result.error) throw new NemesisError(result.error.message, { code: 'PROVIDER_EXECUTION', exitCode: EXIT.INTERNAL_ERROR });
  return { exitCode: result.status ?? EXIT.INTERNAL_ERROR };
}
