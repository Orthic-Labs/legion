import { parseArgs } from 'node:util';
import { spawnSync } from 'node:child_process';
import { EXIT, NemesisError } from '../../errors.mjs';

export function runVerify(argv, { stdout, stderr, env, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: false });
  const [factsArg] = parsed.positionals;
  if (!factsArg) throw new NemesisError('verify requires a run directory or facts.json path', { code: 'USAGE', exitCode: EXIT.USAGE });
  const verifier = new URL('../../../audit-verify.mjs', import.meta.url).pathname;
  const result = spawnSync(process.execPath, [verifier, '--facts', factsArg], { stdio: 'inherit', env });
  if (result.error) throw new NemesisError(result.error.message, { code: 'PROVIDER_EXECUTION', exitCode: EXIT.INTERNAL_ERROR });
  return { exitCode: result.status ?? EXIT.INTERNAL_ERROR };
}
