import { parseArgs } from 'node:util';
import { EXIT, NemesisError } from '../../errors.mjs';

// PR05: surface only — hooks are implemented in PR38.
export function runHooks(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: false });
  const [action, target] = parsed.positionals;
  if (!action || !['install', 'uninstall'].includes(action)) {
    throw new NemesisError('hooks requires install|uninstall [--pre-commit|--pre-push]', { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  stdout.write(`${JSON.stringify({
    schemaVersion: 1, kind: 'nemesis-hooks', action, target: target ?? null,
    implemented: false, note: 'hook generation lands in PR38',
  }, null, 2)}\n`);
  return { exitCode: EXIT.PASS };
}
