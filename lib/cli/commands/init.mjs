import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { EXIT } from '../../errors.mjs';

// PR05: dry-run preview only. PR09 makes init write repository config and
// ignore entries after a preview.
export function runInit(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: false });
  const root = resolve(parsed.positionals[0] ?? cwd);
  const preview = {
    schemaVersion: 1,
    kind: 'nemesis-init-preview',
    root,
    wouldWrite: [
      { path: 'nemesis.config.json', reason: 'repository audit configuration (profiles, providers, policy)' },
      { path: '.nemesis/baseline.json', reason: 'baseline artifact for drift detection' },
      { path: '.gitignore', reason: 'append .nemesis/ run artifacts' },
    ],
    dryRun: true,
  };
  stdout.write(`${JSON.stringify(preview, null, 2)}\n`);
  return { exitCode: EXIT.PASS };
}
