import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { existsSync, writeFileSync, appendFileSync, readFileSync } from 'node:fs';
import { EXIT, LegionError } from '../../errors.mjs';
import { DEFAULT_CONFIG } from '../../config/index.mjs';

const IGNORE_ENTRIES = ['.legion/', '.audit/'];

// PR09: init writes only repository config and ignore entries after a dry-run
// preview (--dry-run default previews; --write performs the writes).
export function runInit(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { write: { type: 'boolean' }, 'dry-run': { type: 'boolean' } },
    strict: true,
  });
  const root = resolve(parsed.positionals[0] ?? cwd);
  if (!existsSync(root)) throw new LegionError(`root does not exist: ${root}`, { code: 'USAGE', exitCode: EXIT.USAGE });
  const configPath = resolve(root, 'legion.config.json');
  const gitignorePath = resolve(root, '.gitignore');
  const baselinePath = resolve(root, '.legion', 'baseline.json');

  const wouldWrite = [
    { path: configPath, reason: 'repository audit configuration (profile, providers, policy, limits)' },
    { path: gitignorePath, reason: `append ${IGNORE_ENTRIES.join(', ')}` },
  ];
  const dryRun = parsed.values.write ? false : true;
  const preview = {
    schemaVersion: 1,
    kind: 'legion-init-preview',
    root,
    wouldWrite,
    dryRun,
  };
  if (!dryRun) {
    if (!existsSync(configPath)) {
      writeFileSync(configPath, `${JSON.stringify({ ...DEFAULT_CONFIG, schemaVersion: 1 }, null, 2)}\n`);
    }
    const existing = existsSync(gitignorePath) ? readFileSync(gitignorePath, 'utf8') : '';
    const additions = IGNORE_ENTRIES.filter((entry) => !existing.includes(entry));
    if (additions.length) appendFileSync(gitignorePath, `\n${additions.join('\n')}\n`);
    preview.wrote = wouldWrite.map((item) => item.path);
  }
  stdout.write(`${JSON.stringify(preview, null, 2)}\n`);
  return { exitCode: EXIT.PASS };
}
