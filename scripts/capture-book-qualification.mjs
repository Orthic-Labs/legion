import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const book = Number(process.argv[process.argv.indexOf('--book') + 1]);
const stage = process.argv[process.argv.indexOf('--stage') + 1];
if (!Number.isInteger(book) || book < 1 || book > 6 || !['red', 'green', 'corrected'].includes(stage)) {
  throw new Error('usage: capture-book-qualification.mjs --book 1|2|3|4|5|6 --stage red|green|corrected');
}
const result = spawnSync(process.execPath, ['scripts/qualify-book.mjs', '--book', String(book)], {
  cwd: root,
  encoding: 'utf8',
  env: { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' }
});
const output = `${result.stdout}${result.stderr}`;
const suffix = stage === 'corrected' ? 'gate.corrected' : `qualification.${stage}`;
const path = resolve(root, `qualification/evidence/source-completion/S2-book-${book}.${suffix}.log`);
mkdirSync(dirname(path), { recursive: true });
writeFileSync(path, output);
process.stdout.write(output);
process.exitCode = result.status ?? 1;
