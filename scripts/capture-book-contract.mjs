import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const book = Number(process.argv[process.argv.indexOf('--book') + 1]);
const stage = process.argv[process.argv.indexOf('--stage') + 1];
const quality=process.argv.includes('--quality');
const cycleIndex=process.argv.indexOf('--cycle');
const cycle=cycleIndex>=0?process.argv[cycleIndex+1]:null;
const tests = {
  1: 'tests/core/book-1-contracts.test.mjs',
  2: 'tests/inventory/book-2-contracts.test.mjs',
  3: 'tests/providers/book-3-contracts.test.mjs'
};
if (!tests[book] || !['red', 'green'].includes(stage)) {
  throw new Error('usage: capture-book-contract.mjs --book 1|2|3 --stage red|green');
}
const testPath=quality?`tests/${book===1?'core':book===2?'inventory':'providers'}/book-${book}-quality.test.mjs`:tests[book];
const result = spawnSync(process.execPath, ['--test', testPath], {
  cwd: root,
  encoding: 'utf8',
  env: { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' }
});
const output = `${result.stdout}${result.stderr}`;
if(cycle&&!/^[a-z0-9-]+$/.test(cycle))throw new Error('invalid cycle label');
const path = resolve(root, `qualification/evidence/source-completion/S2-book-${book}.${quality?'quality':'behavior'}.${stage}${cycle?`.${cycle}`:''}.log`);
mkdirSync(dirname(path), { recursive: true });
writeFileSync(path, output);
process.stdout.write(output);
process.exitCode = result.status ?? 1;
