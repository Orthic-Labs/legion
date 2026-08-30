import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../../..');
const result = JSON.parse(readFileSync(resolve(here, 'arcane-package-migration-result.json'), 'utf8'));
const fileMap = new Map(result.entries.filter((entry) => entry.newPath).map((entry) => [resolve(root, entry.oldPath), resolve(root, entry.newPath)]));
const directoryMap = new Map([
  [resolve(root, 'src/packages/arcane/schemas'), resolve(root, 'src/lib/contracts/arcane-schemas')],
  [resolve(root, 'src/packages/arcane/compatibility/forge'), resolve(root, 'src/lib/host/arcane-compatibility/forge')],
  [resolve(root, 'src/packages/arcane/policy/inject'), resolve(root, 'src/lib/cognitive/arcane/policy')],
]);

function posix(path) {
  return path.split(sep).join('/');
}

function relativeSpecifier(fromFile, toPath) {
  let specifier = posix(relative(dirname(fromFile), toPath));
  if (!specifier.startsWith('.')) specifier = `./${specifier}`;
  return specifier;
}

let changed = 0;
for (const entry of result.entries) {
  if (!entry.newPath || !entry.newPath.endsWith('.mjs')) continue;
  const oldPath = resolve(root, entry.oldPath);
  const newPath = resolve(root, entry.newPath);
  let text = readFileSync(newPath, 'utf8');
  const replacements = [];
  const pattern = /(['"`])(\.{1,2}\/[^'"`\r\n]+)\1/g;
  for (const match of text.matchAll(pattern)) {
    const literal = match[2];
    const clean = literal.split(/[?#]/, 1)[0];
    const suffix = literal.slice(clean.length);
    const oldResolved = resolve(dirname(oldPath), clean);
    const target = fileMap.get(oldResolved) ?? directoryMap.get(oldResolved) ?? (existsSync(oldResolved) ? oldResolved : null);
    if (!target) continue;
    const replacement = `${relativeSpecifier(newPath, target)}${literal.endsWith('/') ? '/' : ''}${suffix}`;
    if (replacement === literal) continue;
    replacements.push({ start: match.index + 1, end: match.index + 1 + literal.length, replacement });
  }
  for (const replacement of replacements.sort((a, b) => b.start - a.start)) {
    text = text.slice(0, replacement.start) + replacement.replacement + text.slice(replacement.end);
  }
  if (replacements.length > 0) {
    writeFileSync(newPath, text);
    changed += 1;
  }
}

console.log(JSON.stringify({ changedFiles: changed }));
