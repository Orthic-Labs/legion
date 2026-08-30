import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, extname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../../..');
const resultPath = resolve(here, 'arcane-package-migration-result.json');
const excludedNames = new Set(['.git', 'node_modules', 'dist', 'target', '.turbo']);
const textExtensions = new Set(['.cjs', '.js', '.json', '.md', '.mjs', '.py', '.rs', '.rules', '.toml', '.ts', '.yaml', '.yml']);

function posix(path) {
  return path.split(sep).join('/');
}

function repoPath(path) {
  return posix(relative(root, path));
}

function walk(directory) {
  if (!existsSync(directory)) return [];
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (excludedNames.has(entry.name)) continue;
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(path));
    else files.push(path);
  }
  return files;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function referencedPaths(source) {
  const text = readFileSync(source, 'utf8');
  const targets = [];
  for (const match of text.matchAll(/(['"`])([^'"`\r\n]+)\1/g)) {
    const literal = match[2].split(/[?#]/, 1)[0];
    if (literal.startsWith('.')) targets.push(resolve(dirname(source), literal));
    else if (/^(?:src|tests|scripts|tools|engine)\//.test(literal)) targets.push(resolve(root, literal));
  }
  return new Set(targets);
}

const result = JSON.parse(readFileSync(resultPath, 'utf8'));
const scan = ['src', 'tests', 'scripts', 'tools', 'engine']
  .flatMap((path) => walk(resolve(root, path)))
  .filter((path) => textExtensions.has(extname(path).toLowerCase()));
const references = new Map(scan.map((path) => [path, referencedPaths(path)]));

for (const entry of result.entries) {
  if (!entry.newPath) continue;
  const target = resolve(root, entry.newPath);
  if (!existsSync(target)) throw new Error(`Missing migration target: ${entry.newPath}`);
  entry.sha256AfterMove = sha256(target);
  entry.newConsumers = scan
    .filter((source) => source !== target && references.get(source).has(target))
    .map(repoPath)
    .sort();
}

result.generatedAt = new Date().toISOString();
result.exclusions = [
  'release files remain integration-owner changes',
  'historical provenance references are evidence, not live consumers',
];
writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify({ entries: result.entries.length, refreshedTargets: result.entries.filter(({ newPath }) => newPath).length }));
