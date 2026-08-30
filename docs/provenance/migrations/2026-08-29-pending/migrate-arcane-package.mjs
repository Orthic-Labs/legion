import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, extname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../../..');
const oldRoot = resolve(root, 'src/packages/arcane');
const triagePath = resolve(here, 'arcane-package-triage-v2.md');
const resultPath = resolve(here, 'arcane-package-migration-result.json');
const oldPrefix = 'src/packages/arcane/';
const retired = new Set([
  'src/packages/arcane/INTERFACES.md',
  'src/packages/arcane/index.mjs',
  'src/packages/arcane/policy/README.md',
]);
const excludedNames = new Set(['.git', 'node_modules', 'dist', 'target', '.turbo']);
const textExtensions = new Set(['.cjs', '.js', '.json', '.md', '.mjs', '.py', '.rs', '.rules', '.toml', '.ts', '.yaml', '.yml']);

function posix(path) {
  return path.split(sep).join('/');
}

function repoPath(path) {
  return posix(relative(root, path));
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function walk(directory, { includeDocs = false } = {}) {
  if (!existsSync(directory)) return [];
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (excludedNames.has(entry.name)) continue;
    if (!includeDocs && entry.name === 'docs' && resolve(directory) === root) continue;
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(path, { includeDocs }));
    else files.push(path);
  }
  return files;
}

function parseTriage() {
  const rows = new Map();
  for (const line of readFileSync(triagePath, 'utf8').split(/\r?\n/)) {
    const pathMatch = line.match(/^- `([^`]+)`/);
    const dispositionMatch = line.match(/\*\*(PORT|MOVE|RESTORE|RETIRE|SPLIT)(?: \(([^)]+)\))?[^*]*\*\*/);
    if (!pathMatch || !dispositionMatch || !pathMatch[1].startsWith(oldPrefix)) continue;
    rows.set(pathMatch[1], {
      triageDisposition: dispositionMatch[1] + (dispositionMatch[2] ? ` (${dispositionMatch[2]})` : ''),
      triageDetail: line.slice(dispositionMatch.index + dispositionMatch[0].length).trim(),
      triageRow: line,
    });
  }
  if (rows.size !== 235) throw new Error(`Expected 235 triage rows, found ${rows.size}`);
  return rows;
}

function ownerFromDetail(oldPath, row) {
  const detail = row.triageRow;
  const owners = [];
  const add = (owner) => { if (!owners.includes(owner)) owners.push(owner); };
  if (detail.includes('engine/crates/legion-policy/')) add('Guard policy');
  if (detail.includes('engine/crates/legion-rules/')) add('Guard rules');
  if (detail.includes('engine/crates/legion-effects/')) add('Guard effects');
  if (detail.includes('engine/crates/legion-host/')) add('Guard host');
  if (detail.includes('engine/crates/legion-audit/')) add('Guard audit');
  if (detail.includes('src/lib/contracts/')) add('Legion contracts');
  if (detail.includes('src/lib/verification/')) add('Legion verification');
  if (detail.includes('governance/delivery.mjs')) add('Legion delivery governance');
  if (detail.includes('governance/execution.mjs')) add('Legion execution governance');
  if (detail.includes('governance/judgment.mjs')) add('Legion judgment governance');
  if (detail.includes('src/lib/host/')) add('Legion host runtime');
  if (row.triageDisposition.includes('RESTORE')) add('Arcane cognitive plane');
  if (oldPath.includes('/compatibility/forge/')) add('Legion host compatibility');
  if (oldPath.includes('/schemas/')) add('Legion contracts');
  if (oldPath.endsWith('/kernel-binding.mjs')) add('Legion kernel');
  if (oldPath.includes('/tests/')) add('Verification suite');
  if (owners.length === 0 && oldPath.includes('/host/')) add('Legion host runtime');
  if (owners.length === 0 && oldPath.endsWith('/lib/codex-escalation.mjs')) add('Legion host runtime');
  if (owners.length === 0 && oldPath.endsWith('/lib/ingest.mjs')) add('Legion verification');
  if (owners.length === 0 && ['/lib/host-event.mjs', '/lib/decision-envelope.mjs', '/lib/discipline-controls.mjs'].some((suffix) => oldPath.endsWith(suffix))) add('Legion host runtime');
  if (owners.length === 0 && oldPath.includes('/policy/')) add('Arcane cognitive plane');
  if (owners.length === 0 && retired.has(oldPath)) add('retired');
  if (owners.length === 0) throw new Error(`No owner derived for ${oldPath}`);
  return owners;
}

function guardArea(row) {
  const detail = row.triageRow;
  if (detail.includes('legion-policy')) return 'policy';
  if (detail.includes('legion-rules')) return 'rules';
  if (detail.includes('legion-effects')) return 'effects';
  if (detail.includes('legion-host')) return 'host';
  if (detail.includes('legion-audit')) return 'audit';
  return null;
}

function targetFor(oldPath, row) {
  if (retired.has(oldPath)) return null;
  const rel = oldPath.slice(oldPrefix.length);
  const name = rel.split('/').at(-1);
  if (oldPath === 'src/packages/arcane/KEY-CUSTODY.md') {
    return 'engine/crates/legion-host/KEY-CUSTODY.md';
  }
  if (rel.startsWith('tests/fixtures/')) {
    return `tests/fixtures/arcane-package/${name}`;
  }
  if (rel.startsWith('tests/')) {
    return `tests/arcane-package-${name}`;
  }
  if (rel.startsWith('compatibility/forge/')) {
    return `src/lib/host/arcane-compatibility/forge/${rel.slice('compatibility/forge/'.length)}`;
  }
  if (rel.startsWith('schemas/')) {
    return `src/lib/contracts/arcane-schemas/${name}`;
  }
  if (rel.startsWith('policy/inject/')) {
    return `src/lib/cognitive/arcane/policy/${name}`;
  }
  if (rel === 'policy/minimize-policy.md') {
    return `src/lib/cognitive/arcane/policy/${name}`;
  }
  if (rel.startsWith('policy/')) {
    const area = guardArea(row) ?? 'policy';
    return `src/lib/guard/compat/${area}/${name}`;
  }
  if (rel.startsWith('host/')) {
    if (name === 'policy-inject.mjs') return `src/lib/cognitive/arcane/host/${name}`;
    if (['claude-code-adapter.mjs', 'codex-adapter.mjs', 'provision-keys.mjs'].includes(name)) {
      return `src/lib/guard/compat/host/${name}`;
    }
    return `src/lib/host/arcane/${name}`;
  }
  if (!rel.startsWith('lib/')) throw new Error(`Unmapped Arcane path: ${oldPath}`);
  const libRel = rel.slice('lib/'.length);
  if (['minimize.mjs', 'user-intent.mjs', 'stop-shape.mjs'].includes(libRel)) {
    return `src/lib/cognitive/arcane/${libRel}`;
  }
  if (libRel === 'kernel-binding.mjs') return 'src/lib/core/kernel-binding.mjs';
  if (libRel === 'codex-escalation.mjs') return 'src/lib/host/arcane/codex-escalation.mjs';
  const area = guardArea(row);
  if (area) return `src/lib/guard/compat/${area}/${libRel}`;
  const detail = row.triageRow;
  if (detail.includes('src/lib/contracts/')) return `src/lib/contracts/arcane/${libRel}`;
  if (detail.includes('governance/delivery.mjs')) return `src/lib/cli/commands/governance/delivery/${libRel}`;
  if (detail.includes('governance/execution.mjs')) return `src/lib/cli/commands/governance/execution/${libRel}`;
  if (detail.includes('governance/judgment.mjs')) return `src/lib/cli/commands/governance/judgment/${libRel}`;
  if (detail.includes('src/lib/verification/')) return `src/lib/verification/arcane/${libRel}`;
  if (detail.includes('src/lib/host/')) return `src/lib/host/arcane/${libRel}`;
  if (row.triageDisposition.includes('RESTORE')) return `src/lib/cognitive/arcane/${libRel}`;
  const splitOverrides = new Map([
    ['host-event.mjs', 'src/lib/host/arcane/host-event.mjs'],
    ['ingest.mjs', 'src/lib/verification/arcane/ingest.mjs'],
    ['decision-envelope.mjs', 'src/lib/host/arcane/decision-envelope.mjs'],
    ['discipline-controls.mjs', 'src/lib/host/arcane/discipline-controls.mjs'],
  ]);
  if (splitOverrides.has(libRel)) return splitOverrides.get(libRel);
  throw new Error(`No physical target derived for ${oldPath}: ${row.triageRow}`);
}

function scanRoots() {
  return ['src', 'tests', 'scripts', 'tools', 'engine']
    .map((entry) => resolve(root, entry))
    .flatMap((entry) => walk(entry));
}

function textualFiles(paths) {
  return paths.filter((path) => textExtensions.has(extname(path).toLowerCase()));
}

function quotedReferences(text) {
  const refs = [];
  const pattern = /(['"`])([^'"`\r\n]+)\1/g;
  for (const match of text.matchAll(pattern)) refs.push({ literal: match[2], start: match.index + 1, end: match.index + 1 + match[2].length });
  return refs;
}

function resolveLiteral(sourcePath, literal) {
  const clean = literal.split(/[?#]/, 1)[0];
  if (clean.startsWith('.')) return resolve(dirname(sourcePath), clean);
  if (clean.startsWith(oldPrefix)) return resolve(root, clean);
  return null;
}

function consumersFor(targetPath, files, sourceOrigins = new Map()) {
  const target = resolve(targetPath);
  const consumers = [];
  for (const source of textualFiles(files)) {
    if (resolve(source) === target) continue;
    let text;
    try { text = readFileSync(source, 'utf8'); } catch { continue; }
    const origin = sourceOrigins.get(resolve(source)) ?? source;
    if (quotedReferences(text).some(({ literal }) => resolveLiteral(origin, literal) === target)) {
      consumers.push(repoPath(source));
    }
  }
  return consumers.sort();
}

function relativeSpecifier(fromFile, toPath) {
  let specifier = posix(relative(dirname(fromFile), toPath));
  if (!specifier.startsWith('.')) specifier = `./${specifier}`;
  return specifier;
}

function rewriteFile(path, originPath, absoluteMapping, directoryMapping) {
  let text;
  try { text = readFileSync(path, 'utf8'); } catch { return false; }
  const refs = quotedReferences(text);
  const replacements = [];
  for (const ref of refs) {
    const resolved = resolveLiteral(originPath, ref.literal);
    if (!resolved) continue;
    const mapped = absoluteMapping.get(resolved) ?? directoryMapping.get(resolved);
    if (!mapped) continue;
    const suffix = ref.literal.slice(ref.literal.split(/[?#]/, 1)[0].length);
    const replacement = ref.literal.startsWith(oldPrefix)
      ? `${repoPath(mapped)}${suffix}`
      : `${relativeSpecifier(path, mapped)}${ref.literal.endsWith('/') ? '/' : ''}${suffix}`;
    replacements.push({ ...ref, replacement });
  }
  for (const replacement of replacements.sort((a, b) => b.start - a.start)) {
    text = text.slice(0, replacement.start) + replacement.replacement + text.slice(replacement.end);
  }
  if (replacements.length > 0) writeFileSync(path, text);
  return replacements.length > 0;
}

const triage = parseTriage();
const inventory = walk(oldRoot, { includeDocs: true }).sort();
if (inventory.length !== 235) throw new Error(`Expected live Arcane inventory of 235, found ${inventory.length}`);
const oldRepoPaths = inventory.map(repoPath);
for (const path of oldRepoPaths) if (!triage.has(path)) throw new Error(`Inventory path absent from triage: ${path}`);

const preScan = scanRoots();
const entries = inventory.map((oldAbsolute) => {
  const oldPath = repoPath(oldAbsolute);
  const row = triage.get(oldPath);
  const newPath = targetFor(oldPath, row);
  const oldConsumers = consumersFor(oldAbsolute, preScan);
  if (retired.has(oldPath) && oldConsumers.length > 0) {
    throw new Error(`Refusing retirement with live consumers: ${oldPath}: ${oldConsumers.join(', ')}`);
  }
  return {
    oldPath,
    triageDisposition: row.triageDisposition,
    resultDisposition: newPath ? 'migrated' : 'retired-unconsumed',
    owners: ownerFromDetail(oldPath, row),
    newPath,
    oldConsumers,
    sha256Before: sha256(oldAbsolute),
    verification: [],
  };
});

const targets = entries.filter((entry) => entry.newPath).map((entry) => entry.newPath);
if (new Set(targets).size !== targets.length) throw new Error('Migration target collision detected');
for (const entry of entries) {
  if (!entry.newPath) continue;
  const target = resolve(root, entry.newPath);
  if (existsSync(target)) throw new Error(`Migration target already exists: ${entry.newPath}`);
}

const absoluteMapping = new Map();
const sourceOrigins = new Map();
for (const entry of entries) {
  const oldAbsolute = resolve(root, entry.oldPath);
  if (!entry.newPath) continue;
  const target = resolve(root, entry.newPath);
  absoluteMapping.set(oldAbsolute, target);
  sourceOrigins.set(target, oldAbsolute);
}
const directoryMapping = new Map([
  [resolve(oldRoot, 'schemas'), resolve(root, 'src/lib/contracts/arcane-schemas')],
  [resolve(oldRoot, 'compatibility/forge'), resolve(root, 'src/lib/host/arcane-compatibility/forge')],
  [resolve(oldRoot, 'policy/inject'), resolve(root, 'src/lib/cognitive/arcane/policy')],
]);

for (const entry of entries) {
  const oldAbsolute = resolve(root, entry.oldPath);
  if (!entry.newPath) {
    rmSync(oldAbsolute);
    continue;
  }
  const target = resolve(root, entry.newPath);
  mkdirSync(dirname(target), { recursive: true });
  renameSync(oldAbsolute, target);
}

for (const path of [...textualFiles(scanRoots()), ...entries.filter((entry) => entry.newPath).map((entry) => resolve(root, entry.newPath))]) {
  if (!existsSync(path) || !statSync(path).isFile()) continue;
  rewriteFile(path, sourceOrigins.get(resolve(path)) ?? path, absoluteMapping, directoryMapping);
}

for (const directory of walk(oldRoot, { includeDocs: true }).sort((a, b) => b.length - a.length)) {
  if (existsSync(directory) && statSync(directory).isDirectory() && readdirSync(directory).length === 0) rmSync(directory);
}
if (existsSync(oldRoot)) {
  const remaining = walk(oldRoot, { includeDocs: true });
  if (remaining.length > 0) throw new Error(`Arcane old root still has ${remaining.length} files`);
  rmSync(oldRoot, { recursive: true });
}

const postScan = scanRoots();
for (const entry of entries) {
  if (!entry.newPath) {
    entry.verification.push('pre-migration consumer scan empty', 'old path removed');
    continue;
  }
  const target = resolve(root, entry.newPath);
  entry.sha256AfterMove = sha256(target);
  entry.newConsumers = consumersFor(target, postScan);
  entry.verification.push('target exists', 'all resolvable imports rewritten');
}

const result = {
  schemaVersion: 1,
  migration: 'P0.5 Arcane package triage execution',
  sourceTriage: repoPath(triagePath),
  generatedAt: new Date().toISOString(),
  inventory: {
    expected: 235,
    observed: entries.length,
    migrated: entries.filter((entry) => entry.newPath).length,
    retiredUnconsumed: entries.filter((entry) => !entry.newPath).length,
  },
  exclusions: [
    'package.json and release manifests remain integration-owner changes',
    'historical provenance references are evidence, not live consumers',
    'naming legacy allowlist remains historical registry data',
  ],
  entries,
};
writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify(result.inventory));
