import { readFileSync } from 'node:fs';
import { basename, join } from 'node:path';

const read = (root, path) => { try { return readFileSync(join(root, path), 'utf8'); } catch { return ''; } };
const unique = (values) => [...new Set(values.map((value) => String(value).trim()).filter(Boolean))].sort();
const record = (path, ecosystem, dependencies, extras = {}) => ({ path, ecosystem, dependencies: unique(dependencies), scripts: unique(extras.scripts ?? []), ...extras });
const pythonName = (value) => String(value).split(/[<>=!~;\s\[]/, 1)[0].trim().toLowerCase().replaceAll('_', '-');

function parseJson(root, path, ecosystem, sections) {
  try {
    const parsed = JSON.parse(read(root, path));
    return record(path, ecosystem, sections.flatMap((section) => Object.keys(parsed[section] ?? {})), {
      scripts: Object.keys(parsed.scripts ?? {}), packageManager: parsed.packageManager ?? null,
    });
  } catch (error) { return record(path, ecosystem, [], { parseError: error.message }); }
}

function parsePyproject(root, path) {
  const text = read(root, path); const dependencies = [];
  for (const match of text.matchAll(/(?:^|\n)\s*dependencies\s*=\s*\[([\s\S]*?)\]/g)) {
    for (const quoted of match[1].matchAll(/['"]([^'"]+)['"]/g)) dependencies.push(pythonName(quoted[1]));
  }
  let section = '';
  for (const line of text.split(/\r?\n/)) {
    section = line.match(/^\s*\[([^\]]+)\]\s*$/)?.[1] ?? section;
    if (!['tool.poetry.dependencies', 'tool.poetry.group.dev.dependencies'].includes(section)) continue;
    const key = line.match(/^\s*([A-Za-z0-9_.-]+)\s*=/)?.[1];
    if (key && key.toLowerCase() !== 'python') dependencies.push(pythonName(key));
  }
  return record(path, 'python', dependencies);
}

function parseRequirements(root, path) {
  return record(path, 'python', read(root, path).split(/\r?\n/).map((line) => line.replace(/\s+#.*$/, '').trim()).filter((line) => line && !line.startsWith('-')).map(pythonName));
}

function parsePom(root, path) {
  const text = read(root, path); const dependencies = [];
  for (const match of text.matchAll(/<(?:dependency|parent)>[\s\S]*?<groupId>\s*([^<]+)\s*<\/groupId>[\s\S]*?<artifactId>\s*([^<]+)\s*<\/artifactId>[\s\S]*?<\/(?:dependency|parent)>/g)) {
    dependencies.push(`${match[1].trim()}:${match[2].trim()}`, match[2].trim());
  }
  return record(path, 'maven', dependencies);
}

function parseGradle(root, path) {
  const text = read(root, path); const dependencies = [];
  for (const match of text.matchAll(/(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s*(?:\(|\s)\s*['"]([^'"]+)['"]/g)) {
    const parts = match[1].split(':'); dependencies.push(match[1], parts.slice(0, 2).join(':'), parts[1]);
  }
  for (const match of text.matchAll(/id\s*(?:\(|\s)\s*['"]([^'"]+)['"]/g)) dependencies.push(match[1]);
  return record(path, 'gradle', dependencies);
}

function parseDotnet(root, path) {
  const text = read(root, path); const dependencies = [];
  for (const match of text.matchAll(/<(?:PackageReference|FrameworkReference)\s+Include=['"]([^'"]+)['"]/g)) dependencies.push(match[1]);
  for (const match of text.matchAll(/<Project\s+Sdk=['"]([^'"]+)['"]/g)) dependencies.push(match[1]);
  return record(path, 'dotnet', dependencies);
}

function parseGo(root, path) {
  const text = read(root, path); const dependencies = [];
  for (const match of text.matchAll(/^\s*require\s+([^\s(]+)\s+/gm)) dependencies.push(match[1]);
  for (const line of (text.match(/require\s*\(([\s\S]*?)\)/)?.[1] ?? '').split(/\r?\n/)) {
    const module = line.trim().match(/^([^\s]+)\s+v/)?.[1]; if (module) dependencies.push(module);
  }
  return record(path, 'go', dependencies);
}

function parseKeyed(root, path, ecosystem, pattern) { return record(path, ecosystem, [...read(root, path).matchAll(pattern)].map((match) => match[1])); }

function parsePubspec(root, path) {
  const dependencies = []; let active = false;
  for (const line of read(root, path).split(/\r?\n/)) {
    if (/^(dependencies|dev_dependencies):\s*$/.test(line)) { active = true; continue; }
    if (/^[A-Za-z_][^:]*:\s*$/.test(line)) { active = false; continue; }
    const name = active ? line.match(/^\s{2}([A-Za-z0-9_.-]+):/)?.[1] : null;
    if (name && name !== 'sdk') dependencies.push(name);
  }
  return record(path, 'dart', dependencies);
}

function parseCargo(root, path) {
  const dependencies = []; let section = '';
  for (const line of read(root, path).split(/\r?\n/)) {
    section = line.match(/^\s*\[([^\]]+)\]/)?.[1] ?? section;
    if (!section.endsWith('dependencies')) continue;
    const name = line.match(/^\s*([A-Za-z0-9_-]+)\s*=/)?.[1]; if (name) dependencies.push(name);
  }
  return record(path, 'cargo', dependencies);
}

export function readEcosystemManifests(root, files) {
  const records = [];
  for (const path of files) {
    const base = basename(path);
    if (base === 'package.json') records.push(parseJson(root, path, 'node', ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']));
    else if (base === 'composer.json') records.push(parseJson(root, path, 'composer', ['require', 'require-dev']));
    else if (base === 'pyproject.toml') records.push(parsePyproject(root, path));
    else if (/^requirements(?:[-_.].*)?\.txt$/i.test(base)) records.push(parseRequirements(root, path));
    else if (base === 'pom.xml') records.push(parsePom(root, path));
    else if (/^build\.gradle(?:\.kts)?$/.test(base)) records.push(parseGradle(root, path));
    else if (/\.(csproj|fsproj|vbproj)$/.test(base)) records.push(parseDotnet(root, path));
    else if (base === 'go.mod') records.push(parseGo(root, path));
    else if (base === 'Gemfile') records.push(parseKeyed(root, path, 'ruby', /^\s*gem\s+['"]([^'"]+)['"]/gm));
    else if (base === 'pubspec.yaml') records.push(parsePubspec(root, path));
    else if (base === 'mix.exs') records.push(parseKeyed(root, path, 'elixir', /\{\s*:([A-Za-z0-9_]+)\s*,/g));
    else if (base === 'Cargo.toml') records.push(parseCargo(root, path));
    else if (base === 'Package.swift') records.push(parseKeyed(root, path, 'swift', /\.product\s*\(\s*name:\s*['"]([^'"]+)['"]/g));
  }
  return records;
}

export function enrichProjectionWithEcosystems(projection, root) {
  if (projection?.state !== 'ready') return projection;
  const byPath = new Map((projection.auditFacts?.packageManifests ?? []).map((item) => [item.path, item]));
  for (const parsed of readEcosystemManifests(root, projection.files ?? [])) {
    const existing = byPath.get(parsed.path) ?? {};
    byPath.set(parsed.path, {
      ...existing, ...parsed,
      dependencies: unique([...(existing.dependencies ?? []), ...(parsed.dependencies ?? [])]),
      scripts: unique([...(existing.scripts ?? []), ...(parsed.scripts ?? [])]),
      packageManager: parsed.packageManager ?? existing.packageManager ?? null,
    });
  }
  return { ...projection, auditFacts: { ...(projection.auditFacts ?? {}), packageManifests: [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path)) } };
}
